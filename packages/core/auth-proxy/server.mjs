#!/usr/bin/env node
/**
 * EverClaw Auth Proxy — Privy JWT authentication for hosted containers
 *
 * Architecture:
 *   Internet → Auth Proxy (:18789) → OpenClaw (:18790, internal)
 *
 * Auth flow:
 *   1. User visits container FQDN
 *   2. If no valid session cookie → serve login page with embedded Privy SDK
 *   3. User authenticates via Privy (Google, email, Apple, etc.)
 *   4. Privy SDK returns access token → browser POSTs to /auth/callback
 *   5. Proxy verifies JWT: ES256 signature, issuer="privy.io", audience=appId, expiration
 *   6. Proxy checks JWT sub === OPENCLAW_OWNER_PRIVY_ID (owner verification)
 *   7. Proxy creates HMAC-signed session cookie (24hr TTL, HttpOnly, Secure-if-HTTPS)
 *   8. Subsequent requests: verify session cookie, inject x-forwarded-user, proxy to OpenClaw
 *   9. WebSocket upgrades also authenticated via session cookie
 *
 * Security properties:
 *   - OpenClaw gateway token never leaves the container (not even used here — trusted-proxy mode)
 *   - InstallOpenClaw.xyz never sees user credentials
 *   - Asymmetric JWT verification (ES256 public key only in container)
 *   - Session cookies: HMAC-SHA256 signed, HttpOnly, Secure (if HTTPS), SameSite=Lax
 *   - Owner identity (sub claim) checked on every JWT verification
 *   - OpenClaw binds to localhost only — no direct external access
 *   - Timing-safe signature comparison prevents timing attacks
 *
 * Environment variables (required):
 *   PRIVY_APP_ID            — Privy app ID (public, from Privy Dashboard)
 *   PRIVY_VERIFICATION_KEY  — Privy ES256 verification key (PEM or JWK, public key)
 *   OPENCLAW_OWNER_PRIVY_ID — Owner's Privy DID (did:privy:xxx)
 *
 * CIG Integration (optional — when set, routes inference through the Central
 * Inference Gateway instead of the in-container Morpheus key):
 *   CIG_MINT_URL            — mint-cig-token endpoint URL
 *   CIG_BINDING_SECRET      — Per-deployment binding secret (from deployments table)
 *   CIG_CONTAINER_FQDN      — This container's public FQDN (e.g. agent.example.com)
 *   CIG_INFERENCE_URL       — cig-inference endpoint URL (overrides OpenClaw model base URL)
 *
 *   VERIFY_OWNER_URL         — Supabase verify-owner function URL (enables dynamic ownership)
 *   VERIFY_OWNER_SECRET      — Shared secret for verify-owner calls
 *   CONTAINER_FQDN           — Container's own FQDN (auto-detected from Host header if not set)
 *
 * Optional:
 *   AUTH_PROXY_PORT          — Port to listen on (default: 18789)
 *   OPENCLAW_INTERNAL_PORT   — OpenClaw internal port (default: 18790)
 *   SESSION_SECRET           — Secret for signing session cookies (auto-generated if not set)
 *   SESSION_TTL_MS           — Session cookie TTL in ms (default: 86400000 = 24 hours)
 *   PRIVY_CLIENT_ID          — Privy client ID for JS SDK (from Dashboard → Settings → Clients)
 *   CIG_FAIL_CLOSED          — When 'true', fail with 503 on CIG mint failure (default: false, graceful fallback)
 */

import { createServer } from 'node:http';
import { randomBytes, timingSafeEqual, createHmac } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import httpProxy from 'http-proxy';
import cookie from 'cookie';
import { importSPKI, importJWK, jwtVerify } from 'jose';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ─── Configuration ───────────────────────────────────────────────────────────

const CONFIG = {
  proxyPort: parseInt(process.env.AUTH_PROXY_PORT || '18789', 10),
  internalPort: parseInt(process.env.OPENCLAW_INTERNAL_PORT || '18790', 10),
  privyAppId: process.env.PRIVY_APP_ID || '',
  privyClientId: process.env.PRIVY_CLIENT_ID || '',
  privyVerificationKey: process.env.PRIVY_VERIFICATION_KEY || '',
  ownerPrivyId: process.env.OPENCLAW_OWNER_PRIVY_ID || '',
  // Dynamic ownership verification (buffer pool mode)
  verifyOwnerUrl: process.env.VERIFY_OWNER_URL || '',
  verifyOwnerSecret: process.env.VERIFY_OWNER_SECRET || '',
  containerFqdn: process.env.CONTAINER_FQDN || '',
  sessionSecret: process.env.SESSION_SECRET || '',
  sessionTtlMs: parseInt(process.env.SESSION_TTL_MS || '86400000', 10), // 24 hours
};

// Dynamic ownership mode: when VERIFY_OWNER_URL is set, ownership is checked
// via Supabase instead of the static OPENCLAW_OWNER_PRIVY_ID env var.
// This enables buffer containers to serve any assigned user without restart.
const DYNAMIC_OWNER_MODE = !!CONFIG.verifyOwnerUrl;

const PRIVY_ISSUER = 'privy.io';
const COOKIE_NAME = 'everclaw_session';
const MAX_BODY_BYTES = 16384; // 16 KB limit for POST bodies

// ─── CIG (Central Inference Gateway) Integration ─────────────────────────────
// When CIG_MINT_URL + CIG_BINDING_SECRET + CIG_CONTAINER_FQDN are all set,
// the auth-proxy mints short-lived CIG tokens and routes model API calls
// through the CIG instead of the in-container Morpheus key. This removes the
// shared Morpheus key from user containers entirely.
//
// Token lifecycle:
//   - Mint on first model API call (or when cached token is about to expire)
//   - Use Service mode (fqdn + binding_secret, no Privy JWT needed)
//   - Cache in memory with TTL tracking
//   - Refresh at 80% of TTL (8 min before 10 min expiry)
//   - On mint failure: fall through to legacy proxy (graceful degradation)

const CIG_CONFIG = {
  mintUrl: process.env.CIG_MINT_URL || '',
  bindingSecret: process.env.CIG_BINDING_SECRET || '',
  containerFqdn: process.env.CIG_CONTAINER_FQDN || '',  // Auto-detected from Host header if not set
  inferenceUrl: process.env.CIG_INFERENCE_URL || '',
  fqdnLocked: !!process.env.CIG_CONTAINER_FQDN,  // Once set (env or auto-detected), don't change
};

const CIG_ENABLED = !!(CIG_CONFIG.mintUrl && CIG_CONFIG.bindingSecret && CIG_CONFIG.inferenceUrl);

// When CIG_FAIL_CLOSED=true, if CIG token minting fails, return 503 instead
// of falling back to the legacy in-container Morpheus key. Recommended for
// production: ensures the shared key is never used when CIG is expected.
// When false (default): graceful degradation — falls back to legacy proxy on
// mint failure. Useful during migration/testing.
const CIG_FAIL_CLOSED = process.env.CIG_FAIL_CLOSED === 'true';

// In-memory CIG token cache
let cigTokenCache = {
  token: null,       // The CIG JWT string
  expiresAt: 0,     // Unix timestamp (ms) when token expires
  refreshing: false, // Mutex: prevent concurrent refresh calls
};

const CIG_TOKEN_TTL_MS = 600_000;  // 10 min (must match mint-cig-token TOKEN_TTL_SECONDS)
const CIG_REFRESH_MARGIN = 0.2;    // Refresh at 80% of TTL (2 min before expiry)

// Timing-safe string comparison (lengths must already match before calling).
// Wraps crypto.timingSafeEqual, which requires equal-length buffers.
function timingSafeEqualStr(a, b) {
  const ab = Buffer.from(String(a), 'utf8');
  const bb = Buffer.from(String(b), 'utf8');
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

// Get the container FQDN. If not set via env, auto-detect from first request's Host header.
// Once set (either way), it's locked and won't change — this prevents Host header spoofing
// after initial detection.
function getContainerFqdn() {
  return CIG_CONFIG.containerFqdn;
}

// Auto-detect FQDN from Host header (one-time, only if not already set)
// Call this early in request handling for CIG-enabled containers without env FQDN.
function maybeAutoDetectFqdn(reqHost) {
  if (CIG_CONFIG.fqdnLocked || !CIG_ENABLED) return;
  if (!reqHost || reqHost === 'localhost' || reqHost.startsWith('127.') || reqHost.startsWith('[::1]')) return;
  // Strip port if present
  const fqdn = reqHost.split(':')[0];
  if (fqdn && fqdn.includes('.')) {
    CIG_CONFIG.containerFqdn = fqdn;
    CIG_CONFIG.fqdnLocked = true;
    console.log(`[cig] Auto-detected container FQDN from Host header: ${fqdn}`);
  }
}

async function mintCigToken() {
  if (!CIG_ENABLED) return null;

  const fqdn = getContainerFqdn();
  if (!fqdn) {
    // FQDN not yet auto-detected — this can happen on the very first request before
    // maybeAutoDetectFqdn() has been called. Return null to skip CIG for this request;
    // subsequent requests will have the FQDN.
    console.warn('[cig] Cannot mint token: FQDN not yet detected (will auto-detect from Host header)');
    return null;
  }

  const now = Date.now();
  const refreshAt = cigTokenCache.expiresAt - (CIG_TOKEN_TTL_MS * CIG_REFRESH_MARGIN);

  // Return cached token if still valid and not time to refresh.
  if (cigTokenCache.token && now < refreshAt) {
    return cigTokenCache.token;
  }

  // Prevent stampede: if a refresh is already in flight, wait briefly and return
  // whatever we have (even if slightly stale, as long as not expired).
  if (cigTokenCache.refreshing) {
    // Wait up to 2s for the in-flight refresh to complete.
    for (let i = 0; i < 20; i++) {
      await new Promise(r => setTimeout(r, 100));
      if (!cigTokenCache.refreshing && cigTokenCache.token && Date.now() < cigTokenCache.expiresAt) {
        return cigTokenCache.token;
      }
    }
    // Still refreshing — return stale token if not expired.
    if (cigTokenCache.token && Date.now() < cigTokenCache.expiresAt) {
      return cigTokenCache.token;
    }
    return null; // Can't mint right now.
  }

  cigTokenCache.refreshing = true;
  try {
    console.log('[cig] Minting CIG token (service mode)...');

    const resp = await fetch(CIG_CONFIG.mintUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        fqdn: getContainerFqdn(),
        binding_secret: CIG_CONFIG.bindingSecret,
      }),
      signal: AbortSignal.timeout(15_000), // 15s timeout
    });

    if (!resp.ok) {
      const errText = await resp.text().catch(() => '');
      // Redact error body if it might contain secrets
      const safeErr = errText.includes('binding_secret') ? '[redacted]' : errText.slice(0, 200);
      console.error(`[cig] Mint failed: HTTP ${resp.status} ${safeErr}`);
      return cigTokenCache.token && Date.now() < cigTokenCache.expiresAt
        ? cigTokenCache.token  // Return stale token if available
        : null;                // No token available
    }

    const data = await resp.json();
    if (!data.token) {
      console.error('[cig] Mint response missing token:', JSON.stringify(data).slice(0, 200));
      return null;
    }

    cigTokenCache.token = data.token;
    cigTokenCache.expiresAt = now + (data.expires_in || 600) * 1000;
    console.log(`[cig] Token minted, expires in ${data.expires_in}s`);
    return cigTokenCache.token;
  } catch (err) {
    console.error('[cig] Mint error:', err.message);
    return cigTokenCache.token && Date.now() < cigTokenCache.expiresAt
      ? cigTokenCache.token
      : null;
  } finally {
    cigTokenCache.refreshing = false;
  }
}


// ─── Rate Limiter (in-memory, per-IP) ────────────────────────────────────────
// Sliding window: max AUTH_RATE_LIMIT attempts per AUTH_RATE_WINDOW_MS per IP.
// Prevents brute-force token guessing and ES256 verification CPU exhaustion.

const AUTH_RATE_LIMIT = 5;
const AUTH_RATE_WINDOW_MS = 60_000; // 1 minute
const rateLimitMap = new Map();

function isRateLimited(ip) {
  const now = Date.now();
  let entry = rateLimitMap.get(ip);

  if (!entry) {
    entry = { timestamps: [] };
    rateLimitMap.set(ip, entry);
  }

  // Evict timestamps outside the window
  entry.timestamps = entry.timestamps.filter(t => now - t < AUTH_RATE_WINDOW_MS);

  if (entry.timestamps.length >= AUTH_RATE_LIMIT) {
    return true;
  }

  entry.timestamps.push(now);
  return false;
}

// Periodic cleanup to prevent memory leak from stale IPs
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of rateLimitMap) {
    entry.timestamps = entry.timestamps.filter(t => now - t < AUTH_RATE_WINDOW_MS);
    if (entry.timestamps.length === 0) rateLimitMap.delete(ip);
  }
}, AUTH_RATE_WINDOW_MS).unref();

// ─── Startup Validation ──────────────────────────────────────────────────────

function validateConfig() {
  const required = [
    ['PRIVY_APP_ID', CONFIG.privyAppId],
    ['PRIVY_VERIFICATION_KEY', CONFIG.privyVerificationKey],
  ];

  // In static mode, OPENCLAW_OWNER_PRIVY_ID is required.
  // In dynamic mode, VERIFY_OWNER_URL + VERIFY_OWNER_SECRET are required instead.
  if (DYNAMIC_OWNER_MODE) {
    if (!CONFIG.verifyOwnerSecret) {
      required.push(['VERIFY_OWNER_SECRET', CONFIG.verifyOwnerSecret]);
    }
  } else {
    required.push(['OPENCLAW_OWNER_PRIVY_ID', CONFIG.ownerPrivyId]);
  }

  // CIG without FQDN: warn but allow (FQDN will be auto-detected from first request Host header).
  // This is needed for buffer pool provisioning where FQDN isn't known until after lease creation.
  if (CIG_ENABLED && !CIG_CONFIG.containerFqdn) {
    console.warn('⚠️  CIG enabled but CIG_CONTAINER_FQDN not set — will auto-detect from first request Host header.');
    console.warn('   For production, set CIG_CONTAINER_FQDN explicitly for tighter security.');
  }

  // Validate CIG URLs are well-formed at startup (fail fast, not on first inference)
  if (CIG_ENABLED) {
    try {
      new URL(CIG_CONFIG.mintUrl);
      new URL(CIG_CONFIG.inferenceUrl);
    } catch (urlErr) {
      console.error('❌ CIG URL validation failed:', urlErr.message);
      console.error('   CIG_MINT_URL and CIG_INFERENCE_URL must be valid URLs.');
      process.exit(1);
    }
  }

  const missing = required.filter(([, value]) => !value);
  if (missing.length > 0) {
    console.error('❌ Auth proxy: missing required environment variables:');
    missing.forEach(([name]) => console.error(`   - ${name}`));
    console.error('');
    console.error('   Auth proxy requires Privy configuration to start.');
    console.error('   Set these variables in your deploy-agent or docker-compose.');
    process.exit(1);
  }

  // Generate session secret if not provided (ephemeral — sessions won't survive restarts)
  if (!CONFIG.sessionSecret) {
    CONFIG.sessionSecret = randomBytes(32).toString('hex');
    console.log('🔑 Session secret generated (ephemeral — sessions reset on container restart)');
  }

  console.log('✅ Auth proxy configuration validated');
  console.log(`   App ID: ${CONFIG.privyAppId}`);
  if (DYNAMIC_OWNER_MODE) {
    console.log(`   Mode:   DYNAMIC (verify-owner via Supabase)`);
    console.log(`   URL:    ${CONFIG.verifyOwnerUrl}`);
  } else {
    console.log(`   Mode:   STATIC (env var owner)`);
    console.log(`   Owner:  ${CONFIG.ownerPrivyId}`);
  }
}

// ─── Session Management ─────────────────────────────────────────────────────
// Custom HMAC-signed session tokens (no JWT library dependency for sessions).
// Format: base64url(JSON payload) + "." + hex(HMAC-SHA256 signature)

function signSession(sub) {
  const now = Date.now();
  const payload = JSON.stringify({
    sub,
    iat: Math.floor(now / 1000),
    exp: Math.floor((now + CONFIG.sessionTtlMs) / 1000),
  });
  const signature = createHmac('sha256', CONFIG.sessionSecret)
    .update(payload)
    .digest('hex');
  return Buffer.from(`${payload}.${signature}`).toString('base64url');
}

function verifySession(sessionCookie) {
  try {
    const decoded = Buffer.from(sessionCookie, 'base64url').toString('utf8');
    const dotIndex = decoded.lastIndexOf('.');
    if (dotIndex === -1) return null;

    const payloadJson = decoded.slice(0, dotIndex);
    const signature = decoded.slice(dotIndex + 1);
    if (!payloadJson || !signature) return null;

    // Verify HMAC using timing-safe comparison
    const expectedSignature = createHmac('sha256', CONFIG.sessionSecret)
      .update(payloadJson)
      .digest('hex');

    const sigBuffer = Buffer.from(signature, 'hex');
    const expectedBuffer = Buffer.from(expectedSignature, 'hex');

    if (sigBuffer.length !== expectedBuffer.length) return null;
    if (!timingSafeEqual(sigBuffer, expectedBuffer)) return null;

    const payload = JSON.parse(payloadJson);

    // Check expiration
    if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000)) return null;

    // Check required fields
    if (!payload.sub) return null;

    return payload;
  } catch {
    return null;
  }
}

// ─── Privy JWT Verification ───────────────────────────────────────────────────

let verificationKey = null;

async function initializeVerificationKey() {
  try {
    // Docker env vars encode multi-line PEMs with literal \n — convert to real newlines
    const keyMaterial = CONFIG.privyVerificationKey.trim().replace(/\\n/g, '\n');

    if (keyMaterial.startsWith('{')) {
      // JWK format (JSON object)
      const jwk = JSON.parse(keyMaterial);
      verificationKey = await importJWK(jwk, 'ES256');
    } else if (keyMaterial.includes('-----BEGIN PUBLIC KEY-----')) {
      // PEM-encoded SPKI public key
      verificationKey = await importSPKI(keyMaterial, 'ES256');
    } else {
      // Raw base64 key body (no PEM headers) — wrap in PEM armor and import.
      // This handles the case where PRIVY_VERIFICATION_KEY is stored as just the
      // base64 key material (e.g. "MFkwEwYHKoZIzj0C...") without PEM headers.
      const wrappedPem = `-----BEGIN PUBLIC KEY-----\n${keyMaterial}\n-----END PUBLIC KEY-----`;
      try {
        verificationKey = await importSPKI(wrappedPem, 'ES256');
      } catch {
        // Fall back: maybe it's base64-encoded PEM
        const decoded = Buffer.from(keyMaterial, 'base64').toString('utf8');
        if (decoded.includes('-----BEGIN PUBLIC KEY-----')) {
          verificationKey = await importSPKI(decoded, 'ES256');
        } else {
          throw new Error(
            'Unrecognized key format. Expected PEM (-----BEGIN PUBLIC KEY-----), ' +
            'JWK ({...}), or raw base64 key body'
          );
        }
      }
    }

    console.log('✅ Privy verification key loaded');
  } catch (error) {
    console.error('❌ Failed to load Privy verification key:', error.message);
    process.exit(1);
  }
}

async function verifyPrivyJwt(token, reqHost) {
  try {
    const { payload } = await jwtVerify(token, verificationKey, {
      issuer: PRIVY_ISSUER,
      audience: CONFIG.privyAppId,
      algorithms: ['ES256'],
    });

    // Verify owner identity
    if (DYNAMIC_OWNER_MODE) {
      // Dynamic mode: check ownership via Supabase verify-owner function
      const fqdn = CONFIG.containerFqdn || reqHost || '';
      if (!fqdn) {
        console.log('[auth] Dynamic mode: no FQDN available for ownership check');
        return { valid: false, reason: 'no_fqdn' };
      }

      try {
        const verifyResp = await fetch(CONFIG.verifyOwnerUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${CONFIG.verifyOwnerSecret}`,
          },
          body: JSON.stringify({
            fqdn: fqdn.replace(/:\d+$/, ''), // strip port if present
            privy_user_id: payload.sub,
          }),
          signal: AbortSignal.timeout(5000), // 5s timeout
        });

        if (!verifyResp.ok) {
          console.log(`[auth] verify-owner returned ${verifyResp.status}`);
          return { valid: false, reason: 'verify_failed' };
        }

        const result = await verifyResp.json();
        if (!result.authorized) {
          console.log(`[auth] Dynamic owner check: not authorized (sub=${payload.sub}, fqdn=${fqdn})`);
          return { valid: false, reason: 'owner_mismatch' };
        }

        console.log(`[auth] Dynamic owner verified: sub=${payload.sub}, fqdn=${fqdn}`);
      } catch (fetchErr) {
        console.error(`[auth] verify-owner fetch error: ${fetchErr.message}`);
        // Fail CLOSED for security — deny access if we can't verify
        return { valid: false, reason: 'verify_unavailable' };
      }
    } else {
      // Static mode: check against env var (original behavior)
      if (payload.sub !== CONFIG.ownerPrivyId) {
        console.log(`[auth] Owner mismatch: JWT sub=${payload.sub}, expected=${CONFIG.ownerPrivyId}`);
        return { valid: false, reason: 'owner_mismatch' };
      }
    }

    return { valid: true, payload };
  } catch (error) {
    console.log(`[auth] JWT verification failed: ${error.code || error.message}`);
    return { valid: false, reason: error.code || error.message };
  }
}

// ─── Login Page ─────────────────────────────────────────────────────────────

let loginPageHtml = null;
let loginBundleJs = null;

async function loadLoginPage() {
  try {
    const htmlPath = join(__dirname, 'login.html');
    let html = await readFile(htmlPath, 'utf8');

    // Inject configuration values at serve time
    html = html.replace(/__PRIVY_APP_ID__/g, CONFIG.privyAppId);
    html = html.replace(/__PRIVY_CLIENT_ID__/g, CONFIG.privyClientId);

    loginPageHtml = html;
    console.log('✅ Login page loaded');

    // Load the bundled JS (built at Docker build time by esbuild)
    const bundlePath = join(__dirname, 'dist', 'login-bundle.js');
    loginBundleJs = await readFile(bundlePath, 'utf8');
    console.log(`✅ Login bundle loaded (${Math.round(loginBundleJs.length / 1024)}KB)`);
  } catch (error) {
    console.error('❌ Failed to load login page:', error.message);
    process.exit(1);
  }
}

function serveLoginPage(res, statusCode = 200) {
  res.writeHead(statusCode, {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
  });
  res.end(loginPageHtml);
}

// ─── Cookie Helpers ──────────────────────────────────────────────────────────

function getCookieOptions(req) {
  const proto = req.headers['x-forwarded-proto'] || req.headers['x-forwarded-protocol'] || '';
  const isSecure = proto === 'https' || req.socket.encrypted;

  return {
    httpOnly: true,
    secure: isSecure,
    sameSite: 'Lax',   // Lax allows initial navigation from external links
    path: '/',
    maxAge: Math.floor(CONFIG.sessionTtlMs / 1000),
  };
}

function clearCookie(req) {
  const opts = getCookieOptions(req);
  opts.maxAge = 0;
  return cookie.serialize(COOKIE_NAME, '', opts);
}

// ─── Body Parser (bounded) ──────────────────────────────────────────────────

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;

    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        req.destroy();
        reject(new Error('Body too large'));
        return;
      }
      chunks.push(chunk);
    });

    req.on('end', () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString()));
      } catch {
        reject(new Error('Invalid JSON'));
      }
    });

    req.on('error', reject);
  });
}

// ─── Reverse Proxy ──────────────────────────────────────────────────────────

const proxy = httpProxy.createProxyServer({
  target: `http://127.0.0.1:${CONFIG.internalPort}`,
  ws: true,
  xfwd: true,
});

proxy.on('error', (error, req, res) => {
  console.error('[proxy] Error:', error.message);
  if (res && typeof res.writeHead === 'function' && !res.headersSent) {
    res.writeHead(502, { 'Content-Type': 'text/plain' });
    res.end('Bad Gateway — OpenClaw may still be starting');
  }
});

// ─── Request Handler ─────────────────────────────────────────────────────────

// ─── CIG Proxy Helpers ─────────────────────────────────────────────────────
// When CIG is enabled, model API calls are proxied to the CIG service instead
// of OpenClaw directly. The CIG holds the master Morpheus key and enforces
// per-user budgets, metering, and revocation.

function isModelApiCall(pathname) {
  // OpenAI-compatible model API paths that should go through CIG.
  // Note: /v1/models is a GET and doesn't require a CIG token (cig-inference
  // allows unauthenticated access to /v1/models), but we route it through
  // CIG anyway for consistency and to avoid exposing the Morpheus key.
  return pathname === '/v1/chat/completions' ||
         pathname === '/v1/models' ||
         pathname.startsWith('/v1/chat/completions/');  // potential future sub-paths
}

async function handleCigProxy(req, res, session) {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

  // Re-validate the (parser-normalized) pathname against the model-API
  // whitelist BEFORE minting a token — defense-in-depth, and avoids a wasted
  // mint on a rejected path.
  if (!isModelApiCall(url.pathname)) {
    if (!res.headersSent) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: { message: 'not_found', type: 'invalid_request' } }));
    }
    return;
  }

  const cigToken = await mintCigToken();
  if (!cigToken) {
    if (CIG_FAIL_CLOSED) {
      if (!res.headersSent) {
        res.writeHead(503, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: { message: 'inference_unavailable', type: 'server_error' } }));
      }
      return;
    }
    console.warn('[cig] No CIG token available — falling back to legacy proxy');
    proxy.web(req, res);
    return;
  }

  // Construct CIG URL safely to prevent SSRF via path traversal.
  // NOTE: do NOT use `new URL(url.pathname, cigBase)` — a leading-slash path
  // REPLACES the base's path entirely, dropping the Supabase
  // `/functions/v1/cig-inference` prefix → 404 "requested path is invalid"
  // (June 10 incident). Append the normalized pathname to the base PATH instead.
  // CIG_INFERENCE_URL must not carry a query string (it would be dropped here).
  const cigBase = new URL(CIG_CONFIG.inferenceUrl);
  const targetPath = cigBase.pathname.replace(/\/+$/, '') + url.pathname;
  const cigUrl = new URL(targetPath + (url.search || ''), cigBase).toString();

  // Collect request body for forwarding.
  const body = await collectBody(req);
  if (body === null) {
    // Body too large or read error.
    if (!res.headersSent) {
      res.writeHead(413, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: { message: 'request_entity_too_large', type: 'invalid_request' } }));
    }
    return;
  }

  // Build headers for CIG.
  const cigHeaders = {
    'Content-Type': req.headers['content-type'] || 'application/json',
    'Authorization': `Bearer ${cigToken}`,
    'X-Container-Fqdn': getContainerFqdn(),
    'X-Forwarded-User': session.sub,
  };

  try {
    const cigResp = await fetch(cigUrl, {
      method: req.method,
      headers: cigHeaders,
      body: req.method !== 'GET' ? body : undefined,
      signal: AbortSignal.timeout(120_000), // 2min timeout for inference
    });

    // Stream the response back.
    const respHeaders = {};
    for (const [key, value] of cigResp.headers.entries()) {
      // Forward all headers except transfer-encoding (node handles chunking).
      if (key.toLowerCase() !== 'transfer-encoding') {
        respHeaders[key] = value;
      }
    }

    res.writeHead(cigResp.status, respHeaders);

    if (cigResp.body) {
      const reader = cigResp.body.getReader();
      const MAX_RESPONSE_BYTES = 50 * 1024 * 1024; // 50 MiB response limit
      let bytesRead = 0;
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          bytesRead += value.length;
          if (bytesRead > MAX_RESPONSE_BYTES) {
            console.error(`[cig] Response exceeded ${MAX_RESPONSE_BYTES} bytes, aborting`);
            reader.cancel().catch(() => {});
            res.destroy(); // Force-close connection on oversized response
            return;
          }
          res.write(value);
        }
      } catch (streamErr) {
        console.error('[cig] Stream read error:', streamErr.message);
      } finally {
        reader.cancel().catch(() => {});
      }
    }

    res.end();
  } catch (err) {
    console.error('[cig] Proxy error:', err.message);
    if (!res.headersSent) {
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: { message: 'cig_upstream_error', type: 'server_error' } }));
    } else {
      res.end();
    }
  }
}

function collectBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    let size = 0;
    const limit = 10 * 1024 * 1024; // 10 MB for model payloads (larger than auth bodies)

    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > limit) {
        req.destroy();
        resolve(null);
        return;
      }
      chunks.push(chunk);
    });

    req.on('end', () => {
      resolve(Buffer.concat(chunks));
    });

    req.on('error', () => {
      resolve(null);
    });
  });
}

async function handleRequest(req, res) {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = url.pathname;

  // Auto-detect container FQDN from Host header (one-time, for buffer pool flow)
  maybeAutoDetectFqdn(req.headers.host);

  // ── Health check (no auth) ──
  if (pathname === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', authProxy: true }));
    return;
  }

  // ── Login bundle JS (built at Docker build time, no CDN dependency) ──
  if (pathname === '/auth/login-bundle.js' && req.method === 'GET') {
    res.writeHead(200, {
      'Content-Type': 'application/javascript; charset=utf-8',
      'Cache-Control': 'public, max-age=86400, immutable',
      'X-Content-Type-Options': 'nosniff',
    });
    res.end(loginBundleJs);
    return;
  }

  // ── Auth callback — receives Privy access token from login page ──
  if (pathname === '/auth/callback' && req.method === 'POST') {
    // Rate limit: 5 attempts per minute per IP
    const clientIp = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
    if (isRateLimited(clientIp)) {
      res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '60' });
      res.end(JSON.stringify({ error: 'rate_limited', retryAfter: 60 }));
      return;
    }

    try {
      const data = await readBody(req);
      const { token } = data;

      if (!token || typeof token !== 'string') {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'missing_token' }));
        return;
      }

      const reqHost = req.headers.host || '';
      const result = await verifyPrivyJwt(token, reqHost);

      if (!result.valid) {
        res.writeHead(result.reason === 'owner_mismatch' ? 403 : 401, {
          'Content-Type': 'application/json',
        });
        res.end(JSON.stringify({ error: 'auth_failed', reason: result.reason }));
        return;
      }

      // Create signed session cookie
      const sessionValue = signSession(result.payload.sub);
      const cookieOpts = getCookieOptions(req);

      res.writeHead(200, {
        'Content-Type': 'application/json',
        'Set-Cookie': cookie.serialize(COOKIE_NAME, sessionValue, cookieOpts),
      });
      res.end(JSON.stringify({ success: true }));
    } catch (error) {
      console.error('[auth] Callback error:', error.message);
      const status = error.message === 'Body too large' ? 413 : 400;
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: error.message }));
    }
    return;
  }

  // ── Logout ──
  if (pathname === '/auth/logout' && req.method === 'POST') {
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Set-Cookie': clearCookie(req),
    });
    res.end(JSON.stringify({ success: true }));
    return;
  }

  // ── CIG routing for internal (localhost) model API calls ──
  // When CIG is enabled, OpenClaw inside the container calls localhost:18789/v1/...
  // These internal requests don't have session cookies (they're not from a browser).
  // We bypass session auth for localhost model API calls and route directly to CIG.
  //
  // Defense-in-depth (two independent gates, BOTH required):
  //   1. Loopback source — req.socket.remoteAddress must be 127.0.0.1 / ::1.
  //   2. Internal secret — Authorization: Bearer <CIG_BINDING_SECRET>. The
  //      docker-entrypoint sets the mor-gateway provider apiKey to the binding
  //      secret, so OpenClaw sends it on every call. The auth-proxy port is exposed
  //      to the internet via Fred ingress, so the loopback check alone is NOT
  //      sufficient — the secret prevents a spoofed-loopback external request from
  //      bypassing browser-session auth and draining the owner's CIG budget.
  if (CIG_ENABLED && isModelApiCall(pathname)) {
    const remoteAddr = req.socket.remoteAddress || '';
    const isLocalhost = remoteAddr === '127.0.0.1' || remoteAddr === '::1' || remoteAddr === '::ffff:127.0.0.1';

    // Extract the bearer token OpenClaw sent (provider apiKey = binding secret).
    const authHeader = req.headers['authorization'] || '';
    const bearer = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
    const secretOk = CIG_CONFIG.bindingSecret.length > 0 &&
      bearer.length === CIG_CONFIG.bindingSecret.length &&
      timingSafeEqualStr(bearer, CIG_CONFIG.bindingSecret);

    if (isLocalhost && secretOk) {
      // Internal request from OpenClaw — use a synthetic session with the deployment owner.
      // The CIG token (minted with binding_secret) validates this container's identity
      // and resolves the budget owner from the deployment record server-side.
      const ownerSub = CONFIG.ownerPrivyId || 'internal-cig-caller';
      const internalSession = { sub: ownerSub };
      console.log(`[cig] Internal model API call from ${remoteAddr}: ${pathname}`);
      // Strip the internal secret before forwarding — handleCigProxy sets its own
      // CIG token in the Authorization header.
      delete req.headers['authorization'];
      return handleCigProxy(req, res, internalSession);
    }

    if (isLocalhost && !secretOk) {
      // Loopback but missing/wrong internal secret — likely a misconfiguration or
      // an attacker probing via a spoofed-loopback path. Refuse explicitly.
      console.warn(`[cig] Internal model API call from ${remoteAddr} rejected: bad/missing internal secret`);
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: { message: 'unauthorized', type: 'auth_error' } }));
      return;
    }
    // Non-loopback model API calls fall through to the normal browser-session path below.
  }

  // ── Check session for all other requests ──
  const cookies = cookie.parse(req.headers.cookie || '');
  const sessionCookie = cookies[COOKIE_NAME];

  if (!sessionCookie) {
    serveLoginPage(res);
    return;
  }

  const session = verifySession(sessionCookie);

  if (!session) {
    // Invalid or expired session — clear cookie and show login in one response
    // (cannot call serveLoginPage separately — writeHead would be called twice)
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Set-Cookie': clearCookie(req),
    });
    res.end(loginPageHtml);
    return;
  }

  // ── Valid session — proxy to OpenClaw with trusted-proxy identity header ──
  // Strip any client-supplied identity headers to prevent spoofing
  delete req.headers['x-forwarded-user'];

  // Inject verified user identity for OpenClaw trusted-proxy mode
  req.headers['x-forwarded-user'] = session.sub;

  // ── CIG routing: intercept model API calls from authenticated browser ──
  // When CIG is enabled, requests to /v1/chat/completions and /v1/models
  // are routed through the Central Inference Gateway instead of the
  // in-container Morpheus key. The CIG holds the master key server-side.
  if (CIG_ENABLED && isModelApiCall(pathname)) {
    return handleCigProxy(req, res, session);
  }

  proxy.web(req, res);
}

// ─── WebSocket Upgrade ──────────────────────────────────────────────────────

function handleUpgrade(req, socket, head) {
  const cookies = cookie.parse(req.headers.cookie || '');
  const sessionCookie = cookies[COOKIE_NAME];

  if (!sessionCookie) {
    socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
    socket.destroy();
    return;
  }

  const session = verifySession(sessionCookie);
  if (!session) {
    socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
    socket.destroy();
    return;
  }

  // Strip and inject identity header
  delete req.headers['x-forwarded-user'];
  req.headers['x-forwarded-user'] = session.sub;

  proxy.ws(req, socket, head, (error) => {
    console.error('[proxy] WebSocket upgrade error:', error.message);
    socket.destroy();
  });
}

// ─── Startup ─────────────────────────────────────────────────────────────────

async function main() {
  console.log('');
  console.log('🔒 EverClaw Auth Proxy');
  console.log('');

  validateConfig();
  await initializeVerificationKey();
  await loadLoginPage();

  const server = createServer(handleRequest);
  server.on('upgrade', handleUpgrade);

  server.listen(CONFIG.proxyPort, '0.0.0.0', () => {
    console.log(`✅ Auth proxy listening on :${CONFIG.proxyPort}`);
    console.log(`   Proxying authenticated requests to OpenClaw :${CONFIG.internalPort}`);
    if (CIG_ENABLED) {
      console.log(`   CIG mode: ENABLED`);
      console.log(`   CIG mint: ${CIG_CONFIG.mintUrl}`);
      console.log(`   CIG inference: ${CIG_CONFIG.inferenceUrl}`);
      console.log(`   Container FQDN: ${CIG_CONFIG.containerFqdn}`);
    } else {
      console.log(`   CIG mode: disabled (set CIG_MINT_URL + CIG_BINDING_SECRET + CIG_CONTAINER_FQDN + CIG_INFERENCE_URL to enable)`);
    }
    console.log('');
  });

  // Graceful shutdown
  const shutdown = () => {
    console.log('🛑 Auth proxy shutting down...');
    server.close(() => {
      proxy.close();
      console.log('✅ Auth proxy stopped');
      process.exit(0);
    });
    // Force exit after 5s if connections hang
    setTimeout(() => process.exit(1), 5000).unref();
  };

  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

main().catch((error) => {
  console.error('❌ Auth proxy fatal error:', error);
  process.exit(1);
});
