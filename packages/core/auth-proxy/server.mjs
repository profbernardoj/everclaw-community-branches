#!/usr/bin/env node
/**
 * OpenClaw Auth Proxy — Privy JWT authentication for hosted containers
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
 * Optional:
 *   AUTH_PROXY_PORT          — Port to listen on (default: 18789)
 *   OPENCLAW_INTERNAL_PORT   — OpenClaw internal port (default: 18790)
 *   SESSION_SECRET           — Secret for signing session cookies (auto-generated if not set)
 *   SESSION_TTL_MS           — Session cookie TTL in ms (default: 86400000 = 24 hours)
 *   PRIVY_CLIENT_ID          — Privy client ID for JS SDK (from Dashboard → Settings → Clients)
 *   VERIFY_OWNER_URL         — Supabase verify-owner function URL (enables dynamic ownership)
 *   VERIFY_OWNER_SECRET      — Shared secret for verify-owner calls
 *   CONTAINER_FQDN           — Container's own FQDN (auto-detected from Host header if not set)
 */

import { createServer } from 'node:http';
import { randomBytes, timingSafeEqual, createHmac, createHash } from 'node:crypto';
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
  sessionSecret: process.env.SESSION_SECRET || '',
  sessionTtlMs: parseInt(process.env.SESSION_TTL_MS || '86400000', 10), // 24 hours
  // Dynamic ownership verification (buffer pool mode)
  verifyOwnerUrl: process.env.VERIFY_OWNER_URL || '',
  verifyOwnerSecret: process.env.VERIFY_OWNER_SECRET || '',
  containerFqdn: process.env.CONTAINER_FQDN || '',
  // SSO handoff: dedicated secret for HS256 JWT verification (separate from verify-owner)
  // Fetched from Supabase at startup to avoid env var pipeline mismatches.
  // The env var is used as initial value; Supabase fetch overrides it in dynamic mode.
  handoffSigningSecret: (process.env.HANDOFF_SIGNING_SECRET || '').trim(),
  // Supabase endpoint to fetch HANDOFF_SIGNING_SECRET (avoids Manifest env var mismatch)
  getHandoffSecretUrl: process.env.GET_HANDOFF_SECRET_URL || '',
  // Consume-handoff endpoint (Supabase Edge Function) for DB-backed single-use enforcement
  consumeHandoffUrl: process.env.CONSUME_HANDOFF_URL || '',
  // Login-page branding (set by provisioner; lobster is the OpenClaw default)
  brandName: process.env.BRAND_NAME || 'OpenClaw',
  brandIcon: process.env.BRAND_ICON || '🦞',
  brandTagline: process.env.BRAND_TAGLINE || 'Your sovereign AI agent',
};

// Dynamic ownership mode: when VERIFY_OWNER_URL is set, ownership is checked
// via Supabase instead of the static OPENCLAW_OWNER_PRIVY_ID env var.
// This enables buffer containers to serve any assigned user without restart.
const DYNAMIC_OWNER_MODE = !!CONFIG.verifyOwnerUrl;

const PRIVY_ISSUER = 'privy.io';
const COOKIE_NAME = 'everclaw_session';
const MAX_BODY_BYTES = 16384; // 16 KB limit for POST bodies

// ─── CIG (Central Inference Gateway) Configuration ───────────────────────────
// When CIG env vars are set, the auth-proxy acts as a CIG proxy for internal
// OpenClaw inference requests. OpenClaw calls localhost:18789/v1/chat/completions
// and the proxy mints a CIG token, then forwards to the external CIG endpoint.
const CIG_CONFIG = {
  mintUrl: process.env.CIG_MINT_URL || '',
  inferenceUrl: process.env.CIG_INFERENCE_URL || '',
  bindingSecret: process.env.CIG_BINDING_SECRET || '',
  containerFqdn: process.env.CIG_CONTAINER_FQDN || process.env.CONTAINER_FQDN || '',
  fqdnLocked: !!(process.env.CIG_CONTAINER_FQDN || process.env.CONTAINER_FQDN),
};
const CIG_ENABLED = !!(CIG_CONFIG.mintUrl && CIG_CONFIG.inferenceUrl && CIG_CONFIG.bindingSecret);
// Optional suffix restriction for auto-detected FQDNs (e.g. ".manifest0.net")
const CIG_ALLOWED_FQDN_SUFFIX = process.env.CIG_ALLOWED_FQDN_SUFFIX || '';
const CIG_TOKEN_TTL_MS = 10 * 60 * 1000;    // 10 minutes
const CIG_TOKEN_REFRESH_MS = 60_000;         // Refresh 60s before expiry
const CIG_FETCH_TIMEOUT_MS = 10_000;         // 10s timeout for CIG HTTP calls
const CIG_MAX_BODY_BYTES = 1024 * 1024;      // 1 MB max inference request body
const CIG_INFERENCE_TIMEOUT_MS = 5 * 60 * 1000; // 5 min timeout for inference (streaming)
let cigTokenCache = { token: '', expiresAt: 0 };

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

async function validateConfig() {
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
  if (CONFIG.handoffSigningSecret) {
    console.log(`   SSO:    ENABLED (env var — will verify via Supabase fetch)`);
  } else {
    console.log(`   SSO:    DISABLED (set HANDOFF_SIGNING_SECRET to enable)`);
  }

  // ── Fetch HANDOFF_SIGNING_SECRET from Supabase ──
  // In dynamic mode, the env var passed through Manifest may not match Supabase.
  // Fetch the canonical secret from Supabase to guarantee JWT sign/verify alignment.
  if (DYNAMIC_OWNER_MODE && CONFIG.verifyOwnerSecret && CONFIG.verifyOwnerUrl) {
    const handoffUrl = CONFIG.getHandoffSecretUrl ||
      CONFIG.verifyOwnerUrl.replace('verify-owner', 'get-handoff-secret');
    try {
      const resp = await fetch(handoffUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${CONFIG.verifyOwnerSecret}`,
        },
        body: '{}',
        signal: AbortSignal.timeout(10000),
      });
      if (resp.ok) {
        const data = await resp.json();
        if (data.secret && typeof data.secret === 'string') {
          CONFIG.handoffSigningSecret = data.secret.trim();
          console.log(`   SSO:    ✓ Secret fetched from Supabase (len=${CONFIG.handoffSigningSecret.length})`);
        } else {
          console.warn(`   SSO:    ⚠ Supabase returned empty secret`);
        }
      } else {
        console.warn(`   SSO:    ⚠ Supabase fetch returned ${resp.status}`);
      }
    } catch (fetchErr) {
      console.warn(`   SSO:    ⚠ Supabase fetch failed: ${fetchErr.message}`);
      console.warn(`   SSO:    Falling back to env var value (len=${CONFIG.handoffSigningSecret.length})`);
    }
  }
}

// ─── SSO Handoff: Single-Use Token Tracking ──────────────────────────────────
// Two-layer replay prevention:
// 1. In-memory Map<jti, timestamp> — instant check, pruned every 90s via setInterval
// 2. Supabase handoff_tokens table — survives process restarts (consumed_at column)
// The DB check is authoritative; in-memory is a fast-path optimization.
const consumedHandoffTokens = new Map();
const HANDOFF_TOKEN_TTL_MS = 90_000; // 90 seconds (matches JWT TTL)

// Prune expired entries every 30 seconds to prevent memory leak
setInterval(() => {
  const now = Date.now();
  for (const [jti, ts] of consumedHandoffTokens) {
    if (now - ts > HANDOFF_TOKEN_TTL_MS) {
      consumedHandoffTokens.delete(jti);
    }
  }
}, 30_000).unref();

// Supabase Edge Function helper for handoff token consumption (no service key in container)
// Calls consume-handoff-token function with VERIFY_OWNER_SECRET for auth.
// Returns { consumed: true } if token was valid and not previously consumed.
async function dbConsumeHandoffToken(jti) {
  if (!CONFIG.consumeHandoffUrl) return { consumed: true }; // Fallback: in-memory only
  try {
    const resp = await fetch(CONFIG.consumeHandoffUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${CONFIG.verifyOwnerSecret}`,
      },
      body: JSON.stringify({ jti }),
      signal: AbortSignal.timeout(5000),
    });
    if (resp.status === 409) {
      // Already consumed
      return { consumed: false, error: 'already_consumed' };
    }
    if (!resp.ok) {
      console.error(`[handoff] consume-handoff returned ${resp.status}`);
      return { consumed: false, error: 'db_error' };
    }
    const result = await resp.json();
    return { consumed: !!result.consumed };
  } catch (err) {
    console.error(`[handoff] consume-handoff error: ${err.message}`);
    return { consumed: false, error: 'db_unavailable' };
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
      // Raw base64 key body (no PEM headers) — wrap in PEM armor and import
      // This handles the case where PRIVY_VERIFICATION_KEY is stored as just the
      // base64 key material (e.g. "MFkwEwYHKoZIzj0C...") without PEM headers.
      // First try wrapping directly, then try base64-decoding in case it's a
      // base64-encoded PEM string.
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
    console.error('   Key preview (first 60 chars):', CONFIG.privyVerificationKey.slice(0, 60) + '...');
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
        // Fail open or closed? Fail CLOSED for security — deny access if we can't verify
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

// Escape HTML special chars for safe interpolation of env-sourced branding.
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

let loginPageHtml = null;
let loginBundleJs = null;

async function loadLoginPage() {
  try {
    const htmlPath = join(__dirname, 'login.html');
    let html = await readFile(htmlPath, 'utf8');

    // Inject configuration values at serve time
    html = html.replace(/__PRIVY_APP_ID__/g, CONFIG.privyAppId);
    html = html.replace(/__PRIVY_CLIENT_ID__/g, CONFIG.privyClientId);
    html = html.replace(/__BRAND_ICON__/g, escapeHtml(CONFIG.brandIcon));
    html = html.replace(/__BRAND_NAME__/g, escapeHtml(CONFIG.brandName));
    html = html.replace(/__BRAND_TAGLINE__/g, escapeHtml(CONFIG.brandTagline));

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

// ─── CIG Proxy Handler ─────────────────────────────────────────────────────────────────────
// Mints a CIG token (cached, refreshed 60s before expiry) and forwards
// the inference request to the external CIG endpoint.

// Auto-detect FQDN from Host header (one-time, only if not set via env).
// Buffer containers don't know their FQDN at provision time; the first external
// request carries the Manifest ingress hostname which we lock as the FQDN.
// Security: CIG_ALLOWED_FQDN_SUFFIX restricts accepted FQDNs to a known ingress
// domain (e.g. ".manifest0.net"), preventing Host-header poisoning.
// Node.js is single-threaded so no mutex is needed for the fqdnLocked flag.
function maybeAutoDetectFqdn(reqHost) {
  if (CIG_CONFIG.fqdnLocked || !CIG_ENABLED) return;
  if (!reqHost || reqHost === 'localhost' || reqHost.startsWith('127.') || reqHost.startsWith('[::1]')) return;
  const fqdn = reqHost.split(':')[0].toLowerCase();
  // Only accept real domain names (must contain a dot)
  if (!fqdn || !fqdn.includes('.')) return;
  // Enforce suffix restriction if configured (prevents Host-header poisoning)
  if (CIG_ALLOWED_FQDN_SUFFIX && !fqdn.endsWith(CIG_ALLOWED_FQDN_SUFFIX)) {
    console.warn(`[cig] Rejected FQDN auto-detect: ${fqdn} does not end with ${CIG_ALLOWED_FQDN_SUFFIX}`);
    return;
  }
  CIG_CONFIG.containerFqdn = fqdn;
  CIG_CONFIG.fqdnLocked = true;
  console.log(`[cig] Auto-detected container FQDN from Host header: ${fqdn}`);
}

async function mintCigToken() {
  // Return cached token if still valid (with refresh buffer)
  if (cigTokenCache.token && Date.now() < cigTokenCache.expiresAt - CIG_TOKEN_REFRESH_MS) {
    return cigTokenCache.token;
  }

  // FQDN is required for per-container binding
  const fqdn = CIG_CONFIG.containerFqdn;
  if (!fqdn) {
    // FQDN not yet auto-detected — skip CIG for this request.
    // Subsequent requests will have the FQDN after auto-detection.
    console.warn('[cig] Cannot mint token: FQDN not yet detected (will auto-detect from Host header)');
    const err = new Error('FQDN not yet detected — awaiting auto-detection from Host header');
    err.code = 'fqdn_not_detected';
    throw err;
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), CIG_FETCH_TIMEOUT_MS);
  try {
    const resp = await fetch(CIG_CONFIG.mintUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        fqdn,
        binding_secret: CIG_CONFIG.bindingSecret,
      }),
      signal: controller.signal,
    });

    if (!resp.ok) {
      const body = await resp.text().catch(() => '');
      throw new Error(`CIG mint failed (${resp.status}): ${body}`);
    }

    const data = await resp.json();
    if (!data.token) throw new Error('CIG mint returned no token');

    cigTokenCache = {
      token: data.token,
      expiresAt: Date.now() + CIG_TOKEN_TTL_MS,
    };

    console.log(`[cig-proxy] Minted CIG token for ${fqdn}`);
    return data.token;
  } finally {
    clearTimeout(timeoutId);
  }
}

async function handleCigProxy(req, res, url) {
  try {
    // Security: Only allow loopback requests (internal OpenClaw inference)
    const remote = (req.socket.remoteAddress || '').replace('::ffff:', '');
    if (!['127.0.0.1', '::1'].includes(remote)) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: { message: 'forbidden', type: 'proxy_error' } }));
      return;
    }

    // Read the request body with size limit
    const chunks = [];
    let totalBytes = 0;
    for await (const chunk of req) {
      totalBytes += chunk.length;
      if (totalBytes > CIG_MAX_BODY_BYTES) {
        res.writeHead(413, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: { message: 'request_too_large', type: 'proxy_error' } }));
        return;
      }
      chunks.push(chunk);
    }
    const bodyBuf = Buffer.concat(chunks);

    // Mint or reuse cached CIG token
    let cigToken;
    try {
      cigToken = await mintCigToken();
    } catch (mintErr) {
      // FQDN not yet detected — return 503 Retry-After so OpenClaw retries
      // instead of treating it as a hard failure ("assistant turn failed").
      // The FQDN will be auto-detected from the first browser request's Host header.
      if (mintErr.code === 'fqdn_not_detected' || mintErr.message.includes('FQDN not yet detected')) {
        console.warn('[cig-proxy] Returning 503 (FQDN not yet detected) — OpenClaw should retry');
        res.writeHead(503, {
          'Content-Type': 'application/json',
          'Retry-After': '5',
          'X-Cig-Status': 'fqdn-pending',
        });
        res.end(JSON.stringify({
          error: {
            message: 'CIG FQDN not yet detected — retry shortly',
            type: 'proxy_error',
            code: 'fqdn_pending',
            retryable: true,
          },
        }));
        return;
      }
      throw mintErr; // Re-raise other mint errors (will be caught below)
    }

    // Forward to CIG inference endpoint, preserving pathname + query string
    // Note: CIG_CONFIG.inferenceUrl path (e.g. /functions/v1/cig-inference) is the
    // base; url.pathname (/v1/chat/completions) appends the OpenAI-compatible route.
    const targetUrl = CIG_CONFIG.inferenceUrl + url.pathname + url.search;

    const controller = new AbortController();
    let timeoutId;
    try {
      timeoutId = setTimeout(() => controller.abort(), CIG_INFERENCE_TIMEOUT_MS);
      const proxyResp = await fetch(targetUrl, {
        method: 'POST',
        headers: {
          'Content-Type': req.headers['content-type'] || 'application/json',
          'Authorization': `Bearer ${cigToken}`,
          'X-Container-Fqdn': CIG_CONFIG.containerFqdn,
        },
        body: bodyBuf,
        signal: controller.signal,
      });

      // Stream the response back
      res.writeHead(proxyResp.status, {
        'Content-Type': proxyResp.headers.get('content-type') || 'application/json',
        'Cache-Control': 'no-store',
      });

      if (proxyResp.body) {
        const reader = proxyResp.body.getReader();
        while (true) {
          const { done, value } = await reader.read();
          if (done) { res.end(); break; }
          res.write(value);
        }
      } else {
        const text = await proxyResp.text();
        res.end(text);
      }
    } catch (err) {
      console.error('[cig-proxy] Error:', err.message);
      const status = err.name === 'AbortError' ? 504 : 502;
      if (!res.headersSent) {
        res.writeHead(status, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: { message: 'inference_proxy_error', type: 'proxy_error' } }));
      } else {
        // Stream already started — don't append JSON error to partial stream
        res.end();
      }
    } finally {
      if (timeoutId) clearTimeout(timeoutId);
    }
  } catch (err) {
    // Catch errors from body reading, token minting, etc.
    console.error('[cig-proxy] Error:', err.message);
    if (!res.headersSent) {
      res.writeHead(502, { 'Content-Type': 'application/json' });
    }
    res.end(JSON.stringify({ error: { message: 'inference_proxy_error', type: 'proxy_error' } }));
  }
}

async function handleRequest(req, res) {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = url.pathname;

  // Auto-detect FQDN from first external request (buffer pool containers)
  if (CIG_ENABLED && !CIG_CONFIG.fqdnLocked) {
    maybeAutoDetectFqdn(req.headers.host);
  }

  // ── Health check (no auth) ──
  if (pathname === '/health') {
    const handoffHash = CONFIG.handoffSigningSecret
      ? createHash('sha256').update(CONFIG.handoffSigningSecret).digest('hex').slice(0, 16)
      : 'not_set';
    const fqdnStatus = CIG_ENABLED
      ? { detected: CIG_CONFIG.fqdnLocked, fqdn: CIG_CONFIG.containerFqdn || null }
      : { enabled: false };
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      status: 'ok',
      authProxy: true,
      sso: {
        enabled: !!CONFIG.handoffSigningSecret,
        secretHashPrefix: handoffHash,
        dynamicOwner: DYNAMIC_OWNER_MODE,
      },
      cig: fqdnStatus,
    }));
    return;
  }

  // ── Logo asset (served for Privy modal branding) ──
  if (pathname === '/auth/logo.png' && req.method === 'GET') {
    try {
      const logoPath = join(__dirname, 'assets', 'logo.png');
      const logoData = await readFile(logoPath);
      res.writeHead(200, {
        'Content-Type': 'image/png',
        'Cache-Control': 'public, max-age=604800, immutable',
        'X-Content-Type-Options': 'nosniff',
      });
      res.end(logoData);
    } catch {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not found');
    }
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

  // ── CIG Proxy: Internal inference requests from OpenClaw ──
  // OpenClaw calls localhost:18789/v1/chat/completions (via mor-gateway provider)
  // We mint a CIG token and forward to the external CIG inference endpoint.
  // These are internal requests (no session cookie needed).
  if (CIG_ENABLED && pathname.startsWith('/v1/') && req.method === 'POST') {
    await handleCigProxy(req, res, url);
    return;
  }

  // ── SSO Handoff — exchange single-use JWT for session cookie ──
  // Receives a short-lived HS256 JWT via POST body (form-urlencoded).
  // Validates JWT signature, expiry, FQDN match, and single-use (in-memory consumed set).
  // On success: sets session cookie and 302 redirects to /.
  // On failure: serves login page (fallback to current behavior).
  if (pathname === '/auth/handoff' && req.method === 'POST') {
    // SSO disabled — don't waste rate-limit slots or attempt JWT verify with empty key
    if (!CONFIG.handoffSigningSecret) {
      serveLoginPage(res, 404);
      return;
    }

    // Rate limit: 5 attempts per minute per IP (shared AUTH_RATE_LIMIT)
    const handoffIp = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
    if (isRateLimited(handoffIp)) {
      res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '60' });
      res.end(JSON.stringify({ error: 'rate_limited', retryAfter: 60 }));
      return;
    }

    try {
      // Parse form-urlencoded body (auto-submitting HTML form)
      const chunks = [];
      let size = 0;
      for await (const chunk of req) {
        size += chunk.length;
        if (size > MAX_BODY_BYTES) {
          req.destroy();
          throw new Error('Body too large');
        }
        chunks.push(chunk);
      }
      const rawBody = Buffer.concat(chunks).toString('utf8');
      const params = new URLSearchParams(rawBody);
      const token = params.get('token');

      if (!token || typeof token !== 'string') {
        console.log('[handoff] No token in POST body');
        serveLoginPage(res, 401);
        return;
      }

      // Verify HS256 JWT using HANDOFF_SIGNING_SECRET
      let handoffPayload;
      try {
        const secretKey = new TextEncoder().encode(CONFIG.handoffSigningSecret);
        const { payload } = await jwtVerify(token, secretKey, {
          algorithms: ['HS256'],
        });
        handoffPayload = payload;
      } catch (jwtErr) {
        console.log(`[handoff] JWT verification failed: ${jwtErr.code || jwtErr.message}`);
        serveLoginPage(res, 401);
        return;
      }

      // Validate required claims
      const { sub, fqdn: tokenFqdn, jti } = handoffPayload;
      if (!sub || !tokenFqdn || !jti) {
        console.log('[handoff] Missing required claims (sub, fqdn, jti)');
        serveLoginPage(res, 401);
        return;
      }

      // Single-use enforcement: check in-memory Map first (fast path only — don't consume yet)
      if (consumedHandoffTokens.has(jti)) {
        console.log(`[handoff] Token already consumed (in-memory): jti=${jti}`);
        serveLoginPage(res, 401);
        return;
      }

      // Validate FQDN: token must match this container's FQDN
      const containerFqdn = (CONFIG.containerFqdn || req.headers.host || '').split(':')[0].toLowerCase();
      const expectedFqdn = containerFqdn;
      const tokenFqdnLower = String(tokenFqdn).toLowerCase();

      if (tokenFqdnLower !== expectedFqdn) {
        console.log(`[handoff] FQDN mismatch: token=${tokenFqdnLower} expected=${expectedFqdn}`);
        serveLoginPage(res, 403);
        return;
      }

      // Defense-in-depth: verify ownership via Supabase (same as /auth/callback)
      if (DYNAMIC_OWNER_MODE) {
        try {
          const verifyResp = await fetch(CONFIG.verifyOwnerUrl, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': `Bearer ${CONFIG.verifyOwnerSecret}`,
            },
            body: JSON.stringify({
              fqdn: expectedFqdn,
              privy_user_id: sub,
            }),
            signal: AbortSignal.timeout(5000),
          });

          if (!verifyResp.ok) {
            console.log(`[handoff] verify-owner returned ${verifyResp.status}`);
            serveLoginPage(res, 403);
            return;
          }

          const result = await verifyResp.json();
          if (!result.authorized) {
            console.log(`[handoff] Owner check failed: sub=${sub} fqdn=${expectedFqdn}`);
            serveLoginPage(res, 403);
            return;
          }
        } catch (fetchErr) {
          console.error(`[handoff] verify-owner error: ${fetchErr.message}`);
          serveLoginPage(res, 403);
          return;
        }
      }

      // All validations passed — NOW consume the token (DB-backed atomic single-use)
      const dbResult = await dbConsumeHandoffToken(jti);
      if (!dbResult.consumed) {
        // DB says already consumed or unavailable — fail closed
        console.log(`[handoff] Token rejected by DB: jti=${jti} reason=${dbResult.error}`);
        serveLoginPage(res, 401);
        return;
      }

      // Mark token as consumed in-memory
      consumedHandoffTokens.set(jti, Date.now());

      // Create signed session cookie (same as /auth/callback)
      const sessionValue = signSession(sub);
      const cookieOpts = getCookieOptions(req);

      console.log(`[handoff] ✓ SSO handoff successful: sub=${sub} fqdn=${expectedFqdn} jti=${jti}`);

      res.writeHead(302, {
        'Set-Cookie': cookie.serialize(COOKIE_NAME, sessionValue, cookieOpts),
        'Location': '/',
      });
      res.end();
      return;
    } catch (error) {
      console.error('[handoff] Error:', error.message);
      serveLoginPage(res, 500);
      return;
    }
  }

  // ── GET /auth/handoff without POST → serve login page ──
  if (pathname === '/auth/handoff' && req.method === 'GET') {
    serveLoginPage(res);
    return;
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
  console.log('🔒 OpenClaw Auth Proxy');
  console.log('');

  await validateConfig();
  await initializeVerificationKey();
  await loadLoginPage();

  const server = createServer(handleRequest);
  server.on('upgrade', handleUpgrade);

  server.listen(CONFIG.proxyPort, '0.0.0.0', () => {
    console.log(`✅ Auth proxy listening on :${CONFIG.proxyPort}`);
    console.log(`   Proxying authenticated requests to OpenClaw :${CONFIG.internalPort}`);
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
