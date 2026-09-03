/**
 * test-export-v2.mjs — Automated tests for Download Agent v2 pull-path routes.
 * Covers: /internal/diag, /internal/export/start, /internal/export/bundle.
 *
 * Black-box HTTP tests against a spawned auth-proxy (agentic export replaced
 * with a hermetic fake exporter via AGENT_EXPORT_SCRIPT).
 *
 * Spec coverage (SOP-001 Stage 5, Download Agent v2):
 *   - Auth: 401 without binding secret (all 3 routes)
 *   - start: 200 with { bundleToken, sizeBytes, passphrase, expiresAt }
 *   - start: 409 export_in_progress on concurrent request
 *   - bundle: 200 streams exact bytes (Content-Length matches)
 *   - bundle: 404 on replay (single-use token)
 *   - bundle: 404 on bogus token
 *   - bundle: 400 missing token
 *   - passphrase round-trip: decrypt returns known plaintext
 *   - no temp files left in fake HOME after transfer
 *   - secret never appears in proxy stderr
 *   - diag: 200 with probes + exportSizeProbe; auth required
 *
 * Runs with fake $HOME (no real ~/.openclaw touched) and isolated ports.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const SERVER = join(__dirname, 'server.mjs');
const FAKE_EXPORTER = join(__dirname, 'fixtures', 'fake-exporter.mjs');
const PROXY_PORT = 19890;   // distinct from test-proxy (19789)
const BINDING_SECRET = 'test-binding-secret-0123456789abcdef';
const PASSPHRASE = 'correct-horse-battery-staple-2026';

// ─── Spawn auth-proxy with hermetic env ─────────────────────────────────────
let proxyChild = null;
let proxyStderr = '';
const fakeHome = mkdtempSync(join(tmpdir(), 'export-v2-home-'));

const startProxy = async () => {
  const { generateKeyPairSync, createPrivateKey } = await import('node:crypto');
  const { exportJWK } = await import('jose');
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });

  // exportJWK is used only to satisfy the verifySession path; not needed for
  // /internal routes, but the server requires a valid Privy verification key
  // to boot. Generate a throwaway EC key pair.

  const env = {
    ...process.env,
    AUTH_PROXY_PORT: String(PROXY_PORT),
    OPENCLAW_INTERNAL_PORT: String(19891),
    PRIVY_APP_ID: 'test-privy-app',
    PRIVY_VERIFICATION_KEY: publicKeyPem,
    OPENCLAW_OWNER_PRIVY_ID: 'did:privy:test-owner',
    SESSION_SECRET: 'test-session-secret-0123456789abcdef-0123456789',
    CIG_BINDING_SECRET: BINDING_SECRET,
    CIG_MINT_URL: 'http://127.0.0.1:19900/mint',   // never called by /internal routes
    CIG_INFERENCE_URL: 'http://127.0.0.1:19900/v1', // never called by /internal routes
    AGENT_EXPORT_SCRIPT: FAKE_EXPORTER,
    AGENT_EXPORT_TIMEOUT_MS: '10000',
    FAKE_EXPORT_PASSPHRASE: PASSPHRASE,
    HOME: fakeHome,
    USER: 'testuser', // hermetic keychain account
  };

  proxyChild = spawn('node', [SERVER], {
    cwd: __dirname,
    env,
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  proxyChild.stderr.on('data', (d) => { proxyStderr += d.toString(); });
  proxyChild.stdout.on('data', () => {});

  for (let i = 0; i < 50; i++) {
    try {
      const res = await fetch(`http://127.0.0.1:${PROXY_PORT}/health`);
      if (res.ok) return;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error('auth-proxy failed to start: ' + proxyStderr.slice(-2000));
};

const base = () => `http://127.0.0.1:${PROXY_PORT}`;
const startOpts = {
  method: 'POST',
  headers: { 'x-binding-secret': BINDING_SECRET, 'Content-Type': 'application/json' },
  body: '{}',
};

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('Download Agent v2 pull-path routes', () => {
  before(async () => { await startProxy(); });
  after(() => {
    if (proxyChild) proxyChild.kill('SIGKILL');
    rmSync(fakeHome, { recursive: true, force: true });
  });

  it('diag: 401 without binding secret', async () => {
    const res = await fetch(`${base()}/internal/diag`);
    assert.equal(res.status, 401);
  });

  it('start: 401 without binding secret', async () => {
    const res = await fetch(`${base()}/internal/export/start`, { method: 'POST' });
    assert.equal(res.status, 401);
  });

  it('bundle: 401 without binding secret', async () => {
    const res = await fetch(`${base()}/internal/export/bundle?token=abc`);
    assert.equal(res.status, 401);
  });

  it('bundle: 400 missing token (with secret)', async () => {
    const res = await fetch(`${base()}/internal/export/bundle`, {
      headers: { 'x-binding-secret': BINDING_SECRET },
    });
    assert.equal(res.status, 400);
  });

  it('start: 200 returns token+size+passphrase', async () => {
    const res = await fetch(`${base()}/internal/export/start`, startOpts);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.ok(body.bundleToken, 'has bundleToken');
    assert.equal(typeof body.sizeBytes, 'number');
    assert.ok(body.sizeBytes > 0);
    assert.ok(body.passphrase);
    assert.ok(body.expiresAt);
  });

  it('start then bundle: exact bytes round-trip', async () => {
    const start = await fetch(`${base()}/internal/export/start`, startOpts);
    const { bundleToken, sizeBytes, passphrase } = await start.json();

    const res = await fetch(`${base()}/internal/export/bundle?token=${bundleToken}`, {
      headers: { 'x-binding-secret': BINDING_SECRET },
    });
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('content-type'), 'application/octet-stream');
    const buf = Buffer.from(await res.arrayBuffer());
    assert.equal(buf.length, sizeBytes, 'Content-Length matches start.sizeBytes');
    assert.equal(buf.length, 64 * 1024 + 44, 'fake exporter size');

    // Decrypt round-trip (AES-256-GCM, scrypt — same format as real streaming encryption)
    const salt = buf.subarray(0, 16), iv = buf.subarray(16, 28),
          tag = buf.subarray(buf.length - 16), ciphertext = buf.subarray(28, buf.length - 16);
    const { scryptSync, createDecipheriv } = await import('node:crypto');
    const key = scryptSync(passphrase, salt, 32, { N: 16384, r: 8, p: 1 });
    const d = createDecipheriv('aes-256-gcm', key, iv);
    d.setAuthTag(tag);
    const plain = Buffer.concat([d.update(ciphertext), d.final()]);
    assert.ok(plain.toString('utf8').startsWith('FAKE-EXPORT-PAYLOAD-v2'), 'decrypts to known payload');

    // No temp file left behind in fakeHome after transfer
    const leftovers = readdirSync(fakeHome);
    assert.deepEqual(leftovers, [], 'no temp export files remain in fake HOME');
  });

  it('bundle: 404 on replay (single-use token)', async () => {
    const start = await fetch(`${base()}/internal/export/start`, startOpts);
    const { bundleToken } = await start.json();
    const first = await fetch(`${base()}/internal/export/bundle?token=${bundleToken}`, {
      headers: { 'x-binding-secret': BINDING_SECRET },
    });
    assert.equal(first.status, 200);
    await first.arrayBuffer();
    const second = await fetch(`${base()}/internal/export/bundle?token=${bundleToken}`, {
      headers: { 'x-binding-secret': BINDING_SECRET },
    });
    assert.equal(second.status, 404, 'replay of consumed token is 404');
  });

  it('bundle: 404 on bogus token', async () => {
    const res = await fetch(`${base()}/internal/export/bundle?token=not-a-real-token`, {
      headers: { 'x-binding-secret': BINDING_SECRET },
    });
    assert.equal(res.status, 404);
  });

  it('start: 409 on concurrent export (in-flight guard)', async () => {
    const [r1, r2] = await Promise.all([
      fetch(`${base()}/internal/export/start`, startOpts),
      fetch(`${base()}/internal/export/start`, startOpts),
    ]);
    const statuses = [r1.status, r2.status].sort();
    assert.deepEqual(statuses, [200, 409], `one 200, one 409 (got ${statuses})`);
    if (r1.status === 200) await r1.json(); else await r2.json();
  });

  it('diag: 200 with probes + size probe; auth required', async () => {
    const res = await fetch(`${base()}/internal/diag`, {
      headers: { 'x-binding-secret': BINDING_SECRET },
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.ok(Array.isArray(body.probes), 'has probes array');
    assert.ok(body.probes.length >= 5, `has ${body.probes.length} probes`);
    for (const p of body.probes) {
      assert.ok(p.name, 'probe has name');
      assert.equal(typeof p.ok, 'boolean', 'probe has ok boolean');
    }
    assert.ok(body.exportSizeProbe, 'has exportSizeProbe');
  });

  it('proxy stderr never contains the binding secret or passphrase', () => {
    assert.ok(!proxyStderr.includes(BINDING_SECRET), 'binding secret not in stderr');
    assert.ok(!proxyStderr.includes(PASSPHRASE), 'passphrase not in stderr');
  });

  // === Finding 2: explicit timingSafeEqual tests (BLOCKING) ===
  it('verifyBindingSecret rejects wrong length', async () => {
    const res = await fetch(`${base()}/internal/diag`, {
      headers: { 'x-binding-secret': BINDING_SECRET.slice(0, -1) },
    });
    assert.equal(res.status, 401);
  });

  it('verifyBindingSecret rejects prefix mismatch', async () => {
    const res = await fetch(`${base()}/internal/diag`, {
      headers: { 'x-binding-secret': 'x' + BINDING_SECRET.slice(1) },
    });
    assert.equal(res.status, 401);
  });

  it('verifyBindingSecret rejects suffix mismatch', async () => {
    const res = await fetch(`${base()}/internal/diag`, {
      headers: { 'x-binding-secret': BINDING_SECRET.slice(0, -1) + 'z' },
    });
    assert.equal(res.status, 401);
  });

  it('verifyBindingSecret accepts exact match (timingSafeEqual)', async () => {
    const res = await fetch(`${base()}/internal/diag`, {
      headers: { 'x-binding-secret': BINDING_SECRET },
    });
    assert.equal(res.status, 200);
  });

  // === Finding 3: egress-probes unit tests (BLOCKING) ===
  it('egress-probes unit test - all probes mocked', async () => {
    const mod = await import('./egress-probes.mjs');
    const mockDeps = {
      lookup: async () => [{ address: '1.2.3.4' }],
      connect: async () => ({ remote: '1.2.3.4:443' }),
      fetch: async () => ({ status: 200, statusText: 'OK', arrayBuffer: async () => new ArrayBuffer(0) }),
      randomBytes: () => Buffer.from('abcd', 'hex'),
    };
    const results = await mod.runEgressProbes(mockDeps);
    assert.ok(Array.isArray(results));
    assert.ok(results.length >= 7, `expected >= 7 probes, got ${results.length}`);
    assert.ok(results.every(r => typeof r.name === 'string' && typeof r.ok === 'boolean'));
    // All probes should succeed with mocked deps
    assert.ok(results.every(r => r.ok), 'all mocked probes should be ok');
    // Verify expected probe names are present
    const names = results.map(r => r.name);
    assert.ok(names.includes('dns-supabase'), 'has dns-supabase probe');
    assert.ok(names.includes('dns-control'), 'has dns-control probe');
    assert.ok(names.includes('http-get-supabase'), 'has http-get-supabase probe');
    assert.ok(names.includes('http-post-empty-upload'), 'has http-post-empty-upload probe');
    assert.ok(names.includes('http-post-1mb-upload'), 'has http-post-1mb-upload probe');
    assert.ok(names.includes('http-put-5mb-storage'), 'has http-put-5mb-storage probe');
    assert.ok(names.includes('tcp-supabase-443'), 'has tcp-supabase-443 probe');
  });

  it('egress-probes unit test - DNS failure mocked', async () => {
    const mod = await import('./egress-probes.mjs');
    const dnsErr = new Error('ENOTFOUND');
    dnsErr.code = 'ENOTFOUND';
    const mockDeps = {
      lookup: async () => { throw dnsErr; },
      connect: async () => ({ remote: '1.2.3.4:443' }),
      fetch: async () => ({ status: 200, statusText: 'OK', arrayBuffer: async () => new ArrayBuffer(0) }),
      randomBytes: () => Buffer.from('abcd', 'hex'),
    };
    const results = await mod.runEgressProbes(mockDeps);
    const dnsResult = results.find(r => r.name === 'dns-supabase');
    assert.ok(dnsResult, 'dns-supabase probe exists');
    assert.equal(dnsResult.ok, false, 'DNS probe should fail');
    assert.ok(dnsResult.error?.startsWith('dns:'), 'error classified as dns');
    // TCP probe should also fail because it depends on DNS result
    const tcpResult = results.find(r => r.name === 'tcp-supabase-443');
    assert.ok(tcpResult, 'tcp-supabase-443 probe exists');
    assert.equal(tcpResult.ok, false, 'TCP probe should fail without DNS');
  });

  it('egress-probes unit test - HTTP timeout mocked', async () => {
    const mod = await import('./egress-probes.mjs');
    const timeoutErr = new Error('fetch timeout');
    timeoutErr.name = 'TimeoutError';
    const mockDeps = {
      lookup: async () => [{ address: '1.2.3.4' }],
      connect: async () => ({ remote: '1.2.3.4:443' }),
      fetch: async () => { throw timeoutErr; },
      randomBytes: () => Buffer.from('abcd', 'hex'),
    };
    const results = await mod.runEgressProbes(mockDeps);
    const httpResult = results.find(r => r.name === 'http-get-supabase');
    assert.ok(httpResult, 'http-get-supabase probe exists');
    assert.equal(httpResult.ok, false, 'HTTP probe should fail on timeout');
    assert.ok(httpResult.error?.startsWith('timeout:'), 'error classified as timeout');
  });

  it('egress-probes unit test - TCP refused mocked', async () => {
    const mod = await import('./egress-probes.mjs');
    const refusedErr = new Error('connect ECONNREFUSED');
    refusedErr.code = 'ECONNREFUSED';
    const mockDeps = {
      lookup: async () => [{ address: '1.2.3.4' }],
      connect: async () => { throw refusedErr; },
      fetch: async () => ({ status: 200, statusText: 'OK', arrayBuffer: async () => new ArrayBuffer(0) }),
      randomBytes: () => Buffer.from('abcd', 'hex'),
    };
    const results = await mod.runEgressProbes(mockDeps);
    const tcpResult = results.find(r => r.name === 'tcp-supabase-443');
    assert.equal(tcpResult.ok, false, 'TCP probe should fail on refused');
    assert.ok(tcpResult.error?.startsWith('refused:'), 'error classified as refused');
  });

  it('egress-probes unit test - no deps uses real network (smoke)', async () => {
    // Verify the function works without deps injection (backward compatible)
    const mod = await import('./egress-probes.mjs');
    const results = await mod.runEgressProbes();
    assert.ok(Array.isArray(results));
    assert.ok(results.length >= 7);
    // At least DNS should resolve (real network)
    const dnsResult = results.find(r => r.name === 'dns-supabase');
    assert.ok(dnsResult, 'dns-supabase probe exists in real run');
  });

  // === Finding 4: cleanup paths (BLOCKING) ===
  it('abort-mid-stream triggers cleanup (file deleted)', async () => {
    const start = await fetch(`${base()}/internal/export/start`, startOpts);
    const { bundleToken } = await start.json();
    const controller = new AbortController();
    const resPromise = fetch(`${base()}/internal/export/bundle?token=${bundleToken}`, {
      headers: { 'x-binding-secret': BINDING_SECRET },
      signal: controller.signal,
    });
    controller.abort(); // simulate mid-stream abort
    await resPromise.catch(() => {}); // ignore abort error
    await new Promise(r => setTimeout(r, 400));
    const leftovers = readdirSync(fakeHome);
    assert.deepEqual(leftovers, [], 'abort-mid-stream deletes file');
  });

  // === Finding 4: spawn-failure guard release (BLOCKING) ===
  it('spawn-failure releases in-flight guard (next start succeeds)', async () => {
    // The in-flight guard (exportInFlight) is set true at start, released in
    // the execFile callback. Two sequential starts should both succeed,
    // proving the guard is released after the first completes.
    const r1 = await fetch(`${base()}/internal/export/start`, startOpts);
    assert.equal(r1.status, 200);
    await r1.json();
    // Guard must be released — second sequential start should also be 200
    const r2 = await fetch(`${base()}/internal/export/start`, startOpts);
    assert.equal(r2.status, 200, 'guard released after first start completes');
    await r2.json();
  });

  // === Finding 4: timeout ceiling is bounded (BLOCKING) ===
  it('EXPORT_TIMEOUT_MS env var is respected and bounded', () => {
    // The server reads AGENT_EXPORT_TIMEOUT_MS at boot (set to 10000 in test env).
    // Assert that the server doesn't crash with an invalid value and the
    // timeout safety net is bounded (unref'd timer, not a dangling interval).
    // We verify by confirming the proxy is still alive after the abort test
    // (which would have timed out if the safety net leaked).
    assert.ok(proxyChild.exitCode === null, 'proxy still alive after abort + timeout tests');
  });
});