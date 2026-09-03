// egress-probes.mjs — bounded container egress diagnostics for /internal/diag
//
// Purpose: give ops ground truth about what the container can reach WITHOUT
// shell access. Every probe is bounded (AbortSignal / socket timeout) and the
// module NEVER throws — it returns structured results for every probe.
//
// Probes target fixed constants only (no user input → no SSRF surface):
//   1. DNS resolve        supabase.co
//   2. DNS resolve        inference.installopenclaw.xyz (known-good control)
//   3. TCP connect :443   supabase.co first IPv4
//   4. HTTPS GET          supabase functions base (any HTTP status = reachable)
//   5. HTTPS POST (empty) agent-export-upload (expect fast 401 = small-POST egress)
//   6. HTTPS POST (1 MB)  agent-export-upload — documents the FUNCTIONS-GATEWAY
//                         large-body cliff (confirmed 2026-09-02: bodies ≥ ~1 MB
//                         hang forever on the functions gateway from ANY client;
//                         storage gateway handles 5 MB in ~1 s) — expect timeout
//   7. HTTPS PUT (5 MB)   storage object path, no auth — expect fast 401/400 =
//                         storage gateway answers large bodies (direct-upload path)
//   8. HTTPS GET          inference.installopenclaw.xyz (control; note: this host
//                         resolves only inside the Manifest container network —
//                         ENOTFOUND from external hosts is EXPECTED)
//
// The export SIZE probe is not here — auth-proxy runs it (it needs the
// EXPORT_SCRIPT path) and merges it into the diag payload.
//
// Probe result shape: { name, ok, ms, ...detail } or { name, ok:false, ms, error }
// error is a compact classifier: "timeout:...", "dns:...", "refused:...",
// "reset:...", "tls:...", "unreachable:...", "err:...".

import { lookup } from 'node:dns/promises';
import { connect } from 'node:net';
import { randomBytes } from 'node:crypto';

const SUPABASE_HOST = 'lqmzlflbhitipergiwjo.supabase.co';
const FUNCTIONS_BASE = `https://${SUPABASE_HOST}`;
const UPLOAD_PATH = '/functions/v1/agent-export-upload';
const CONTROL_BASE = 'https://inference.installopenclaw.xyz';

// Bounds per probe class. The body probes get longer bounds so a
// legitimately-slow but working path must not false-positive.
const DNS_TIMEOUT_MS = 8_000;
const TCP_TIMEOUT_MS = 8_000;
const HTTP_GET_TIMEOUT_MS = 10_000;
const HTTP_POST_EMPTY_TIMEOUT_MS = 10_000;
const HTTP_POST_CLIFF_TIMEOUT_MS = 15_000; // 1 MB to functions gateway: EXPECT hang
const HTTP_PUT_STORAGE_TIMEOUT_MS = 20_000; // 5 MB to storage gateway: EXPECT fast reject without auth

const CLIFF_BYTES = 1024 * 1024; // 1 MB — just past the confirmed ~512 KB–1 MB cliff
const STORAGE_PUT_BYTES = 5 * 1024 * 1024; // 5 MB

function classifyErr(err) {
  const cause = err?.cause;
  const code = err?.code || cause?.code || '';
  const name = err?.name || cause?.name || '';
  const msg = String(err?.message || err).slice(0, 140);
  if (name === 'TimeoutError' || cause?.name === 'TimeoutError' ||
      code === 'ETIMEDOUT' || code === 'UND_ERR_CONNECT_TIMEOUT' ||
      code === 'UND_ERR_HEADERS_TIMEOUT' || code === 'UND_ERR_BODY_TIMEOUT') {
    return `timeout:${msg}`;
  }
  if (code === 'ENOTFOUND' || code === 'EAI_AGAIN') return `dns:${msg}`;
  if (code === 'ECONNREFUSED') return `refused:${msg}`;
  if (code === 'ECONNRESET' || code === 'EPIPE') return `reset:${msg}`;
  if (code === 'EHOSTUNREACH' || code === 'ENETUNREACH') return `unreachable:${msg}`;
  if (code === 'CERT_HAS_EXPIRED' || code === 'DEPTH_ZERO_SELF_SIGNED_CERT' ||
      code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' || code === 'ERR_TLS_CERT_ALTNAME_INVALID') {
    return `tls:${msg}`;
  }
  return `${code || 'err'}:${msg}`;
}

async function probe(name, fn) {
  const t0 = Date.now();
  try {
    const detail = await fn();
    return { name, ok: true, ms: Date.now() - t0, ...detail };
  } catch (err) {
    return { name, ok: false, ms: Date.now() - t0, error: classifyErr(err) };
  }
}

function timeoutSignal(ms) {
  return AbortSignal.timeout(ms);
}

async function dnsLookup(host, timeoutMs) {
  return lookup(host, { all: true, verbatim: true, signal: timeoutSignal(timeoutMs) });
}

function tcpConnect(host, port, timeoutMs) {
  return new Promise((resolve, reject) => {
    const sock = connect({ host, port });
    const timer = setTimeout(() => {
      sock.destroy();
      const e = new Error(`connect timeout ${host}:${port}`);
      e.name = 'TimeoutError';
      reject(e);
    }, timeoutMs);
    sock.once('connect', () => {
      clearTimeout(timer);
      sock.destroy();
      resolve({ remote: `${host}:${port}` });
    });
    sock.once('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

async function httpStatus(url, method, body, timeoutMs, extraHeaders, _fetch) {
  const f = _fetch || fetch;
  const resp = await f(url, {
    method,
    headers: extraHeaders || {},
    body: body ?? undefined,
    redirect: 'manual',
    signal: timeoutSignal(timeoutMs),
  });
  // Drain the body even on non-2xx: reusing the connection requires the
  // response to be fully consumed, and an undrained body can stall the next
  // request on the same keep-alive socket. Bounded by the same signal.
  try { await resp.arrayBuffer(); } catch { /* connection may be gone — result stands */ }
  return { status: resp.status, statusText: resp.statusText.slice(0, 40) };
}

// ─── Public API ──────────────────────────────────────────────────────────────

/**
 * Run all egress probes sequentially. Never throws.
 * Returns: array of probe result objects (see module header).
 *
 * @param {object} [deps] — Optional dependency injection for hermetic tests.
 *        When provided, replaces real dns/connect/fetch/randomBytes.
 *        { lookup, connect, fetch, randomBytes }
 */
export async function runEgressProbes(deps) {
  const _lookup = deps?.lookup || lookup;
  const _connect = deps?.connect || connect;
  const _fetch = deps?.fetch || fetch;
  const _randomBytes = deps?.randomBytes || randomBytes;

  // Internal helper to use the injected lookup
  const _dnsLookup = async (host, timeoutMs) => {
    const result = await _lookup(host, { all: true, verbatim: true, signal: timeoutSignal(timeoutMs) });
    return Array.isArray(result) ? result : (result?.address ? [result] : []);
  };

  // Independent probes run in parallel (Claude v2-C1: worst-case wall time was
  // the sequential sum of all bounds ~80s+; parallelized it is ~20s). The TCP
  // probe depends on DNS results, so it runs after the DNS pair resolves.
  const [dnsSupabase, dnsControl, httpGetSupabase, postEmpty, cliff, storagePut, control] = await Promise.all([
    probe('dns-supabase', async () => {
      const addrs = await _dnsLookup(SUPABASE_HOST, DNS_TIMEOUT_MS);
      return { addresses: addrs.map(a => a.address || a).slice(0, 4) };
    }),
    probe('dns-control', async () => {
      const addrs = await _dnsLookup('inference.installopenclaw.xyz', DNS_TIMEOUT_MS);
      return { addresses: addrs.map(a => a.address || a).slice(0, 4) };
    }),
    probe('http-get-supabase', async () =>
      httpStatus(`${FUNCTIONS_BASE}/`, 'GET', null, HTTP_GET_TIMEOUT_MS, {}, _fetch)),
    probe('http-post-empty-upload', async () =>
      httpStatus(`${FUNCTIONS_BASE}${UPLOAD_PATH}`, 'POST', null, HTTP_POST_EMPTY_TIMEOUT_MS, {}, _fetch)),
    // 1 MB to functions gateway: EXPECT hang (documents the cliff)
    probe('http-post-1mb-upload', async () => {
      const body = Buffer.alloc(CLIFF_BYTES, 0x1f);
      return httpStatus(`${FUNCTIONS_BASE}${UPLOAD_PATH}`, 'POST', body, HTTP_POST_CLIFF_TIMEOUT_MS, {}, _fetch);
    }),
    // 5 MB PUT to storage object path: EXPECT fast reject without auth —
    // proves the storage gateway answers large bodies (direct-upload path).
    probe('http-put-5mb-storage', async () => {
      const body = Buffer.alloc(STORAGE_PUT_BYTES, 0x1f);
      const rand = _randomBytes(4).toString('hex');
      const storageUrl = `${FUNCTIONS_BASE}/storage/v1/object/agent-exports/egress-probe-${rand}.bin`;
      return httpStatus(storageUrl, 'PUT', body, HTTP_PUT_STORAGE_TIMEOUT_MS, {}, _fetch);
    }),
    probe('http-get-control', async () =>
      httpStatus(`${CONTROL_BASE}/`, 'GET', null, HTTP_GET_TIMEOUT_MS, {}, _fetch)),
  ]);

  const results = [dnsSupabase, dnsControl];

  // 3. TCP connect to first IPv4 of supabase.co (needs the DNS result)
  const firstV4 = dnsSupabase.ok
    ? (dnsSupabase.addresses || []).find(a => !a.includes(':'))
    : null;
  results.push(await probe('tcp-supabase-443', async () => {
    if (!firstV4) throw new Error('no IPv4 address from DNS probe');
    if (deps?.connect) return deps.connect(firstV4, 443, TCP_TIMEOUT_MS);
    return tcpConnect(firstV4, 443, TCP_TIMEOUT_MS);
  }));

  results.push(httpGetSupabase, postEmpty, cliff, storagePut, control);
  return results;
}
