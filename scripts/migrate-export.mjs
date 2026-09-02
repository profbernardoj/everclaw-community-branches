#!/usr/bin/env node
/**
 * migrate-export.mjs — Full-Host Migration Export (Gap 8)
 *
 * Exports everything needed to move an OpenClaw agent host to a new machine
 * as a single passphrase-encrypted bundle (AES-256-GCM, scrypt KDF).
 *
 * Proven live 2026-08-27 (Mac mini → MacBook Pro "bernardo3" migration).
 * Use cases: local→local machine move; hosted→local designed in this gap
 * (implementation deferred — see gap8-migration-plan.md §4.3).
 *
 * Usage:
 *   node migrate-export.mjs [--output <path>] [--passphrase <pw|env:MIGRATE_PASSPHRASE>]
 *                           [--role primary|worker] [--crons <cron-jobs.json>]
 *                           [--keychain-service <svc>]... [--dry-run] [--help]
 *
 * Bundle (v2, encrypted):
 *   manifest.json            — schema, host info, versions, role, excluded, checksum
 *   dependency-manifest.json — brew/npm/plugins/ollama with install commands
 *   config.json.tmpl         — openclaw.json with {{HOME}} literalized
 *   keychain.json.enc        — secret map, AES-256-GCM (bundle passphrase)
 *   cron-jobs.json           — cron definitions (JSON, version-tolerant)
 *   workspaces.tar           — main workspace + sub-agent workspaces (uncompressed)
 *   skills-state.json        — skills.entries enabled map
 *   RUNBOOK.md               — generated ordered steps for THIS bundle
 */

import { existsSync, mkdirSync, writeFileSync, readFileSync, readdirSync, statSync, chmodSync,
         createReadStream, createWriteStream, rmSync, mkdtempSync } from 'node:fs';
import { join, dirname, resolve, basename } from 'node:path';
import { homedir, tmpdir, arch, platform, EOL } from 'node:os';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash, createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'node:crypto';
import { STATE_DIR, OPENCLAW_DIR } from './paths.mjs';
import { pipeline } from 'node:stream/promises';

const MANIFEST_VERSION = '2.0';
const MIN_PASSPHRASE_LEN = 16;
const BUNDLE_NAME_STEM = 'migrate-bundle';

// OpenClaw version pin (David, 2026-08-31): NEVER use @latest —
// 8.1.2024 is a major unstable change. Probe the source version at export;
// fall back to the current proven version if the binary is absent.
const PINNED_OPENCLAW_VERSION = '2026.7.1-2';

// Known plugin-id → npm package map (proven 2026-08-27 on bernardo3).
const PLUGIN_NPM_MAP = {
  signal: '@openclaw/signal',
  brave: '@openclaw/brave-plugin',
  venice: '@openclaw/venice-provider',
  'llama-cpp': '@openclaw/llama-cpp-provider',
};

// ── Version / env probing ────────────────────────────────────────

function probeVersion(cmd, args) {
  try {
    return execFileSync(cmd, args, { encoding: 'utf8', timeout: 15000 }).trim();
  } catch { return null; }
}

function probeHost() {
  const ocVersion = probeVersion('openclaw', ['--version']);
  return {
    platform: platform(),
    arch: arch(),
    node: process.version,
    openclaw: ocVersion || `OpenClaw ${PINNED_OPENCLAW_VERSION}`,
    openclawPinned: PINNED_OPENCLAW_VERSION,
    ollamaModels: probeOllamaModels(),
  };
}

/**
 * Extract a clean version string for npm install.
 * `openclaw --version` returns "OpenClaw 2026.7.1-2 (0790d9f)" → "2026.7.1-2".
 * Falls back to PINNED_OPENCLAW_VERSION.
 */
export function probeOpenclawVersion() {
  const raw = probeVersion('openclaw', ['--version']);
  if (raw) {
    const m = raw.match(/(\d{4}\.\d+\.\d+[-.]\d+)/);
    if (m) return m[1];
  }
  return PINNED_OPENCLAW_VERSION;
}

function probeOllamaModels() {
  try {
    const out = execFileSync('ollama', ['list'], { encoding: 'utf8', timeout: 15000 });
    return out.trim().split('\n').slice(1).map(l => l.split(/\s+/)[0]).filter(Boolean);
  } catch { return null; }
}

// ── Dependency manifest (L1, L2) ─────────────────────────────────

/**
 * Build the dependency manifest from live host state + config.
 * @param {object} cfg parsed openclaw.json
 */
export function buildDependencyManifest(cfg, targetPlatform = process.platform) {
  const deps = { brew: [], casks: [], npmGlobal: [], plugins: [], ollamaModels: [], commands: [], unknownPlugins: [] };
  const ocVer = probeOpenclawVersion();
  const ocInstall = `npm install -g openclaw@${ocVer}`;

  const pluginEntries = cfg?.plugins?.entries || {};
  for (const [id, entry] of Object.entries(pluginEntries)) {
    if (entry && entry.enabled === false) continue;
    if (PLUGIN_NPM_MAP[id]) {
      deps.plugins.push({ id, npm: PLUGIN_NPM_MAP[id] });
      deps.commands.push(`openclaw plugins install ${PLUGIN_NPM_MAP[id]}`);
    } else {
      deps.unknownPlugins.push(id);
      deps.commands.push(`# plugin "${id}": no known npm package — install manually`);
    }
  }

  for (const model of probeOllamaModels() || []) {
    deps.ollamaModels.push(model);
    // R8 minor: these are SOURCE-observed models. On a hosted→ClawBox target
    // they may be irrelevant — the runbook note tells the user to edit as
    // needed for target hardware.
    deps.commands.push(`ollama pull ${model}   # source-observed; edit for target hardware`);
  }

  // Core runtime requirements (L1): node + openclaw. Platform-aware (R4/R7):
  // commands are generated for the TARGET machine, not the source — so a
  // Linux-hosted bundle can still tell a macOS ClawBox user to `brew install`.
  // Explicitly: brew is macOS-only; Linux targets use apt/npm.
  if (targetPlatform === 'darwin') {
    deps.commands.unshift('# Core runtime:', 'brew install node', ocInstall);
  } else if (targetPlatform === 'linux') {
    // NodeSource for Debian/Ubuntu (David approved 2026-08-31).
    // Falls through to apt nodejs/npm if NodeSource fails.
    deps.commands.unshift('# Core runtime:',
      "curl -fsSL https://deb.nodesource.com/setup_22.x | bash -",
      'apt-get install -y nodejs',
      ocInstall);
  } else {
    deps.commands.unshift('# Core runtime:', ocInstall);
  }

  return deps;
}

// ── Config templating (L3) ───────────────────────────────────────

/**
 * Literalize the home path in a config object into a template string.
 * @param {object} cfg
 * @param {string} home
 * @returns {{ template: string, hits: number }}
 */
export function templateConfig(cfg, home = homedir()) {
  // Documented limitation (Grok R6 minor): a whole-JSON regex literalizes the
  // home path everywhere. Any config value that legitimately contains the
  // source home as a substring would be mutated too. Proven on bernardo3
  // (47 hits, all genuine paths). If false positives ever appear, replace with
  // a JSON walker that only rewrites known path-bearing fields.
  const raw = JSON.stringify(cfg, null, 2);
  const escaped = home.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp(escaped, 'g');
  const hits = (raw.match(re) || []).length;
  return { template: raw.replace(re, '{{HOME}}'), hits };
}

/**
 * Restore a config template for a target home.
 * @param {string} template
 * @param {string} home
 */
export function untemplateConfig(template, home = homedir()) {
  return template.split('{{HOME}}').join(home);
}

// ── Skills state (L2, L10) ───────────────────────────────────────

export function extractSkillsState(cfg) {
  // Lesson L2/L10 (bernardo3): `openclaw doctor` disables skills whose binaries
  // are missing, so the OBSERVED state is not the DESIRED state. Export both:
  //   .enabled    — what the config says NOW (may be doctor-disabled)
  //   .wanted     — DESIRED: any skill present in the source config is wanted
  //                 once its binaries exist. Doctor-disabled skills typically
  //                 CARRY a disabledReason (binary/doctor), so excluding by
  //                 reason would defeat L2 exactly when it matters (Grok R9).
  // Import re-enables anything `wanted:true` that landed disabled after deps
  // install — this makes the runbook's "re-enable after deps" claim true.
  const out = {};
  const entries = cfg?.skills?.entries || {};
  for (const [name, entry] of Object.entries(entries)) {
    const enabled = entry?.enabled !== false;
    out[name] = {
      enabled,
      // A skill present in the source config is wanted once deps exist.
      wanted: true,
    };
  }
  return out;
}

// ── Cron export (L4, L5) ─────────────────────────────────────────

/**
 * Load cron jobs. Tries `openclaw cron list --json`, else an explicit file.
 * Never SQL — schema differs across OpenClaw versions (L4, proven 2026-08-27).
 * @returns {{ jobs: object[], source: string }}
 */
export function loadCronJobs(explicitFile = null) {
  if (explicitFile) {
    // Normalize the explicit-file case the same way as the live CLI path
    // (Grok R4 minor): accept a bare array or { jobs: [...] } root.
    const parsed = JSON.parse(readFileSync(explicitFile, 'utf8'));
    const jobs = Array.isArray(parsed) ? parsed : (parsed.jobs || []);
    return { jobs, source: explicitFile };
  }
  try {
    const out = execFileSync('openclaw', ['cron', 'list', '--json'], {
      encoding: 'utf8', timeout: 30000,
    });
    const parsed = JSON.parse(out);
    const jobs = Array.isArray(parsed) ? parsed : (parsed.jobs || []);
    return { jobs, source: 'openclaw cron list --json' };
  } catch {
    return { jobs: null, source: 'unavailable' };
  }
}

/**
 * Apply role policy to cron jobs (L5): worker → all jobs disabled.
 */
export function applyCronRole(jobs, role) {
  if (!Array.isArray(jobs)) return jobs;
  if (role !== 'worker') return jobs;
  return jobs.map(j => ({ ...j, enabled: false }));
}

// ── Keychain export (L6) ─────────────────────────────────────────

const DEFAULT_KEYCHAIN_SERVICES = [
  'venice-key1', 'venice-key2', 'xai-grok45-api-key',
  'supabase-service-key', 'manifest-testnet-mnemonic',
];

/**
 * Collect secrets from macOS keychain. Values are never written in cleartext
 * to the staging dir — only into the encrypted blob.
 */
export function collectKeychainSecrets(services = DEFAULT_KEYCHAIN_SERVICES, account = process.env.USER || 'openclaw') {
  if (platform() !== 'darwin') return { secrets: {}, missing: services.slice(), account };
  const secrets = {};
  const missing = [];
  for (const svc of services) {
    try {
      // Match account to the item's existing account when one is stored
      // (Grok R8: the import side must use the SAME -a value, else keys are
      // misclassified as present/skipped on a differently-named target).
      // Claude M1: capture the QUOTED value only — `security` emits
      // "acct"<blob>="bernardo"; the old [^\s]+ regex kept the quotes and
      // the follow-up -a lookup failed, silently dropping the secret.
      const found = execFileSync('security', ['find-generic-password', '-s', svc], {
        encoding: 'utf8', timeout: 10000,
      });
      const acct = parseKeychainAccount(found, account);
      const val = execFileSync('security', ['find-generic-password', '-a', acct, '-s', svc, '-w'], {
        encoding: 'utf8', timeout: 10000,
      }).trim();
      if (val) secrets[svc] = { value: val, account: acct }; else missing.push(svc);
    } catch { missing.push(svc); }
  }
  return { secrets, missing, account };
}

/**
 * Parse the account name out of `security find-generic-password -s <svc>`
 * output. The attribute line is `"acct"<blob>="bernardo"` — only the quoted
 * value is the account. Returns the fallback when the line is absent or the
 * value is empty (e.g. <NULL> or a hex blob). Exported for unit tests.
 */
export function parseKeychainAccount(found, fallback) {
  const m = found.match(/"acct"<blob>="([^"]*)"/);
  return m && m[1] ? m[1] : fallback;
}

// ── Crypto (same format as buddy-export.mjs identity blobs) ──────

const KDF_OPTS = { N: 16384, r: 8, p: 1 };

export function encryptBuffer(plaintext, passphrase) {
  const salt = randomBytes(16);
  const key = scryptSync(passphrase, salt, 32, KDF_OPTS);
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([salt, iv, tag, ciphertext]);
}

export function decryptBuffer(blob, passphrase) {
  if (blob.length < 44) throw new Error('Encrypted blob too short');
  const salt = blob.subarray(0, 16);
  const iv = blob.subarray(16, 28);
  const tag = blob.subarray(28, 44);
  const ciphertext = blob.subarray(44);
  const key = scryptSync(passphrase, salt, 32, KDF_OPTS);
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

/**
 * Streaming encryption for large files (>2 GiB).
 * Format: salt(16) + iv(12) + ciphertext + tag(16)
 * Uses a header file + streaming pipeline, then concatenates.
 */
export async function encryptFileStreaming(inputPath, outputPath, passphrase) {
  const salt = randomBytes(16);
  const key = scryptSync(passphrase, salt, 32, KDF_OPTS);
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);

  // Write header (salt+iv) to temp file
  const tmpCipher = outputPath + '.cipher';
  const fs = await import('node:fs/promises');
  await fs.writeFile(outputPath + '.hdr', Buffer.concat([salt, iv]));

  // Stream: input plaintext → cipher → cipher-file
  await pipeline(
    createReadStream(inputPath, { highWaterMark: 1024 * 1024 * 8 }),
    cipher,
    createWriteStream(tmpCipher)
  );

  // Append GCM auth tag to cipher file
  const tag = cipher.getAuthTag();
  await fs.appendFile(tmpCipher, tag);

  // Concatenate: header + cipher+tag → output
  await pipeline(
    createReadStream(outputPath + '.hdr'),
    createWriteStream(outputPath)
  );
  await pipeline(
    createReadStream(tmpCipher),
    createWriteStream(outputPath, { flags: 'a' })
  );

  // Cleanup temps
  await fs.unlink(outputPath + '.hdr').catch(() => {});
  await fs.unlink(tmpCipher).catch(() => {});
}

/**
 * Streaming decryption for large files (>2 GiB).
 * Reads header (salt+iv) from input, decrypts in chunks.
 * Verifies GCM tag at the end.
 */
export async function decryptFileStreaming(inputPath, outputPath, passphrase) {
  const fs = await import('node:fs/promises');
  const stat = await fs.stat(inputPath);
  if (stat.size < 44) throw new Error('Encrypted file too short');

  // Read header (salt + iv = 28 bytes) and tag (last 16 bytes)
  const fd = await fs.open(inputPath, 'r');
  const header = Buffer.alloc(28);
  await fd.read(header, 0, 28, 0);
  const tag = Buffer.alloc(16);
  await fd.read(tag, 0, 16, stat.size - 16);
  await fd.close();

  const salt = header.subarray(0, 16);
  const iv = header.subarray(16, 28);
  const key = scryptSync(passphrase, salt, 32, KDF_OPTS);
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);

  // Stream: input[28:size-16] → decipher → output
  // Create a read stream that skips the first 28 bytes and stops 16 before end
  const { createReadStream: crs } = await import('node:fs');
  const totalCipherLen = stat.size - 28 - 16;
  const input = crs(inputPath, {
    start: 28,
    end: 28 + totalCipherLen - 1,
    highWaterMark: 1024 * 1024 * 8
  });

  try {
    await pipeline(input, decipher, createWriteStream(outputPath));
  } catch (err) {
    throw new Error(`decryption stream failed: ${err.message}`);
  }
}

// ── Workspace packing (L12) ──────────────────────────────────────

/**
 * Find all workspace directories under the openclaw dir:
 * main workspace/ plus workspace-* sub-agent workspaces.
 */
export function findWorkspaces(openclawDir = OPENCLAW_DIR) {
  const found = [];
  if (!existsSync(openclawDir)) return found;
  for (const name of readdirSync(openclawDir)) {
    if (name === 'workspace' || name.startsWith('workspace-')) {
      const p = join(openclawDir, name);
      try { if (statSync(p).isDirectory()) found.push({ name, path: p }); } catch { /* skip */ }
    }
  }
  return found;
}

// ── Runbook generation ───────────────────────────────────────────

export function generateRunbook(manifest, deps) {
  const roleNote = manifest.role === 'worker'
    ? 'ROLE=worker: all cron jobs import DISABLED to avoid double execution.'
    : 'ROLE=primary: cron jobs import enabled.';
  const lines = [
    '# Migration Runbook (generated)', '',
    `Source host: ${manifest.source.host} (${manifest.source.platform}/${manifest.source.arch})`,
    `OpenClaw: ${manifest.source.openclaw || 'unknown'} · Node: ${manifest.source.node}`,
    `OpenClaw PIN: openclaw@${manifest.source.openclawPinned || 'unversioned'} — do NOT install @latest (8.1.x is unstable for this setup)`,
    `Role: ${manifest.role} — ${roleNote}`, '',
    '## 1. Core runtime + dependencies',
    '```', ...deps.commands, '```', '',
    '## 2. Import this bundle',
    '```',
    `node migrate-import.mjs --import ${BUNDLE_NAME_STEM}-<timestamp>.tar.gz.enc`,
    '```', '',
    '## 3. VERIFY before importing (tamper check)',
    'The export script prints the SHA-256 of the ENCRYPTED bundle file to the',
    'terminal. Compare it with the bundle you hold BEFORE importing (out-of-band).',
    'That value is deliberately NOT stored inside this bundle: a file cannot',
    'contain a hash of its own final bytes, so any in-bundle checksum would be',
    'recomputable by a tamperer. In-bundle per-file checksums in manifest.json',
    'guard against ACCIDENTAL corruption; the out-of-band hash guards against',
    'deliberate tampering.', '',
    '## 4. Cron jobs',
    manifest.excluded.crons
      ? 'Cron jobs NOT included in this bundle. Recreate them manually.'
      : 'Restored by the import script from cron-jobs.json (never SQL).\nAfter import: pending jobs are staged at ~/.openclaw/pending-cron-import.json —\nhave your agent create each one with the cron tool (gateway API).', '',
    '## 5. Not portable (excluded by design)',
    `- Signal account link: one Signal number per instance (L7) — relink separately.`,
    `- Session history: non-portable across versions (L13).`,
    ...Object.entries(manifest.excluded).filter(([, v]) => v).map(([k]) => `- ${k}`), '',
    '## 6. After import',
    '1. Run the verification checklist printed by the import script.',
    '2. Send a test message to the agent.',
    '3. DELETE the bundle file — it contains live secrets (L14).', '',
  ];
  return lines.join(EOL);
}

// ── Export ───────────────────────────────────────────────────────

/**
 * Build the migration bundle.
 * @param {object} options
 * @param {string} [options.output]
 * @param {string} options.passphrase
 * @param {string} [options.role=primary]
 * @param {string} [options.cronsFile]
 * @param {string[]} [options.keychainServices]
 * @param {string} [options.openclawDir] — override for testing
 * @param {string} [options.stagingDir] — override for testing
 * @param {boolean} [options.dryRun=false]
 */
// Phase instrumentation (staging debug 2026-09-02): every phase emits one
// stderr line with elapsed seconds. stderr is NOT part of the --agentic JSON
// stdout contract, so this is safe for production. Enable verbose listing via
// MIGRATE_EXPORT_TRACE=1 (default on — lines are tiny and aid incident triage).
const _t0 = Date.now();
function tracePhase(name) {
  if (process.env.MIGRATE_EXPORT_TRACE === '0') return;
  console.error(`[export-phase] t=${((Date.now() - _t0) / 1000).toFixed(1)}s ${name}`);
}

export async function exportMigrateBundle(options = {}) {
  tracePhase('start');
  const {
    output = null,
    role = 'primary',
    cronsFile = null,
    openclawDir = OPENCLAW_DIR,
    dryRun = false,
  } = options;

  // Claude R1 fix: resolve keychainServices and targetPlatform explicitly
  // (parseArgs seeds [] and null, bypassing destructure defaults).
  const keychainServices =
    (Array.isArray(options.keychainServices) && options.keychainServices.length)
      ? options.keychainServices
      : DEFAULT_KEYCHAIN_SERVICES;
  const targetPlatform = options.targetPlatform ?? process.platform;

  // Claude R4 fix: same null-vs-undefined bug as keychainServices/targetPlatform.
  // parseArgs seeds passphrase: null, bypassing the destructure default.
  // Use nullish coalescing so MIGRATE_PASSPHRASE env works (recommended path
  // to keep the secret out of ps/history).
  const passphrase = options.passphrase ?? process.env.MIGRATE_PASSPHRASE ?? null;

  if (!passphrase || passphrase.length < MIN_PASSPHRASE_LEN) {
    throw new Error(`passphrase required (min ${MIN_PASSPHRASE_LEN} chars)`);
  }
  if (!['primary', 'worker'].includes(role)) {
    throw new Error(`role must be primary|worker, got: ${role}`);
  }
  tracePhase('env-validated');
  if (!existsSync(join(openclawDir, 'openclaw.json'))) {
    throw new Error(`openclaw.json not found in ${openclawDir}`);
  }

  const cfg = JSON.parse(readFileSync(join(openclawDir, 'openclaw.json'), 'utf8'));
  tracePhase('config-loaded');
  const { template: configTmpl, hits: pathHits } = templateConfig(cfg, homedir());
  const host = probeHost();
  tracePhase('host-probed');
  const deps = buildDependencyManifest(cfg, targetPlatform);
  const skillsState = extractSkillsState(cfg);

  // Crons (L4: JSON only, never SQL)
  const cronRaw = loadCronsFileCompat(cronsFile);
  tracePhase('crons-loaded');
  const crons = applyCronRole(cronRaw.jobs, role);
  const excluded = {
    crons: !crons,
    signalLink: true,   // always — one number per instance (L7)
    sessionHistory: true, // always — non-portable (L13)
    walletKey: keychainMissingWallet(),
  };

  // Keychain secrets (encrypted, never cleartext on disk)
  tracePhase('keychain-start');
  const kc = collectKeychainSecrets(keychainServices);
  tracePhase('keychain-done');

  const checksumOf = (s) => createHash('sha256').update(s).digest('hex');

  const manifest = {
    schemaVersion: MANIFEST_VERSION,
    created: new Date().toISOString(),
    role,
    source: { host: hostnameSafe(), platform: host.platform, arch: host.arch, node: host.node, openclaw: host.openclaw, openclawPinned: host.openclawPinned },
    configPathHitsLiteralized: pathHits,
    keychainImported: Object.keys(kc.secrets),
    keychainMissing: kc.missing,
    ollamaModels: host.ollamaModels || [],
    excluded,
  };

  tracePhase('dry-run-check');
  if (dryRun) {
    return { manifest, deps, skillsState, cronCount: Array.isArray(crons) ? crons.length : 0, dryRun: true };
  }

  // Stage everything
  const stage = options.stagingDir || join(tmpdir(), `${BUNDLE_NAME_STEG()}`);
  rmSync(stage, { recursive: true, force: true });
  mkdirSync(stage, { recursive: true, mode: 0o700 });

  writeFileSync(join(stage, 'manifest.json'), JSON.stringify(manifest, null, 2), { mode: 0o600 });
  writeFileSync(join(stage, 'dependency-manifest.json'), JSON.stringify(deps, null, 2), { mode: 0o600 });
  writeFileSync(join(stage, 'config.json.tmpl'), configTmpl, { mode: 0o600 });
  writeFileSync(join(stage, 'skills-state.json'), JSON.stringify(skillsState, null, 2), { mode: 0o600 });

  if (crons) {
    writeFileSync(join(stage, 'cron-jobs.json'), JSON.stringify(crons, null, 2), { mode: 0o600 });
  }

  // Workspaces tar (L12: includes sub-agent workspaces automatically)
  // NO -z flag: macOS bsdtar gzip has a 2 GiB internal limit.
  // The outer bundle tar uses -z for compression.
  const workspaces = findWorkspaces(openclawDir);
  tracePhase(`workspaces-found count=${workspaces.length}`);
  if (workspaces.length > 0) {
    const tarArgs = ['-cf', join(stage, 'workspaces.tar'),
      '-C', openclawDir, ...workspaces.map(w => w.name)];
    const wsResult = spawnSync('tar', tarArgs,
      { timeout: 600000 });
    tracePhase('workspaces-tarred');
    if (wsResult.status !== 0) {
      throw new Error(`workspace tar failed (exit ${wsResult.status}): ${wsResult.stderr?.toString()?.slice(0, 500)}`);
    }
  }

  // Encrypted keychain map (inner layer; the outer bundle tar is encrypted too —
  // same passphrase, so this adds no cryptographic strength. Defense-in-depth /
  // future-proofing: the map stays opaque if the outer layer is ever decrypted
  // for inspection or a future key-change flow (Grok R7 minor note).)
  writeFileSync(join(stage, 'keychain.json.enc'),
    encryptBuffer(Buffer.from(JSON.stringify(kc), 'utf8'), passphrase), { mode: 0o600 });

  // Runbook: NEVER embeds the out-of-band checksum. A file cannot contain a
  // hash of its own final bytes (fixed point), so any in-bundle value would be
  // recomputable by a tamperer. The exporter prints the SHA-256 of the
  // ENCRYPTED bundle to the terminal; that out-of-band value is the tamper
  // gate (Claude audit B1 fix).
  writeFileSync(join(stage, 'RUNBOOK.md'), generateRunbook(manifest, deps), { mode: 0o600 });
  // Payload list for checksumming (finalized after the runbook write below).
  const payloadFiles = ['dependency-manifest.json', 'config.json.tmpl', 'skills-state.json', 'RUNBOOK.md'];
  if (crons) payloadFiles.push('cron-jobs.json');
  if (workspaces.length > 0) payloadFiles.push('workspaces.tar');
  payloadFiles.push('keychain.json.enc');

  // Single definitive tar pass (no two-pass: nothing inside the bundle needs
  // the out-of-band hash). Plaintext tars live only in a private 0o700 tmp
  // dir, never next to the output (Grok R2 fix).
  const outPath = output || join(homedir(), 'Documents', `${BUNDLE_NAME_STEM}-${timestamp()}.tar.gz.enc`);
  mkdirSync(dirname(resolve(outPath)), { recursive: true });
  const tmpTarDir = mkdtempSync(join(tmpdir(), 'mig-tar-'));
  chmodSync(tmpTarDir, 0o700);
  const tarPath = join(tmpTarDir, 'bundle.tar.gz');
  let bundleChecksum = null;
  try {
    // Finalize manifest: per-file SHA-256 checksums of the staged payload files
    // exactly as they will ship.
    tracePhase('final-checksums-start');
    const finalChecksums = {};
    for (const f of payloadFiles) {
      // Streaming hash for large files (>2 GiB workspaces.tar)
      const h = createHash('sha256');
      await pipeline(createReadStream(join(stage, f), { highWaterMark: 1024 * 1024 * 8 }), h);
      finalChecksums[f] = h.digest('hex');
    }
    tracePhase('final-checksums-done');
    manifest.checksums = finalChecksums;

    // Self-checksum (Grok R9/R10): the in-bundle checksum guarantee must cover
    // the manifest that carries the table. A file cannot hash the exact bytes
    // that contain its own hash (fixed point), so both sides hash the manifest
    // with the self-reference normalized to a fixed placeholder (''). The value
    // is stored in the on-disk manifest; import recomputes it the same way.
    manifest.checksums['manifest.json'] = '';
    const selfBuf = Buffer.from(JSON.stringify(manifest, null, 2) + '\n', 'utf8');
    const selfHash = createHash('sha256').update(selfBuf).digest('hex');
    manifest.checksums['manifest.json'] = selfHash;
    writeFileSync(join(stage, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n', { mode: 0o600 });

    // Definitive tar + encrypt to the output path.
    // Use spawnSync for tar (no buffer issue — writes to file).
    const tarResult = spawnSync('tar', ['-cf', tarPath, '-C', stage, '.'],
      { timeout: 600000, maxBuffer: 1024 * 1024 * 1024 * 4 });
    tracePhase('bundle-tarred');
    if (tarResult.status !== 0) {
      throw new Error(`bundle tar failed (exit ${tarResult.status}): ${tarResult.stderr?.toString()?.slice(0, 500)}`);
    }
    // Stream-encrypt the tar (handles >2 GiB files).
    await encryptFileStreaming(tarPath, outPath, passphrase);
    tracePhase('bundle-encrypted');
    // B1 fix (Claude audit): the out-of-band checksum is the SHA-256 of the
    // ENCRYPTED FILE — the exact artifact the operator holds and imports.
    const ckHash = createHash('sha256');
    await pipeline(
      createReadStream(outPath, { highWaterMark: 1024 * 1024 * 8 }),
      ckHash
    );
    bundleChecksum = ckHash.digest('hex');
    tracePhase('bundle-checksummed');
  } finally {
    rmSync(tmpTarDir, { recursive: true, force: true });
    rmSync(stage, { recursive: true, force: true });
  }

  return {
    outputPath: resolve(outPath),
    manifest,
    bundleChecksum,
    deps,
    workspaceCount: workspaces.length,
    cronCount: Array.isArray(crons) ? crons.length : 0,
    keychainCount: Object.keys(kc.secrets).length,
    keychainMissing: kc.missing,
    dryRun: false,
  };
}

// ── helpers ──────────────────────────────────────────────────────

function loadCronsFileCompat(cronsFile) {
  const r = loadCronJobs(cronsFile);
  if (r.jobs === null) {
    return { jobs: null, source: r.source };
  }
  return r;
}

function keychainMissingWallet() {
  // Wallet key is not under a known keychain service (lesson from bernardo3 L11)
  try {
    execFileSync('security', ['find-generic-password', '-s', 'morpheus-wallet-key', '-w'],
      { encoding: 'utf8', timeout: 10000 });
    return false;
  } catch { return true; }
}

function hostnameSafe() {
  try { return execFileSync('hostname', { encoding: 'utf8' }).trim(); }
  catch { return 'unknown'; }
}

function timestamp() {
  return new Date().toISOString().replace(/[-:T]/g, '').slice(0, 12);
}

function BUNDLE_NAME_STEG() {
  return `${BUNDLE_NAME_STEM}-stage-${process.pid}-${randomBytes(4).toString('hex')}`;
}

// ── Upload to Edge Function (agentic + --upload) ─────────────────

// NOTE (audit R3-F2 / R4-F1): basename is imported at module level line 30
// (node:path); randomBytes at line 33 (node:crypto). FormData/Blob/fetch are
// Node 18+ globals (undici) — the container runs Node 22+, so no import needed.
// This comment exists so future auditors do not reopen the "unused import" item.

const MAX_UPLOAD_BYTES = 100 * 1024 * 1024; // 100 MB — must match Edge Function limit

/**
 * Upload the encrypted bundle to the agent-export-upload Edge Function.
 * Uses OPENCLAW_BINDING_SECRET env var for auth — never passed via argv.
 * Pre-checks size against MAX_UPLOAD_BYTES, then loads into a single Buffer.
 * 100 MB is well within container memory limits and matches the Edge Function's
 * own arrayBuffer() path. Simpler and more reliable than manual stream orchestration.
 * Returns { download_url, expires_at, file_path, size }.
 */
async function uploadBundle(outputPath, uploadUrl) {
  const bindingSecret = process.env.OPENCLAW_BINDING_SECRET;
  if (!bindingSecret) {
    throw new Error('OPENCLAW_BINDING_SECRET env var required for --upload');
  }
  const fs = await import('node:fs/promises');
  const { statSync } = await import('node:fs');

  // Pre-upload size check — prevent OOM on container
  const fileSize = statSync(outputPath).size;
  if (fileSize > MAX_UPLOAD_BYTES) {
    throw new Error(`Bundle too large: ${fileSize} bytes (max ${MAX_UPLOAD_BYTES} bytes)`);
  }

  // Load file into Buffer — safe because size check above caps at 100 MB.
  const fileBuffer = await fs.readFile(outputPath);

  // Use the platform FormData + Blob API (available in Node 18+ via undici).
  // This avoids fragile manual multipart construction.
  // If the globals are somehow absent in a minimal runtime, fall back to
  // undici's named exports (bundled with Node, no extra dependency).
  const { FormData: FD, Blob: BL } = globalThis.FormData && globalThis.Blob
    ? { FormData: globalThis.FormData, Blob: globalThis.Blob }
    : await import('undici');
  const formData = new FD();
  formData.append('file', new BL([fileBuffer], { type: 'application/octet-stream' }), basename(outputPath));

  tracePhase(`upload-start size=${(fileSize / 1024 / 1024).toFixed(1)}MB`);
  const resp = await fetch(uploadUrl, {
    method: 'POST',
    headers: {
      'x-binding-secret': bindingSecret,
    },
    body: formData,
    signal: AbortSignal.timeout(90_000), // bounded — a hung upload must not eat the 120s route budget
  });
  tracePhase(`upload-response status=${resp.status}`);

  if (!resp.ok) {
    const errText = await resp.text();
    throw new Error(`Upload failed (${resp.status}): ${errText.slice(0, 500)}`);
  }

  return await resp.json();
}

// ── CLI ──────────────────────────────────────────────────────────

function parseArgs(argv) {
  const args = { output: null, passphrase: null, role: 'primary', cronsFile: null,
    keychainServices: [], targetPlatform: null, dryRun: false, serve: false, agentic: false,
    upload: false, uploadUrl: null, callbackUrl: null, help: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const val = () => { if (i + 1 >= argv.length) { console.error(`❌ ${a} requires a value`); process.exit(1); } return argv[++i]; };
    switch (a) {
      case '--output': args.output = val(); break;
      case '--passphrase': args.passphrase = val(); break;
      case '--role': args.role = val(); break;
      case '--crons': args.cronsFile = val(); break;
      case '--target-platform': args.targetPlatform = val(); break;
      case '--keychain-service': args.keychainServices.push(val()); break;
      case '--dry-run': args.dryRun = true; break;
      case '--serve': args.serve = true; break;
      case '--agentic': args.agentic = true; break;
      case '--upload': args.upload = true; break;
      case '--upload-url': args.uploadUrl = val(); break;
      case '--callback-url': args.callbackUrl = val(); break;
      case '--help': args.help = true; break;
      default: console.error(`❌ Unknown flag: ${a}`); process.exit(1);
    }
  }
  return args;
}

function printHelp() {
  console.log(`migrate-export — Full-Host Migration Export (Gap 8)

Usage:
  node migrate-export.mjs [--output <path>] [--role primary|worker] [--dry-run]

Flags:
  --output <path>            Output .tar.gz.enc path (default ~/Documents/)
  --passphrase <pw>         Bundle passphrase — PREFER MIGRATE_PASSPHRASE env
                            (argv is visible in ps/history). Min 16 chars.
  --role primary|worker      worker = import all crons DISABLED (default primary)
  --crons <file>             Use this cron-jobs.json instead of live CLI export
  --target-platform <p>      Generate install commands for this target platform
                             (darwin|linux; default: source host platform)
  --keychain-service <svc>   Extra keychain service to include (repeatable)
  --dry-run                  Show plan without writing anything
  --serve                     Export + start download server (Option D)
  --agentic                   Non-interactive mode: auto-generate passphrase,
                             output JSON to stdout ({ outputPath, passphrase,
                             bundleChecksum, size }). No /dev/tty access.
                             For agent/chat-triggered exports.
  --upload                    After export, upload bundle to Supabase Storage
                             via the agent-export-upload Edge Function.
                             Requires --upload-url and OPENCLAW_BINDING_SECRET env.
  --upload-url <url>          The Edge Function endpoint URL for upload.
  --callback-url <url>        Edge Function to POST result JSON after upload (async job pattern).
                              If set, the script POSTs { download_url, expires_at } to this URL
                              so the dashboard can poll for completion without the LLM response.
  --help                     This help

SECURITY: the bundle is encrypted (AES-256-GCM, scrypt). Delete it after import.`);
}

if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith('migrate-export.mjs')) {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) { printHelp(); process.exit(0); }
  (async () => {
    try {
      if (args.serve) {
        // --serve: export then hand off to migrate-serve.mjs
        const { runServe } = await import('./migrate-serve.mjs');
        await runServe(args);
        return; // runServe spawns the server child and exits when it exits
      }

      if (args.agentic) {
        // --agentic: non-interactive mode for agent/chat-triggered exports.
        // Auto-generate passphrase, output JSON to stdout, never touch /dev/tty.
        // If --upload is set, also upload the bundle and include download_url in output.
        // Force output to /tmp in agentic mode — containers may lack ~/Documents.
        if (!args.output) {
          args.output = join(tmpdir(), `migrate-bundle-${timestamp()}.tar.gz.enc`);
        }
        const { generatePassphrase } = await import('./lib/encryption.mjs');
        const passphrase = args.passphrase || process.env.MIGRATE_PASSPHRASE || generatePassphrase(6);
        if (passphrase.length < MIN_PASSPHRASE_LEN) {
          process.stderr.write(`Error: auto-passphrase too short (${passphrase.length} chars, min ${MIN_PASSPHRASE_LEN})\n`);
          process.exit(1);
        }
        let bundlePath = null;
        let uploadSucceeded = false;
        try {
          const res = await exportMigrateBundle({ ...args, passphrase });
          if (res.dryRun) {
            process.stdout.write(JSON.stringify({ dryRun: true, manifest: res.manifest, cronCount: res.cronCount }) + '\n');
            return;
          }
          bundlePath = res.outputPath;
          const { statSync } = await import('node:fs');
          const size = statSync(res.outputPath).size;
          const output = {
            passphrase,
            bundleChecksum: res.bundleChecksum,
            size,
            workspaceCount: res.workspaceCount,
            cronCount: res.cronCount,
            keychainCount: res.keychainCount,
            keychainMissing: res.keychainMissing,
          };
          if (args.upload) {
            if (!args.uploadUrl) {
              process.stderr.write('Error: --upload requires --upload-url\n');
              output.upload_error = 'Missing --upload-url';
              // Keep the bundle locally so user can manually upload.
              output.outputPath = res.outputPath;
            } else {
              try {
                const uploadResult = await uploadBundle(res.outputPath, args.uploadUrl);
                output.download_url = uploadResult.download_url;
                output.expires_at = uploadResult.expires_at;
                output.uploaded = true;
                uploadSucceeded = true;
                // Post result to callback URL if provided (async job pattern).
                // This lets the dashboard poll for completion even if the
                // LLM response doesn't make it back in time.
                if (args.callbackUrl) {
                  try {
                    await fetch(args.callbackUrl, {
                      method: 'POST',
                      headers: { 'Content-Type': 'application/json' },
                      body: JSON.stringify({
                        download_url: uploadResult.download_url,
                        expires_at: uploadResult.expires_at,
                        // NOTE: passphrase is NOT sent to the callback.
                        // It is returned synchronously to the caller via stdout.
                        // The callback only stores download_url for polling.
                      }),
                    });
                  } catch (cbErr) {
                    process.stderr.write(`Callback failed (non-fatal): ${cbErr.message}\n`);
                  }
                }
              } catch (err) {
                process.stderr.write(`Upload failed: ${err.message}\n`);
                output.upload_error = err.message.slice(0, 200);
                // Keep the bundle locally so user can retry or manually import.
                // The bundle is encrypted — passphrase is required to decrypt.
                output.outputPath = res.outputPath;
              }
            }
          } else {
            // No upload requested — keep the bundle locally.
            // This is the standalone export use case (e.g. manual --agentic
            // run or the auth-proxy passing --upload explicitly). The caller
            // receives outputPath and must handle/delete the bundle.
            output.outputPath = res.outputPath;
            // Note: do NOT set uploadSucceeded here — that flag means "upload
            // completed", and the finally block deletes the bundle when true.
          }
          process.stdout.write(JSON.stringify(output) + '\n');
        } catch (err) {
          process.stderr.write(`Export failed: ${err.message}\n`);
          process.stdout.write(JSON.stringify({ error: err.message.slice(0, 200) }) + '\n');
        } finally {
          // Delete the bundle ONLY when an upload actually succeeded.
          // If no upload was requested, or upload failed, keep the bundle
          // (it is AES-256-GCM encrypted; the passphrase is in caller hands).
          // Platform pattern: --agentic --upload success -> delete;
          // --agentic (no upload) -> keep; --agentic --upload failure -> keep.
          if (bundlePath && uploadSucceeded === true) {
            const fs2 = await import('node:fs/promises');
            await fs2.unlink(bundlePath).catch(() => {});
          }
        }
        return;
      }

      const res = await exportMigrateBundle(args);
      if (res.dryRun) {
        console.log('DRY RUN — no files written.');
        console.log(JSON.stringify({ manifest: res.manifest, cronCount: res.cronCount, deps: res.deps.commands }, null, 2));
      } else {
        console.log(`✅ Bundle: ${res.outputPath}`);
        console.log(`   workspaces: ${res.workspaceCount} · crons: ${res.cronCount} · keychain: ${res.keychainCount} (missing: ${res.keychainMissing.join(', ') || 'none'})`);
        console.log(`   config paths literalized: ${res.manifest.configPathHitsLiteralized}`);
        console.log(`   SHA-256 (encrypted bundle file): ${res.bundleChecksum}`);
        console.log(`   Short match: ${res.bundleChecksum ? res.bundleChecksum.slice(0, 12) : 'n/a'} — compare this value with the bundle BEFORE importing (out-of-band)`);
        console.log('⚠️  DELETE this bundle after successful import — it contains live secrets.');
      }
    } catch (err) {
      if (args.agentic) {
        process.stderr.write(`Error: ${err.message}\n`);
        process.exit(1);
      }
      console.error(`❌ ${err.message}`);
      process.exit(1);
    }
  })();
}
