#!/usr/bin/env node

/**
 * Everclaw setup.mjs — Config setup for OpenClaw + Morpheus
 *
 * Stage 1: Detects OS, picks template, loads it.
 * Stage 2: Finds openclaw.json, deep-merges providers, writes on --apply.
 * Stage 3: Updates auth-profiles.json, --test pings gateway, --restart restarts.
 * Stage 4: Configures security tier (exec-approvals.json + safeBins).
 *
 * Usage:
 *   node scripts/setup.mjs                              # Dry-run (auto-detect OS)
 *   node scripts/setup.mjs --template gateway-only      # Pick specific template
 *   node scripts/setup.mjs --key <api-key>              # Substitute API key
 *   node scripts/setup.mjs --apply                      # Write changes to disk
 *   node scripts/setup.mjs --test                       # Test gateway connectivity
 *   node scripts/setup.mjs --restart                    # Restart OpenClaw after apply
 *   node scripts/setup.mjs --with-ollama                # Also setup local Ollama fallback
 *   node scripts/setup.mjs --security-tier <tier>       # Set security tier (low|recommended|maximum)
 *   node scripts/setup.mjs --help
 */

import { readFileSync, writeFileSync, existsSync, createReadStream, readdirSync, rmSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { platform, homedir } from 'os';
import { execSync } from 'child_process';
import { createInterface } from 'readline';
import { resolveBins, getPlatformBins } from './lib/detect-bins.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const TEMPLATES_DIR = join(__dirname, '..', 'templates');

// ─── Security Helpers ──────────────────────────────────────────

/**
 * Sanitize an API key for safe shell interpolation.
 * Strips anything that isn't alphanumeric, dot, underscore, or hyphen.
 */
function sanitizeApiKey(key) {
  return String(key || '').replace(/[^A-Za-z0-9._-]/g, '');
}

/**
 * Create a timestamped backup before overwriting a config file.
 */
function backupBeforeWrite(filePath) {
  if (!existsSync(filePath)) return;
  const backup = `${filePath}.bak-${Date.now()}`;
  writeFileSync(backup, readFileSync(filePath, 'utf-8'));
  console.log(`  💾 Config backed up → ${backup}`);
}

// ─── Template map ──────────────────────────────────────────────

const TEMPLATES = {
  mac: 'openclaw-config-mac.json',
  linux: 'openclaw-config-linux.json',
  'gateway-only': 'openclaw-config-gateway-only.json',
};

// ─── Helpers ───────────────────────────────────────────────────

function detectTemplate() {
  const os = platform();
  if (os === 'darwin') return 'mac';
  if (os === 'linux') return 'linux';
  return 'gateway-only';
}

function loadTemplate(name) {
  const file = TEMPLATES[name];
  if (!file) {
    console.error(`  ❌ Unknown template: "${name}"`);
    console.error(`  Available: ${Object.keys(TEMPLATES).join(', ')}`);
    process.exit(1);
  }

  const path = join(TEMPLATES_DIR, file);
  if (!existsSync(path)) {
    console.error(`  ❌ Template file not found: ${path}`);
    process.exit(1);
  }

  const raw = JSON.parse(readFileSync(path, 'utf-8'));
  delete raw.$schema;
  delete raw._instructions;

  // Strip _comment fields recursively
  stripComments(raw);

  return { name, file, path, config: raw };
}

function stripComments(obj) {
  if (!obj || typeof obj !== 'object') return;
  for (const key of Object.keys(obj)) {
    if (key.startsWith('_')) {
      delete obj[key];
    } else {
      stripComments(obj[key]);
    }
  }
}

function findOpenClawConfig() {
  const candidates = [
    process.env.OPENCLAW_CONFIG,
    join(process.env.HOME || '', '.openclaw', 'openclaw.json'),
    join(process.cwd(), 'openclaw.json'),
  ].filter(Boolean);

  for (const p of candidates) {
    if (existsSync(p)) return p;
  }
  return null;
}

/**
 * Deep-merge template providers into existing config.
 * - Adds new providers without clobbering existing ones
 * - Updates model lists for providers that already exist
 * - Merges fallback arrays (appends new, no duplicates)
 */
function mergeConfig(existing, template) {
  const merged = JSON.parse(JSON.stringify(existing));

  // Ensure structure
  if (!merged.models) merged.models = {};
  if (!merged.models.providers) merged.models.providers = {};
  if (!merged.models.mode) merged.models.mode = 'merge';

  // Merge providers
  const tplProviders = template.models?.providers || {};
  for (const [name, provider] of Object.entries(tplProviders)) {
    if (!merged.models.providers[name]) {
      // New provider — add it wholesale
      merged.models.providers[name] = provider;
    } else {
      // Existing provider — update models list, preserve apiKey if already set
      const existingKey = merged.models.providers[name].apiKey;
      const templateKey = provider.apiKey;
      merged.models.providers[name] = { ...provider };
      // Keep existing key if template has placeholder
      if (templateKey === 'YOUR_MOR_GATEWAY_API_KEY' && existingKey && existingKey !== 'YOUR_MOR_GATEWAY_API_KEY') {
        merged.models.providers[name].apiKey = existingKey;
      }
    }
  }

  // Merge gateway.controlUi (safe — don't overwrite user customizations)
  const tplControlUi = template['[REDACTED]']?.controlUi || template.gateway?.controlUi;
  if (tplControlUi) {
    if (!merged.gateway) merged.gateway = {};
    if (!merged.gateway.controlUi) merged.gateway.controlUi = {};
    // Only set allowedOrigins if user hasn't customized them
    if (!merged.gateway.controlUi.allowedOrigins || merged.gateway.controlUi.allowedOrigins.length === 0) {
      merged.gateway.controlUi.allowedOrigins = tplControlUi.allowedOrigins;
    }
    // Set enabled if not already explicitly set
    if (merged.gateway.controlUi.enabled === undefined) {
      merged.gateway.controlUi.enabled = tplControlUi.enabled;
    }
    // Set host-header fallback only if not already set
    if (merged.gateway.controlUi.dangerouslyAllowHostHeaderOriginFallback === undefined) {
      merged.gateway.controlUi.dangerouslyAllowHostHeaderOriginFallback = tplControlUi.dangerouslyAllowHostHeaderOriginFallback;
    }
    // Set device auth bypass if not already set (needed for HTTP access from non-localhost)
    if (merged.gateway.controlUi.dangerouslyDisableDeviceAuth === undefined && tplControlUi.dangerouslyDisableDeviceAuth !== undefined) {
      merged.gateway.controlUi.dangerouslyDisableDeviceAuth = tplControlUi.dangerouslyDisableDeviceAuth;
    }
    console.log('🔧 Auto-configured safe gateway.controlUi defaults');
  }

  // Merge agent defaults (primary + fallbacks)
  const tplDefaults = template.agents?.defaults?.model;
  if (tplDefaults) {
    if (!merged.agents) merged.agents = {};
    if (!merged.agents.defaults) merged.agents.defaults = {};
    if (!merged.agents.defaults.model) merged.agents.defaults.model = {};

    // Set primary if not already set to a morpheus/mor-gateway model
    const curPrimary = merged.agents.defaults.model.primary || '';
    if (!curPrimary.startsWith('morpheus/') && !curPrimary.startsWith('mor-gateway/')) {
      merged.agents.defaults.model.primary = tplDefaults.primary;
    }

    // Merge fallbacks — append new ones, skip duplicates
    const curFallbacks = merged.agents.defaults.model.fallbacks || [];
    const tplFallbacks = tplDefaults.fallbacks || [];
    for (const fb of tplFallbacks) {
      if (!curFallbacks.includes(fb)) {
        curFallbacks.push(fb);
      }
    }
    merged.agents.defaults.model.fallbacks = curFallbacks;
  }

  // === MORPHEUS GATEWAY TIMEOUT COMPATIBILITY (v2026.3.20+) ===
  // Morpheus Gateway models (GLM-5, gpt-oss-120b) can take 30-120s on first
  // request due to P2P provider discovery. Enforce minimum timeout so
  // gateway-only users don't hit "LLM request timed out" on every first message.
  if (!merged.agents) merged.agents = {};
  if (!merged.agents.defaults) merged.agents.defaults = {};
  const currentTimeout = merged.agents.defaults.timeoutSeconds || 0;
  if (currentTimeout < 180) {
    merged.agents.defaults.timeoutSeconds = 300;
    console.log(`  ✅ Set timeoutSeconds=300 (was ${currentTimeout || 'unset'}) — required for Morpheus Gateway P2P discovery`);
  } else if (currentTimeout !== 300) {
    console.log(`  ℹ️  timeoutSeconds already ${currentTimeout}s (user value preserved)`);
  }

  // === STREAMING COMPATIBILITY (v2026.3.20+) ===
  // Enable streaming on all model definitions via agents.defaults.models.<id>.streaming.
  // OpenClaw's provider model schema (models.providers.*.models.*) does NOT accept "streaming"
  // — it's strict (additionalProperties: false). Streaming must be set at the agent model
  // override level: agents.defaults.models["provider/model-id"].streaming = true.
  // Without streaming, OpenClaw waits for the complete response. With Morpheus P2P provider
  // discovery taking 30-120s, non-streaming requests timeout before the first token arrives.
  if (merged.models?.providers) {
    if (!merged.agents) merged.agents = {};
    if (!merged.agents.defaults) merged.agents.defaults = {};
    if (!merged.agents.defaults.models) merged.agents.defaults.models = {};
    let streamingFixed = 0;
    for (const [provName, prov] of Object.entries(merged.models.providers)) {
      if (Array.isArray(prov.models)) {
        for (const m of prov.models) {
          const fullId = `${provName}/${m.id}`;
          // Remove any stale streaming key from provider model definition (invalid location)
          if ('streaming' in m) {
            delete m.streaming;
          }
          // Set streaming at the correct location: agents.defaults.models
          if (!merged.agents.defaults.models[fullId]) {
            merged.agents.defaults.models[fullId] = {};
          }
          if (merged.agents.defaults.models[fullId].streaming !== true) {
            merged.agents.defaults.models[fullId].streaming = true;
            streamingFixed++;
          }
        }
      }
    }
    if (streamingFixed > 0) {
      console.log(`  ✅ Enabled streaming on ${streamingFixed} model(s) — prevents timeout on slow P2P connections`);
    }
  }

  return merged;
}

// ─── Auth Profiles ─────────────────────────────────────────────

function findAuthProfiles(configPath) {
  // auth-profiles.json lives next to the agent dir, not next to openclaw.json
  const candidates = [
    join(process.env.HOME || '', '.openclaw', 'agents', 'main', 'agent', 'auth-profiles.json'),
    join(dirname(configPath), 'agents', 'main', 'agent', 'auth-profiles.json'),
  ];

  for (const p of candidates) {
    if (existsSync(p)) return p;
  }
  return null;
}

function updateAuthProfiles(authPath, providerName, apiKey) {
  let data;
  if (existsSync(authPath)) {
    data = JSON.parse(readFileSync(authPath, 'utf-8'));
  } else {
    data = { version: 1, profiles: {}, lastGood: {}, usageStats: {} };
  }

  const profileKey = `${providerName}:default`;
  data.profiles[profileKey] = {
    type: 'api_key',
    provider: providerName,
    key: apiKey,
  };

  // Set as lastGood for this provider
  if (!data.lastGood) data.lastGood = {};
  data.lastGood[providerName] = profileKey;

  backupBeforeWrite(authPath);
  writeFileSync(authPath, JSON.stringify(data, null, 2) + '\n');
  return profileKey;
}

// ─── Gateway Test ──────────────────────────────────────────────

function testGateway(apiKey, baseUrl) {
  const safeKey = sanitizeApiKey(apiKey);
  const url = `${baseUrl || 'https://api.mor.org/api/v1'}/chat/completions`;
  const body = JSON.stringify({
    model: 'glm-5',
    messages: [{ role: 'user', content: 'Respond with exactly: GATEWAY_OK' }],
    max_tokens: 50,
  });

  try {
    const result = execSync(
      `curl -s -w '\\n%{http_code}' -X POST "${url}" ` +
      `-H "Authorization: Bearer ${safeKey}" ` +
      `-H "Content-Type: application/json" ` +
      `-d '${body.replace(/'/g, "'\\''")}'`,
      { timeout: 30000, encoding: 'utf-8' }
    );

    const lines = result.trim().split('\n');
    const httpCode = lines.pop();
    const responseBody = lines.join('\n');

    if (httpCode === '200') {
      const data = JSON.parse(responseBody);
      const content = data.choices?.[0]?.message?.content || '';
      return { ok: true, model: data.model, content: content.trim() };
    } else {
      try {
        const data = JSON.parse(responseBody);
        return { ok: false, error: data.detail || data.error?.message || `HTTP ${httpCode}` };
      } catch {
        return { ok: false, error: `HTTP ${httpCode}` };
      }
    }
  } catch (e) {
    return { ok: false, error: `Request failed: ${e.message}` };
  }
}

// ─── Restart ───────────────────────────────────────────────────

function restartGateway() {
  try {
    execSync('openclaw gateway restart', { timeout: 15000, encoding: 'utf-8', stdio: 'pipe' });
    return { ok: true };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

// ─── Security Tier Setup ─────────────────────────────────────────

const VALID_TIERS = ['low', 'recommended', 'maximum'];

function loadTierTemplate(tier) {
  const file = `exec-approvals-${tier}.json`;
  const tplPath = join(TEMPLATES_DIR, file);
  if (!existsSync(tplPath)) {
    console.error(`  ❌ Security tier template not found: ${tplPath}`);
    return null;
  }
  return JSON.parse(readFileSync(tplPath, 'utf-8'));
}

/**
 * Prompt the user to select a security tier interactively.
 * Returns the chosen tier name or null if non-interactive.
 */
async function promptSecurityTier() {
  const isCI = process.env.EVERCLAW_YES === '1' || !process.stdin.isTTY;
  if (isCI) return null;

  console.log('');
  console.log('  ╔═══════════════════════════════════════════════════════════╗');
  console.log('  ║                    EverClaw Security Setup                ║');
  console.log('  ╠═══════════════════════════════════════════════════════════╣');
  console.log('  ║                                                          ║');
  console.log('  ║  EverClaw can run shell commands on your machine.         ║');
  console.log('  ║  Choose how much approval you want for potentially        ║');
  console.log('  ║  sensitive operations.                                    ║');
  console.log('  ║                                                          ║');
  console.log('  ║  1. 🟢 Low Security                                      ║');
  console.log('  ║     Fastest for daily dev. Money operations gated at     ║');
  console.log('  ║     app layer. rm, docker, ssh still blocked.            ║');
  console.log('  ║                                                          ║');
  console.log('  ║  2. 🟡 Recommended                                       ║');
  console.log('  ║     Best balance. Blocks deploys, destructive ops,       ║');
  console.log('  ║     and inline eval. Good for most users.                ║');
  console.log('  ║                                                          ║');
  console.log('  ║  3. 🔴 Maximum Protection                                ║');
  console.log('  ║     Everything asks unless explicitly safe-listed.        ║');
  console.log('  ║     Read-only routines still allowed. Maximum oversight.  ║');
  console.log('  ║                                                          ║');
  console.log('  ╚═══════════════════════════════════════════════════════════╝');
  console.log('');

  const rl = createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question('  Choose your security tier (1/2/3) [default: 2]: ', (answer) => {
      rl.close();
      const choice = answer.trim();
      if (choice === '1' || choice === 'low') resolve('low');
      else if (choice === '3' || choice === 'maximum') resolve('maximum');
      else resolve('recommended'); // default
    });
  });
}

/**
 * Generate exec-approvals.json from a tier template with auto-detected binary paths.
 */
function generateExecApprovals(template) {
  const allBins = getPlatformBins(template.bins, template.macBins || [], template.linuxBins || []);
  const { found, missing, warnings } = resolveBins(allBins, { verbose: false });

  if (missing.length > 0) {
    console.log(`  ⚠️  ${missing.length} binaries not found (skipped): ${missing.join(', ')}`);
  }

  const allowlist = found.map(({ name, path }) => ({
    pattern: path,
    _name: name,
  }));

  return {
    version: 1,
    generatedBy: 'everclaw-setup-v1',
    generatedAt: new Date().toISOString(),
    tier: template.tier,
    tierLabel: template.label,
    defaults: {
      security: template.config.security,
      ask: template.config.ask,
      askFallback: template.config.askFallback,
      autoAllowSkills: template.config.autoAllowSkills,
    },
    agents: {
      main: {
        security: template.config.security,
        ask: template.config.ask,
        askFallback: template.config.askFallback,
        autoAllowSkills: template.config.autoAllowSkills,
        allowlist,
      },
    },
  };
}

/**
 * Apply a security tier: write exec-approvals.json and patch openclaw.json.
 * Respects upgrade safety — never overwrites user-customized files.
 */
function applySecurityTier(tierName, configPath, options = {}) {
  const { force = false } = options;
  const template = loadTierTemplate(tierName);
  if (!template) return false;

  console.log(`\n  ─── Security Tier: ${template.label} ─────────────────────────────`);
  console.log(`  ${template.description}`);
  console.log('  Detecting binaries...');

  const approvals = generateExecApprovals(template);
  const openclawDir = dirname(configPath);
  const approvalsPath = join(openclawDir, 'exec-approvals.json');

  // Upgrade safety check
  if (existsSync(approvalsPath) && !force) {
    const existing = JSON.parse(readFileSync(approvalsPath, 'utf-8'));
    if (!existing.generatedBy) {
      console.log('  ⚠️  exec-approvals.json exists but was not generated by EverClaw.');
      console.log('  Preserving your customizations. Use --force to override.');
      return false;
    }
    if (existing.generatedBy !== 'everclaw-setup-v1') {
      console.log(`  ⚠️  exec-approvals.json was generated by: ${existing.generatedBy}`);
      console.log('  Preserving it. Use --force to override.');
      return false;
    }
    // Generated by us — safe to overwrite
    backupBeforeWrite(approvalsPath);
  }

  // Write exec-approvals.json
  writeFileSync(approvalsPath, JSON.stringify(approvals, null, 2) + '\n');
  console.log(`  ✅ Written: ${approvalsPath}`);
  console.log(`     Allowlist: ${approvals.agents.main.allowlist.length} binaries`);

  // Patch openclaw.json with safeBins + strictInlineEval
  if (existsSync(configPath)) {
    const config = JSON.parse(readFileSync(configPath, 'utf-8'));
    if (!config.tools) config.tools = {};
    if (!config.tools.exec) config.tools.exec = {};
    config.tools.exec.safeBins = template.config.safeBins;
    config.tools.exec.safeBinTrustedDirs = template.config.safeBinTrustedDirs;
    config.tools.exec.safeBinProfiles = template.config.safeBinProfiles;
    config.tools.exec.strictInlineEval = template.config.strictInlineEval;
    writeFileSync(configPath, JSON.stringify(config, null, 2) + '\n');
    console.log(`  ✅ Patched: ${configPath} (safeBins, strictInlineEval)`);
  }

  return true;
}

function printUsage() {
  console.log(`
♾️  Everclaw Setup

Usage:
  node scripts/setup.mjs                              Dry-run (auto-detect OS)
  node scripts/setup.mjs --template <name>            Pick template manually
  node scripts/setup.mjs --key <api-key>              Substitute API key
  node scripts/setup.mjs --apply                      Write changes to disk
  node scripts/setup.mjs --help                       Show this help

Templates:
  mac            macOS — morpheus (local P2P) + mor-gateway
  linux          Linux — morpheus (local P2P) + mor-gateway
  gateway-only   Simplest — mor-gateway only (no local proxy)

Flags:
  --key <key>      Your Morpheus API Gateway key (from app.mor.org)
  --apply          Actually write the merged config (default is dry-run)
  --test           Test gateway connectivity after setup
  --restart        Restart OpenClaw gateway after apply
  --template       Override OS auto-detection
  --with-ollama    Also setup local Ollama inference fallback
  --ollama-model   Override auto-detected Ollama model (e.g. gemma4:26b)
  --skip-embeddings  Skip node-llama-cpp install (local embeddings)
  --security-tier  Set security tier (low|recommended|maximum)
  --no-security    Skip security tier prompt
`);
}

// ─── CLI parsing ───────────────────────────────────────────────

const args = process.argv.slice(2);

if (args.includes('--help') || args.includes('-h')) {
  printUsage();
  process.exit(0);
}

function getArg(flag) {
  const idx = args.indexOf(flag);
  return idx >= 0 && args[idx + 1] ? args[idx + 1] : null;
}

const templateName = getArg('--template') || detectTemplate();
const apiKey = getArg('--key');
const applyMode = args.includes('--apply');
const testMode = args.includes('--test');
const restartMode = args.includes('--restart');
const withOllama = args.includes('--with-ollama');
const ollamaModel = getArg('--ollama-model');
const securityTierArg = getArg('--security-tier');
const noSecurity = args.includes('--no-security');
const skipEmbeddings = args.includes('--skip-embeddings');

// ─── Stage 1: Template Discovery ───────────────────────────────

console.log('\n♾️  Everclaw Setup\n');
console.log(`  OS detected:  ${platform()}`);
console.log(`  Template:     ${templateName}`);

const tpl = loadTemplate(templateName);
console.log(`  File:         ${tpl.file}`);

// Substitute API key if provided
if (apiKey) {
  const gw = tpl.config.models?.providers?.['mor-gateway'];
  if (gw && gw.apiKey === 'YOUR_MOR_GATEWAY_API_KEY') {
    gw.apiKey = apiKey;
    console.log(`  API key:      ${apiKey.slice(0, 12)}... (substituted)`);
  }
} else {
  const gwKey = tpl.config.models?.providers?.['mor-gateway']?.apiKey;
  if (gwKey === 'YOUR_MOR_GATEWAY_API_KEY') {
    console.log('  API key:      ⚠️  placeholder — pass --key <key> or edit after');
  }
}

// Show providers
const providers = Object.keys(tpl.config.models?.providers || {});
console.log(`  Providers:    ${providers.join(', ')}`);
for (const p of providers) {
  const models = (tpl.config.models.providers[p].models || []).map(m => m.id);
  console.log(`    ${p}: ${models.join(', ')}`);
}

const primary = tpl.config.agents?.defaults?.model?.primary;
const fallbacks = tpl.config.agents?.defaults?.model?.fallbacks || [];
if (primary) console.log(`  Primary:      ${primary}`);
if (fallbacks.length) console.log(`  Fallbacks:    ${fallbacks.join(' → ')}`);

// ─── Stage 2: Config Merge ─────────────────────────────────────

console.log('');
const configPath = findOpenClawConfig();

if (!configPath) {
  console.log('  ⚠️  Could not find openclaw.json');
  console.log('  Searched:');
  if (process.env.OPENCLAW_CONFIG) console.log(`    $OPENCLAW_CONFIG = ${process.env.OPENCLAW_CONFIG}`);
  console.log(`    ~/.openclaw/openclaw.json`);
  console.log(`    ./openclaw.json`);
  console.log('\n  To use this template, copy it manually into your OpenClaw config.\n');
  process.exit(1);
}

console.log(`  Config found: ${configPath}`);

const existing = JSON.parse(readFileSync(configPath, 'utf-8'));
const merged = mergeConfig(existing, tpl.config);

// Show what changed
const existingProviders = Object.keys(existing.models?.providers || {});
const mergedProviders = Object.keys(merged.models?.providers || {});
const newProviders = mergedProviders.filter(p => !existingProviders.includes(p));
const updatedProviders = mergedProviders.filter(p => existingProviders.includes(p) && providers.includes(p));

if (newProviders.length) {
  console.log(`  Adding:       ${newProviders.join(', ')}`);
}
if (updatedProviders.length) {
  console.log(`  Updating:     ${updatedProviders.join(', ')}`);
}

const mergedPrimary = merged.agents?.defaults?.model?.primary;
const existingPrimary = existing.agents?.defaults?.model?.primary;
if (mergedPrimary !== existingPrimary) {
  console.log(`  Primary:      ${existingPrimary || '(none)'} → ${mergedPrimary}`);
} else {
  console.log(`  Primary:      ${mergedPrimary} (unchanged)`);
}

const mergedFallbacks = merged.agents?.defaults?.model?.fallbacks || [];
const existingFallbacks = existing.agents?.defaults?.model?.fallbacks || [];
const newFallbacks = mergedFallbacks.filter(f => !existingFallbacks.includes(f));
if (newFallbacks.length) {
  console.log(`  New fallbacks: ${newFallbacks.join(', ')}`);
}

// Apply or dry-run
if (applyMode) {
  backupBeforeWrite(configPath);
  writeFileSync(configPath, JSON.stringify(merged, null, 2) + '\n');
  console.log(`\n  ✅ Config written to ${configPath}`);
  console.log('  ⚠️  First GLM-5 or gpt-oss-120b message may take 30-120s due to Morpheus Gateway warm-up. This is normal.');

  // ─── Stage 3: Auth Profiles ────────────────────────────────────

  if (apiKey) {
    const authPath = findAuthProfiles(configPath);
    if (authPath) {
      const profileKey = updateAuthProfiles(authPath, 'mor-gateway', apiKey);
      console.log(`  ✅ Auth profile updated: ${profileKey}`);
      console.log(`     File: ${authPath}`);
    } else {
      console.log('  ⚠️  auth-profiles.json not found — skipping auth profile update');
      console.log('     You may need to add the API key manually to your agent config');
    }
  }

  // ─── Ollama API Migration ──────────────────────────────────────
  // Fix existing configs where ollama has api:"openai-completions" instead of
  // api:"ollama". Without this, ollama requests route through the previous
  // provider's HTTP client in the fallback chain.
  // See: https://github.com/openclaw/openclaw/issues/45369
  try {
    const ollamaProvider = merged.models?.providers?.ollama;
    if (ollamaProvider && ollamaProvider.api === 'openai-completions') {
      ollamaProvider.api = 'ollama';
      // Remove model-level api:"openai-completions" (inherit from provider)
      if (Array.isArray(ollamaProvider.models)) {
        for (const m of ollamaProvider.models) {
          if (m.api === 'openai-completions') delete m.api;
        }
      }
      writeFileSync(configPath, JSON.stringify(merged, null, 2) + '\n');
      console.log('  ✅ Ollama API type migrated: "openai-completions" → "ollama"');
    }
  } catch (e) {
    console.log(`  ⚠️  Ollama migration check failed (not fatal): ${e.message}`);
  }

  // ─── Model Input Modality Sanitization ─────────────────────────────
  // OpenClaw's config validator only allows "text" and "image" in model
  // input arrays. Gemma 4 E2B/E4B support "audio" natively, but the
  // validator rejects it — causing gateway startup failure on fresh
  // installs and upgrades. Strip unsupported values defensively across
  // ALL providers (not just Ollama) to future-proof.
  try {
    const ALLOWED_INPUTS = new Set(['text', 'image']);
    const providers = merged.models?.providers;
    let sanitized = false;
    if (providers && typeof providers === 'object') {
      for (const [provId, prov] of Object.entries(providers)) {
        if (!Array.isArray(prov.models)) continue;
        for (const m of prov.models) {
          if (!Array.isArray(m.input)) continue;
          const filtered = m.input.filter(v => ALLOWED_INPUTS.has(v));
          if (filtered.length !== m.input.length) {
            m.input = filtered;
            sanitized = true;
          }
        }
      }
    }
    if (sanitized) {
      writeFileSync(configPath, JSON.stringify(merged, null, 2) + '\n');
      console.log('  🔧 Sanitized model input modalities (removed unsupported values like "audio")');
    }
  } catch (e) {
    console.log(`  ⚠️  Input modality sanitization failed (not fatal): ${e.message}`);
  }

  // ─── Stage 4: Security Tier ───────────────────────────────────────

  if (!noSecurity) {
    let tier = securityTierArg;

    // Docker / CI: use env var or default to 'recommended'
    if (!tier && process.env.EVERCLAW_SECURITY_TIER) {
      tier = process.env.EVERCLAW_SECURITY_TIER;
    }

    // Interactive prompt if no tier specified
    if (!tier) {
      tier = await promptSecurityTier();
    }

    // CI with no tier specified: default to recommended
    if (!tier) {
      tier = 'recommended';
    }

    if (VALID_TIERS.includes(tier)) {
      applySecurityTier(tier, configPath);
    } else {
      console.log(`  ⚠️  Invalid security tier: "${tier}" — skipped.`);
      console.log(`  Valid tiers: ${VALID_TIERS.join(', ')}`);
    }
  } else {
    console.log('\n  ─── Security tier skipped (--no-security) ────────────────');
  }

  // ─── Bonjour/mDNS Mitigation (OpenClaw v2026.4.24) ────────────────────
  // OpenClaw v2026.4.24 ships a broken bonjour (mDNS/CIAO) plugin that throws
  // unhandled promise rejections on macOS and headless Linux.
  // This crashes WebSocket connections with ECONNRESET → 1006.
  // Ref: https://github.com/openclaw/openclaw/issues/70232
  //
  // Mitigation: disable the bonjour plugin in config + clean corrupted
  // plugin-runtime-deps. Safe — bonjour is only for local network discovery.

  console.log('\n  ─── Bonjour/mDNS Mitigation (v2026.4.24) ─────────────────');
  try {
    const bonjourEnabled = merged?.gateway?.plugins?.bonjour?.enabled;
    if (bonjourEnabled !== false) {
      if (!merged.gateway) merged.gateway = {};
      if (!merged.gateway.plugins) merged.gateway.plugins = {};
      if (!merged.gateway.plugins.bonjour) merged.gateway.plugins.bonjour = {};
      merged.gateway.plugins.bonjour.enabled = false;
      writeFileSync(configPath, JSON.stringify(merged, null, 2) + '\n');
      console.log('  ✅ Bonjour plugin disabled (prevents mDNS crash)');
    } else {
      console.log('  ✅ Bonjour plugin already disabled');
    }
  } catch (e) {
    console.log(`  ⚠️  Bonjour mitigation failed (not fatal): ${e.message}`);
  }

  // Clean corrupted plugin-runtime-deps (ENOTEMPTY fix)
  try {
    const pluginDepsDir = join(homedir(), '.openclaw', 'plugin-runtime-deps');
    if (existsSync(pluginDepsDir)) {
      const entries = readdirSync(pluginDepsDir);
      for (const entry of entries) {
        if (entry.startsWith('openclaw-2026.4.24')) {
          const target = join(pluginDepsDir, entry);
          rmSync(target, { recursive: true, force: true });
          console.log('  ✅ Cleaned corrupted plugin-runtime-deps');
        }
      }
    }
  } catch (e) {
    console.log(`  ⚠️  Plugin cleanup failed (not fatal): ${e.message}`);
  }

  // Test gateway if requested
  if (testMode) {
    const testKey = apiKey || merged.models?.providers?.['mor-gateway']?.apiKey;
    const testUrl = merged.models?.providers?.['mor-gateway']?.baseUrl;
    if (testKey && testKey !== 'YOUR_MOR_GATEWAY_API_KEY') {
      console.log('\n  Testing gateway connectivity...');
      const result = testGateway(testKey, testUrl);
      if (result.ok) {
        console.log(`  ✅ Gateway online — model: ${result.model}`);
      } else {
        console.log(`  ❌ Gateway test failed: ${result.error}`);
      }
    } else {
      console.log('\n  ⚠️  No API key available — skipping gateway test');
      console.log('     Pass --key <key> to test connectivity');
    }
  }

  // Restart if requested
  if (restartMode) {
    console.log('\n  Restarting OpenClaw gateway...');
    const result = restartGateway();
    if (result.ok) {
      console.log('  ✅ Gateway restarted');
    } else {
      console.log(`  ❌ Restart failed: ${result.error}`);
      console.log('  Run manually: openclaw gateway restart');
    }
  } else if (!withOllama) {
    console.log('\n  Run "openclaw gateway restart" to apply changes.');
    console.log('  Or re-run with --restart to do it automatically.\n');
  }

  // Run Ollama setup if requested
  if (withOllama) {
    console.log('\n  ─── Ollama Local Fallback ────────────────────────────');
    const ollamaScript = join(__dirname, 'setup-ollama.sh');
    if (!existsSync(ollamaScript)) {
      console.log('  ❌ setup-ollama.sh not found');
    } else {
      const ollamaArgs = ['--apply'];
      if (ollamaModel) ollamaArgs.push('--model', ollamaModel);
      const ollamaCmd = `bash "${ollamaScript}" ${ollamaArgs.join(' ')}`;
      try {
        const output = execSync(ollamaCmd, {
          timeout: 600000, // 10 min (model pull can be slow)
          encoding: 'utf-8',
          stdio: ['pipe', 'pipe', 'pipe'],
        });
        console.log(output);
      } catch (e) {
        console.log(`  ❌ Ollama setup failed: ${e.message}`);
        console.log('  You can run it separately: bash scripts/setup-ollama.sh --apply');
      }
    }

    if (restartMode) {
      console.log('\n  Restarting OpenClaw gateway...');
      const result = restartGateway();
      if (result.ok) {
        console.log('  ✅ Gateway restarted');
      } else {
        console.log(`  ❌ Restart failed: ${result.error}`);
      }
    } else {
      console.log('\n  Run "openclaw gateway restart" to apply changes.');
      console.log('  Or re-run with --restart to do it automatically.\n');
    }
  }
  // ─── Stage 5: Memory Search (Local Embeddings) ────────────────

  if (skipEmbeddings) {
    console.log('\n  ─── Memory Search (Local Embeddings) ────────────────────');
    console.log('  ⏭️  Skipped (--skip-embeddings)');
  } else {
    console.log('\n  ─── Memory Search (Local Embeddings) ────────────────────');
    let npmGlobalRoot = '';
    try {
      npmGlobalRoot = execSync('npm root -g', { encoding: 'utf-8', timeout: 5000 }).trim();
    } catch {
      // npm root -g failed — fall through to install path (safe)
    }
    try {
      execSync('node -e "try { require.resolve(\'node-llama-cpp\'); process.exit(0) } catch { process.exit(1) }"', {
        timeout: 10000,
        stdio: 'pipe',
        env: { ...process.env, NODE_PATH: npmGlobalRoot },
      });
      console.log('  ✅ node-llama-cpp already installed');
    } catch {
      console.log('  📦 Installing local embedding engine (node-llama-cpp@3.18.1)...');
      console.log('     One-time install, ~30-90s. May need build tools on some systems.');
      try {
        execSync('npm install -g node-llama-cpp@3.18.1', {
          timeout: 120000,
          stdio: 'inherit',
        });
        // Post-install verification
        try {
          execSync('node -e "try { require.resolve(\'node-llama-cpp\'); process.exit(0) } catch { process.exit(1) }"', {
            timeout: 10000,
            stdio: 'pipe',
            env: { ...process.env, NODE_PATH: npmGlobalRoot },
          });
          console.log('  ✅ node-llama-cpp installed — local memory search enabled');
        } catch {
          console.log('  ⚠️  node-llama-cpp installed but import failed');
          console.log('     You may need build tools: Xcode CLT (macOS) or build-essential (Linux)');
          console.log('     Memory search will fall back to remote provider if configured');
        }
      } catch {
        console.log('  ⚠️  node-llama-cpp install failed (not critical)');
        console.log('     Memory search will use remote provider or be unavailable');
        console.log('     Install manually: npm install -g node-llama-cpp@3.18.1');
        console.log('     If build fails, you may need: Xcode CLT (macOS) or build-essential + cmake (Linux)');
      }
    }
  }

  // ─── Stage 6: MemPalace Enhanced Memory (Optional) ──────────

  console.log('\n  ─── MemPalace Enhanced Memory (Optional) ────────────────');
  try {
    execSync('python3 -c "import mempalace"', { stdio: 'pipe', timeout: 10000 });
    console.log('  ✅ MemPalace SDK detected (pip install mempalace)');

    // Check if palace exists
    const palacePath = join(homedir(), '.mempalace', 'palace');
    if (existsSync(palacePath)) {
      console.log(`  ✅ Palace exists at ${palacePath}`);
    } else {
      console.log('  ℹ️  No palace found yet — run migration to initialize:');
      console.log('     node scripts/memory/migrate-to-mempalace.mjs --dry-run');
    }

    // Verify bridge is functional
    try {
      const bridgePath = join(dirname(fileURLToPath(import.meta.url)), 'python', 'mempalace_bridge.py');
      if (existsSync(bridgePath)) {
        const bridgeResult = execSync(`python3 "${bridgePath}" status`, {
          encoding: 'utf-8',
          timeout: 15000,
          stdio: ['pipe', 'pipe', 'pipe'],
        });
        const status = JSON.parse(bridgeResult);
        if (status.healthy) {
          console.log(`  ✅ Bridge healthy — ${status.fact_count || 0} facts in palace`);
        } else {
          console.log('  ⚠️  Bridge returned unhealthy status — run mine to populate');
        }
      }
    } catch (bridgeErr) {
      console.log('  ⚠️  Bridge check failed (non-critical)');
    }
  } catch {
    console.log('  ℹ️  MemPalace not installed (optional enhancement)');
    console.log('     Install with: pip install mempalace');
    console.log('     Docs: https://github.com/AiEnigma-Labs/MemPalace');
  }

} else {
  // Dry-run — but still allow --test
  if (testMode) {
    const testKey = apiKey || existing.models?.providers?.['mor-gateway']?.apiKey;
    const testUrl = existing.models?.providers?.['mor-gateway']?.baseUrl || 'https://api.mor.org/api/v1';
    if (testKey && testKey !== 'YOUR_MOR_GATEWAY_API_KEY') {
      console.log('\n  Testing gateway connectivity...');
      const result = testGateway(testKey, testUrl);
      if (result.ok) {
        console.log(`  ✅ Gateway online — model: ${result.model}`);
      } else {
        console.log(`  ❌ Gateway test failed: ${result.error}`);
      }
    } else {
      console.log('\n  ⚠️  No API key available — pass --key <key> to test');
    }
  }

  console.log('\n  🔍 Dry-run complete — no changes written.');
  console.log('  Add --apply to write the merged config.\n');
}
