#!/usr/bin/env node

/**
 * Everclaw setup.mjs — Config setup for OpenClaw + Morpheus
 *
 * Stage 1: Detects OS, picks template, loads it.
 * Stage 2: Finds openclaw.json, deep-merges providers, writes on --apply.
 * Stage 3: Updates auth-profiles.json, --test pings gateway, --restart restarts.
 *
 * Usage:
 *   node scripts/setup.mjs                              # Dry-run (auto-detect OS)
 *   node scripts/setup.mjs --template gateway-only      # Pick specific template
 *   node scripts/setup.mjs --key <api-key>              # Substitute API key
 *   node scripts/setup.mjs --apply                      # Write changes to disk
 *   node scripts/setup.mjs --test                       # Test gateway connectivity
 *   node scripts/setup.mjs --restart                    # Restart OpenClaw after apply
 *   node scripts/setup.mjs --help
 */

import { readFileSync, writeFileSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { platform } from 'os';
import { execSync } from 'child_process';

const __dirname = dirname(fileURLToPath(import.meta.url));
const TEMPLATES_DIR = join(__dirname, '..', 'templates');

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
    if (key === '_comment') {
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

  writeFileSync(authPath, JSON.stringify(data, null, 2) + '\n');
  return profileKey;
}

// ─── Gateway Test ──────────────────────────────────────────────

function testGateway(apiKey, baseUrl) {
  const url = `${baseUrl || 'https://api.mor.org/api/v1'}/chat/completions`;
  const body = JSON.stringify({
    model: 'glm-5',
    messages: [{ role: 'user', content: 'Respond with exactly: GATEWAY_OK' }],
    max_tokens: 50,
  });

  try {
    const result = execSync(
      `curl -s -w '\\n%{http_code}' -X POST "${url}" ` +
      `-H "Authorization: Bearer ${apiKey}" ` +
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
  --key <key>    Your Morpheus API Gateway key (from app.mor.org)
  --apply        Actually write the merged config (default is dry-run)
  --test         Test gateway connectivity after setup
  --restart      Restart OpenClaw gateway after apply
  --template     Override OS auto-detection
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
  writeFileSync(configPath, JSON.stringify(merged, null, 2) + '\n');
  console.log(`\n  ✅ Config written to ${configPath}`);

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
  } else {
    console.log('\n  Run "openclaw gateway restart" to apply changes.');
    console.log('  Or re-run with --restart to do it automatically.\n');
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
