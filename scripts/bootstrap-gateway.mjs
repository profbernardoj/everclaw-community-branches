#!/usr/bin/env node

/**
 * Everclaw v0.8 — Morpheus API Gateway Bootstrap
 *
 * Configures the Morpheus API Gateway as an OpenClaw provider,
 * giving new users immediate access to free inference (no API key setup needed).
 *
 * The bundled community key provides free beta access to Kimi K2.5 via the
 * Morpheus inference marketplace at api.mor.org. Users should get their own
 * key from app.mor.org for continued use.
 *
 * Usage:
 *   node scripts/bootstrap-gateway.mjs              # Interactive setup
 *   node scripts/bootstrap-gateway.mjs --key <key>  # Use your own API key
 *   node scripts/bootstrap-gateway.mjs --test       # Test current config
 *   node scripts/bootstrap-gateway.mjs --status     # Show gateway status
 */

import { readFileSync, writeFileSync, existsSync } from 'fs';
import { execSync } from 'child_process';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ─── Configuration ─────────────────────────────────────────────
const GATEWAY_BASE_URL = 'https://api.mor.org/api/v1';
const PROVIDER_NAME = 'mor-gateway';

// Community bootstrap key — Morpheus API Gateway free beta (expires Mar 1 2026)
// Obfuscated to prevent trivial scraping; decoded at runtime
// This is a shared community key for initial bootstrapping only.
// Get your own free key at https://app.mor.org
const COMMUNITY_KEY_B64 = 'c2staWR0TVBJLmJlZTA0NjU3ZmNlOTBlYjk3MWQ0ZTJjMmMzYWFhZmJkZGI2NGY5YmZhMWY5NGVkMDJiMmIxOGNhNGEwMTQxZDA=';

function decodeCommunityKey() {
  return Buffer.from(COMMUNITY_KEY_B64, 'base64').toString('utf-8');
}

// Models available via the API Gateway (free beta)
const GATEWAY_MODELS = [
  {
    id: 'kimi-k2.5',
    name: 'Kimi K2.5 (via Morpheus Gateway)',
    reasoning: false,   // Gateway's upstream rejects reasoning_effort param
    input: ['text'],
    cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
    contextWindow: 131072,
    maxTokens: 8192,
  },
  {
    id: 'glm-4.7-flash',
    name: 'GLM 4.7 Flash (via Morpheus Gateway)',
    reasoning: false,
    input: ['text'],
    cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
    contextWindow: 131072,
    maxTokens: 8192,
  },
  {
    id: 'llama-3.3-70b',
    name: 'Llama 3.3 70B (via Morpheus Gateway)',
    reasoning: false,
    input: ['text'],
    cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
    contextWindow: 131072,
    maxTokens: 8192,
  },
];

// ─── Helpers ───────────────────────────────────────────────────

function findOpenClawConfig() {
  // Check standard locations
  const candidates = [
    join(process.env.HOME || '', '.openclaw', 'openclaw.json'),
    join(process.cwd(), 'openclaw.json'),
  ];
  if (process.env.OPENCLAW_CONFIG) candidates.unshift(process.env.OPENCLAW_CONFIG);
  
  for (const p of candidates) {
    if (existsSync(p)) return p;
  }
  return null;
}

async function testGateway(apiKey) {
  const url = `${GATEWAY_BASE_URL}/chat/completions`;
  const body = JSON.stringify({
    model: 'kimi-k2.5',
    messages: [{ role: 'user', content: 'Respond with exactly: GATEWAY_OK' }],
    max_tokens: 100,
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
    } else if (httpCode === '403') {
      return { ok: false, error: 'Access denied (403). The API Gateway may be down or the key is invalid.' };
    } else {
      try {
        const data = JSON.parse(responseBody);
        return { ok: false, error: data.detail || data.error?.message || `HTTP ${httpCode}` };
      } catch {
        return { ok: false, error: `HTTP ${httpCode}: ${responseBody.slice(0, 200)}` };
      }
    }
  } catch (e) {
    return { ok: false, error: `Request failed: ${e.message}` };
  }
}

async function listGatewayModels(apiKey) {
  try {
    const result = execSync(
      `curl -s "${GATEWAY_BASE_URL}/models" ` +
      `-H "Authorization: Bearer ${apiKey}"`,
      { timeout: 15000, encoding: 'utf-8' }
    );
    const data = JSON.parse(result);
    return data.data || [];
  } catch {
    return [];
  }
}

function patchOpenClawConfig(configPath, apiKey) {
  const raw = readFileSync(configPath, 'utf-8');
  const config = JSON.parse(raw);

  // Ensure models.providers exists
  if (!config.models) config.models = {};
  if (!config.models.providers) config.models.providers = {};

  // ── Fix "everclaw/" misconfiguration (v0.9.6) ──────────────────────────
  // "everclaw" is a skill, not a provider. If someone set their model to
  // "everclaw/kimi-k2.5:web", requests go to Venice (billing errors) instead
  // of Morpheus. Detect and fix this automatically.
  const primary = config.agents?.defaults?.model?.primary || '';
  if (primary.startsWith('everclaw/')) {
    const fixedModel = primary.replace('everclaw/', `${PROVIDER_NAME}/`);
    config.agents.defaults.model.primary = fixedModel;
    console.log(`  ⚠️  Fixed misconfigured primary model:`);
    console.log(`     ${primary} → ${fixedModel}`);
    console.log(`     ("everclaw/" is a skill, not a provider)`);
  }

  if (config.agents?.defaults?.model?.fallbacks) {
    config.agents.defaults.model.fallbacks = config.agents.defaults.model.fallbacks.map(fb => {
      if (fb.startsWith('everclaw/')) {
        const fixed = fb.replace('everclaw/', `${PROVIDER_NAME}/`);
        console.log(`  ⚠️  Fixed misconfigured fallback: ${fb} → ${fixed}`);
        return fixed;
      }
      return fb;
    });
  }

  // Remove invalid "everclaw" provider entry if present
  if (config.models.providers.everclaw) {
    console.log(`  ⚠️  Removing invalid "everclaw" provider (not a real endpoint)`);
    delete config.models.providers.everclaw;
  }
  // ── End fix ────────────────────────────────────────────────────────────

  // Add or update the mor-gateway provider
  config.models.providers[PROVIDER_NAME] = {
    baseUrl: GATEWAY_BASE_URL,
    apiKey: apiKey,
    api: 'openai-completions',
    models: GATEWAY_MODELS,
  };

  // Ensure mode is merge so we don't overwrite other providers
  if (!config.models.mode) config.models.mode = 'merge';

  // Add mor-gateway/kimi-k2.5 to fallbacks if not already there
  if (config.agents?.defaults?.model?.fallbacks) {
    const fallbacks = config.agents.defaults.model.fallbacks;
    const gatewayModel = `${PROVIDER_NAME}/kimi-k2.5`;
    if (!fallbacks.includes(gatewayModel)) {
      fallbacks.push(gatewayModel);
      console.log(`  ✅ Added ${gatewayModel} to fallback chain`);
    }
  }

  // Add alias
  if (!config.agents) config.agents = {};
  if (!config.agents.defaults) config.agents.defaults = {};
  if (!config.agents.defaults.models) config.agents.defaults.models = {};
  config.agents.defaults.models[`${PROVIDER_NAME}/kimi-k2.5`] = {
    alias: 'Kimi K2.5 (Gateway)',
  };
  config.agents.defaults.models[`${PROVIDER_NAME}/glm-4.7-flash`] = {
    alias: 'GLM 4.7 Flash (Gateway)',
  };

  // Write back with pretty formatting
  writeFileSync(configPath, JSON.stringify(config, null, 2) + '\n');
  return config;
}

// ─── Commands ──────────────────────────────────────────────────

async function cmdSetup(userKey) {
  console.log('\n♾️  Everclaw v0.8 — Morpheus API Gateway Bootstrap\n');
  
  const apiKey = userKey || decodeCommunityKey();
  const isOwnKey = !!userKey;
  
  if (!isOwnKey) {
    console.log('  Using community bootstrap key (free beta, expires Mar 1 2026)');
    console.log('  → Get your own free key at https://app.mor.org\n');
  } else {
    console.log(`  Using your API key: ${apiKey.slice(0, 12)}...`);
  }

  // Test the key
  console.log('  Testing API Gateway connection...');
  const test = await testGateway(apiKey);
  
  if (!test.ok) {
    console.log(`  ❌ Gateway test failed: ${test.error}`);
    if (!isOwnKey) {
      console.log('\n  The community key may have expired or hit rate limits.');
      console.log('  Get your own free key at https://app.mor.org');
    }
    process.exit(1);
  }
  
  console.log(`  ✅ Gateway responding — model: ${test.model}`);

  // Find and patch OpenClaw config
  const configPath = findOpenClawConfig();
  if (!configPath) {
    console.log('\n  ⚠️  Could not find openclaw.json');
    console.log('  To configure manually, add this provider to your config:\n');
    console.log(JSON.stringify({
      [PROVIDER_NAME]: {
        baseUrl: GATEWAY_BASE_URL,
        apiKey: isOwnKey ? apiKey : '<get key from app.mor.org>',
        api: 'openai-completions',
        models: GATEWAY_MODELS,
      }
    }, null, 2));
    process.exit(0);
  }

  console.log(`  Patching config: ${configPath}`);
  patchOpenClawConfig(configPath, apiKey);
  
  console.log('\n  🎉 Morpheus API Gateway configured!\n');
  console.log('  Provider name: mor-gateway');
  console.log('  Models available:');
  for (const m of GATEWAY_MODELS) {
    console.log(`    • ${PROVIDER_NAME}/${m.id} — ${m.name}`);
  }
  console.log('\n  Added to fallback chain: mor-gateway/kimi-k2.5');
  
  if (!isOwnKey) {
    console.log('\n  ⚡ Next step: Get your own free API key');
    console.log('     1. Go to https://app.mor.org');
    console.log('     2. Create an account and sign in');
    console.log('     3. Click "Create API Key" and enable automation');
    console.log('     4. Run: node scripts/bootstrap-gateway.mjs --key YOUR_KEY');
  }

  console.log('\n  To restart OpenClaw with the new config:');
  console.log('     openclaw gateway restart\n');
}

async function cmdTest() {
  console.log('\n♾️  Testing Morpheus API Gateway...\n');
  
  const configPath = findOpenClawConfig();
  let apiKey;
  
  if (configPath) {
    const config = JSON.parse(readFileSync(configPath, 'utf-8'));
    apiKey = config.models?.providers?.[PROVIDER_NAME]?.apiKey;
  }
  
  if (!apiKey) {
    apiKey = decodeCommunityKey();
    console.log('  No gateway config found — testing with community key\n');
  }

  // List models
  console.log('  Listing available models...');
  const models = await listGatewayModels(apiKey);
  if (models.length > 0) {
    console.log(`  Found ${models.length} models:`);
    for (const m of models.slice(0, 10)) {
      console.log(`    • ${m.id} [${(m.tags || []).join(', ')}]`);
    }
    if (models.length > 10) console.log(`    ... and ${models.length - 10} more`);
  } else {
    console.log('  ⚠️  Could not list models');
  }

  // Test inference
  console.log('\n  Testing inference (kimi-k2.5)...');
  const result = await testGateway(apiKey);
  
  if (result.ok) {
    console.log(`  ✅ Success — model: ${result.model}, response: "${result.content.slice(0, 60)}"`);
  } else {
    console.log(`  ❌ Failed: ${result.error}`);
  }
  console.log('');
}

async function cmdStatus() {
  console.log('\n♾️  Morpheus API Gateway Status\n');
  
  const configPath = findOpenClawConfig();
  if (!configPath) {
    console.log('  OpenClaw config: not found');
    return;
  }
  
  const config = JSON.parse(readFileSync(configPath, 'utf-8'));
  const gateway = config.models?.providers?.[PROVIDER_NAME];
  
  if (!gateway) {
    console.log('  Gateway provider: not configured');
    console.log('  Run: node scripts/bootstrap-gateway.mjs');
    return;
  }
  
  console.log(`  Provider: ${PROVIDER_NAME}`);
  console.log(`  Base URL: ${gateway.baseUrl}`);
  console.log(`  API Key: ${gateway.apiKey?.slice(0, 12)}...`);
  console.log(`  Models: ${(gateway.models || []).map(m => m.id).join(', ')}`);
  
  // Check if in fallback chain
  const fallbacks = config.agents?.defaults?.model?.fallbacks || [];
  const inChain = fallbacks.some(f => f.startsWith(PROVIDER_NAME));
  console.log(`  In fallback chain: ${inChain ? 'yes' : 'no'}`);
  
  // Test connectivity
  console.log('\n  Testing connection...');
  const result = await testGateway(gateway.apiKey);
  console.log(result.ok ? `  ✅ Online — ${result.model}` : `  ❌ ${result.error}`);
  console.log('');
}

// ─── Main ──────────────────────────────────────────────────────

const args = process.argv.slice(2);

if (args.includes('--test')) {
  await cmdTest();
} else if (args.includes('--status')) {
  await cmdStatus();
} else {
  const keyIdx = args.indexOf('--key');
  const userKey = keyIdx >= 0 ? args[keyIdx + 1] : null;
  await cmdSetup(userKey);
}
