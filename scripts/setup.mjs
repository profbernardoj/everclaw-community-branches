#!/usr/bin/env node

/**
 * Everclaw setup.mjs — Stage 1: Template Loader
 *
 * Detects OS, picks the right config template, loads it,
 * and prints what it found. No writes — just discovery.
 *
 * Usage:
 *   node scripts/setup.mjs                        # Auto-detect OS
 *   node scripts/setup.mjs --template gateway-only # Pick specific template
 *   node scripts/setup.mjs --help
 */

import { readFileSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { platform } from 'os';

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
  // Default to gateway-only for unknown OS (Windows WSL2, etc.)
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

  // Strip meta fields — not part of real config
  delete raw.$schema;
  delete raw._instructions;

  return { name, file, path, config: raw };
}

function printUsage() {
  console.log(`
♾️  Everclaw Setup

Usage:
  node scripts/setup.mjs                          Auto-detect OS template
  node scripts/setup.mjs --template <name>        Pick template manually
  node scripts/setup.mjs --help                   Show this help

Templates:
  mac            macOS — morpheus (local P2P) + mor-gateway
  linux          Linux — morpheus (local P2P) + mor-gateway
  gateway-only   Simplest — mor-gateway only (no local proxy)
`);
}

// ─── CLI parsing ───────────────────────────────────────────────

const args = process.argv.slice(2);

if (args.includes('--help') || args.includes('-h')) {
  printUsage();
  process.exit(0);
}

let templateName;
const tIdx = args.indexOf('--template');
if (tIdx >= 0 && args[tIdx + 1]) {
  templateName = args[tIdx + 1];
} else {
  templateName = detectTemplate();
}

// ─── Main ──────────────────────────────────────────────────────

console.log('\n♾️  Everclaw Setup — Stage 1: Template Discovery\n');
console.log(`  OS detected:  ${platform()}`);
console.log(`  Template:     ${templateName}`);

const tpl = loadTemplate(templateName);

console.log(`  File:         ${tpl.file}`);

// Show providers found
const providers = Object.keys(tpl.config.models?.providers || {});
console.log(`  Providers:    ${providers.join(', ') || 'none'}`);

// Show models per provider
for (const p of providers) {
  const models = (tpl.config.models.providers[p].models || []).map(m => m.id);
  console.log(`    ${p}: ${models.join(', ')}`);
}

// Show default model
const primary = tpl.config.agents?.defaults?.model?.primary;
const fallbacks = tpl.config.agents?.defaults?.model?.fallbacks || [];
if (primary) {
  console.log(`  Primary:      ${primary}`);
}
if (fallbacks.length) {
  console.log(`  Fallbacks:    ${fallbacks.join(' → ')}`);
}

// Check for placeholder API key
const gwKey = tpl.config.models?.providers?.['mor-gateway']?.apiKey;
if (gwKey === 'YOUR_MOR_GATEWAY_API_KEY') {
  console.log('\n  ⚠️  Template has placeholder API key.');
  console.log('     Pass --key <your-key> in Stage 2 to substitute it.');
  console.log('     Get a free key at https://app.mor.org');
}

console.log('\n  ✅ Template loaded successfully. No changes written.\n');
