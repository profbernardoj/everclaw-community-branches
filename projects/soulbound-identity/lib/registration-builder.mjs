#!/usr/bin/env node
/**
 * ERC-8004 Registration File Builder
 *
 * Generates the agent registration JSON that becomes the agentURI on-chain.
 * Includes identity file hashes, agent capabilities, and service endpoints.
 *
 * Usage:
 *   node registration-builder.mjs <config-path>
 *   node registration-builder.mjs config/bernardo.json
 *
 * Programmatic:
 *   import { buildRegistration, toBase64DataURI } from './registration-builder.mjs';
 */

import { readFile, writeFile } from "fs/promises";
import { hashIdentityFiles } from "./hash-identity.mjs";

// ─── Builder ────────────────────────────────────────────────────────────────

/**
 * Build an ERC-8004 registration file for an agent.
 *
 * @param {Object} config - Agent configuration
 * @param {string} config.name - Agent display name
 * @param {string} config.description - Natural language description
 * @param {string} config.image - Agent avatar/image URL
 * @param {string} config.workspacePath - Path to agent workspace (for hashing)
 * @param {string} config.ownerAddress - Ethereum address of the agent owner
 * @param {number} [config.agentId] - Existing agentId if already registered
 * @param {string} [config.chainId="8453"] - Chain ID (Base = 8453)
 * @param {string} [config.identityRegistry] - Identity Registry address
 * @param {Array} [config.services] - Service endpoints
 * @param {Array} [config.supportedTrust] - Trust models supported
 * @param {Object} [config.soulbound] - Soulbound configuration
 * @returns {Promise<Object>} The registration file JSON
 */
export async function buildRegistration(config) {
  const {
    name,
    description,
    image = "",
    workspacePath,
    ownerAddress,
    agentId = null,
    chainId = "8453",
    identityRegistry = "0x8004A169FB4a3325136EB29fA0ceB6D2e539a432",
    services = [],
    supportedTrust = ["reputation"],
    soulbound = { locked: true, standard: "ERC-5192" },
  } = config;

  // Hash identity files
  const identityHashes = workspacePath
    ? await hashIdentityFiles(workspacePath)
    : null;

  const registration = {
    // ERC-8004 required fields
    type: "https://eips.ethereum.org/EIPS/eip-8004#registration-v1",
    name,
    description,
    image,

    // Service endpoints
    services: [
      ...services,
    ],

    // x402 payment support
    x402Support: true,

    // Active status
    active: true,

    // On-chain registrations
    registrations: agentId
      ? [
          {
            agentId,
            agentRegistry: `eip155:${chainId}:${identityRegistry}`,
          },
        ]
      : [],

    // Trust models
    supportedTrust,

    // ─── Custom Extensions ────────────────────────────────────────────

    // Soulbound configuration (ERC-5192)
    soulbound,

    // Identity file hashes — the core of our soul-binding
    identityFiles: identityHashes
      ? {
          "SOUL.md": identityHashes["SOUL.md"]?.hash || null,
          "USER.md": identityHashes["USER.md"]?.hash || null,
          "IDENTITY.md": identityHashes["IDENTITY.md"]?.hash || null,
          _composite: identityHashes._composite?.hash || null,
          _algorithm: "keccak256",
          _hashDate: new Date().toISOString(),
        }
      : null,

    // Owner verification
    owner: {
      address: ownerAddress,
      chain: `eip155:${chainId}`,
    },

    // Metadata
    _generatedAt: new Date().toISOString(),
    _generator: "soulbound-identity/registration-builder v1.0.0",
  };

  return registration;
}

/**
 * Encode a registration file as a base64 data URI for fully on-chain storage.
 * @param {Object} registration - The registration JSON object
 * @returns {string} data:application/json;base64,... URI
 */
export function toBase64DataURI(registration) {
  const json = JSON.stringify(registration);
  const base64 = Buffer.from(json).toString("base64");
  return `data:application/json;base64,${base64}`;
}

/**
 * Estimate the gas cost of storing a registration file on-chain.
 * @param {Object} registration - The registration JSON object
 * @returns {Object} Size info and rough gas estimates
 */
export function estimateOnChainCost(registration) {
  const json = JSON.stringify(registration);
  const base64URI = toBase64DataURI(registration);

  // Rough estimates for Base L2
  // ~16 gas per non-zero byte of calldata (EIP-2028)
  // Base L2 fees are ~$0.001-0.01 per tx typically
  const calldataBytes = Buffer.from(base64URI).length;
  const calldataGas = calldataBytes * 16;
  const baseGas = 50000; // register() overhead
  const storageGas = Math.ceil(calldataBytes / 32) * 20000; // SSTORE slots

  return {
    jsonBytes: json.length,
    base64URIBytes: base64URI.length,
    estimatedGas: baseGas + calldataGas + storageGas,
    note: "Actual gas depends on Base L2 fees. Estimate is rough upper bound.",
  };
}

// ─── CLI ────────────────────────────────────────────────────────────────────

async function main() {
  const configPath = process.argv[2];

  if (!configPath) {
    console.log(`
🔐 ERC-8004 Registration Builder

Usage:
  node registration-builder.mjs <config-path>
  node registration-builder.mjs config/bernardo.json

Config file format:
{
  "name": "Bernardo",
  "description": "Business & engineering agent for decentralized AI infrastructure",
  "image": "",
  "workspacePath": "~/.openclaw/workspace",
  "ownerAddress": "0x...",
  "services": []
}
`);
    process.exit(1);
  }

  const configRaw = await readFile(configPath, "utf-8");
  const config = JSON.parse(configRaw);

  console.log(`\n🔐 Building registration for: ${config.name}`);

  const registration = await buildRegistration(config);

  // Output
  const outputPath = configPath.replace(".json", "-registration.json");
  await writeFile(outputPath, JSON.stringify(registration, null, 2));
  console.log(`\n  ✅ Registration written to: ${outputPath}`);

  // Cost estimate
  const cost = estimateOnChainCost(registration);
  console.log(`\n  📊 On-chain cost estimate:`);
  console.log(`     JSON size: ${cost.jsonBytes} bytes`);
  console.log(`     Base64 URI size: ${cost.base64URIBytes} bytes`);
  console.log(`     Estimated gas: ~${cost.estimatedGas.toLocaleString()}`);

  // Base64 data URI
  const dataURI = toBase64DataURI(registration);
  console.log(`\n  🔗 Data URI (first 100 chars): ${dataURI.slice(0, 100)}...`);
  console.log(`     Full URI length: ${dataURI.length} chars\n`);

  return registration;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch(console.error);
}
