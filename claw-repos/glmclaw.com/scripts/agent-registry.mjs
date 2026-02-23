#!/usr/bin/env node
/**
 * ERC-8004 Agent Registry Reader for Base Mainnet
 *
 * Discovers agents via the three ERC-8004 registries:
 *   - Identity Registry (ERC-721): agent names, URIs, wallets
 *   - Reputation Registry: client feedback, scores
 *   - Validation Registry: validator attestations
 *
 * Usage:
 *   node agent-registry.mjs lookup <agentId>
 *   node agent-registry.mjs reputation <agentId>
 *   node agent-registry.mjs discover <agentId>
 *   node agent-registry.mjs total
 *
 * Programmatic:
 *   import { lookupAgent, getReputation, discoverAgent } from './agent-registry.mjs';
 *
 * @license MIT
 */

import { createPublicClient, http, parseAbi } from "viem";
import { base } from "viem/chains";

// ─── Config ─────────────────────────────────────────────────────────────────

const RPC_URL = "https://base-mainnet.public.blastapi.io";

// ERC-8004 contract addresses on Base mainnet (same on all chains)
const IDENTITY_REGISTRY = "0x8004A169FB4a3325136EB29fA0ceB6D2e539a432";
const REPUTATION_REGISTRY = "0x8004BAa17C55a88189AE136b182e5fdA19dE9b63";

// ─── ABIs (minimal, only what we need) ──────────────────────────────────────

const identityAbi = parseAbi([
  // ERC-721 standard
  "function ownerOf(uint256 tokenId) view returns (address)",
  "function tokenURI(uint256 tokenId) view returns (string)",
  "function balanceOf(address owner) view returns (uint256)",
  "function totalSupply() view returns (uint256)",
  // ERC-8004 extensions
  "function getMetadata(uint256 agentId, string metadataKey) view returns (bytes)",
  "function getAgentWallet(uint256 agentId) view returns (address)",
  // Events
  "event Registered(uint256 indexed agentId, string agentURI, address indexed owner)",
  "event URIUpdated(uint256 indexed agentId, string newURI, address indexed updatedBy)",
]);

const reputationAbi = parseAbi([
  "function getSummary(uint256 agentId, address[] clientAddresses, string tag1, string tag2) view returns (uint64 count, int128 summaryValue, uint8 summaryValueDecimals)",
  "function getClients(uint256 agentId) view returns (address[])",
  "function readFeedback(uint256 agentId, address clientAddress, uint64 feedbackIndex) view returns (int128 value, uint8 valueDecimals, string tag1, string tag2, bool isRevoked)",
  "function readAllFeedback(uint256 agentId, address[] clientAddresses, string tag1, string tag2, bool includeRevoked) view returns (address[] clients, uint64[] feedbackIndexes, int128[] values, uint8[] valueDecimals, string[] tag1s, string[] tag2s, bool[] revokedStatuses)",
  "function getLastIndex(uint256 agentId, address clientAddress) view returns (uint64)",
  "function getIdentityRegistry() view returns (address)",
]);

// ─── Client ─────────────────────────────────────────────────────────────────

const client = createPublicClient({
  chain: base,
  transport: http(RPC_URL),
});

// ─── Helpers ────────────────────────────────────────────────────────────────

/**
 * Fetch and parse an agent registration file from its URI.
 * Handles https://, ipfs://, and data: URIs.
 */
async function fetchRegistrationFile(uri) {
  if (!uri) return null;

  try {
    let url = uri;

    // Handle data: URIs (base64 encoded JSON on-chain)
    if (uri.startsWith("data:")) {
      const match = uri.match(/^data:[^;]*;base64,(.+)$/);
      if (match) {
        return JSON.parse(Buffer.from(match[1], "base64").toString("utf-8"));
      }
      // Try as plain JSON data URI
      const plainMatch = uri.match(/^data:[^,]*,(.+)$/);
      if (plainMatch) {
        return JSON.parse(decodeURIComponent(plainMatch[1]));
      }
      return null;
    }

    // Handle ipfs:// URIs
    if (uri.startsWith("ipfs://")) {
      const cid = uri.replace("ipfs://", "");
      url = `https://ipfs.io/ipfs/${cid}`;
    }

    // Fetch with timeout
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);
    const res = await fetch(url, { signal: controller.signal });
    clearTimeout(timeout);

    if (!res.ok) return { _fetchError: `HTTP ${res.status}`, _url: url };

    const text = await res.text();
    try {
      return JSON.parse(text);
    } catch {
      return { _rawText: text.slice(0, 500), _url: url };
    }
  } catch (e) {
    return { _fetchError: e.message, _uri: uri };
  }
}

/**
 * Format a USDC-like amount (6 decimals) into human-readable string.
 */
function formatFeedbackValue(value, decimals) {
  if (decimals === 0) return value.toString();
  const divisor = 10n ** BigInt(decimals);
  const intPart = value / divisor;
  const fracPart = (value < 0n ? -value : value) % divisor;
  return `${intPart}.${fracPart.toString().padStart(Number(decimals), "0")}`;
}

// ─── Core Functions ─────────────────────────────────────────────────────────

/**
 * Look up an agent's identity from the registry.
 * Returns owner, URI, wallet, and parsed registration file.
 */
export async function lookupAgent(agentId) {
  const id = BigInt(agentId);

  const [owner, uri, wallet] = await Promise.all([
    client.readContract({
      address: IDENTITY_REGISTRY,
      abi: identityAbi,
      functionName: "ownerOf",
      args: [id],
    }).catch(() => null),
    client.readContract({
      address: IDENTITY_REGISTRY,
      abi: identityAbi,
      functionName: "tokenURI",
      args: [id],
    }).catch(() => null),
    client.readContract({
      address: IDENTITY_REGISTRY,
      abi: identityAbi,
      functionName: "getAgentWallet",
      args: [id],
    }).catch(() => null),
  ]);

  if (!owner) {
    throw new Error(`Agent #${agentId} not found on Base Identity Registry`);
  }

  const registration = await fetchRegistrationFile(uri);

  return {
    agentId: Number(id),
    owner,
    uri,
    wallet: wallet || owner,
    registration,
    chain: "eip155:8453",
    registry: IDENTITY_REGISTRY,
  };
}

/**
 * Get the total number of registered agents.
 * Falls back to binary search if totalSupply() is not available.
 */
export async function totalAgents() {
  // Try totalSupply first (may not be available on all deployments)
  try {
    const supply = await client.readContract({
      address: IDENTITY_REGISTRY,
      abi: identityAbi,
      functionName: "totalSupply",
    });
    return Number(supply);
  } catch {
    // Binary search: find the highest agentId that exists
    let low = 1, high = 100000, result = 0;
    while (low <= high) {
      const mid = Math.floor((low + high) / 2);
      try {
        await client.readContract({
          address: IDENTITY_REGISTRY,
          abi: identityAbi,
          functionName: "ownerOf",
          args: [BigInt(mid)],
        });
        result = mid;
        low = mid + 1;
      } catch {
        high = mid - 1;
      }
    }
    return result;
  }
}

/**
 * Get reputation data for an agent.
 */
export async function getReputation(agentId) {
  const id = BigInt(agentId);

  // Get all clients who gave feedback
  let clients;
  try {
    clients = await client.readContract({
      address: REPUTATION_REGISTRY,
      abi: reputationAbi,
      functionName: "getClients",
      args: [id],
    });
  } catch {
    return { agentId: Number(id), clients: [], feedbackCount: 0, summary: null, feedback: [] };
  }

  if (!clients || clients.length === 0) {
    return { agentId: Number(id), clients: [], feedbackCount: 0, summary: null, feedback: [] };
  }

  // Get summary (pass all clients for Sybil-resistant aggregation)
  let summary = null;
  try {
    const [count, summaryValue, summaryValueDecimals] = await client.readContract({
      address: REPUTATION_REGISTRY,
      abi: reputationAbi,
      functionName: "getSummary",
      args: [id, clients, "", ""],
    });
    summary = {
      count: Number(count),
      value: formatFeedbackValue(summaryValue, summaryValueDecimals),
      rawValue: summaryValue.toString(),
      decimals: Number(summaryValueDecimals),
    };
  } catch (e) {
    summary = { error: e.message };
  }

  // Read all feedback
  let feedback = [];
  try {
    const result = await client.readContract({
      address: REPUTATION_REGISTRY,
      abi: reputationAbi,
      functionName: "readAllFeedback",
      args: [id, clients, "", "", false],
    });
    const [fbClients, fbIndexes, fbValues, fbDecimals, fbTag1s, fbTag2s, fbRevoked] = result;
    for (let i = 0; i < fbClients.length; i++) {
      feedback.push({
        client: fbClients[i],
        index: Number(fbIndexes[i]),
        value: formatFeedbackValue(fbValues[i], fbDecimals[i]),
        rawValue: fbValues[i].toString(),
        decimals: Number(fbDecimals[i]),
        tag1: fbTag1s[i] || null,
        tag2: fbTag2s[i] || null,
        revoked: fbRevoked[i],
      });
    }
  } catch (e) {
    feedback = [{ error: e.message }];
  }

  return {
    agentId: Number(id),
    clients: clients.map(c => c),
    feedbackCount: summary?.count ?? clients.length,
    summary,
    feedback,
  };
}

/**
 * Full agent discovery: identity + registration file + endpoints + reputation.
 */
export async function discoverAgent(agentId) {
  const [identity, reputation] = await Promise.all([
    lookupAgent(agentId),
    getReputation(agentId).catch(e => ({ error: e.message })),
  ]);

  const reg = identity.registration;
  const services = reg?.services || [];
  const x402Support = reg?.x402Support ?? false;
  const active = reg?.active ?? null;
  const supportedTrust = reg?.supportedTrust || [];

  return {
    ...identity,
    name: reg?.name || `Agent #${agentId}`,
    description: reg?.description || null,
    image: reg?.image || null,
    active,
    x402Support,
    supportedTrust,
    services,
    reputation,
  };
}

/**
 * Look up multiple agents by ID range.
 */
export async function listAgents(startId, count = 10) {
  const results = [];
  for (let i = startId; i < startId + count; i++) {
    try {
      const agent = await lookupAgent(i);
      results.push({
        agentId: i,
        name: agent.registration?.name || `Agent #${i}`,
        active: agent.registration?.active ?? null,
        x402: agent.registration?.x402Support ?? false,
        services: (agent.registration?.services || []).map(s => s.name).join(", "),
      });
    } catch {
      // Agent doesn't exist, skip
    }
  }
  return results;
}

// ─── CLI ────────────────────────────────────────────────────────────────────

async function main() {
  const args = process.argv.slice(2);
  const command = args[0];
  const agentId = args[1];

  if (!command) {
    console.error("Usage:");
    console.error("  node agent-registry.mjs lookup <agentId>");
    console.error("  node agent-registry.mjs reputation <agentId>");
    console.error("  node agent-registry.mjs discover <agentId>");
    console.error("  node agent-registry.mjs list <startId> [count]");
    console.error("  node agent-registry.mjs total");
    process.exit(1);
  }

  try {
    switch (command) {
      case "total": {
        const total = await totalAgents();
        console.log(`Total registered agents on Base: ${total.toLocaleString()}`);
        break;
      }
      case "lookup": {
        if (!agentId) throw new Error("Missing agentId");
        const agent = await lookupAgent(agentId);
        console.log(JSON.stringify(agent, null, 2));
        break;
      }
      case "reputation": {
        if (!agentId) throw new Error("Missing agentId");
        const rep = await getReputation(agentId);
        console.log(JSON.stringify(rep, null, 2));
        break;
      }
      case "discover": {
        if (!agentId) throw new Error("Missing agentId");
        const full = await discoverAgent(agentId);
        console.log(JSON.stringify(full, null, 2));
        break;
      }
      case "list": {
        const start = parseInt(agentId || "1", 10);
        const count = parseInt(args[2] || "10", 10);
        const agents = await listAgents(start, count);
        console.table(agents);
        break;
      }
      default:
        console.error(`Unknown command: ${command}`);
        process.exit(1);
    }
  } catch (e) {
    console.error(`Error: ${e.message}`);
    process.exit(1);
  }
}

const isMain = process.argv[1]?.endsWith("agent-registry.mjs");
if (isMain) main().catch(e => { console.error(e); process.exit(1); });
