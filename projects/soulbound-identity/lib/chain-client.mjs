#!/usr/bin/env node
/**
 * Chain Client — On-chain interaction layer for Soulbound Identity
 *
 * Handles reading from and writing to ERC-8004 Identity Registry,
 * ERC-6551 Token Bound Account creation, and soulbound lock verification.
 *
 * Read operations work without a private key.
 * Write operations require a signer (via Bagman/1Password pattern).
 *
 * Usage:
 *   import { ChainClient } from './chain-client.mjs';
 *   const client = new ChainClient();
 *   const agent = await client.lookupAgent(1);
 */

import { createPublicClient, http, parseAbi, encodeFunctionData, keccak256 as viemKeccak256, toBytes } from "viem";
import { base } from "viem/chains";

// ─── Contract Addresses (Base Mainnet) ──────────────────────────────────────

export const CONTRACTS = {
  IDENTITY_REGISTRY: "0x8004A169FB4a3325136EB29fA0ceB6D2e539a432",
  REPUTATION_REGISTRY: "0x8004BAa17C55a88189AE136b182e5fdA19dE9b63",
  // ERC-6551 (canonical deployment, same on all EVM chains)
  TBA_REGISTRY: "0x000000006551c19487814612e58FE06813775758",
  TBA_IMPLEMENTATION: "0x55266d75D1a14E4572138116aF39863Ed6596E7F",
  // Chain
  CHAIN_ID: 8453n,
};

// ─── ABIs ───────────────────────────────────────────────────────────────────

const identityAbi = parseAbi([
  // ERC-721 standard
  "function ownerOf(uint256 tokenId) view returns (address)",
  "function tokenURI(uint256 tokenId) view returns (string)",
  "function balanceOf(address owner) view returns (uint256)",
  // ERC-8004 Identity
  "function register(string agentURI) returns (uint256 agentId)",
  "function register(string agentURI, (string metadataKey, bytes metadataValue)[] metadata) returns (uint256 agentId)",
  "function register() returns (uint256 agentId)",
  "function setAgentURI(uint256 agentId, string newURI)",
  "function getMetadata(uint256 agentId, string metadataKey) view returns (bytes)",
  "function setMetadata(uint256 agentId, string metadataKey, bytes metadataValue)",
  "function getAgentWallet(uint256 agentId) view returns (address)",
  "function setAgentWallet(uint256 agentId, address newWallet, uint256 deadline, bytes signature)",
  // Events
  "event Registered(uint256 indexed agentId, string agentURI, address indexed owner)",
  "event URIUpdated(uint256 indexed agentId, string newURI, address indexed updatedBy)",
]);

const tbaRegistryAbi = parseAbi([
  "function createAccount(address implementation, bytes32 salt, uint256 chainId, address tokenContract, uint256 tokenId) returns (address)",
  "function account(address implementation, bytes32 salt, uint256 chainId, address tokenContract, uint256 tokenId) view returns (address)",
]);

// ─── Client ─────────────────────────────────────────────────────────────────

export class ChainClient {
  constructor(rpcUrl = "https://base-mainnet.public.blastapi.io") {
    this.publicClient = createPublicClient({
      chain: base,
      transport: http(rpcUrl),
    });
  }

  // ─── Read Operations (no signer needed) ─────────────────────────────────

  /**
   * Look up an agent by ID.
   */
  async lookupAgent(agentId) {
    const [owner, tokenURI] = await Promise.all([
      this.publicClient.readContract({
        address: CONTRACTS.IDENTITY_REGISTRY,
        abi: identityAbi,
        functionName: "ownerOf",
        args: [BigInt(agentId)],
      }),
      this.publicClient.readContract({
        address: CONTRACTS.IDENTITY_REGISTRY,
        abi: identityAbi,
        functionName: "tokenURI",
        args: [BigInt(agentId)],
      }),
    ]);

    let agentWallet = null;
    try {
      agentWallet = await this.publicClient.readContract({
        address: CONTRACTS.IDENTITY_REGISTRY,
        abi: identityAbi,
        functionName: "getAgentWallet",
        args: [BigInt(agentId)],
      });
    } catch {
      // agentWallet not set
    }

    // Parse registration file from URI
    const registration = await this.fetchRegistrationFile(tokenURI);

    return {
      agentId,
      owner,
      tokenURI,
      agentWallet,
      registration,
    };
  }

  /**
   * Fetch and parse a registration file from any URI scheme.
   */
  async fetchRegistrationFile(uri) {
    if (!uri) return null;

    try {
      // data: URI (base64 on-chain)
      if (uri.startsWith("data:")) {
        const match = uri.match(/^data:[^;]*;base64,(.+)$/);
        if (match) {
          return JSON.parse(Buffer.from(match[1], "base64").toString("utf-8"));
        }
        const plainMatch = uri.match(/^data:[^,]*,(.+)$/);
        if (plainMatch) {
          return JSON.parse(decodeURIComponent(plainMatch[1]));
        }
        return null;
      }

      // ipfs:// URI
      let url = uri;
      if (uri.startsWith("ipfs://")) {
        url = `https://ipfs.io/ipfs/${uri.replace("ipfs://", "")}`;
      }

      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 10000);
      const res = await fetch(url, { signal: controller.signal });
      clearTimeout(timeout);

      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  }

  /**
   * Get the deterministic TBA address for an agent NFT.
   * This doesn't require the TBA to exist — it returns the address it WOULD have.
   */
  async getTBAAddress(agentId, salt = "0x" + "0".repeat(64)) {
    return await this.publicClient.readContract({
      address: CONTRACTS.TBA_REGISTRY,
      abi: tbaRegistryAbi,
      functionName: "account",
      args: [
        CONTRACTS.TBA_IMPLEMENTATION,
        salt,
        CONTRACTS.CHAIN_ID,
        CONTRACTS.IDENTITY_REGISTRY,
        BigInt(agentId),
      ],
    });
  }

  /**
   * Check if a TBA exists (has code deployed).
   */
  async tbaExists(agentId) {
    const tbaAddress = await this.getTBAAddress(agentId);
    const code = await this.publicClient.getCode({ address: tbaAddress });
    return {
      address: tbaAddress,
      exists: code && code !== "0x",
    };
  }

  /**
   * Read on-chain metadata for an agent.
   */
  async getMetadata(agentId, key) {
    try {
      return await this.publicClient.readContract({
        address: CONTRACTS.IDENTITY_REGISTRY,
        abi: identityAbi,
        functionName: "getMetadata",
        args: [BigInt(agentId), key],
      });
    } catch {
      return null;
    }
  }

  // ─── Write Operations (transaction builders — need signer) ──────────────

  /**
   * Build a register() transaction.
   * Returns unsigned transaction data — caller must sign and submit.
   */
  buildRegisterTx(agentURI) {
    return {
      to: CONTRACTS.IDENTITY_REGISTRY,
      data: encodeFunctionData({
        abi: identityAbi,
        functionName: "register",
        args: [agentURI],
      }),
      description: `Register new agent with URI: ${agentURI.slice(0, 80)}...`,
    };
  }

  /**
   * Build a setAgentURI() transaction (for updating identity hashes).
   */
  buildUpdateURITx(agentId, newURI) {
    return {
      to: CONTRACTS.IDENTITY_REGISTRY,
      data: encodeFunctionData({
        abi: identityAbi,
        functionName: "setAgentURI",
        args: [BigInt(agentId), newURI],
      }),
      description: `Update URI for agent #${agentId}`,
    };
  }

  /**
   * Build a createAccount() transaction for ERC-6551 TBA.
   */
  buildCreateTBATx(agentId, salt = "0x" + "0".repeat(64)) {
    return {
      to: CONTRACTS.TBA_REGISTRY,
      data: encodeFunctionData({
        abi: tbaRegistryAbi,
        functionName: "createAccount",
        args: [
          CONTRACTS.TBA_IMPLEMENTATION,
          salt,
          CONTRACTS.CHAIN_ID,
          CONTRACTS.IDENTITY_REGISTRY,
          BigInt(agentId),
        ],
      }),
      description: `Create Token Bound Account for agent #${agentId}`,
    };
  }

  /**
   * Build a setMetadata() transaction.
   */
  buildSetMetadataTx(agentId, key, value) {
    const valueBytes =
      typeof value === "string" ? toBytes(value) : value;

    return {
      to: CONTRACTS.IDENTITY_REGISTRY,
      data: encodeFunctionData({
        abi: identityAbi,
        functionName: "setMetadata",
        args: [BigInt(agentId), key, valueBytes],
      }),
      description: `Set metadata "${key}" for agent #${agentId}`,
    };
  }
}

// ─── Utility ────────────────────────────────────────────────────────────────

/**
 * Compute keccak256 using viem (Ethereum-compatible).
 */
export function keccak256(data) {
  if (typeof data === "string") {
    return viemKeccak256(toBytes(data));
  }
  return viemKeccak256(data);
}

// ─── CLI ────────────────────────────────────────────────────────────────────

async function main() {
  const cmd = process.argv[2];
  const arg = process.argv[3];

  const client = new ChainClient();

  switch (cmd) {
    case "lookup": {
      if (!arg) { console.log("Usage: chain-client.mjs lookup <agentId>"); break; }
      const agent = await client.lookupAgent(parseInt(arg));
      console.log(JSON.stringify(agent, null, 2));
      break;
    }
    case "tba": {
      if (!arg) { console.log("Usage: chain-client.mjs tba <agentId>"); break; }
      const tba = await client.tbaExists(parseInt(arg));
      console.log(`TBA for agent #${arg}: ${tba.address} (exists: ${tba.exists})`);
      break;
    }
    default:
      console.log(`
🔗 Chain Client — Soulbound Identity

Commands:
  lookup <agentId>   Look up an agent by ID
  tba <agentId>      Check TBA address for an agent
`);
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch(console.error);
}
