#!/usr/bin/env node
/**
 * CoinGecko x402 Price Fetcher
 * 
 * Standalone script to fetch token prices via x402 ($0.01 USDC on Base).
 * 
 * Usage:
 *   node coingecko-x402.mjs bitcoin,ethereum
 *   node coingecko-x402.mjs bitcoin,ethereum,solana
 */

import { x402Client, wrapFetchWithPayment } from "@x402/fetch";
import { registerExactEvmScheme } from "@x402/evm/exact/client";
import { privateKeyToAccount } from "viem/accounts";
import { execSync } from "node:child_process";

const COINGECKO_X402_BASE = "https://pro-api.coingecko.com/api/v3/x402";

// ─── Key Retrieval — edit to match your setup ───────────────────────────────

function getPrivateKey() {
  // Option A: 1Password via macOS Keychain
  const token = execSync(
    'security find-generic-password -a "your-agent" -s "op-service-account-token" -w',
    { encoding: "utf-8", timeout: 5000 }
  ).trim();
  return execSync(
    `OP_SERVICE_ACCOUNT_TOKEN=${token} op item get "Your Wallet Key" --vault "Your Vault" --fields "Private Key" --reveal`,
    { encoding: "utf-8", timeout: 10000, env: { ...process.env, OP_SERVICE_ACCOUNT_TOKEN: token } }
  ).trim();

  // Option B: Environment variable
  // return process.env.AGENT_PRIVATE_KEY;
}

// ─── Main ───────────────────────────────────────────────────────────────────

async function main() {
  const tokenIds = process.argv[2];
  if (!tokenIds) {
    console.error("Usage: node coingecko-x402.mjs token1,token2,...");
    console.error("Example: node coingecko-x402.mjs bitcoin,ethereum,solana");
    process.exit(1);
  }

  console.error("🔑 Retrieving wallet key...");
  const signer = privateKeyToAccount(getPrivateKey());
  console.error(`✅ Wallet: ${signer.address}`);

  const client = new x402Client();
  registerExactEvmScheme(client, { signer });
  const fetchWithPayment = wrapFetchWithPayment(fetch, client);

  const url = `${COINGECKO_X402_BASE}/simple/price?ids=${tokenIds}&vs_currencies=usd&include_24hr_change=true&include_market_cap=true&include_last_updated_at=true&precision=full`;

  console.error(`💰 Requesting prices via x402 ($0.01 USDC on Base)...`);
  const response = await fetchWithPayment(url, { method: "GET" });

  if (!response.ok) {
    console.error(`❌ HTTP ${response.status}: ${await response.text()}`);
    process.exit(1);
  }

  const data = await response.json();
  console.log(JSON.stringify(data, null, 2));
  console.error(`\n✅ x402 payment successful — $0.01 USDC on Base`);
  console.error(`   Tokens: ${Object.keys(data).join(", ")}`);
}

main().catch(e => { console.error(`❌ Error: ${e.message}`); process.exit(1); });
