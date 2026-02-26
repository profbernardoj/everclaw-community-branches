#!/usr/bin/env node
/**
 * CoinGecko x402 Price Fetcher
 * 
 * Uses the official @x402/fetch SDK to pay $0.01 USDC per request on Base.
 * Retrieves private key from 1Password at runtime (Bagman pattern).
 * 
 * Usage:
 *   node coingecko-x402.mjs morpheusai,venice-token,bitcoin,ethereum
 *   node coingecko-x402.mjs --all   (fetches all Finance.md tokens)
 */

import { x402Client, wrapFetchWithPayment } from "@x402/fetch";
import { registerExactEvmScheme } from "@x402/evm/exact/client";
import { privateKeyToAccount } from "viem/accounts";
import { execSync } from "node:child_process";

// ─── Config ─────────────────────────────────────────────────────────────────

const COINGECKO_X402_BASE = "https://pro-api.coingecko.com/api/v3/x402";

// Finance.md token IDs on CoinGecko
const FINANCE_TOKENS = "morpheusai,venice-token,diem,bitcoin,ethereum,usd-coin";

// ─── Key Retrieval (Bagman pattern) ─────────────────────────────────────────

function getPrivateKey() {
  const token = execSync(
    'security find-generic-password -a "AGENT_USER" -s "op-service-account-token" -w',
    { encoding: "utf-8", timeout: 5000 }
  ).trim();

  const key = execSync(
    `OP_SERVICE_ACCOUNT_TOKEN=${token} op item get "Base Session Key" --vault "AGENT_VAULT" --fields "Private Key" --reveal`,
    { encoding: "utf-8", timeout: 10000, env: { ...process.env, OP_SERVICE_ACCOUNT_TOKEN: token } }
  ).trim();

  if (!key.startsWith("0x") || key.length !== 66) {
    throw new Error("Invalid private key format");
  }
  return key;
}

// ─── Main ───────────────────────────────────────────────────────────────────

async function main() {
  const args = process.argv.slice(2);
  const tokenIds = args.includes("--all") || args.length === 0
    ? FINANCE_TOKENS
    : args[0];

  console.error(`🔑 Retrieving wallet key from 1Password...`);
  const privateKey = getPrivateKey();
  const signer = privateKeyToAccount(privateKey);
  console.error(`✅ Wallet: ${signer.address}`);

  // Set up x402 client
  const client = new x402Client();
  registerExactEvmScheme(client, { signer });
  const fetchWithPayment = wrapFetchWithPayment(fetch, client);

  // Build URL
  const url = `${COINGECKO_X402_BASE}/simple/price?ids=${tokenIds}&vs_currencies=usd&include_24hr_change=true&include_market_cap=true&include_last_updated_at=true&precision=full`;

  console.error(`💰 Requesting prices via x402 ($0.01 USDC on Base)...`);
  console.error(`   URL: ${url}`);

  const response = await fetchWithPayment(url, { method: "GET" });

  if (!response.ok) {
    const text = await response.text();
    console.error(`❌ HTTP ${response.status}: ${text}`);
    process.exit(1);
  }

  const data = await response.json();
  
  // Output clean JSON to stdout
  console.log(JSON.stringify(data, null, 2));

  // Summary to stderr
  console.error(`\n✅ x402 payment successful — $0.01 USDC on Base`);
  console.error(`   Tokens: ${Object.keys(data).join(", ")}`);
}

main().catch(e => {
  console.error(`❌ Error: ${e.message}`);
  process.exit(1);
});
