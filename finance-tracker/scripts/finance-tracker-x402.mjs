#!/usr/bin/env node
/**
 * Finance Tracker — x402 Edition
 * 
 * Daily portfolio snapshot using CoinGecko x402 ($0.01 USDC on Base).
 * Updates Finance.md and saves daily snapshots.
 * 
 * Usage:
 *   node finance-tracker-x402.mjs              # full run: fetch, snapshot, update Finance.md
 *   node finance-tracker-x402.mjs --snapshot    # snapshot only (no Finance.md update)
 *   node finance-tracker-x402.mjs --json        # output JSON to stdout
 * 
 * Setup:
 *   1. npm install @x402/fetch @x402/evm viem
 *   2. Edit HOLDINGS below with your tokens
 *   3. Edit getPrivateKey() for your key storage method
 *   4. Edit TIMEZONE for your locale
 */

import { x402Client, wrapFetchWithPayment } from "@x402/fetch";
import { registerExactEvmScheme } from "@x402/evm/exact/client";
import { privateKeyToAccount } from "viem/accounts";
import { execSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

// ─── CONFIGURE THESE ────────────────────────────────────────────────────────

const WORKSPACE = process.env.OPENCLAW_WORKSPACE_DIR || 
  path.join(process.env.HOME, ".openclaw", "workspace");
const FINANCE_MD = path.join(WORKSPACE, "memory", "Finance.md");
const SNAPSHOT_DIR = path.join(WORKSPACE, "memory", "daily", "finance-snapshots");
const TIMEZONE = "America/Chicago"; // Your timezone

// Your holdings — use CoinGecko IDs as keys
// Find IDs at: https://www.coingecko.com/en/coins/<id>
const HOLDINGS = {
  // bitcoin:        { symbol: "BTC",  name: "Bitcoin",      amount: 1 },
  // ethereum:       { symbol: "ETH",  name: "Ethereum",     amount: 10 },
  // "usd-coin":     { symbol: "USDC", name: "USDC",         amount: 5000 },
  // "your-token":   { symbol: "TKN",  name: "Token Name",   amount: 1000 },
};

// Optional: non-crypto assets to include in net worth
const OTHER_ASSETS = {
  // "Company Equity": { value: 0, note: "25% equity at $X valuation" },
};

// Goal tracking (set to null to disable)
const GOAL = null; // e.g., 1_000_000
const TARGET_DATE = null; // e.g., "2026-12-31"

// ─── CoinGecko x402 ────────────────────────────────────────────────────────

const COINGECKO_X402 = "https://pro-api.coingecko.com/api/v3/x402/simple/price";

// ─── Key Retrieval ──────────────────────────────────────────────────────────
// Edit this function to match your key storage method.

function getPrivateKey() {
  // Option A: 1Password via macOS Keychain (recommended)
  const token = execSync(
    'security find-generic-password -a "your-agent" -s "op-service-account-token" -w',
    { encoding: "utf-8", timeout: 5000 }
  ).trim();
  return execSync(
    `OP_SERVICE_ACCOUNT_TOKEN=${token} op item get "Your Wallet Key" --vault "Your Vault" --fields "Private Key" --reveal`,
    { encoding: "utf-8", timeout: 10000, env: { ...process.env, OP_SERVICE_ACCOUNT_TOKEN: token } }
  ).trim();

  // Option B: Environment variable
  // const key = process.env.AGENT_PRIVATE_KEY;
  // if (!key) throw new Error("Set AGENT_PRIVATE_KEY");
  // return key;

  // Option C: macOS Keychain directly
  // return execSync(
  //   'security find-generic-password -a "my-agent" -s "wallet-key" -w',
  //   { encoding: "utf-8", timeout: 5000 }
  // ).trim();
}

// ─── Formatting ─────────────────────────────────────────────────────────────

function fmtUsd(n) {
  return n.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}

function fmtPrice(n) {
  if (n < 1) return n.toFixed(4);
  if (n < 100) return n.toFixed(2);
  return fmtUsd(n);
}

// ─── Main ───────────────────────────────────────────────────────────────────

async function main() {
  const args = process.argv.slice(2);
  const jsonOnly = args.includes("--json");
  const snapshotOnly = args.includes("--snapshot");

  // Validate config
  const tokenIds = Object.keys(HOLDINGS);
  if (tokenIds.length === 0) {
    console.error("❌ No tokens configured. Edit HOLDINGS in this script.");
    process.exit(1);
  }

  // 1. Fetch prices via x402
  console.error("🔑 Retrieving wallet key...");
  const signer = privateKeyToAccount(getPrivateKey());
  
  const client = new x402Client();
  registerExactEvmScheme(client, { signer });
  const fetchPaid = wrapFetchWithPayment(fetch, client);

  const url = `${COINGECKO_X402}?ids=${tokenIds.join(",")}&vs_currencies=usd&include_24hr_change=true&include_market_cap=true&include_last_updated_at=true&precision=full`;
  
  console.error("💰 Fetching prices via x402 ($0.01 USDC on Base)...");
  const res = await fetchPaid(url, { method: "GET" });
  if (!res.ok) throw new Error(`CoinGecko x402 failed: HTTP ${res.status}`);
  
  const prices = await res.json();
  console.error("✅ x402 payment successful");

  // 2. Calculate portfolio
  const now = new Date();
  const dateStr = now.toISOString().slice(0, 10);
  const timeStr = now.toLocaleString("en-US", { timeZone: TIMEZONE, dateStyle: "short", timeStyle: "medium" });

  let liquidTotal = 0;
  const rows = [];

  for (const [id, holding] of Object.entries(HOLDINGS)) {
    const price = prices[id]?.usd || 0;
    const change24h = prices[id]?.usd_24h_change || 0;
    const value = holding.amount * price;
    liquidTotal += value;
    rows.push({ id, symbol: holding.symbol, name: holding.name, amount: holding.amount, price, value, change24h });
  }

  let otherTotal = 0;
  for (const [, asset] of Object.entries(OTHER_ASSETS)) {
    otherTotal += asset.value;
  }

  const totalNet = liquidTotal + otherTotal;
  const gap = GOAL ? GOAL - totalNet : null;
  const daysRemaining = TARGET_DATE ? Math.ceil((new Date(TARGET_DATE) - now) / 86_400_000) : null;

  const result = { date: dateStr, timestamp: now.toISOString(), source: "CoinGecko x402", cost: "$0.01 USDC (Base)", assets: rows, liquidTotal, otherTotal, totalNet, goal: GOAL, gap, daysRemaining };

  // 3. JSON output mode
  if (jsonOnly) {
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  // 4. Save snapshot
  fs.mkdirSync(SNAPSHOT_DIR, { recursive: true });
  const snapshotFile = path.join(SNAPSHOT_DIR, `${dateStr}.md`);

  const snapshotMd = `---
tags: [finance, daily-snapshot, x402]
date: ${dateStr}
source: CoinGecko x402 ($0.01 USDC on Base)
---

# Portfolio Snapshot — ${timeStr}

## Current Prices

| Asset | Price (USD) | 24h Change |
|-------|-------------|------------|
${rows.map(r => `| ${r.symbol} | $${fmtPrice(r.price)} | ${r.change24h >= 0 ? "▲" : "▼"} ${r.change24h.toFixed(2)}% |`).join("\n")}

## Holdings Value

| Asset | Holdings | Price | Value |
|-------|----------|-------|-------|
${rows.map(r => `| ${r.symbol} | ${r.amount.toLocaleString()} | $${fmtPrice(r.price)} | $${fmtUsd(r.value)} |`).join("\n")}

## Summary

| Metric | Value |
|--------|-------|
| **Liquid Assets** | $${fmtUsd(liquidTotal)} |
${otherTotal > 0 ? `| **Other Assets** | $${fmtUsd(otherTotal)} |\n` : ""}| **Total Net Worth** | $${fmtUsd(totalNet)} |
${GOAL ? `| **Goal** | $${fmtUsd(GOAL)} |\n| **Gap** | $${fmtUsd(gap)} |\n` : ""}${daysRemaining !== null ? `| **Days Remaining** | ${daysRemaining} |\n` : ""}
---
_Source: CoinGecko x402 · Paid $0.01 USDC on Base · Wallet: ${signer.address}_
`;

  fs.writeFileSync(snapshotFile, snapshotMd);
  console.error(`📸 Snapshot: ${snapshotFile}`);

  // 5. Update Finance.md (unless --snapshot)
  if (!snapshotOnly && fs.existsSync(FINANCE_MD)) {
    let finance = fs.readFileSync(FINANCE_MD, "utf-8");

    // Update the Primary Assets table
    const tableStart = finance.indexOf("| Asset | Holdings | Current Price | Current Value | Data Source |");
    if (tableStart > -1) {
      const headerEnd = finance.indexOf("\n", finance.indexOf("\n", tableStart) + 1) + 1;
      // Find the next section (--- or ##) after the table
      const nextSection = finance.indexOf("\n---", headerEnd);
      const newRows = rows.map(r => 
        `| ${r.symbol} (${r.name}) | ${r.amount.toLocaleString()} | $${fmtPrice(r.price)} | $${fmtUsd(r.value)} | CoinGecko x402 |`
      ).join("\n") + "\n";
      
      if (nextSection > -1) {
        finance = finance.slice(0, headerEnd) + newRows + finance.slice(nextSection);
      }
    }

    // Update summary values
    finance = finance.replace(/\| \*\*Total Liquid Assets\*\* \| \$[\d,.]+\s*\|/, `| **Total Liquid Assets** | $${fmtUsd(liquidTotal)} |`);
    finance = finance.replace(/\| \*\*Total Net Worth\*\* \| \$[\d,.]+\s*\|/, `| **Total Net Worth** | $${fmtUsd(totalNet)} |`);
    if (gap !== null) finance = finance.replace(/\| \*\*Gap to Goal\*\* \| \$[\d,.]+\s*\|/, `| **Gap to Goal** | $${fmtUsd(gap)} |`);
    if (daysRemaining !== null) finance = finance.replace(/\| \*\*Days Remaining\*\* \| \d+[^|]*\|/, `| **Days Remaining** | ${daysRemaining} (${dateStr} → ${TARGET_DATE}) |`);

    // Update timestamp
    finance = finance.replace(/_Last updated:.*_/, `_Last updated: ${timeStr} — via x402 payment on Base_`);

    fs.writeFileSync(FINANCE_MD, finance);
    console.error("📝 Finance.md updated");
  }

  // 6. Print summary
  console.log(`📊 Portfolio Snapshot — ${dateStr}`);
  console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
  for (const r of rows) {
    const arrow = r.change24h >= 0 ? "▲" : "▼";
    console.log(`  ${r.symbol.padEnd(5)} $${fmtPrice(r.price).padStart(12)}  ${arrow} ${r.change24h.toFixed(1).padStart(5)}%  → $${fmtUsd(r.value).padStart(14)}`);
  }
  console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
  console.log(`  Liquid:   $${fmtUsd(liquidTotal)}`);
  if (otherTotal > 0) console.log(`  Other:    $${fmtUsd(otherTotal)}`);
  console.log(`  Total:    $${fmtUsd(totalNet)}`);
  if (GOAL) console.log(`  Goal:     $${fmtUsd(GOAL)}`);
  if (gap !== null) console.log(`  Gap:      $${fmtUsd(gap)}`);
  if (daysRemaining !== null) console.log(`  Days:     ${daysRemaining}`);
  console.log(`  Source:   CoinGecko x402 ($0.01 USDC on Base)`);
}

main().catch(e => {
  console.error(`❌ Error: ${e.message}`);
  process.exit(1);
});
