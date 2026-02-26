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
 */

import { x402Client, wrapFetchWithPayment } from "@x402/fetch";
import { registerExactEvmScheme } from "@x402/evm/exact/client";
import { privateKeyToAccount } from "viem/accounts";
import { execSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

// ─── Config ─────────────────────────────────────────────────────────────────

const WORKSPACE = process.env.OPENCLAW_WORKSPACE_DIR || 
  path.join(process.env.HOME, ".openclaw", "workspace");
const FINANCE_MD = path.join(WORKSPACE, "memory", "Finance.md");
const SNAPSHOT_DIR = path.join(WORKSPACE, "memory", "daily", "finance-snapshots");
const COINGECKO_X402 = "https://pro-api.coingecko.com/api/v3/x402/simple/price";
const TOKEN_IDS = "morpheusai,venice-token,diem,bitcoin,ethereum,usd-coin";

// Holdings — keep in sync with Finance.md
const HOLDINGS = {
  morpheusai:      { symbol: "MOR",  name: "Morpheus AI",  amount: 363936 },
  "venice-token":  { symbol: "VVV",  name: "Venice Token", amount: 168800 },
  diem:            { symbol: "DIEM", name: "DIEM",         amount: 240 },
  bitcoin:         { symbol: "BTC",  name: "Bitcoin",      amount: 1 },
  ethereum:        { symbol: "ETH",  name: "Ethereum",     amount: 2 },
  "usd-coin":      { symbol: "USDC", name: "USDC",         amount: 25000 },
};

const BASEDAI = { valuation: 120_000_000, equityPct: 0.25 };
const GOAL = 1_000_000_000;
const TARGET_DATE = "2026-04-18";

// ─── Key Retrieval ──────────────────────────────────────────────────────────

function getPrivateKey() {
  const token = execSync(
    'security find-generic-password -a "AGENT_USER" -s "op-service-account-token" -w',
    { encoding: "utf-8", timeout: 5000 }
  ).trim();
  return execSync(
    `OP_SERVICE_ACCOUNT_TOKEN=${token} op item get "Base Session Key" --vault "AGENT_VAULT" --fields "Private Key" --reveal`,
    { encoding: "utf-8", timeout: 10000, env: { ...process.env, OP_SERVICE_ACCOUNT_TOKEN: token } }
  ).trim();
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

  // 1. Fetch prices via x402
  console.error("🔑 Retrieving wallet key...");
  const signer = privateKeyToAccount(getPrivateKey());
  
  const client = new x402Client();
  registerExactEvmScheme(client, { signer });
  const fetchPaid = wrapFetchWithPayment(fetch, client);

  const url = `${COINGECKO_X402}?ids=${TOKEN_IDS}&vs_currencies=usd&include_24hr_change=true&include_market_cap=true&include_last_updated_at=true&precision=full`;
  
  console.error("💰 Fetching prices via x402 ($0.01 USDC on Base)...");
  const res = await fetchPaid(url, { method: "GET" });
  if (!res.ok) throw new Error(`CoinGecko x402 failed: HTTP ${res.status}`);
  
  const prices = await res.json();
  console.error("✅ x402 payment successful");

  // 2. Calculate portfolio
  const now = new Date();
  const dateStr = now.toISOString().slice(0, 10);
  const timeStr = now.toLocaleString("en-US", { timeZone: "America/Chicago", dateStyle: "short", timeStyle: "medium" });

  let liquidTotal = 0;
  const rows = [];

  for (const [id, holding] of Object.entries(HOLDINGS)) {
    const price = prices[id]?.usd || 0;
    const change24h = prices[id]?.usd_24h_change || 0;
    const value = holding.amount * price;
    liquidTotal += value;
    rows.push({
      id,
      symbol: holding.symbol,
      name: holding.name,
      amount: holding.amount,
      price,
      value,
      change24h,
    });
  }

  const basedaiValue = BASEDAI.valuation * BASEDAI.equityPct;
  const totalNet = liquidTotal + basedaiValue;
  const gap = GOAL - totalNet;
  const daysRemaining = Math.ceil((new Date(TARGET_DATE) - now) / 86_400_000);

  const result = {
    date: dateStr,
    timestamp: now.toISOString(),
    source: "CoinGecko x402",
    cost: "$0.01 USDC (Base)",
    assets: rows,
    liquidTotal,
    basedaiValue,
    totalNet,
    goal: GOAL,
    gap,
    daysRemaining,
  };

  // 3. Output
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
| BasedAI | 25% equity | $120M val | $${fmtUsd(basedaiValue)} |

## Summary

| Metric | Value |
|--------|-------|
| **Liquid Assets** | $${fmtUsd(liquidTotal)} |
| **BasedAI Equity** | $${fmtUsd(basedaiValue)} |
| **Total Net Worth** | $${fmtUsd(totalNet)} |
| **Goal** | $1,000,000,000.00 |
| **Gap** | $${fmtUsd(gap)} |
| **Days to Apr 18** | ${daysRemaining} |

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
    const basedaiRow = finance.indexOf("| **BasedAI**");
    
    if (tableStart > -1 && basedaiRow > -1) {
      const headerEnd = finance.indexOf("\n", finance.indexOf("\n", tableStart) + 1) + 1; // skip header + separator
      const newRows = rows.map(r => 
        `| ${r.symbol} (${r.name}) | ${r.amount.toLocaleString()} | $${fmtPrice(r.price)} | $${fmtUsd(r.value)} | CoinGecko x402 |`
      ).join("\n") + "\n";
      
      finance = finance.slice(0, headerEnd) + newRows + finance.slice(basedaiRow);
    }

    // Update Portfolio Summary
    finance = finance.replace(
      /\| \*\*Total Liquid Assets\*\* \| \$[\d,.]+\s*\|/,
      `| **Total Liquid Assets** | $${fmtUsd(liquidTotal)} |`
    );
    finance = finance.replace(
      /\| \*\*Total Net Worth\*\* \| \$[\d,.]+\s*\|/,
      `| **Total Net Worth** | $${fmtUsd(totalNet)} |`
    );
    finance = finance.replace(
      /\| \*\*Gap to Goal\*\* \| \$[\d,.]+\s*\|/,
      `| **Gap to Goal** | $${fmtUsd(gap)} |`
    );
    finance = finance.replace(
      /\| \*\*Days Remaining\*\* \| \d+[^|]*\|/,
      `| **Days Remaining** | ${daysRemaining} (${dateStr} → Apr 18) |`
    );

    // Update multipliers in Price Targets
    const morPrice = prices.morpheusai?.usd || 0.59;
    const vvvPrice = prices["venice-token"]?.usd || 3.68;
    if (morPrice > 0) {
      const morMult = Math.round(2747 / morPrice);
      finance = finance.replace(
        /\| MOR \| \$[\d.]+ \| \$2,747 \| 363,936 \| [\d,]+x \|/,
        `| MOR | $${morPrice.toFixed(2)} | $2,747 | 363,936 | ${morMult.toLocaleString()}x |`
      );
    }
    if (vvvPrice > 0) {
      const vvvMult = Math.round(5952 / vvvPrice);
      finance = finance.replace(
        /\| VVV \| \$[\d.]+ \| \$5,952 \| 168,800 \| [\d,]+x \|/,
        `| VVV | $${vvvPrice.toFixed(2)} | $5,952 | 168,800 | ${vvvMult.toLocaleString()}x |`
      );
    }

    // Update timestamp
    finance = finance.replace(
      /_Last updated:.*_/,
      `_Last updated: ${timeStr} — via x402 payment on Base_`
    );

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
  console.log(`  BasedAI:  $${fmtUsd(basedaiValue)}`);
  console.log(`  Total:    $${fmtUsd(totalNet)}`);
  console.log(`  Goal:     $${fmtUsd(GOAL)}`);
  console.log(`  Gap:      $${fmtUsd(gap)}`);
  console.log(`  Days:     ${daysRemaining}`);
  console.log(`  Source:   CoinGecko x402 ($0.01 USDC on Base)`);
}

main().catch(e => {
  console.error(`❌ Error: ${e.message}`);
  process.exit(1);
});
