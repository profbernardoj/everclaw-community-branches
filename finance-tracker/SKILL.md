---
name: finance-tracker
description: >
  Daily portfolio tracking via x402 micropayments. Fetches live token prices from
  CoinGecko's x402 endpoint ($0.01 USDC per request on Base), saves daily snapshots,
  and updates a Finance.md portfolio file. No API key needed — pay per use with USDC.
  Demonstrates the x402 payment protocol for agent-driven financial tracking.
version: 1.0.0
---

# Finance Tracker (x402)

Track your crypto portfolio with live pricing via x402 micropayments on Base. No API keys, no subscriptions — just $0.01 USDC per price fetch.

## Prerequisites

- **Node.js** 18+ with npm
- **USDC on Base** — even $5 is enough for 500 daily snapshots (~1.4 years)
- **ETH on Base** — small amount for gas (x402 uses EIP-3009, but wallet needs some ETH)
- **Private key access** — via 1Password, macOS Keychain, or environment variable
- **npm packages:** `@x402/fetch`, `@x402/evm`, `viem`

## Setup

### 1. Install Dependencies

```bash
cd ~/.openclaw/workspace
npm install @x402/fetch @x402/evm viem
```

### 2. Configure Your Portfolio

Edit `scripts/finance-tracker-x402.mjs` and update the `HOLDINGS` object with your tokens:

```javascript
const HOLDINGS = {
  bitcoin:        { symbol: "BTC",  name: "Bitcoin",      amount: 1 },
  ethereum:       { symbol: "ETH",  name: "Ethereum",     amount: 10 },
  "usd-coin":     { symbol: "USDC", name: "USDC",         amount: 5000 },
  // Add your tokens here — use CoinGecko IDs
  // Find IDs at: https://www.coingecko.com/ (in the URL slug)
};
```

### 3. Configure Key Retrieval

The script retrieves the wallet private key at runtime. Edit the `getPrivateKey()` function to match your setup:

**Option A: 1Password (recommended)**
```javascript
// Already configured for 1Password + macOS Keychain
// Update the item name and vault to match yours
```

**Option B: Environment Variable**
```javascript
function getPrivateKey() {
  const key = process.env.AGENT_PRIVATE_KEY;
  if (!key) throw new Error("Set AGENT_PRIVATE_KEY env var");
  return key;
}
```

**Option C: macOS Keychain only**
```javascript
function getPrivateKey() {
  return execSync(
    'security find-generic-password -a "my-agent" -s "wallet-key" -w',
    { encoding: "utf-8", timeout: 5000 }
  ).trim();
}
```

### 4. Create Finance.md

Copy the template to your workspace:

```bash
cp skills/everclaw/finance-tracker/templates/Finance.template.md memory/Finance.md
```

Edit `memory/Finance.md` with your holdings, goals, and targets.

### 5. Test

```bash
node scripts/finance-tracker-x402.mjs --json  # output JSON only
node scripts/finance-tracker-x402.mjs          # full run: fetch, snapshot, update Finance.md
```

## Daily Cron Job

Register a cron job to run daily:

```
Name: Daily Finance Tracker (x402)
Schedule: 0 8 * * * (your timezone)
Model: your-light-model (e.g. GLM-4.7 Flash)
Session: isolated
Timeout: 120s
Message: >
  Run the daily finance tracker that fetches live prices via x402 payment
  ($0.01 USDC on Base) and updates Finance.md.
  
  Execute: cd ~/.openclaw/workspace && node scripts/finance-tracker-x402.mjs
  
  After the script completes, send the user a brief portfolio summary
  via their messaging channel.
```

**Cost:** ~$0.30/month for daily pricing. ~$3.65/year. No API key management.

## How x402 Works

1. Script sends GET request to CoinGecko's x402 endpoint
2. Server responds with HTTP 402 + payment requirements header
3. `@x402/fetch` SDK automatically signs a USDC authorization (EIP-712)
4. Request retries with the payment signature
5. Server verifies payment on Base, returns data
6. $0.01 USDC is transferred on Base

The wallet never sends a transaction directly — it signs an authorization that the server's facilitator executes. This means:
- No gas costs for the payment itself
- Atomic: you only pay if you get data
- No account, no API key, no subscription

## Files

```
finance-tracker/
├── SKILL.md                          # This file
├── scripts/
│   ├── finance-tracker-x402.mjs      # Main tracker script
│   └── coingecko-x402.mjs           # Standalone price fetcher
└── templates/
    └── Finance.template.md           # Portfolio template
```

## CoinGecko Token IDs

Find your token's CoinGecko ID in the URL when you visit its page:
- `https://www.coingecko.com/en/coins/bitcoin` → ID: `bitcoin`
- `https://www.coingecko.com/en/coins/ethereum` → ID: `ethereum`

Or search the full list: [CoinGecko ID CSV](https://raw.githubusercontent.com/sachiew/coingecko-id-map/refs/heads/main/coin_ids.csv)

## Extending

- **More data:** Add `include_24hr_vol=true`, `include_market_cap=true` to the URL params
- **On-chain prices:** Use the `/x402/onchain/simple/networks/{network}/token_price/{address}` endpoint for DEX prices
- **Multiple currencies:** Add `vs_currencies=usd,eur,btc` for multi-currency tracking
- **Pool data:** Use `/x402/onchain/search/pools` to track liquidity positions
