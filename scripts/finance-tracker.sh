#!/bin/bash
# finance-tracker.sh — Daily portfolio snapshot
# Fetches current prices and calculates net worth toward $1B goal

set -e

WORKSPACE="~/.openclaw/workspace"
SNAPSHOT_DIR="$WORKSPACE/memory/daily/finance-snapshots"
DATE=$(date +%Y-%m-%d)
TIMESTAMP=$(date +%Y-%m-%d\ %H:%M:%S\ %Z)

# Holdings
MOR_HOLDINGS=363936
VVV_HOLDINGS=168800
DIEM_HOLDINGS=240
BTC_HOLDINGS=1
ETH_HOLDINGS=2
USDC_HOLDINGS=25000
BASEDAI_VALUATION=120000000
BASEDAI_EQUITY_PERCENT=0.25

# Goal and deadline
GOAL=1000000000
TARGET_DATE="2026-04-18"
START_DATE="2026-02-22"

# Create snapshot directory if needed
mkdir -p "$SNAPSHOT_DIR"

# Fetch prices from CoinGecko
echo "Fetching current prices..."
PRICES=$(curl -s "https://api.coingecko.com/api/v3/simple/price?ids=morpheusai,venice-token,diem,bitcoin,ethereum,usd-coin&vs_currencies=usd")

# Parse prices
MOR_PRICE=$(echo "$PRICES" | jq -r '.morpheusai.usd // 0')
VVV_PRICE=$(echo "$PRICES" | jq -r '.["venice-token"].usd // 0')
DIEM_PRICE=$(echo "$PRICES" | jq -r '.diem.usd // 0')
BTC_PRICE=$(echo "$PRICES" | jq -r '.bitcoin.usd // 0')
ETH_PRICE=$(echo "$PRICES" | jq -r '.ethereum.usd // 0')
USDC_PRICE=$(echo "$PRICES" | jq -r '.["usd-coin"].usd // 1')

# Calculate values
MOR_VALUE=$(echo "$MOR_HOLDINGS * $MOR_PRICE" | bc -l)
VVV_VALUE=$(echo "$VVV_HOLDINGS * $VVV_PRICE" | bc -l)
DIEM_VALUE=$(echo "$DIEM_HOLDINGS * $DIEM_PRICE" | bc -l)
BTC_VALUE=$(echo "$BTC_HOLDINGS * $BTC_PRICE" | bc -l)
ETH_VALUE=$(echo "$ETH_HOLDINGS * $ETH_PRICE" | bc -l)
USDC_VALUE=$(echo "$USDC_HOLDINGS * $USDC_PRICE" | bc -l)
BASEDAI_VALUE=$(echo "$BASEDAI_VALUATION * $BASEDAI_EQUITY_PERCENT" | bc -l)

# Total liquid
LIQUID_TOTAL=$(echo "$MOR_VALUE + $VVV_VALUE + $DIEM_VALUE + $BTC_VALUE + $ETH_VALUE + $USDC_VALUE" | bc -l)

# Total net worth
TOTAL_NET=$(echo "$LIQUID_TOTAL + $BASEDAI_VALUE" | bc -l)

# Days remaining
DAYS_REMAINING=$(( ($(date -j -f "%Y-%m-%d" "$TARGET_DATE" "+%s") - $(date -j -f "%Y-%m-%d" "$DATE" "+%s")) / 86400 ))

# Gap to goal
GAP=$(echo "$GOAL - $TOTAL_NET" | bc -l)

# Format for display
format_usd() {
    printf "$'%.2f'" "$1" | sed 's/\B\(.\{3\}\)/,\&/g'
}

# Output snapshot
SNAPSHOT_FILE="$SNAPSHOT_DIR/$DATE.md"

cat > "$SNAPSHOT_FILE" << EOF
---
tags: [finance, daily-snapshot]
date: $DATE
---

# Portfolio Snapshot — $TIMESTAMP

## Current Prices

| Asset | Price (USD) |
|-------|-------------|
| MOR | \$$MOR_PRICE |
| VVV | \$$VVV_PRICE |
| DIEM | \$$DIEM_PRICE |
| BTC | \$$BTC_PRICE |
| ETH | \$$ETH_PRICE |
| USDC | \$$USDC_PRICE |

## Holdings Value

| Asset | Holdings | Price | Value |
|-------|----------|-------|-------|
| MOR | $MOR_HOLDINGS | \$$MOR_PRICE | \$$(format_usd $MOR_VALUE) |
| VVV | $VVV_HOLDINGS | \$$VVV_PRICE | \$$(format_usd $VVV_VALUE) |
| DIEM | $DIEM_HOLDINGS | \$$DIEM_PRICE | \$$(format_usd $DIEM_VALUE) |
| BTC | $BTC_HOLDINGS | \$$BTC_PRICE | \$$(format_usd $BTC_VALUE) |
| ETH | $ETH_HOLDINGS | \$$ETH_PRICE | \$$(format_usd $ETH_VALUE) |
| USDC | $USDC_HOLDINGS | \$$USDC_PRICE | \$$(format_usd $USDC_VALUE) |
| BasedAI | 25% | \$30M val | \$$(format_usd $BASEDAI_VALUE) |

## Summary

| Metric | Value |
|--------|-------|
| **Liquid Assets** | \$$(format_usd $LIQUID_TOTAL) |
| **BasedAI Equity** | \$$(format_usd $BASEDAI_VALUE) |
| **Total Net Worth** | \$$(format_usd $TOTAL_NET) |
| **Goal** | \$1,000,000,000 |
| **Gap** | \$$(format_usd $GAP) |
| **Days to Apr 18** | $DAYS_REMAINING |

---
EOF

echo "✅ Snapshot saved to: $SNAPSHOT_FILE"
echo ""
echo "📊 Portfolio Summary:"
echo "   Liquid: \$$(format_usd $LIQUID_TOTAL)"
echo "   BasedAI: \$$(format_usd $BASEDAI_VALUE)"
echo "   Total: \$$(format_usd $TOTAL_NET)"
echo "   Goal: \$1,000,000,000"
echo "   Gap: \$$(format_usd $GAP)"
echo "   Days remaining: $DAYS_REMAINING"