#!/bin/bash# Asset Value Tracker - Bernardo's Portfolio
# Fetches current prices and calculates portfolio value

# CoinGecko API (free tier, 10-30 calls/min)
COINGECKO_API="https://api.coingecko.com/api/v3"

# Token IDs on CoinGecko
MOR_ID="morpheusai"
VVV_ID="venice-token"
DIEM_ID="diem"
BTC_ID="bitcoin"
ETH_ID="ethereum"
USDC_ID="usdc"

# Holdings
MOR_QTY=363936
VVV_QTY=168800
DIEM_QTY=240
BTC_QTY=1
ETH_QTY=2
USDC_QTY=25000
BASEDAI_VALUE=7500000  # Fixed until valuation update

# Fetch prices
fetch_price() {
    local id=$1
    curl -s "${COINGECKO_API}/simple/price?ids=${id}&vs_currencies=usd" | jq -r ".${id}.usd"
}

echo "Fetching prices..."
MOR_PRICE=$(fetch_price $MOR_ID)
VVV_PRICE=$(fetch_price $VVV_ID)
DIEM_PRICE=$(fetch_price $DIEM_ID)
BTC_PRICE=$(fetch_price $BTC_ID)
ETH_PRICE=$(fetch_price $ETH_ID)
USDC_PRICE=$(fetch_price $USDC_ID)

# Calculate values
MOR_VALUE=$(echo "$MOR_QTY * $MOR_PRICE" | bc -l)
VVV_VALUE=$(echo "$VVV_QTY * $VVV_PRICE" | bc -l)
DIEM_VALUE=$(echo "$DIEM_QTY * $DIEM_PRICE" | bc -l)
BTC_VALUE=$(echo "$BTC_QTY * $BTC_PRICE" | bc -l)
ETH_VALUE=$(echo "$ETH_QTY * $ETH_PRICE" | bc -l)
USDC_VALUE=$(echo "$USDC_QTY * $USDC_PRICE" | bc -l)

# Total
TOTAL=$(echo "$MOR_VALUE + $VVV_VALUE + $DIEM_VALUE + $BTC_VALUE + $ETH_VALUE + $USDC_VALUE + $BASEDAI_VALUE" | bc -l)

# Format output
echo ""
echo "========================================"
echo "📊 ASSET VALUE REPORT -$(date '+%Y-%m-%d %H:%M')"
echo "========================================"
echo ""
printf "%-15s %12s %15s %18s\n" "Asset" "Price" "Quantity" "Value (USD)"
echo "----------------------------------------"
printf "%-15s %12s %15.0f %18.2f\n" "MOR" "\$${MOR_PRICE}" "$MOR_QTY" "$MOR_VALUE"
printf "%-15s %12s %15.0f %18.2f\n" "VVV" "\$${VVV_PRICE}" "$VVV_QTY" "$VVV_VALUE"
printf "%-15s %12s %15.0f %18.2f\n" "DIEM" "\$${DIEM_PRICE}" "$DIEM_QTY" "$DIEM_VALUE"
printf "%-15s %12s %15.0f %18.2f\n" "BTC" "\$${BTC_PRICE}" "$BTC_QTY" "$BTC_VALUE"
printf "%-15s %12s %15.0f %18.2f\n" "ETH" "\$${ETH_PRICE}" "$ETH_QTY" "$ETH_VALUE"
printf "%-15s %12s %15.0f %18.2f\n" "USDC" "\$${USDC_PRICE}" "$USDC_QTY" "$USDC_VALUE"
printf "%-15s %12s %15s %18.2f\n" "BasedAI" "(private)" "25%" "$BASEDAI_VALUE"
echo "----------------------------------------"
printf "%-45s %18.2f\n" "" "$TOTAL"
echo ""
echo "🎯 Target: \$1,000,000,000 | Gap: $(echo "1000000000 - $TOTAL" | bc -l | xargs printf '%.2f')"
echo ""