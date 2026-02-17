#!/bin/bash
set -euo pipefail

# Everclaw Swap — Convert ETH/USDC/USDT to MOR on Base
# Usage: ./swap.sh <token> <amount> [--quote]
#   token:  eth, usdc, or usdt
#   amount: amount in human-readable units (e.g., 0.01 for ETH, 50 for USDC)
#   --quote: just show estimated routes without executing
#
# Requires: Foundry (cast) installed. Install: curl -L https://foundry.paradigm.xyz | bash && foundryup
# Swaps via Uniswap V3 on Base. Private key retrieved from 1Password at runtime.

MORPHEUS_DIR="$HOME/morpheus"
RPC="https://base-mainnet.public.blastapi.io"

# Token addresses on Base
MOR="0x7431aDa8a591C955a994a21710752EF9b882b8e3"
WETH="0x4200000000000000000000000000000000000006"
USDC="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
USDT="0xfde4C96c8593536E31F229EA8f37b2ADa2699bb2"

# Uniswap V3 SwapRouter02 on Base
SWAP_ROUTER="0x2626664c2603336E57B271c5C0b26F421741e481"

# Pool fee tiers (discovered empirically on Base):
# - WETH/MOR: 3000 (0.3%) — has deep liquidity
# - USDC/WETH: 500 (0.05%) — standard stablecoin/ETH pair
# - Direct USDC/MOR and USDT/MOR pools have zero liquidity
# So USDC/USDT swaps route: token → WETH (500 fee) → MOR (3000 fee)

# Parse arguments
TOKEN="${1:?Usage: swap.sh <eth|usdc|usdt> <amount> [--quote]}"
AMOUNT="${2:?Usage: swap.sh <eth|usdc|usdt> <amount> [--quote]}"
QUOTE_ONLY="${3:-}"

TOKEN_LOWER=$(echo "$TOKEN" | tr '[:upper:]' '[:lower:]')

case "$TOKEN_LOWER" in
  eth|weth)
    TOKEN_IN="$WETH"
    TOKEN_NAME="ETH"
    DECIMALS=18
    IS_ETH=true
    SWAP_ROUTE="ETH → MOR (direct, 0.3% fee)"
    ;;
  usdc)
    TOKEN_IN="$USDC"
    TOKEN_NAME="USDC"
    DECIMALS=6
    IS_ETH=false
    SWAP_ROUTE="USDC → WETH → MOR (multi-hop, 0.05% + 0.3%)"
    ;;
  usdt)
    TOKEN_IN="$USDT"
    TOKEN_NAME="USDT"
    DECIMALS=6
    IS_ETH=false
    SWAP_ROUTE="USDT → WETH → MOR (multi-hop, 0.05% + 0.3%)"
    ;;
  *)
    echo "❌ Unsupported token: $TOKEN"
    echo "   Supported: eth, usdc, usdt"
    exit 1
    ;;
esac

# Convert human amount to smallest unit
AMOUNT_WEI=$(python3 -c "print(int(float('$AMOUNT') * 10**$DECIMALS))")

echo "♾️  Everclaw Swap"
echo "================"
echo "   From:   $AMOUNT $TOKEN_NAME"
echo "   To:     MOR"
echo "   Route:  $SWAP_ROUTE"
echo "   Chain:  Base (8453)"
echo ""

if [[ "$QUOTE_ONLY" == "--quote" ]]; then
  echo "💡 Quote mode — swap will NOT be executed."
  echo ""
  echo "To get a live quote with current prices, check:"
  echo "   Uniswap:   https://app.uniswap.org/explore/tokens/base/0x7431ada8a591c955a994a21710752ef9b882b8e3"
  echo "   Aerodrome:  https://aerodrome.finance/swap?from=eth&to=0x7431ada8a591c955a994a21710752ef9b882b8e3"
  exit 0
fi

# Check if cast (Foundry) is available
if ! command -v cast &> /dev/null; then
  echo "❌ Foundry (cast) is not installed."
  echo ""
  echo "Install it with:"
  echo "   curl -L https://foundry.paradigm.xyz | bash"
  echo "   foundryup"
  echo ""
  echo "Or swap manually via a DEX:"
  echo "   Uniswap:   https://app.uniswap.org/explore/tokens/base/0x7431ada8a591c955a994a21710752ef9b882b8e3"
  echo "   Aerodrome:  https://aerodrome.finance/swap?from=eth&to=0x7431ada8a591c955a994a21710752ef9b882b8e3"
  exit 1
fi

# Get private key from 1Password
echo "🔐 Retrieving wallet key from 1Password..."
OP_TOKEN=$(security find-generic-password -a "${OP_KEYCHAIN_ACCOUNT:-op-agent}" -s "op-service-account-token" -w 2>/dev/null) || {
  echo "❌ Could not retrieve 1Password service account token from keychain."
  echo "   Set OP_KEYCHAIN_ACCOUNT env var to your keychain account name."
  exit 1
}

PRIVATE_KEY=$(OP_SERVICE_ACCOUNT_TOKEN="$OP_TOKEN" op item get "${OP_ITEM_NAME:-YOUR_ITEM_NAME}" --vault "${OP_VAULT_NAME:-YOUR_VAULT_NAME}" --fields "Private Key" --reveal 2>/dev/null) || {
  echo "❌ Could not retrieve wallet private key from 1Password."
  echo "   Set OP_ITEM_NAME and OP_VAULT_NAME environment variables."
  exit 1
}

WALLET_ADDR=$(cast wallet address "$PRIVATE_KEY" 2>/dev/null)
echo "   Wallet: $WALLET_ADDR"
echo ""

echo "🔄 Executing swap: $AMOUNT $TOKEN_NAME → MOR..."

if [[ "$IS_ETH" == "true" ]]; then
  # ETH → MOR: direct swap via WETH/MOR pool (3000 fee)
  echo "   Route: ETH → MOR (WETH/MOR pool, 0.3% fee)"

  RESULT=$(cast send "$SWAP_ROUTER" \
    "exactInputSingle((address,address,uint24,address,uint256,uint256,uint160)) returns (uint256)" \
    "($WETH,$MOR,3000,$WALLET_ADDR,$AMOUNT_WEI,0,0)" \
    --rpc-url "$RPC" \
    --private-key "$PRIVATE_KEY" \
    --value "$AMOUNT_WEI" \
    2>&1) || {
    echo "❌ Swap failed."
    echo "   $RESULT"
    unset PRIVATE_KEY
    exit 1
  }

  TX_HASH=$(echo "$RESULT" | grep "transactionHash" | awk '{print $2}')
  echo "   ✅ TX: $TX_HASH"

else
  # USDC/USDT → MOR: multi-hop via WETH
  # Route: token → WETH (500 fee) → MOR (3000 fee)

  # Step 1: Approve token for router
  echo "   Approving $TOKEN_NAME for Uniswap router..."
  APPROVE_RESULT=$(cast send "$TOKEN_IN" \
    "approve(address,uint256)" \
    "$SWAP_ROUTER" "$AMOUNT_WEI" \
    --rpc-url "$RPC" \
    --private-key "$PRIVATE_KEY" \
    2>&1) || {
    echo "❌ Approval failed: $APPROVE_RESULT"
    unset PRIVATE_KEY
    exit 1
  }
  echo "   Approved ✓"
  sleep 2

  # Step 2: Multi-hop swap using exactInput with packed path
  # Path encoding: tokenIn(20 bytes) + fee(3 bytes) + tokenMiddle(20 bytes) + fee(3 bytes) + tokenOut(20 bytes)
  echo "   Swapping $TOKEN_NAME → WETH → MOR..."

  TOKEN_IN_CLEAN=$(echo "$TOKEN_IN" | sed 's/0x//')
  WETH_CLEAN=$(echo "$WETH" | sed 's/0x//')
  MOR_CLEAN=$(echo "$MOR" | sed 's/0x//')
  # Fee 500 = 0x0001f4 (3 bytes), Fee 3000 = 0x000bb8 (3 bytes)
  PATH_HEX="0x${TOKEN_IN_CLEAN}0001f4${WETH_CLEAN}000bb8${MOR_CLEAN}"

  RESULT=$(cast send "$SWAP_ROUTER" \
    "exactInput((bytes,address,uint256,uint256)) returns (uint256)" \
    "($PATH_HEX,$WALLET_ADDR,$AMOUNT_WEI,0)" \
    --rpc-url "$RPC" \
    --private-key "$PRIVATE_KEY" \
    2>&1) || {
    echo "❌ Swap failed."
    echo "   $RESULT"
    unset PRIVATE_KEY
    exit 1
  }

  TX_HASH=$(echo "$RESULT" | grep "transactionHash" | awk '{print $2}')
  echo "   ✅ TX: $TX_HASH"
fi

unset PRIVATE_KEY

# Check new MOR balance
sleep 3
echo ""
echo "📊 Updated balance:"
NEW_MOR=$(cast call "$MOR" "balanceOf(address)(uint256)" "$WALLET_ADDR" --rpc-url "$RPC" 2>/dev/null | awk '{printf "%.4f", $1/1e18}')
NEW_ETH=$(cast balance "$WALLET_ADDR" --rpc-url "$RPC" --ether 2>/dev/null)
echo "   MOR: $NEW_MOR"
echo "   ETH: $NEW_ETH"
echo ""
echo "✅ Swap complete! You can now open inference sessions with your MOR."
