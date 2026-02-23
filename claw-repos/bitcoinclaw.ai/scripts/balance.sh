#!/bin/bash
set -euo pipefail

# Everclaw Balance — Shows MOR/ETH balance, active sessions, and allowance
# Usage: ./balance.sh

MORPHEUS_DIR="$HOME/morpheus"
API_BASE="http://localhost:8082"

# Read auth cookie
if [[ ! -f "$MORPHEUS_DIR/.cookie" ]]; then
  echo "❌ .cookie file not found. Is the proxy-router running?" >&2
  exit 1
fi
COOKIE_PASS=$(cat "$MORPHEUS_DIR/.cookie" | cut -d: -f2)

echo "🦋 Morpheus Balance Report"
echo "=========================="
echo ""

# MOR and ETH balance
echo "💰 Wallet Balance:"
BALANCE=$(curl -s -u "admin:$COOKIE_PASS" "${API_BASE}/blockchain/balance" 2>/dev/null || echo "{}")

MOR_WEI=$(echo "$BALANCE" | jq -r '.mor // .MOR // "0"' 2>/dev/null || echo "0")
ETH_WEI=$(echo "$BALANCE" | jq -r '.eth // .ETH // "0"' 2>/dev/null || echo "0")

# Convert from wei to human-readable (basic awk division)
if [[ "$MOR_WEI" != "0" && "$MOR_WEI" != "null" ]]; then
  MOR_HUMAN=$(echo "$MOR_WEI" | awk '{printf "%.4f", $1 / 1000000000000000000}')
  echo "   MOR: $MOR_HUMAN ($MOR_WEI wei)"
else
  echo "   MOR: 0"
fi

if [[ "$ETH_WEI" != "0" && "$ETH_WEI" != "null" ]]; then
  ETH_HUMAN=$(echo "$ETH_WEI" | awk '{printf "%.6f", $1 / 1000000000000000000}')
  echo "   ETH: $ETH_HUMAN ($ETH_WEI wei)"
else
  echo "   ETH: 0"
fi

echo ""

# Allowance
echo "✅ MOR Allowance (Diamond contract):"
ALLOWANCE=$(curl -s -u "admin:$COOKIE_PASS" "${API_BASE}/blockchain/allowance?spender=0x6aBE1d282f72B474E54527D93b979A4f64d3030a" 2>/dev/null || echo "{}")
ALLOWANCE_VAL=$(echo "$ALLOWANCE" | jq -r '.allowance // .Allowance // empty' 2>/dev/null || echo "unknown")
if [[ -n "$ALLOWANCE_VAL" && "$ALLOWANCE_VAL" != "null" && "$ALLOWANCE_VAL" != "unknown" ]]; then
  ALLOWANCE_HUMAN=$(echo "$ALLOWANCE_VAL" | awk '{printf "%.4f", $1 / 1000000000000000000}')
  echo "   Approved: $ALLOWANCE_HUMAN MOR"
else
  echo "   Approved: (could not determine — check /blockchain/allowance)"
fi

echo ""

# Active sessions
echo "📋 Active Sessions:"
SESSIONS=$(curl -s -u "admin:$COOKIE_PASS" "${API_BASE}/blockchain/sessions" 2>/dev/null || echo "[]")

SESSION_COUNT=$(echo "$SESSIONS" | jq 'if type == "array" then length elif type == "object" and has("sessions") then .sessions | length else 0 end' 2>/dev/null || echo "0")

if [[ "$SESSION_COUNT" -gt 0 ]]; then
  echo "   Count: $SESSION_COUNT"
  echo ""
  echo "$SESSIONS" | jq -r '
    (if type == "array" then . elif has("sessions") then .sessions else [] end) |
    .[] |
    "   Session: \(.Id // .id // .sessionId // "??")\n   Model:   \(.ModelAgentId // .modelAgentId // .modelId // "??")\n   ---"
  ' 2>/dev/null || echo "$SESSIONS" | jq . 2>/dev/null || echo "   (could not parse sessions)"
else
  echo "   No active sessions."
fi

echo ""
echo "🔗 API: ${API_BASE}"
echo "📖 Swagger: ${API_BASE}/swagger/index.html"
