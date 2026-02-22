#!/usr/bin/env bash
set -uo pipefail

# Memory Upgrade — Verify
# Confirms memory search is working after configuration.
# Waits for gateway restart, triggers indexing, runs test query.

# Colors
if [ -t 1 ] && command -v tput >/dev/null 2>&1; then
  RED=$(tput setaf 1)
  GREEN=$(tput setaf 2)
  YELLOW=$(tput setaf 3)
  BOLD=$(tput bold)
  RESET=$(tput sgr0)
else
  RED="" GREEN="" YELLOW="" BOLD="" RESET=""
fi

echo "${BOLD}Memory Upgrade — Verify${RESET}"
echo "======================="
echo ""

# Check openclaw CLI
if ! command -v openclaw >/dev/null 2>&1; then
  echo "${RED}ERROR:${RESET} openclaw CLI not found"
  exit 1
fi

# Step 1: Wait for provider to be ready
echo "Waiting for embedding provider..."
ATTEMPTS=0
MAX_ATTEMPTS=30
while [ $ATTEMPTS -lt $MAX_ATTEMPTS ]; do
  STATUS=$(openclaw memory status --deep 2>&1) || true
  PROVIDER=$(echo "$STATUS" | grep -i "^Provider:" | head -1)
  EMBEDDINGS=$(echo "$STATUS" | grep -i "^Embeddings:" | head -1)

  if echo "$PROVIDER" | grep -q "local" && echo "$EMBEDDINGS" | grep -q "ready"; then
    echo "${GREEN}✓ Provider ready${RESET}"
    break
  fi

  ATTEMPTS=$((ATTEMPTS + 1))
  if [ $ATTEMPTS -ge $MAX_ATTEMPTS ]; then
    echo "${RED}✗ Timed out waiting for provider (${MAX_ATTEMPTS}s)${RESET}"
    echo "  Last status: $PROVIDER / $EMBEDDINGS"
    echo ""
    echo "The embedding model may still be downloading (~328MB)."
    echo "Try again in a minute: bash $0"
    exit 1
  fi
  printf "  Attempt %d/%d...\r" "$ATTEMPTS" "$MAX_ATTEMPTS"
  sleep 2
done

# Step 2: Trigger indexing
echo ""
echo "Triggering index..."
openclaw memory index 2>&1 | tail -5 || true

# Step 3: Wait for indexing
echo ""
echo "Waiting for indexing to complete..."
ATTEMPTS=0
MAX_ATTEMPTS=60
while [ $ATTEMPTS -lt $MAX_ATTEMPTS ]; do
  STATUS=$(openclaw memory status --deep 2>&1) || true
  INDEXED_LINE=$(echo "$STATUS" | grep -i "^Indexed:" | head -1)
  DIRTY=$(echo "$STATUS" | grep -i "^Dirty:" | head -1)

  # Check if we have chunks and not dirty
  CHUNKS=$(echo "$INDEXED_LINE" | grep -o '[0-9]* chunks' | grep -o '[0-9]*')
  if [ -n "$CHUNKS" ] && [ "$CHUNKS" -gt 0 ]; then
    if echo "$DIRTY" | grep -qi "no"; then
      echo "${GREEN}✓ Indexing complete${RESET}"
      break
    fi
  fi

  ATTEMPTS=$((ATTEMPTS + 1))
  if [ $ATTEMPTS -ge $MAX_ATTEMPTS ]; then
    echo "${YELLOW}⚠ Indexing still in progress after ${MAX_ATTEMPTS}s${RESET}"
    echo "  This is normal for large memory stores. It will finish in the background."
    break
  fi
  printf "  Waiting... (%ds)\r" "$((ATTEMPTS * 2))"
  sleep 2
done

# Step 4: Final status
echo ""
echo "${BOLD}Final Status${RESET}"
echo "============"
STATUS=$(openclaw memory status --deep 2>&1) || true

PROVIDER=$(echo "$STATUS" | grep -i "^Provider:" | head -1 | sed 's/Provider:[[:space:]]*//')
MODEL=$(echo "$STATUS" | grep -i "^Model:" | head -1 | sed 's/Model:[[:space:]]*//')
SOURCES=$(echo "$STATUS" | grep -i "^Sources:" | head -1 | sed 's/Sources:[[:space:]]*//')
INDEXED=$(echo "$STATUS" | grep -i "^Indexed:" | head -1 | sed 's/Indexed:[[:space:]]*//')
VECTOR=$(echo "$STATUS" | grep -i "^Vector:" | head -1 | sed 's/Vector:[[:space:]]*//')
FTS=$(echo "$STATUS" | grep -i "^FTS:" | head -1 | sed 's/FTS:[[:space:]]*//')
CACHE=$(echo "$STATUS" | grep -i "^Embedding cache:" | head -1 | sed 's/Embedding cache:[[:space:]]*//')

echo "  Provider:  ${PROVIDER:-unknown}"
echo "  Model:     ${MODEL:-unknown}"
echo "  Sources:   ${SOURCES:-unknown}"
echo "  Indexed:   ${INDEXED:-unknown}"
echo "  Vector:    ${VECTOR:-unknown}"
echo "  FTS:       ${FTS:-unknown}"
echo "  Cache:     ${CACHE:-unknown}"

# Source breakdown
echo ""
echo "${BOLD}Sources:${RESET}"
echo "$STATUS" | grep "^  memory\|^  sessions" | while read -r line; do
  echo "  $line"
done

echo ""

# Overall verdict
CHUNKS=$(echo "$INDEXED" | grep -o '[0-9]* chunks' | grep -o '[0-9]*' || echo "0")
if [ "${CHUNKS:-0}" -gt 0 ] && echo "$VECTOR" | grep -qi "ready"; then
  echo "${GREEN}${BOLD}✓ Memory search is working! ${CHUNKS} chunks indexed.${RESET}"
  echo ""
  echo "Your agent can now recall information across sessions."
  echo "Test it: ask your agent to remember something, then ask about it in a new session."
  exit 0
else
  echo "${RED}${BOLD}✗ Memory search may not be fully ready yet.${RESET}"
  echo ""
  echo "If indexing is still running, wait a minute and try again."
  echo "If the problem persists, check: openclaw memory status --deep --verbose"
  exit 1
fi
