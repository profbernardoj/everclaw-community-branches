#!/usr/bin/env bash
set -uo pipefail

# Memory Upgrade — Diagnose
# Checks if OpenClaw memory search is working or broken.

# Colors (with fallback)
if [ -t 1 ] && command -v tput >/dev/null 2>&1; then
  RED=$(tput setaf 1)
  GREEN=$(tput setaf 2)
  YELLOW=$(tput setaf 3)
  BOLD=$(tput bold)
  RESET=$(tput sgr0)
else
  RED="" GREEN="" YELLOW="" BOLD="" RESET=""
fi

echo "${BOLD}Memory Search Diagnostic${RESET}"
echo "========================"
echo ""

# Check openclaw CLI
if ! command -v openclaw >/dev/null 2>&1; then
  echo "${RED}ERROR:${RESET} openclaw CLI not found in PATH"
  echo "Install OpenClaw first: https://docs.openclaw.ai"
  exit 1
fi

# Run deep status check
echo "Running openclaw memory status --deep ..."
echo ""
STATUS_OUTPUT=$(openclaw memory status --deep 2>&1) || true

# Parse key fields
PROVIDER=$(echo "$STATUS_OUTPUT" | grep -i "^Provider:" | head -1 | sed 's/Provider:[[:space:]]*//')
EMBEDDINGS=$(echo "$STATUS_OUTPUT" | grep -i "^Embeddings:" | head -1 | sed 's/Embeddings:[[:space:]]*//')
INDEXED_LINE=$(echo "$STATUS_OUTPUT" | grep -i "^Indexed:" | head -1)
VECTOR=$(echo "$STATUS_OUTPUT" | grep -i "^Vector:" | head -1 | sed 's/Vector:[[:space:]]*//')
FTS=$(echo "$STATUS_OUTPUT" | grep -i "^FTS:" | head -1 | sed 's/FTS:[[:space:]]*//')

# Extract indexed counts
if [ -n "$INDEXED_LINE" ]; then
  INDEXED_FILES=$(echo "$INDEXED_LINE" | grep -o '[0-9]*/[0-9]* files' | head -1)
  INDEXED_CHUNKS=$(echo "$INDEXED_LINE" | grep -o '[0-9]* chunks' | head -1)
else
  INDEXED_FILES="unknown"
  INDEXED_CHUNKS="unknown"
fi

# Display results
echo "${BOLD}Provider:${RESET}   ${PROVIDER:-unknown}"
echo "${BOLD}Embeddings:${RESET} ${EMBEDDINGS:-unknown}"
echo "${BOLD}Indexed:${RESET}    ${INDEXED_FILES:-unknown} / ${INDEXED_CHUNKS:-unknown}"
echo "${BOLD}Vector:${RESET}     ${VECTOR:-unknown}"
echo "${BOLD}FTS:${RESET}        ${FTS:-unknown}"
echo ""

# Determine health
HEALTHY=true

# Check provider
case "$PROVIDER" in
  *none*|*"(requested: auto)"*)
    echo "${RED}✗ No embedding provider configured${RESET}"
    HEALTHY=false
    ;;
  *)
    echo "${GREEN}✓ Embedding provider: $PROVIDER${RESET}"
    ;;
esac

# Check embeddings
case "$EMBEDDINGS" in
  *unavailable*|*error*)
    echo "${RED}✗ Embeddings unavailable${RESET}"
    HEALTHY=false
    ;;
  *ready*)
    echo "${GREEN}✓ Embeddings ready${RESET}"
    ;;
esac

# Check indexed count
if echo "$INDEXED_LINE" | grep -q "Indexed: 0/"; then
  echo "${RED}✗ Zero files indexed${RESET}"
  HEALTHY=false
elif [ -n "$INDEXED_CHUNKS" ] && echo "$INDEXED_CHUNKS" | grep -q "^0 "; then
  echo "${YELLOW}⚠ Files found but zero chunks indexed${RESET}"
  HEALTHY=false
else
  echo "${GREEN}✓ Files indexed: $INDEXED_FILES${RESET}"
fi

echo ""

if [ "$HEALTHY" = true ]; then
  echo "${GREEN}${BOLD}Memory search is healthy.${RESET}"
  exit 0
else
  echo "${RED}${BOLD}Memory search is BROKEN.${RESET}"
  echo ""
  echo "Your agent's memory_search tool returns empty results."
  echo "This means cross-session recall doesn't work."
  echo ""
  echo "${BOLD}Fix it:${RESET}"
  SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
  echo "  bash ${SCRIPT_DIR}/configure.sh"
  exit 1
fi
