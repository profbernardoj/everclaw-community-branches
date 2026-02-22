#!/usr/bin/env bash
set -uo pipefail

# Memory Upgrade — Configure
# Patches openclaw.json with local embeddings + hybrid search + session transcripts.
# Requires gateway restart after running.

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

echo "${BOLD}Memory Upgrade — Configure${RESET}"
echo "=========================="
echo ""

# Find openclaw.json
CONFIG_FILE="${OPENCLAW_STATE_DIR:-$HOME/.openclaw}/openclaw.json"

if [ ! -f "$CONFIG_FILE" ]; then
  echo "${RED}ERROR:${RESET} openclaw.json not found at $CONFIG_FILE"
  echo "Is OpenClaw installed?"
  exit 1
fi

echo "Config: $CONFIG_FILE"

# Check if memorySearch is already configured
if node -e "
  const c = JSON.parse(require('fs').readFileSync('$CONFIG_FILE','utf8'));
  const ms = c.agents?.defaults?.memorySearch;
  if (ms && ms.provider && ms.provider !== 'auto') {
    console.log('CONFIGURED:' + ms.provider);
    process.exit(0);
  }
  process.exit(1);
" 2>/dev/null; then
  EXISTING=$(node -e "
    const c = JSON.parse(require('fs').readFileSync('$CONFIG_FILE','utf8'));
    console.log(c.agents.defaults.memorySearch.provider);
  " 2>/dev/null)
  echo ""
  echo "${YELLOW}⚠ memorySearch already configured (provider: $EXISTING)${RESET}"
  echo ""
  printf "Overwrite with local embedding config? [y/N] "
  read -r REPLY
  if [ "$REPLY" != "y" ] && [ "$REPLY" != "Y" ]; then
    echo "Aborted."
    exit 0
  fi
fi

# Backup config
BACKUP="${CONFIG_FILE}.backup.$(date +%Y%m%d%H%M%S)"
cp "$CONFIG_FILE" "$BACKUP"
echo "Backup: $BACKUP"

# Apply patch
echo ""
echo "Applying memory search configuration..."

node -e "
const fs = require('fs');
const config = JSON.parse(fs.readFileSync('$CONFIG_FILE', 'utf8'));

// Ensure path exists
if (!config.agents) config.agents = {};
if (!config.agents.defaults) config.agents.defaults = {};

// Memory search config
config.agents.defaults.memorySearch = {
  provider: 'local',
  fallback: 'none',
  experimental: { sessionMemory: true },
  sources: ['memory', 'sessions'],
  cache: { enabled: true, maxEntries: 50000 },
  query: {
    hybrid: {
      enabled: true,
      vectorWeight: 0.7,
      textWeight: 0.3,
      candidateMultiplier: 4,
      mmr: { enabled: true, lambda: 0.7 },
      temporalDecay: { enabled: true, halfLifeDays: 30 }
    }
  },
  sync: {
    watch: true,
    sessions: { deltaBytes: 50000, deltaMessages: 25 }
  }
};

fs.writeFileSync('$CONFIG_FILE', JSON.stringify(config, null, 2) + '\n');
console.log('Config patched successfully.');
" || {
  echo "${RED}ERROR:${RESET} Failed to patch config"
  echo "Restoring backup..."
  cp "$BACKUP" "$CONFIG_FILE"
  exit 1
}

echo ""
echo "${GREEN}${BOLD}✓ Memory search configured!${RESET}"
echo ""
echo "What was applied:"
echo "  • Provider: local (embeddinggemma-300m, ~328MB, auto-downloads)"
echo "  • Hybrid search: BM25 + vector (70/30 weight)"
echo "  • Session transcripts: enabled"
echo "  • MMR diversity: enabled (λ=0.7)"
echo "  • Temporal decay: enabled (30-day half-life)"
echo "  • Embedding cache: 50k entries"
echo "  • File watcher: enabled"
echo ""
echo "${BOLD}Next steps:${RESET}"
echo "  1. Restart gateway:  openclaw gateway restart"
echo "  2. Wait ~30s for embedding model to download (~328MB first time)"
echo "  3. Verify:  bash $(cd "$(dirname "$0")" && pwd)/verify.sh"
