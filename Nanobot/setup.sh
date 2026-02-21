#!/bin/bash
# nanobot-everclaw setup — installs EverClaw proxy + Nanobot config
set -euo pipefail

echo "🚀 Installing nanobot-everclaw (EverClaw proxy + Nanobot integration)"
echo ""

OS="$(uname -s)"
echo "Platform: $OS / $(uname -m)"

# ─── Prerequisites ───────────────────────────────────────────────────────────
check_dep() {
  if ! command -v "$1" &>/dev/null; then
    echo "❌ Required: $1 not found."
    exit 1
  fi
}

check_dep node
check_dep git
check_dep curl

# Check for nanobot
if command -v nanobot &>/dev/null; then
  echo "✓ Nanobot found: $(nanobot --version 2>/dev/null || echo 'installed')"
else
  echo "⚠ Nanobot CLI not found. Install it first:"
  echo "  brew install nanobot-ai/tap/nanobot  # macOS"
  echo "  go install github.com/nanobot-ai/nanobot@latest  # Go"
  echo ""
  echo "Continuing anyway (proxy will be ready when you install Nanobot)..."
fi

echo "✓ Prerequisites OK"

# ─── Install EverClaw Proxy ──────────────────────────────────────────────────
EVERCLAW_DIR="${EVERCLAW_DIR:-$HOME/.everclaw}"

if [ -d "$EVERCLAW_DIR" ]; then
  echo "✓ EverClaw already installed at $EVERCLAW_DIR"
  cd "$EVERCLAW_DIR" && git pull --ff-only 2>/dev/null || true
else
  echo "Cloning EverClaw..."
  git clone https://github.com/EverClaw/everclaw.git "$EVERCLAW_DIR"
fi

cd "$EVERCLAW_DIR"

if [ -f package.json ]; then
  npm ci --omit=dev 2>/dev/null || npm install --omit=dev
fi

[ -f scripts/install-proxy.sh ] && bash scripts/install-proxy.sh
[ -f scripts/start.sh ] && bash scripts/start.sh

echo "✓ EverClaw proxy running on port 8083"

# ─── Create Nanobot Config ───────────────────────────────────────────────────
echo ""
echo "Creating Nanobot Morpheus config..."

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG_DEST="$HOME/nanobot-morpheus.yaml"

if [ -f "$SCRIPT_DIR/nanobot-morpheus.yaml" ]; then
  cp "$SCRIPT_DIR/nanobot-morpheus.yaml" "$CONFIG_DEST"
else
  cat > "$CONFIG_DEST" << 'YAMLEOF'
agents:
  main:
    name: Morpheus Agent
    model: glm-5
    temperature: 0.7
    system: |
      You are a helpful assistant powered by decentralized inference via the Morpheus network.
    mcpServers: []
YAMLEOF
fi

echo "✓ Config created at $CONFIG_DEST"

# ─── Add Shell Alias ─────────────────────────────────────────────────────────
echo ""
echo "Adding shell alias..."

ALIAS_LINE='alias nanobot-morpheus="OPENAI_API_KEY=morpheus-local OPENAI_BASE_URL=http://127.0.0.1:8083/v1 nanobot run ~/nanobot-morpheus.yaml"'

add_alias() {
  local rcfile="$1"
  if [ -f "$rcfile" ]; then
    if ! grep -q "nanobot-morpheus" "$rcfile" 2>/dev/null; then
      echo "" >> "$rcfile"
      echo "# nanobot-everclaw: run Nanobot with Morpheus inference" >> "$rcfile"
      echo "$ALIAS_LINE" >> "$rcfile"
      echo "  ✓ Added alias to $rcfile"
      return 0
    else
      echo "  ✓ Alias already in $rcfile"
      return 0
    fi
  fi
  return 1
}

# Try zsh first (macOS default), then bash
add_alias "$HOME/.zshrc" || add_alias "$HOME/.bashrc" || echo "  ⚠ No .zshrc/.bashrc found — add the alias manually"

# ─── Verify ──────────────────────────────────────────────────────────────────
echo ""
sleep 2

if curl -sf http://127.0.0.1:8083/health >/dev/null 2>&1; then
  echo "✓ EverClaw proxy is healthy!"
else
  echo "⚠ Proxy not responding yet."
  echo "  Check: curl http://127.0.0.1:8083/health"
fi

# ─── Done ────────────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "🎉 nanobot-everclaw installed!"
echo ""
echo "  Run:    nanobot-morpheus"
echo "  Or:     OPENAI_API_KEY=morpheus-local OPENAI_BASE_URL=http://127.0.0.1:8083/v1 nanobot run ~/nanobot-morpheus.yaml"
echo "  UI:     http://localhost:8080"
echo "  Health: curl http://127.0.0.1:8083/health"
echo ""
echo "  Reload your shell first: source ~/.zshrc  (or ~/.bashrc)"
echo ""
echo "  For unlimited P2P inference, stake MOR:"
echo "    cd ~/.everclaw && node scripts/everclaw-wallet.mjs setup"
echo "═══════════════════════════════════════════════════════════════"
