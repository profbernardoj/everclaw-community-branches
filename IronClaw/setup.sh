#!/bin/bash
# iron-everclaw setup — installs EverClaw proxy for IronClaw agents
# Usage: bash setup.sh
set -euo pipefail

echo "🚀 Installing iron-everclaw (EverClaw proxy + IronClaw integration)"
echo ""

# ─── OS Detection ────────────────────────────────────────────────────────────
OS="$(uname -s)"
ARCH="$(uname -m)"
echo "Platform: $OS / $ARCH"

# ─── Prerequisites ───────────────────────────────────────────────────────────
check_dep() {
  if ! command -v "$1" &>/dev/null; then
    echo "❌ Required: $1 not found."
    echo "   Install it first:"
    case "$OS" in
      Darwin) echo "   brew install $2" ;;
      Linux)  echo "   sudo apt-get install -y $2  # or your distro's package manager" ;;
    esac
    exit 1
  fi
}

check_dep node node
check_dep git git
check_dep curl curl

NODE_MAJOR=$(node -v | cut -d. -f1 | tr -d 'v')
if [ "$NODE_MAJOR" -lt 18 ]; then
  echo "❌ Node.js 18+ required (found $(node -v))"
  echo "   Upgrade: https://nodejs.org or use nvm/fnm"
  exit 1
fi

echo "✓ Prerequisites OK (node $(node -v), git, curl)"

# ─── Install EverClaw Proxy ──────────────────────────────────────────────────
EVERCLAW_DIR="${EVERCLAW_DIR:-$HOME/.everclaw}"

if [ -d "$EVERCLAW_DIR" ]; then
  echo "✓ EverClaw already installed at $EVERCLAW_DIR"
  echo "  Pulling latest..."
  cd "$EVERCLAW_DIR" && git pull --ff-only 2>/dev/null || echo "  (git pull skipped — not a git repo or has local changes)"
else
  echo "Cloning EverClaw..."
  git clone https://github.com/EverClaw/everclaw.git "$EVERCLAW_DIR"
fi

cd "$EVERCLAW_DIR"

# Install dependencies
if [ -f package.json ]; then
  echo "Installing Node.js dependencies..."
  npm ci --omit=dev 2>/dev/null || npm install --omit=dev
fi

echo "✓ EverClaw proxy installed at $EVERCLAW_DIR"

# ─── Start Proxy + Guardian ──────────────────────────────────────────────────
echo ""
echo "Starting proxy and guardian services..."

if [ -f scripts/install-proxy.sh ]; then
  bash scripts/install-proxy.sh
  echo "✓ Proxy service installed (port 8083)"
fi

if [ -f scripts/start.sh ]; then
  bash scripts/start.sh
  echo "✓ Services started"
fi

# ─── Configure IronClaw ──────────────────────────────────────────────────────
echo ""
echo "Configuring IronClaw..."

# Auto-detect IronClaw config location
IRON_ENV=""
for candidate in "$HOME/.ironclaw/.env" "$HOME/.config/ironclaw/.env" "./.env"; do
  if [ -f "$candidate" ]; then
    IRON_ENV="$candidate"
    break
  fi
done

if [ -n "$IRON_ENV" ]; then
  # Backup existing config
  cp "$IRON_ENV" "${IRON_ENV}.bak.$(date +%s)"
  echo "  Backed up $IRON_ENV"

  # Check if already configured
  if grep -q "127.0.0.1:8083" "$IRON_ENV" 2>/dev/null; then
    echo "  ✓ IronClaw already configured for EverClaw proxy"
  else
    cat >> "$IRON_ENV" << 'EOF'

# === iron-everclaw (added by setup.sh) ===
OPENAI_API_BASE=http://127.0.0.1:8083/v1
OPENAI_API_KEY=morpheus-local
# Models: glm-5 (default), glm-4.7-flash (fast), kimi-k2.5, qwen3-235b
EOF
    echo "  ✓ Added Morpheus proxy config to $IRON_ENV"
  fi
else
  echo "  ⚠ No IronClaw .env found. Add these to your IronClaw config manually:"
  echo "    OPENAI_API_BASE=http://127.0.0.1:8083/v1"
  echo "    OPENAI_API_KEY=morpheus-local"
  echo ""
  echo "  Or in Rust code:"
  echo '    let client = openai::Client::from_url("http://127.0.0.1:8083/v1", "morpheus-local");'
fi

# ─── Verify ──────────────────────────────────────────────────────────────────
echo ""
echo "Verifying proxy health..."
sleep 2

if curl -sf http://127.0.0.1:8083/health >/dev/null 2>&1; then
  echo "✓ Proxy is healthy!"
else
  echo "⚠ Proxy not responding yet. It may need a few seconds to start."
  echo "  Check manually: curl http://127.0.0.1:8083/health"
  echo "  Logs: tail -f ~/.everclaw/data/logs/proxy.log"
fi

# ─── Done ────────────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "🎉 iron-everclaw installed!"
echo ""
echo "  Proxy:    http://127.0.0.1:8083/v1"
echo "  Health:   curl http://127.0.0.1:8083/health"
echo "  Models:   glm-5, glm-4.7-flash, kimi-k2.5, qwen3-235b"
echo ""
echo "  Next steps:"
echo "    1. Restart IronClaw (or start a new agent session)"
echo "    2. For unlimited P2P inference, stake MOR:"
echo "       cd ~/.everclaw"
echo "       node scripts/everclaw-wallet.mjs setup"
echo "       node scripts/everclaw-wallet.mjs stake"
echo "═══════════════════════════════════════════════════════════════"
