#!/bin/bash
# install-proxy.sh — Install the Morpheus-to-OpenAI proxy and Gateway Guardian
#
# Sets up:
# 1. morpheus-proxy.mjs → ~/morpheus/proxy/ (OpenAI-compatible proxy)
# 2. gateway-guardian.sh → ~/.openclaw/workspace/scripts/ (gateway watchdog)
# 3. launchd plists for both (auto-start, auto-restart)
#
# Usage: bash skills/everclaw/scripts/install-proxy.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="$(dirname "$SCRIPT_DIR")"
MORPHEUS_DIR="${MORPHEUS_DIR:-$HOME/morpheus}"
PROXY_DIR="$MORPHEUS_DIR/proxy"
OPENCLAW_DIR="${OPENCLAW_DIR:-$HOME/.openclaw}"
NODE_PATH="${NODE_PATH_OVERRIDE:-$(which node)}"
LAUNCH_AGENTS="$HOME/Library/LaunchAgents"

echo "╔══════════════════════════════════════════╗"
echo "║  Everclaw — Proxy & Guardian Installer   ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# --- 1. Install Morpheus Proxy ---
echo "📡 Installing Morpheus-to-OpenAI proxy..."
mkdir -p "$PROXY_DIR"

cp "$SCRIPT_DIR/morpheus-proxy.mjs" "$PROXY_DIR/morpheus-proxy.mjs"
echo "   ✓ Copied morpheus-proxy.mjs → $PROXY_DIR/"

# --- 2. Install Gateway Guardian ---
echo "🛡️  Installing Gateway Guardian..."
mkdir -p "$OPENCLAW_DIR/workspace/scripts"
mkdir -p "$OPENCLAW_DIR/logs"

cp "$SCRIPT_DIR/gateway-guardian.sh" "$OPENCLAW_DIR/workspace/scripts/gateway-guardian.sh"
chmod +x "$OPENCLAW_DIR/workspace/scripts/gateway-guardian.sh"
echo "   ✓ Copied gateway-guardian.sh → $OPENCLAW_DIR/workspace/scripts/"

# --- 3. Install launchd plists (macOS only) ---
if [[ "$(uname)" == "Darwin" ]]; then
  echo "🍎 Setting up launchd services..."
  mkdir -p "$LAUNCH_AGENTS"

  # Unload existing if present
  launchctl unload "$LAUNCH_AGENTS/com.morpheus.proxy.plist" 2>/dev/null || true
  launchctl unload "$LAUNCH_AGENTS/ai.openclaw.guardian.plist" 2>/dev/null || true

  # Morpheus proxy plist
  sed \
    -e "s|__NODE_PATH__|$NODE_PATH|g" \
    -e "s|__PROXY_SCRIPT_PATH__|$PROXY_DIR/morpheus-proxy.mjs|g" \
    -e "s|__MORPHEUS_DIR__|$MORPHEUS_DIR|g" \
    -e "s|__HOME__|$HOME|g" \
    "$SKILL_DIR/templates/com.morpheus.proxy.plist" > "$LAUNCH_AGENTS/com.morpheus.proxy.plist"
  echo "   ✓ Installed com.morpheus.proxy.plist"

  # Guardian plist
  sed \
    -e "s|__GUARDIAN_SCRIPT_PATH__|$OPENCLAW_DIR/workspace/scripts/gateway-guardian.sh|g" \
    -e "s|__OPENCLAW_DIR__|$OPENCLAW_DIR|g" \
    -e "s|__HOME__|$HOME|g" \
    "$SKILL_DIR/templates/ai.openclaw.guardian.plist" > "$LAUNCH_AGENTS/ai.openclaw.guardian.plist"
  echo "   ✓ Installed ai.openclaw.guardian.plist"

  # Load services
  launchctl load "$LAUNCH_AGENTS/com.morpheus.proxy.plist" 2>/dev/null
  launchctl load "$LAUNCH_AGENTS/ai.openclaw.guardian.plist" 2>/dev/null
  echo "   ✓ Services loaded"

  sleep 2

  # Verify proxy is running
  if curl -s --max-time 3 http://127.0.0.1:8083/health > /dev/null 2>&1; then
    echo "   ✓ Morpheus proxy is healthy (port 8083)"
  else
    echo "   ⚠️  Morpheus proxy not responding yet — check ~/morpheus/proxy/proxy.log"
  fi

  # Verify guardian
  if launchctl list | grep -q "ai.openclaw.guardian"; then
    echo "   ✓ Gateway Guardian is scheduled (every 2 minutes)"
  else
    echo "   ⚠️  Gateway Guardian not loaded — check manually"
  fi
else
  echo "⚠️  Non-macOS detected. Skipping launchd setup."
  echo "   For Linux, create systemd units or cron jobs manually."
  echo "   Proxy: node $PROXY_DIR/morpheus-proxy.mjs"
  echo "   Guardian: bash $OPENCLAW_DIR/workspace/scripts/gateway-guardian.sh"
fi

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║  Installation complete!                  ║"
echo "╠══════════════════════════════════════════╣"
echo "║                                          ║"
echo "║  Proxy:    http://127.0.0.1:8083         ║"
echo "║  Health:   curl localhost:8083/health     ║"
echo "║  Guardian: ~/.openclaw/logs/guardian.log  ║"
echo "║                                          ║"
echo "║  Next: Configure OpenClaw to use the     ║"
echo "║  Morpheus provider as a fallback model.  ║"
echo "║  See SKILL.md § OpenClaw Integration.    ║"
echo "╚══════════════════════════════════════════╝"
