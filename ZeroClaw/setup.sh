#!/bin/bash
# zero-everclaw setup — installs EverClaw proxy + ZeroClaw config
set -euo pipefail

echo "🚀 Installing zero-everclaw (EverClaw proxy + ZeroClaw integration)"
echo ""

OS="$(uname -s)"
echo "Platform: $OS / $(uname -m)"

# ─── Prerequisites ───────────────────────────────────────────────────────────
for dep in node git curl; do
  if ! command -v "$dep" &>/dev/null; then
    echo "❌ Required: $dep not found."
    exit 1
  fi
done

echo "✓ Prerequisites OK"

# ─── Install EverClaw Proxy ──────────────────────────────────────────────────
EVERCLAW_DIR="${EVERCLAW_DIR:-$HOME/.everclaw}"

if [ -d "$EVERCLAW_DIR" ]; then
  echo "✓ EverClaw already at $EVERCLAW_DIR"
  cd "$EVERCLAW_DIR" && git pull --ff-only 2>/dev/null || true
else
  echo "Cloning EverClaw..."
  git clone https://github.com/EverClaw/everclaw.git "$EVERCLAW_DIR"
fi

cd "$EVERCLAW_DIR"
[ -f package.json ] && (npm ci --omit=dev 2>/dev/null || npm install --omit=dev)
[ -f scripts/install-proxy.sh ] && bash scripts/install-proxy.sh
[ -f scripts/start.sh ] && bash scripts/start.sh

echo "✓ EverClaw proxy running on port 8083"

# ─── Install Service ─────────────────────────────────────────────────────────
echo ""
echo "Installing proxy service..."

case "$OS" in
  Linux)
    if command -v systemctl &>/dev/null; then
      UNIT_DIR="$HOME/.config/systemd/user"
      mkdir -p "$UNIT_DIR"
      cat > "$UNIT_DIR/everclaw-proxy.service" << EOF
[Unit]
Description=EverClaw Morpheus Proxy
After=network.target

[Service]
Type=simple
ExecStart=$(command -v node) $EVERCLAW_DIR/scripts/morpheus-proxy.mjs
Restart=always
RestartSec=5
Environment=NODE_ENV=production

[Install]
WantedBy=default.target
EOF
      systemctl --user daemon-reload
      systemctl --user enable everclaw-proxy.service
      systemctl --user start everclaw-proxy.service
      echo "  ✓ Systemd user service installed"
    elif command -v rc-service &>/dev/null; then
      echo "  ⚠ OpenRC detected — see examples/openrc-service for manual setup"
    fi
    ;;
  Darwin)
    echo "  ✓ macOS launchd handled by install-proxy.sh"
    ;;
esac

# ─── Patch ZeroClaw TOML Config ──────────────────────────────────────────────
echo ""
echo "Patching ZeroClaw config..."

ZEROCLAW_DIR=""
for candidate in "$HOME/.zeroclaw" "$HOME/zeroclaw" "$HOME/.config/zeroclaw"; do
  if [ -d "$candidate" ]; then
    ZEROCLAW_DIR="$candidate"
    break
  fi
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ -n "$ZEROCLAW_DIR" ] && [ -f "$ZEROCLAW_DIR/config.toml" ]; then
  cp "$ZEROCLAW_DIR/config.toml" "$ZEROCLAW_DIR/config.toml.bak.$(date +%s)"
  echo "  Backed up config.toml"

  # Check if already patched
  if grep -q "zero-everclaw" "$ZEROCLAW_DIR/config.toml" 2>/dev/null; then
    echo "  ✓ Already configured for EverClaw"
  else
    # Append the TOML patch (TOML supports appending sections)
    echo "" >> "$ZEROCLAW_DIR/config.toml"
    cat "$SCRIPT_DIR/config.patch.toml" >> "$ZEROCLAW_DIR/config.toml"
    echo "  ✓ Appended Morpheus config to config.toml"
    echo "  ℹ Note: default_provider was appended. If there's an existing"
    echo "    default_provider line, the LAST one wins in most TOML parsers."
    echo "    You may want to remove or comment out the old one."
  fi
else
  echo "  ⚠ ZeroClaw config not found."
  echo "    Run 'zeroclaw onboard' first, then re-run this setup."
  echo "    Or manually append config.patch.toml to your config."
fi

# ─── Install Skill ───────────────────────────────────────────────────────────
if [ -n "$ZEROCLAW_DIR" ]; then
  SKILL_DIR="$ZEROCLAW_DIR/workspace/skills/enable-morpheus"
  mkdir -p "$SKILL_DIR"
  if [ -f "$SCRIPT_DIR/workspace/skills/enable-morpheus/SKILL.md" ]; then
    cp "$SCRIPT_DIR/workspace/skills/enable-morpheus/SKILL.md" "$SKILL_DIR/SKILL.md"
    echo "✓ Installed enable-morpheus skill"
  fi
fi

# ─── Verify ──────────────────────────────────────────────────────────────────
echo ""
sleep 2
if curl -sf http://127.0.0.1:8083/health >/dev/null 2>&1; then
  echo "✓ Proxy is healthy!"
else
  echo "⚠ Proxy not responding. Check: curl http://127.0.0.1:8083/health"
fi

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "🎉 zero-everclaw installed!"
echo ""
echo "  Proxy:   http://127.0.0.1:8083/v1"
echo "  Start:   zeroclaw service restart"
echo "  Status:  zeroclaw status"
echo "  Skill:   /enable-morpheus"
echo ""
echo "  For unlimited P2P inference:"
echo "    cd ~/.everclaw && node scripts/everclaw-wallet.mjs setup"
echo "═══════════════════════════════════════════════════════════════"
