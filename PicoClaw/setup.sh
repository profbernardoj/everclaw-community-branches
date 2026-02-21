#!/bin/bash
# pico-everclaw setup — installs EverClaw proxy + PicoClaw config
set -euo pipefail

echo "🚀 Installing pico-everclaw (EverClaw proxy + PicoClaw integration)"
echo ""

OS="$(uname -s)"
ARCH="$(uname -m)"
echo "Platform: $OS / $ARCH"

# ─── Detect constrained environment ──────────────────────────────────────────
TOTAL_MEM_MB=0
case "$OS" in
  Linux)
    TOTAL_MEM_MB=$(awk '/MemTotal/ {printf "%.0f", $2/1024}' /proc/meminfo 2>/dev/null || echo 0)
    ;;
  Darwin)
    TOTAL_MEM_MB=$(( $(sysctl -n hw.memsize 2>/dev/null || echo 0) / 1024 / 1024 ))
    ;;
esac

if [ "$TOTAL_MEM_MB" -gt 0 ] && [ "$TOTAL_MEM_MB" -lt 256 ]; then
  echo "⚠ Low memory detected (${TOTAL_MEM_MB} MB)."
  echo "  The EverClaw proxy needs ~80 MB RAM."
  echo "  Consider running the proxy on a separate, more capable device"
  echo "  and pointing PicoClaw at it over the network."
  echo ""
  read -p "  Continue anyway? [y/N] " -n 1 -r
  echo
  [[ ! $REPLY =~ ^[Yy]$ ]] && exit 0
fi

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

# ─── Patch PicoClaw Config ───────────────────────────────────────────────────
echo ""
echo "Patching PicoClaw config..."

PICOCLAW_DIR=""
for candidate in "$HOME/.picoclaw" "$HOME/picoclaw" "$HOME/.config/picoclaw"; do
  if [ -d "$candidate" ]; then
    PICOCLAW_DIR="$candidate"
    break
  fi
done

PROXY_HOST="${PROXY_HOST:-127.0.0.1}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ -n "$PICOCLAW_DIR" ] && [ -f "$PICOCLAW_DIR/config.json" ]; then
  cp "$PICOCLAW_DIR/config.json" "$PICOCLAW_DIR/config.json.bak.$(date +%s)"
  echo "  Backed up config.json"

  # Merge model entries using node
  node -e "
    const fs = require('fs');
    const config = JSON.parse(fs.readFileSync('$PICOCLAW_DIR/config.json', 'utf8'));
    const patch = JSON.parse(fs.readFileSync('$SCRIPT_DIR/config.patch.json', 'utf8'));

    // Update api_base if proxy is remote
    const proxyHost = '$PROXY_HOST';
    patch.models.forEach(m => {
      m.api_base = m.api_base.replace('127.0.0.1', proxyHost);
    });

    // Merge models into model_list (avoid duplicates)
    if (!config.model_list) config.model_list = [];
    const existingNames = new Set(config.model_list.map(m => m.model_name));
    for (const model of patch.models) {
      if (!existingNames.has(model.model_name)) {
        config.model_list.push(model);
      }
    }

    // Set default
    if (!config.agents) config.agents = {};
    if (!config.agents.defaults) config.agents.defaults = {};
    config.agents.defaults.model = patch.default_model;

    fs.writeFileSync('$PICOCLAW_DIR/config.json', JSON.stringify(config, null, 2) + '\n');
    console.log('  ✓ Merged ' + patch.models.length + ' Morpheus models into config');
  "
else
  echo "  ⚠ PicoClaw config not found."
  echo "    Run 'picoclaw onboard' first, then re-run this setup."
fi

# ─── Install Skill ───────────────────────────────────────────────────────────
if [ -n "$PICOCLAW_DIR" ]; then
  SKILL_DIR="$PICOCLAW_DIR/workspace/skills/enable-morpheus"
  mkdir -p "$SKILL_DIR"
  if [ -f "$SCRIPT_DIR/workspace/skills/enable-morpheus/SKILL.md" ]; then
    sed "s/127\.0\.0\.1/$PROXY_HOST/g" "$SCRIPT_DIR/workspace/skills/enable-morpheus/SKILL.md" > "$SKILL_DIR/SKILL.md"
    echo "✓ Installed enable-morpheus skill"
  fi
fi

# ─── Verify ──────────────────────────────────────────────────────────────────
echo ""
sleep 2
if curl -sf "http://${PROXY_HOST}:8083/health" >/dev/null 2>&1; then
  echo "✓ Proxy is healthy!"
else
  echo "⚠ Proxy not responding. Check: curl http://${PROXY_HOST}:8083/health"
fi

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "🎉 pico-everclaw installed!"
echo ""
echo "  Proxy:   http://${PROXY_HOST}:8083/v1"
echo "  Test:    picoclaw agent -m 'Hello from Morpheus'"
echo "  Health:  curl http://${PROXY_HOST}:8083/health"
echo ""
echo "  For unlimited P2P inference:"
echo "    cd ~/.everclaw && node scripts/everclaw-wallet.mjs setup"
echo "═══════════════════════════════════════════════════════════════"
