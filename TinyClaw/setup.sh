#!/bin/bash
# tiny-everclaw setup — installs EverClaw proxy + TinyClaw config
set -euo pipefail

echo "🚀 Installing tiny-everclaw (EverClaw proxy + TinyClaw integration)"
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
  echo "✓ EverClaw already installed at $EVERCLAW_DIR"
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

# ─── Patch TinyClaw Settings ─────────────────────────────────────────────────
echo ""
echo "Patching TinyClaw settings..."

TINYCLAW_DIR=""
for candidate in "$HOME/.tinyclaw" "$HOME/tinyclaw" "$HOME/.config/tinyclaw"; do
  if [ -d "$candidate" ]; then
    TINYCLAW_DIR="$candidate"
    break
  fi
done

if [ -n "$TINYCLAW_DIR" ] && [ -f "$TINYCLAW_DIR/settings.json" ]; then
  # Backup
  cp "$TINYCLAW_DIR/settings.json" "$TINYCLAW_DIR/settings.json.bak.$(date +%s)"
  echo "  Backed up settings.json"

  # Merge patch using node (safe JSON merge)
  SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
  node -e "
    const fs = require('fs');
    const settings = JSON.parse(fs.readFileSync('$TINYCLAW_DIR/settings.json', 'utf8'));
    const patch = JSON.parse(fs.readFileSync('$SCRIPT_DIR/settings.patch.json', 'utf8'));
    delete patch._comment;

    // Deep merge agents
    settings.agents = { ...settings.agents, ...patch.agents };
    settings.default_provider = patch.default_provider;
    settings.default_model = patch.default_model;

    fs.writeFileSync('$TINYCLAW_DIR/settings.json', JSON.stringify(settings, null, 2) + '\n');
    console.log('  ✓ Merged Morpheus config into settings.json');
  "
else
  echo "  ⚠ TinyClaw settings.json not found."
  echo "    Run 'tinyclaw start' first, then re-run this setup."
  echo "    Or manually merge settings.patch.json into your config."
fi

# ─── Export Environment Variables ─────────────────────────────────────────────
echo ""
echo "Adding environment variables..."

ENV_BLOCK='
# tiny-everclaw: Morpheus proxy for TinyClaw
export OPENAI_BASE_URL=http://127.0.0.1:8083/v1
export OPENAI_API_KEY=morpheus-local'

add_env() {
  local rcfile="$1"
  if [ -f "$rcfile" ]; then
    if ! grep -q "tiny-everclaw" "$rcfile" 2>/dev/null; then
      echo "$ENV_BLOCK" >> "$rcfile"
      echo "  ✓ Added env vars to $rcfile"
      return 0
    else
      echo "  ✓ Env vars already in $rcfile"
      return 0
    fi
  fi
  return 1
}

add_env "$HOME/.zshrc" || add_env "$HOME/.bashrc" || echo "  ⚠ Add manually: export OPENAI_BASE_URL=http://127.0.0.1:8083/v1"

# ─── Install TinyClaw Skill ──────────────────────────────────────────────────
echo ""
if [ -n "$TINYCLAW_DIR" ]; then
  SKILL_DIR="$TINYCLAW_DIR/workspace/skills/enable-morpheus"
  mkdir -p "$SKILL_DIR"
  SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
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
  echo "⚠ Proxy not responding yet. Check: curl http://127.0.0.1:8083/health"
fi

# ─── Done ────────────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "🎉 tiny-everclaw installed!"
echo ""
echo "  Reload shell:  source ~/.zshrc  (or ~/.bashrc)"
echo "  Start:         tinyclaw start"
echo "  In any channel: /enable-morpheus"
echo "  Health:        curl http://127.0.0.1:8083/health"
echo ""
echo "  For unlimited P2P inference:"
echo "    cd ~/.everclaw && node scripts/everclaw-wallet.mjs setup"
echo "═══════════════════════════════════════════════════════════════"
