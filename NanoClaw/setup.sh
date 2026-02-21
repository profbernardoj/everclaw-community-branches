#!/bin/bash
# nano-everclaw setup — installs EverClaw proxy + NanoClaw skill
set -euo pipefail

echo "🚀 Installing nano-everclaw (EverClaw proxy + NanoClaw integration)"
echo ""

# ─── OS Detection ────────────────────────────────────────────────────────────
OS="$(uname -s)"
ARCH="$(uname -m)"
echo "Platform: $OS / $ARCH"

# ─── Docker Host Address ─────────────────────────────────────────────────────
# NanoClaw runs in Docker — determine how containers reach the host
detect_docker_host() {
  case "$OS" in
    Darwin|MINGW*|MSYS*)
      # macOS / Windows: Docker Desktop provides this alias
      echo "host.docker.internal"
      ;;
    Linux)
      # Try docker0 bridge first
      local bridge_ip
      bridge_ip=$(ip -4 addr show docker0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || true)
      if [ -n "$bridge_ip" ]; then
        echo "$bridge_ip"
      else
        # Fallback: standard Docker bridge gateway
        echo "172.17.0.1"
      fi
      ;;
    *)
      echo "172.17.0.1"
      ;;
  esac
}

DOCKER_HOST_ADDR=$(detect_docker_host)
echo "Docker host address: $DOCKER_HOST_ADDR"

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

NODE_MAJOR=$(node -v | cut -d. -f1 | tr -d 'v')
if [ "$NODE_MAJOR" -lt 18 ]; then
  echo "❌ Node.js 18+ required (found $(node -v))"
  exit 1
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

# Start services
[ -f scripts/install-proxy.sh ] && bash scripts/install-proxy.sh
[ -f scripts/start.sh ] && bash scripts/start.sh

echo "✓ EverClaw proxy running on port 8083"

# ─── Create NanoClaw Skill ───────────────────────────────────────────────────
echo ""
echo "Creating NanoClaw skill..."

# Auto-detect NanoClaw directory
NANOCLAW_DIR=""
for candidate in "$HOME/nanoclaw" "$HOME/NanoClaw" "$HOME/.nanoclaw"; do
  if [ -d "$candidate" ]; then
    NANOCLAW_DIR="$candidate"
    break
  fi
done

if [ -z "$NANOCLAW_DIR" ]; then
  NANOCLAW_DIR="$HOME/nanoclaw"
  echo "  ⚠ NanoClaw directory not found. Skill will be created at $NANOCLAW_DIR/.claude/skills/add-morpheus/"
  echo "  Move it to your actual NanoClaw directory if different."
fi

SKILL_DIR="$NANOCLAW_DIR/.claude/skills/add-morpheus"
mkdir -p "$SKILL_DIR"

cat > "$SKILL_DIR/SKILL.md" << SKILLEOF
# Add Morpheus — Decentralized Inference for NanoClaw

## What This Does

Connects NanoClaw to the EverClaw proxy for decentralized AI inference via the Morpheus network.
The proxy runs on the host at \`http://${DOCKER_HOST_ADDR}:8083/v1\`.

## When To Use

Use \`/add-morpheus\` to:
- Enable hybrid mode (Claude + Morpheus)
- Check proxy health
- Switch default model

## Configuration

Add these environment variables to the NanoClaw container:

\`\`\`env
MORPHEUS_API_BASE=http://${DOCKER_HOST_ADDR}:8083/v1
MORPHEUS_API_KEY=morpheus-local
MORPHEUS_DEFAULT_MODEL=glm-5
\`\`\`

## Available Models

- \`glm-5\` — Heavy reasoning, coding, analysis (default)
- \`glm-4.7-flash\` — Fast, lightweight tasks
- \`kimi-k2.5\` — General purpose
- \`qwen3-235b\` — Large context, multilingual

## Docker Networking

This NanoClaw installation reaches the host proxy at: \`${DOCKER_HOST_ADDR}:8083\`

If the proxy is unreachable from inside the container, check:
1. Proxy is running: \`curl http://127.0.0.1:8083/health\` (from host)
2. Docker network mode allows host access
3. Firewall isn't blocking port 8083

## Health Check

\`\`\`bash
curl -sf http://${DOCKER_HOST_ADDR}:8083/health
\`\`\`

## Staking for Unlimited Inference

\`\`\`bash
cd ~/.everclaw
node scripts/everclaw-wallet.mjs setup
node scripts/everclaw-wallet.mjs stake
\`\`\`

MOR tokens are staked, not spent — returned when sessions close.
SKILLEOF

echo "✓ Skill created at $SKILL_DIR/SKILL.md"

# ─── Create Anthropic→OpenAI Bridge Config ───────────────────────────────────
echo ""
echo "Creating lite-proxy config..."

LITE_PROXY_DIR="$EVERCLAW_DIR/lite-proxy"
mkdir -p "$LITE_PROXY_DIR"

# The lite-proxy config for NanoClaw
cat > "$LITE_PROXY_DIR/config.json" << CONFEOF
{
  "listen": "127.0.0.1:8084",
  "upstream": "http://127.0.0.1:8083/v1",
  "modelMap": {
    "claude-3.5-sonnet": "glm-5",
    "claude-3-haiku": "glm-4.7-flash",
    "claude-3-opus": "glm-5",
    "claude-sonnet-4": "glm-5",
    "claude-haiku-4": "glm-4.7-flash"
  },
  "dockerHost": "${DOCKER_HOST_ADDR}"
}
CONFEOF

echo "✓ Lite-proxy config at $LITE_PROXY_DIR/config.json"

# ─── Verify ──────────────────────────────────────────────────────────────────
echo ""
echo "Verifying..."
sleep 2

if curl -sf http://127.0.0.1:8083/health >/dev/null 2>&1; then
  echo "✓ EverClaw proxy is healthy!"
else
  echo "⚠ Proxy not responding yet — may need a few seconds."
  echo "  Check: curl http://127.0.0.1:8083/health"
fi

# ─── Done ────────────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "🎉 nano-everclaw installed!"
echo ""
echo "  Proxy:        http://127.0.0.1:8083/v1 (host)"
echo "  From Docker:  http://${DOCKER_HOST_ADDR}:8083/v1"
echo "  Skill:        $SKILL_DIR/SKILL.md"
echo ""
echo "  Next steps:"
echo "    1. cd $NANOCLAW_DIR && claude"
echo "    2. /add-morpheus"
echo "    3. Restart NanoClaw"
echo ""
echo "  For unlimited P2P inference, stake MOR:"
echo "    cd ~/.everclaw && node scripts/everclaw-wallet.mjs setup"
echo "═══════════════════════════════════════════════════════════════"
