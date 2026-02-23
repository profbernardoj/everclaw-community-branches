#!/bin/bash
# EverClaw Docker Entrypoint
#
# Starts both OpenClaw gateway and Morpheus proxy.
# Handles first-run scaffolding (boot templates, default config).

set -e

OPENCLAW_HOME="${HOME}/.openclaw"
WORKSPACE="${OPENCLAW_HOME}/workspace"
SKILLS_DIR="${WORKSPACE}/skills/everclaw"
CONFIG_FILE="${OPENCLAW_HOME}/openclaw.json"
DEFAULT_CONFIG="${OPENCLAW_HOME}/openclaw-default.json"

# ─── First Run: Scaffold workspace ──────────────────────────────────────────

echo "🔧 EverClaw v${EVERCLAW_VERSION:-unknown} — Full Stack Container"
echo "   OpenClaw Gateway: http://0.0.0.0:18789"
echo "   Morpheus Proxy:   http://0.0.0.0:${EVERCLAW_PROXY_PORT:-8083}"
echo ""

# Copy default config if none exists
if [ ! -f "$CONFIG_FILE" ]; then
  echo "📝 First run — creating default OpenClaw config..."
  
  # Substitute env vars into default config
  if [ -n "$MOR_GATEWAY_API_KEY" ]; then
    sed "s/\${MOR_GATEWAY_API_KEY:-}/$MOR_GATEWAY_API_KEY/g" "$DEFAULT_CONFIG" > "$CONFIG_FILE"
  else
    sed 's/\${MOR_GATEWAY_API_KEY:-}//g' "$DEFAULT_CONFIG" > "$CONFIG_FILE"
  fi
  
  echo "   Config: $CONFIG_FILE"
fi

# Copy boot file templates if workspace is empty
for template in AGENTS SOUL USER IDENTITY HEARTBEAT TOOLS; do
  target="${WORKSPACE}/${template}.md"
  source="${SKILLS_DIR}/templates/boot/${template}.template.md"
  if [ ! -f "$target" ] && [ -f "$source" ]; then
    cp "$source" "$target"
    echo "   Scaffolded: ${template}.md"
  fi
done

# Create memory directory structure
mkdir -p "${WORKSPACE}/memory/daily"
mkdir -p "${WORKSPACE}/memory/goals"
mkdir -p "${WORKSPACE}/shifts"
mkdir -p "${WORKSPACE}/shifts/history"

# Copy shift templates if needed
for f in state.json context.md handoff.md tasks.md; do
  target="${WORKSPACE}/shifts/$f"
  source="${SKILLS_DIR}/three-shifts/templates/$f"
  if [ ! -f "$target" ] && [ -f "$source" ]; then
    cp "$source" "$target"
    echo "   Scaffolded: shifts/$f"
  fi
done

echo ""

# ─── Start Morpheus Proxy (background) ──────────────────────────────────────

PROXY_SCRIPT="${SKILLS_DIR}/scripts/morpheus-proxy.mjs"

if [ -f "$PROXY_SCRIPT" ]; then
  echo "🚀 Starting Morpheus proxy on port ${EVERCLAW_PROXY_PORT:-8083}..."
  node "$PROXY_SCRIPT" &
  PROXY_PID=$!
  echo "   PID: $PROXY_PID"
else
  echo "⚠️  Morpheus proxy script not found at $PROXY_SCRIPT"
  echo "   Skipping proxy — OpenClaw will use API Gateway providers only"
  PROXY_PID=""
fi

echo ""

# ─── Start OpenClaw Gateway (foreground) ─────────────────────────────────────

echo "🚀 Starting OpenClaw Gateway on port 18789..."
echo "   Open http://localhost:18789 in your browser"
echo ""

# Trap signals to clean up proxy on exit
cleanup() {
  echo ""
  echo "🛑 Shutting down..."
  if [ -n "$PROXY_PID" ]; then
    kill "$PROXY_PID" 2>/dev/null || true
    wait "$PROXY_PID" 2>/dev/null || true
    echo "   Morpheus proxy stopped"
  fi
  echo "   Done"
}
trap cleanup EXIT INT TERM

# Start gateway in foreground — bind to LAN so Docker port mapping works
exec node /app/openclaw.mjs gateway --allow-unconfigured --bind lan
