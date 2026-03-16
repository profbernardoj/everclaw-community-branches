#!/bin/bash
# EverClaw Docker Entrypoint
#
# Starts both OpenClaw gateway and Morpheus proxy.
# Handles first-run scaffolding, auth token injection, and health-gated startup.
#
# Auth layers:
#   1. Token auto-inject: OPENCLAW_GATEWAY_TOKEN env → existing config → auto-generate
#   2. Disable device auth for Docker bridge network (opt-out: OPENCLAW_ENABLE_DEVICE_AUTH=true)
#   3. Health-gated startup: poll /health before printing dashboard URL

set -e

OPENCLAW_HOME="${HOME}/.openclaw"
WORKSPACE="${OPENCLAW_HOME}/workspace"
SKILLS_DIR="${WORKSPACE}/skills/everclaw"
CONFIG_FILE="${OPENCLAW_HOME}/openclaw.json"
DEFAULT_CONFIG="${OPENCLAW_HOME}/openclaw-default.json"

GATEWAY_PID=""
PROXY_PID=""

# ─── First Run: Scaffold workspace ──────────────────────────────────────────

OPENCLAW_VER=$(node -e "try{console.log(require('/app/package.json').version)}catch{console.log('unknown')}" 2>/dev/null)
echo "🔧 EverClaw v${EVERCLAW_VERSION:-unknown} (OpenClaw v${OPENCLAW_VER}) starting..."

# Copy default config if none exists
if [ ! -f "$CONFIG_FILE" ]; then
  echo "📝 First run — creating default OpenClaw config..."
  cp "$DEFAULT_CONFIG" "$CONFIG_FILE"
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

# ─── Auth Setup: Auto-inject token + disable device auth ────────────────────

# Validate config is valid JSON before modifying
if ! jq . "$CONFIG_FILE" > /dev/null 2>&1; then
  echo "⚠️  Config file is malformed JSON — skipping auth injection"
  echo "   Fix $CONFIG_FILE manually or delete it to regenerate on next start"
  AUTH_TOKEN=""
  TOKEN_SOURCE="none (malformed config)"
else

  # Determine auth token: env var > existing config > auto-generate
  AUTH_TOKEN=""
  TOKEN_SOURCE=""

  if [ -n "${OPENCLAW_GATEWAY_TOKEN:-}" ]; then
    AUTH_TOKEN="$OPENCLAW_GATEWAY_TOKEN"
    TOKEN_SOURCE="environment variable"
  elif [ -f "$CONFIG_FILE" ]; then
    EXISTING_TOKEN=$(jq -r '.gateway.auth.token // empty' "$CONFIG_FILE" 2>/dev/null)
    if [ -n "$EXISTING_TOKEN" ]; then
      AUTH_TOKEN="$EXISTING_TOKEN"
      TOKEN_SOURCE="existing config"
    fi
  fi

  if [ -z "$AUTH_TOKEN" ]; then
    AUTH_TOKEN=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' | head -c 64)
    TOKEN_SOURCE="auto-generated"
    # Fallback if od fails
    if [ -z "$AUTH_TOKEN" ]; then
      AUTH_TOKEN="everclaw-$(date +%s)-$(head -c 8 /dev/urandom | od -An -tu4 | tr -d ' ')"
      TOKEN_SOURCE="fallback-generated"
    fi
  fi

  # Compute device auth setting once (respects OPENCLAW_ENABLE_DEVICE_AUTH in all paths)
  if [ "${OPENCLAW_ENABLE_DEVICE_AUTH:-}" = "true" ]; then
    DDA_VALUE=false
  else
    DDA_VALUE=true
  fi

  # Check if gateway.auth.mode is already explicitly configured
  CURRENT_MODE=$(jq -r '.gateway.auth.mode // empty' "$CONFIG_FILE" 2>/dev/null)

  if [ -z "$CURRENT_MODE" ]; then
    # No auth mode set — inject full auth config
    TMP_CONFIG=$(mktemp)
    if jq --arg token "$AUTH_TOKEN" --argjson dda "$DDA_VALUE" '
      .gateway.auth.mode = "token" |
      .gateway.auth.token = $token |
      .gateway.controlUi.enabled = true |
      .gateway.controlUi.dangerouslyDisableDeviceAuth = $dda
    ' "$CONFIG_FILE" > "$TMP_CONFIG"; then
      mv "$TMP_CONFIG" "$CONFIG_FILE"
      echo "🔑 Auth token configured ($TOKEN_SOURCE)"
    else
      rm -f "$TMP_CONFIG"
      echo "⚠️  Failed to inject auth config — jq error"
    fi
  elif [ "$CURRENT_MODE" = "token" ] && [ -n "${OPENCLAW_GATEWAY_TOKEN:-}" ]; then
    # Auth mode is token and user provided env var override — update token
    TMP_CONFIG=$(mktemp)
    if jq --arg token "$AUTH_TOKEN" --argjson dda "$DDA_VALUE" '
      .gateway.auth.token = $token |
      .gateway.controlUi.dangerouslyDisableDeviceAuth = $dda
    ' "$CONFIG_FILE" > "$TMP_CONFIG"; then
      mv "$TMP_CONFIG" "$CONFIG_FILE"
      echo "🔑 Auth token updated from environment variable"
    else
      rm -f "$TMP_CONFIG"
      echo "⚠️  Failed to update auth token — jq error"
    fi
  else
    # User has their own auth config — respect it
    echo "🔑 Using existing auth config (mode: $CURRENT_MODE)"
    # Still need a token for the dashboard URL if mode is token
    if [ "$CURRENT_MODE" = "token" ]; then
      AUTH_TOKEN=$(jq -r '.gateway.auth.token // empty' "$CONFIG_FILE" 2>/dev/null)
    fi
  fi

  # Ensure dangerouslyDisableDeviceAuth is set for non-initial configs too
  # (covers case where user has auth mode but DDA wasn't set yet)
  if [ -n "$CURRENT_MODE" ] && [ "$CURRENT_MODE" != "none" ]; then
    CURRENT_DDA=$(jq -r '.gateway.controlUi.dangerouslyDisableDeviceAuth // empty' "$CONFIG_FILE" 2>/dev/null)
    if [ "$CURRENT_DDA" != "$(echo $DDA_VALUE)" ]; then
      TMP_CONFIG=$(mktemp)
      if jq --argjson dda "$DDA_VALUE" '.gateway.controlUi.dangerouslyDisableDeviceAuth = $dda' "$CONFIG_FILE" > "$TMP_CONFIG"; then
        mv "$TMP_CONFIG" "$CONFIG_FILE"
      else
        rm -f "$TMP_CONFIG"
      fi
    fi
  fi

fi

# Build dashboard URL
if [ -n "$AUTH_TOKEN" ]; then
  DASHBOARD_URL="http://localhost:18789/#token=${AUTH_TOKEN}"
else
  DASHBOARD_URL="http://localhost:18789"
fi

echo ""

# ─── Start Morpheus Proxy (background) ──────────────────────────────────────

# Trap signals to clean up all children on exit
cleanup() {
  echo ""
  echo "🛑 Shutting down..."
  if [ -n "${GATEWAY_PID:-}" ]; then
    kill "$GATEWAY_PID" 2>/dev/null || true
    wait "$GATEWAY_PID" 2>/dev/null || true
    echo "   OpenClaw gateway stopped"
  fi
  if [ -n "${PROXY_PID:-}" ]; then
    kill "$PROXY_PID" 2>/dev/null || true
    wait "$PROXY_PID" 2>/dev/null || true
    echo "   Morpheus proxy stopped"
  fi
  echo "   Done"
}
trap cleanup EXIT INT TERM

PROXY_SCRIPT="${SKILLS_DIR}/scripts/morpheus-proxy.mjs"

if [ -f "$PROXY_SCRIPT" ]; then
  echo "🚀 Starting Morpheus proxy on port ${EVERCLAW_PROXY_PORT:-8083}..."
  node "$PROXY_SCRIPT" &
  PROXY_PID=$!
else
  echo "⚠️  Morpheus proxy script not found at $PROXY_SCRIPT"
  echo "   Skipping proxy — OpenClaw will use API Gateway providers only"
  PROXY_PID=""
fi

# ─── Start OpenClaw Gateway ─────────────────────────────────────────────────

node /app/openclaw.mjs gateway --allow-unconfigured --bind lan &
GATEWAY_PID=$!

# ─── Health Gate: Wait for gateway readiness ─────────────────────────────────

echo "⏳ Waiting for gateway..."
HEALTH_ATTEMPTS=0
MAX_ATTEMPTS=60
while [ $HEALTH_ATTEMPTS -lt $MAX_ATTEMPTS ]; do
  if curl -sf http://127.0.0.1:18789/health > /dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$GATEWAY_PID" 2>/dev/null; then
    echo "⚠️  Gateway process exited unexpectedly"
    break
  fi
  HEALTH_ATTEMPTS=$((HEALTH_ATTEMPTS + 1))
  sleep 1
done

if [ $HEALTH_ATTEMPTS -lt $MAX_ATTEMPTS ]; then
  echo ""
  echo "╔══════════════════════════════════════════════════════════════════╗"
  echo "║  ✅ EverClaw is ready!                                          ║"
  echo "║                                                                 ║"
  echo "║  Dashboard:  ${DASHBOARD_URL}"
  echo "║  Proxy:      http://localhost:${EVERCLAW_PROXY_PORT:-8083}/v1"
  echo "║                                                                 ║"
  echo "║  Auth token: ${AUTH_TOKEN}"
  echo "║  Token from: ${TOKEN_SOURCE}"
  echo "╚══════════════════════════════════════════════════════════════════╝"
  echo ""
  echo "💡 Bookmark the Dashboard URL — it includes your auth token."
  echo "⚠️  For local use only. Do not expose to the internet without"
  echo "   additional authentication (reverse proxy, VPN, etc)."
  echo ""
else
  echo ""
  echo "⚠️  Gateway did not respond within ${MAX_ATTEMPTS}s"
  echo "   URL: ${DASHBOARD_URL}"
  echo "   Check logs: docker logs everclaw"
  echo ""
fi

# Block on gateway process (container lifecycle tied to gateway)
wait $GATEWAY_PID
