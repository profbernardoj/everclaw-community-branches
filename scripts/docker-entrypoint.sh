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

# ─── Template Placeholder Values ─────────────────────────────────────────────
# Resolve placeholder values from env vars with sensible defaults.
# These are substituted into boot templates during first-run scaffold.
TPL_AGENT_NAME="${EVERCLAW_AGENT_NAME:-EverClaw}"
TPL_AGENT_VIBE="${EVERCLAW_AGENT_VIBE:-Resourceful, direct, always shipping}"
TPL_USER_NAME="${EVERCLAW_USER_NAME:-User}"
TPL_USER_DISPLAY_NAME="${EVERCLAW_USER_DISPLAY_NAME:-$TPL_USER_NAME}"
TPL_USER_TIMEZONE="${TZ:-UTC}"
TPL_PROXY_PORT="${EVERCLAW_PROXY_PORT:-8083}"
TPL_DEFAULT_MODEL="${EVERCLAW_DEFAULT_MODEL:-glm-5}"

# Copy boot file templates if workspace is empty, substituting placeholders
for template in AGENTS SOUL USER IDENTITY HEARTBEAT TOOLS; do
  target="${WORKSPACE}/${template}.md"
  source="${SKILLS_DIR}/templates/boot/${template}.template.md"
  if [ ! -f "$target" ] && [ -f "$source" ]; then
    sed \
      -e "s|__AGENT_NAME__|${TPL_AGENT_NAME}|g" \
      -e "s|__AGENT_VIBE__|${TPL_AGENT_VIBE}|g" \
      -e "s|__USER_NAME__|${TPL_USER_NAME}|g" \
      -e "s|__USER_DISPLAY_NAME__|${TPL_USER_DISPLAY_NAME}|g" \
      -e "s|__USER_TIMEZONE__|${TPL_USER_TIMEZONE}|g" \
      -e "s|__MORPHEUS_PROXY_PORT__|${TPL_PROXY_PORT}|g" \
      -e "s|__DEFAULT_MODEL__|${TPL_DEFAULT_MODEL}|g" \
      "$source" > "$target"
    echo "   Scaffolded: ${template}.md"
  fi
done

# Create memory directory structure
mkdir -p "${WORKSPACE}/memory/daily"
mkdir -p "${WORKSPACE}/memory/goals"
mkdir -p "${WORKSPACE}/shifts"
mkdir -p "${WORKSPACE}/shifts/history"

# Create Morpheus directories to avoid ENOENT warnings on first run/shutdown
MORPHEUS_HOME="${HOME}/.morpheus"
mkdir -p "${MORPHEUS_HOME}"
# Placeholder files so proxy never warns about missing cookie/sessions
touch "${MORPHEUS_HOME}/.cookie" 2>/dev/null || true
touch "${MORPHEUS_HOME}/sessions.json" 2>/dev/null || true

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
  # Treat "none" the same as empty — gateway refuses to bind to LAN without auth,
  # so we must upgrade to token mode. Only "token" and "password" are real auth modes.
  CURRENT_MODE=$(jq -r '.gateway.auth.mode // empty' "$CONFIG_FILE" 2>/dev/null)

  if [ -z "$CURRENT_MODE" ] || [ "$CURRENT_MODE" = "none" ]; then
    # No auth mode set — inject full auth config + controlUi origins (safe merge)
    TMP_CONFIG=$(mktemp)
    if jq --arg token "$AUTH_TOKEN" --argjson dda "$DDA_VALUE" '
      .gateway.auth.mode = "token" |
      .gateway.auth.token = $token |
      .gateway.controlUi.enabled = (.gateway.controlUi.enabled // true) |
      .gateway.controlUi.dangerouslyDisableDeviceAuth = $dda |
      .gateway.controlUi.allowInsecureAuth = true |
      .gateway.controlUi.allowedOrigins = (
        if (.gateway.controlUi.allowedOrigins // [] | length) == 0
        then ["http://localhost:18789", "http://127.0.0.1:18789", "http://[::1]:18789"]
        else .gateway.controlUi.allowedOrigins end
      ) |
      .gateway.controlUi.dangerouslyAllowHostHeaderOriginFallback = (
        .gateway.controlUi.dangerouslyAllowHostHeaderOriginFallback // true
      )
    ' "$CONFIG_FILE" > "$TMP_CONFIG"; then
      mv "$TMP_CONFIG" "$CONFIG_FILE"
      echo "🔑 Auth token configured ($TOKEN_SOURCE)"
      echo "🔧 Auto-configured gateway.controlUi for container environment"
    else
      rm -f "$TMP_CONFIG"
      echo "⚠️  Failed to inject auth config — jq error"
    fi
  elif [ "$CURRENT_MODE" = "token" ] && [ -n "${OPENCLAW_GATEWAY_TOKEN:-}" ]; then
    # Auth mode is token and user provided env var override — update token + ensure origins
    TMP_CONFIG=$(mktemp)
    if jq --arg token "$AUTH_TOKEN" --argjson dda "$DDA_VALUE" '
      .gateway.auth.token = $token |
      .gateway.controlUi.dangerouslyDisableDeviceAuth = $dda |
      .gateway.controlUi.allowInsecureAuth = true |
      .gateway.controlUi.allowedOrigins = (
        if (.gateway.controlUi.allowedOrigins // []) | length > 0
        then .gateway.controlUi.allowedOrigins
        else ["http://localhost:18789", "http://127.0.0.1:18789", "http://[::1]:18789"]
        end
      ) |
      if (.gateway.controlUi.dangerouslyAllowHostHeaderOriginFallback // null) == null
      then .gateway.controlUi.dangerouslyAllowHostHeaderOriginFallback = true
      else .
      end
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

# ─── Config Verification: Ensure device auth bypass is set ───────────────────
# Defensive check: regardless of how the config was built, make sure DDA is true
# and allowInsecureAuth is true for container environments.

if jq . "$CONFIG_FILE" > /dev/null 2>&1; then
  DDA_CHECK=$(jq -r '.gateway.controlUi.dangerouslyDisableDeviceAuth // "false"' "$CONFIG_FILE" 2>/dev/null)
  AIA_CHECK=$(jq -r '.gateway.controlUi.allowInsecureAuth // "false"' "$CONFIG_FILE" 2>/dev/null)
  NEEDS_FIX=false

  if [ "$DDA_CHECK" != "true" ] || [ "$AIA_CHECK" != "true" ]; then
    NEEDS_FIX=true
  fi

  if [ "$NEEDS_FIX" = "true" ] && [ "${OPENCLAW_ENABLE_DEVICE_AUTH:-}" != "true" ]; then
    TMP_CONFIG=$(mktemp)
    if jq '
      .gateway.controlUi.dangerouslyDisableDeviceAuth = true |
      .gateway.controlUi.allowInsecureAuth = true
    ' "$CONFIG_FILE" > "$TMP_CONFIG"; then
      mv "$TMP_CONFIG" "$CONFIG_FILE"
      echo "🔧 Verified: device auth bypass enabled for container environment"
    else
      rm -f "$TMP_CONFIG"
      echo "⚠️  Config verification failed — device auth may not work over HTTP"
    fi
  fi
fi

# ─── API Key Injection: Morpheus Gateway + morpheus-local ────────────────────
# mor-gateway is a custom provider not in OpenClaw's PROVIDER_ENV_API_KEY_CANDIDATES,
# so env vars won't be auto-detected. We inject them into the config directly.
#
# Supported env vars:
#   MORPHEUS_GATEWAY_API_KEY  → mor-gateway provider apiKey (Morpheus API Gateway)
#   MORPHEUS_PROXY_API_KEY    → morpheus-local provider apiKey (local proxy-router)

if jq . "$CONFIG_FILE" > /dev/null 2>&1; then
  API_KEY_CHANGES=false

  # Morpheus API Gateway key (mor-gateway provider)
  if [ -n "${MORPHEUS_GATEWAY_API_KEY:-}" ]; then
    TMP_CONFIG=$(mktemp)
    if jq --arg key "$MORPHEUS_GATEWAY_API_KEY" '
      .models.providers["mor-gateway"].apiKey = $key
    ' "$CONFIG_FILE" > "$TMP_CONFIG"; then
      mv "$TMP_CONFIG" "$CONFIG_FILE"
      echo "🔑 Morpheus Gateway API key configured (mor-gateway)"
      API_KEY_CHANGES=true
    else
      rm -f "$TMP_CONFIG"
      echo "⚠️  Failed to inject Morpheus Gateway API key"
    fi
  fi

  # Local proxy-router key (morpheus-local provider)
  if [ -n "${MORPHEUS_PROXY_API_KEY:-}" ]; then
    TMP_CONFIG=$(mktemp)
    if jq --arg key "$MORPHEUS_PROXY_API_KEY" '
      .models.providers["morpheus-local"].apiKey = $key
    ' "$CONFIG_FILE" > "$TMP_CONFIG"; then
      mv "$TMP_CONFIG" "$CONFIG_FILE"
      echo "🔑 Morpheus proxy API key configured (morpheus-local)"
      API_KEY_CHANGES=true
    else
      rm -f "$TMP_CONFIG"
      echo "⚠️  Failed to inject Morpheus proxy API key"
    fi
  fi

  # Warn if no AI provider keys are configured at all
  if [ "$API_KEY_CHANGES" = "false" ]; then
    MG_KEY=$(jq -r '.models.providers["mor-gateway"].apiKey // empty' "$CONFIG_FILE" 2>/dev/null)
    ML_KEY=$(jq -r '.models.providers["morpheus-local"].apiKey // empty' "$CONFIG_FILE" 2>/dev/null)
    if [ -z "$MG_KEY" ] && [ -z "$ML_KEY" ]; then
      echo "⚠️  No AI provider API keys configured!"
      echo "   Set MORPHEUS_GATEWAY_API_KEY env var (get one free at https://app.mor.org)"
      echo "   Or set MORPHEUS_PROXY_API_KEY for local proxy-router"
    fi
  fi
fi

# ─── Config Compatibility: Streaming + Timeout ───────────────────────────────
# Ensure all model definitions have streaming=true and timeout is sufficient.
# Without streaming, OpenClaw waits for the complete response — Morpheus P2P
# provider discovery (30-120s) causes timeout before first token arrives.
# Since v2026.3.20.1625.

if jq . "$CONFIG_FILE" > /dev/null 2>&1; then
  COMPAT_CHANGES=false
  TMP_CONFIG=$(mktemp)

  if jq '
    # Remove any stale "streaming" from provider model definitions (invalid location)
    if .models.providers then
      .models.providers |= with_entries(
        .value.models = (
          if (.value.models | type) == "array" then
            [.value.models[] | del(.streaming)]
          else .value.models end
        )
      )
    else . end |
    # Enable streaming at the correct location: agents.defaults.models.<provider/id>
    if .models.providers then
      reduce (
        .models.providers | to_entries[] |
        select(.value.models | type == "array") |
        .key as $prov | .value.models[] | "\($prov)/\(.id)"
      ) as $mid (.;
        .agents.defaults.models[$mid].streaming = true
      )
    else . end |
    # Enforce minimum timeout for Morpheus Gateway
    if (.agents.defaults.timeoutSeconds // 0) < 180 then
      .agents.defaults.timeoutSeconds = 300
    else . end
  ' "$CONFIG_FILE" > "$TMP_CONFIG" 2>/dev/null; then
    # Check if anything actually changed
    if ! diff -q "$CONFIG_FILE" "$TMP_CONFIG" > /dev/null 2>&1; then
      mv "$TMP_CONFIG" "$CONFIG_FILE"
      echo "🔧 Auto-configured: streaming + timeout for Morpheus compatibility"
      COMPAT_CHANGES=true
    else
      rm -f "$TMP_CONFIG"
    fi
  else
    rm -f "$TMP_CONFIG"
  fi
fi

# ─── Smart Model Routing: Fix primary model if proxy isn't available ──────────
# If primary model points at morpheus-local/* but MORPHEUS_PROXY_API_KEY isn't set,
# the local proxy won't start and every request hits a dead endpoint → instant timeout.
# Swap primary to mor-gateway equivalent so users with only a Gateway API key work out of the box.

if jq . "$CONFIG_FILE" > /dev/null 2>&1; then
  CURRENT_PRIMARY=$(jq -r '.agents.defaults.model.primary // empty' "$CONFIG_FILE" 2>/dev/null)
  if [[ "$CURRENT_PRIMARY" == morpheus-local/* ]] && [ -z "${MORPHEUS_PROXY_API_KEY:-}" ]; then
    # Extract the model name (e.g., "glm-5" from "morpheus-local/glm-5")
    MODEL_NAME="${CURRENT_PRIMARY#morpheus-local/}"
    NEW_PRIMARY="mor-gateway/${MODEL_NAME}"
    TMP_CONFIG=$(mktemp)
    # Swap primary + any morpheus-local/* entries in fallbacks array
    if jq --arg old "$CURRENT_PRIMARY" --arg new "$NEW_PRIMARY" '
      .agents.defaults.model.primary = $new |
      .agents.defaults.model.fallbacks |= map(if . == $old then $new else . end)
    ' "$CONFIG_FILE" > "$TMP_CONFIG" 2>/dev/null; then
      mv "$TMP_CONFIG" "$CONFIG_FILE"
      echo "🔄 Primary model: ${CURRENT_PRIMARY} → ${NEW_PRIMARY} (local proxy not configured)"
    else
      rm -f "$TMP_CONFIG"
    fi
  fi
fi

# ─── Start Morpheus Proxy (background, only if configured) ──────────────────

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

if [ -f "$PROXY_SCRIPT" ] && [ -n "${MORPHEUS_PROXY_API_KEY:-}" ]; then
  echo "🚀 Starting Morpheus proxy on port ${EVERCLAW_PROXY_PORT:-8083}..."
  node "$PROXY_SCRIPT" &
  PROXY_PID=$!
elif [ -f "$PROXY_SCRIPT" ] && [ -z "${MORPHEUS_PROXY_API_KEY:-}" ]; then
  echo "ℹ️  Morpheus local proxy skipped (MORPHEUS_PROXY_API_KEY not set)"
  echo "   Using Morpheus API Gateway (mor-gateway) for inference"
  echo "   This is the recommended setup for gateway-only installs."
  PROXY_PID=""
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
GATEWAY_ALIVE=true
GATEWAY_HEALTHY=false

while [ $HEALTH_ATTEMPTS -lt $MAX_ATTEMPTS ]; do
  if curl -sf http://127.0.0.1:18789/health > /dev/null 2>&1; then
    GATEWAY_HEALTHY=true
    break
  fi
  if ! kill -0 "$GATEWAY_PID" 2>/dev/null; then
    echo "⚠️  Gateway process exited unexpectedly"
    GATEWAY_ALIVE=false
    break
  fi
  HEALTH_ATTEMPTS=$((HEALTH_ATTEMPTS + 1))
  sleep 1
done

if [ "$GATEWAY_HEALTHY" = "true" ]; then
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
elif [ "$GATEWAY_ALIVE" = "false" ]; then
  echo ""
  echo "╔══════════════════════════════════════════════════════════════════╗"
  echo "║  ❌ EverClaw failed to start                                    ║"
  echo "║                                                                 ║"
  echo "║  The OpenClaw gateway crashed during startup.                   ║"
  echo "║  Check the error message above for details.                     ║"
  echo "║                                                                 ║"
  echo "║  Quick fixes to try:                                            ║"
  echo "║  1. Delete config and restart (auto-regenerates):               ║"
  echo "║     rm ~/.openclaw/openclaw.json && docker restart everclaw     ║"
  echo "║  2. Check gateway.controlUi.allowedOrigins is set              ║"
  echo "║  3. Report at github.com/everclaw with docker logs             ║"
  echo "╚══════════════════════════════════════════════════════════════════╝"
  echo ""
  echo "   Config: ${CONFIG_FILE}"
  echo "   Logs:   docker logs everclaw"
  echo ""
  exit 1
else
  echo ""
  echo "⚠️  Gateway did not respond within ${MAX_ATTEMPTS}s"
  echo "   URL: ${DASHBOARD_URL}"
  echo "   Check logs: docker logs everclaw"
  echo ""
fi

# Block on gateway process (container lifecycle tied to gateway)
if [ "$GATEWAY_ALIVE" = "true" ]; then
  wait $GATEWAY_PID
fi
