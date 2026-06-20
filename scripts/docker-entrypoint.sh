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
DEFAULT_CONFIG="/opt/everclaw/defaults/openclaw-default.json"

GATEWAY_PID=""
PROXY_PID=""
FIRST_RUN_MARKER="${OPENCLAW_HOME}/.first-run-complete"

# ─── First Run: Scaffold workspace ──────────────────────────────────────────

OPENCLAW_VER=$(node -e "try{console.log(require('/app/package.json').version)}catch{console.log('unknown')}" 2>/dev/null)
echo "🔧 EverClaw v${EVERCLAW_VERSION:-unknown} (OpenClaw v${OPENCLAW_VER}) starting..."

# Copy default config if none exists
if [ ! -f "$CONFIG_FILE" ]; then
  echo "📝 First run — creating default OpenClaw config..."
  cp "$DEFAULT_CONFIG" "$CONFIG_FILE"
  echo "   Config: $CONFIG_FILE"
fi

# Defensive strip of underscore-prefixed comment keys (OpenClaw schema is strict)
# Prevents config validation failures from _note, _comment, _morpheusNote, etc.
if [ -f "$CONFIG_FILE" ] && jq . "$CONFIG_FILE" > /dev/null 2>&1; then
  TMP_STRIP=$(mktemp)
  if jq 'walk(if type == "object" then with_entries(select(.key | startswith("_") | not)) else . end)' "$CONFIG_FILE" > "$TMP_STRIP" 2>/dev/null; then
    if ! diff -q "$CONFIG_FILE" "$TMP_STRIP" > /dev/null 2>&1; then
      mv "$TMP_STRIP" "$CONFIG_FILE"
      echo "🔧 Stripped comment keys from config (OpenClaw schema compliance)"
    else
      rm -f "$TMP_STRIP"
    fi
  else
    rm -f "$TMP_STRIP"
  fi
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
TPL_DEFAULT_MODEL="${EVERCLAW_DEFAULT_MODEL:-glm-5.1}"

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
# NOTE: When all three Privy env vars are set (PRIVY_APP_ID, PRIVY_VERIFICATION_KEY,
# OPENCLAW_OWNER_PRIVY_ID), the auth proxy handles authentication via trusted-proxy mode.
# Token auth is skipped in that case to avoid OpenClaw's mixed token/trusted-proxy rejection.
# The actual trusted-proxy config is injected later, just before starting the auth proxy.

PRIVY_AUTH_CONFIGURED=false
if [ -n "${PRIVY_APP_ID:-}" ] && [ -n "${PRIVY_VERIFICATION_KEY:-}" ] && [ -n "${OPENCLAW_OWNER_PRIVY_ID:-}" ]; then
  PRIVY_AUTH_CONFIGURED=true
fi

# Validate config is valid JSON before modifying
if ! jq . "$CONFIG_FILE" > /dev/null 2>&1; then
  echo "⚠️  Config file is malformed JSON — skipping auth injection"
  echo "   Fix $CONFIG_FILE manually or delete it to regenerate on next start"
  AUTH_TOKEN=""
  TOKEN_SOURCE="none (malformed config)"
elif [ "$PRIVY_AUTH_CONFIGURED" = "true" ]; then
  # Privy auth proxy mode — skip token auth entirely
  # trusted-proxy mode config will be injected before starting the auth proxy
  AUTH_TOKEN=""
  TOKEN_SOURCE="privy-auth-proxy (no token needed)"
  echo "🔒 Privy auth detected — skipping token auth (trusted-proxy mode)"
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

# ─── CIG Mode: Route inference through auth-proxy ────────────────────────────
# When CIG (Central Inference Gateway) env vars are set, the auth-proxy intercepts
# /v1/chat/completions and routes through the CIG, which holds the master Morpheus key.
# We redirect mor-gateway's baseUrl to localhost:18789 (auth-proxy) instead of the
# external Morpheus API. The auth-proxy mints CIG tokens using the binding_secret.
#
# CIG env vars (required for CIG mode):
#   CIG_MINT_URL        → mint-cig-token endpoint URL (required)
#   CIG_BINDING_SECRET  → Per-container binding secret (required)
#   CIG_INFERENCE_URL   → cig-inference endpoint URL (required)
#   CIG_CONTAINER_FQDN  → This container's public FQDN (used by auth-proxy, not checked here)

CIG_ENABLED=false
if [ -n "${CIG_MINT_URL:-}" ] && [ -n "${CIG_BINDING_SECRET:-}" ] && [ -n "${CIG_INFERENCE_URL:-}" ]; then
  CIG_ENABLED=true
  echo "🔐 CIG mode detected — routing inference through auth-proxy"
fi

if [ "$CIG_ENABLED" = "true" ] && jq . "$CONFIG_FILE" > /dev/null 2>&1; then
  # In CIG mode, redirect mor-gateway to localhost:18789 (auth-proxy)
  # The auth-proxy intercepts /v1/chat/completions and handles CIG token minting
  TMP_CONFIG=$(mktemp)
  if jq '
    .models.providers["mor-gateway"].baseUrl = "http://localhost:18789/v1" |
    .models.providers["mor-gateway"].apiKey = "cig-proxy-mode"
  ' "$CONFIG_FILE" > "$TMP_CONFIG"; then
    mv "$TMP_CONFIG" "$CONFIG_FILE"
    echo "   mor-gateway baseUrl → http://localhost:18789/v1 (auth-proxy intercept)"
    echo "   CIG will mint tokens using binding_secret and forward to Morpheus"
  else
    rm -f "$TMP_CONFIG"
    echo "⚠️  Failed to configure CIG mode for mor-gateway"
  fi
fi

# ─── API Key Injection: Morpheus Gateway + morpheus-local ────────────────────
# mor-gateway is a custom provider not in OpenClaw's PROVIDER_ENV_API_KEY_CANDIDATES,
# so env vars won't be auto-detected. We inject them into the config directly.
#
# Supported env vars:
#   MORPHEUS_GATEWAY_API_KEY  → mor-gateway provider apiKey (Morpheus API Gateway)
#   MORPHEUS_PROXY_API_KEY    → morpheus-local provider apiKey (local proxy-router)
#
# Note: In CIG mode, these are ignored — CIG routing takes precedence.

if jq . "$CONFIG_FILE" > /dev/null 2>&1; then
  API_KEY_CHANGES=false

  # Morpheus API Gateway key (mor-gateway provider) — skip if CIG mode
  if [ -n "${MORPHEUS_GATEWAY_API_KEY:-}" ] && [ "$CIG_ENABLED" != "true" ]; then
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

  # Warn if no AI provider keys are configured at all (skip warning if CIG mode)
  if [ "$API_KEY_CHANGES" = "false" ] && [ "$CIG_ENABLED" != "true" ]; then
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

# ─── Per-Tier Default Model Override ─────────────────────────────────────────
# When EVERCLAW_DEFAULT_MODEL is explicitly set (e.g., by provision-buffer for
# free-tier containers), override the primary model in openclaw.json.
# This ensures free-tier containers use deepseek-v4-flash (which CIG allows)
# instead of glm-5.1 (which gets 403'd for free tier).

if [ -n "${EVERCLAW_DEFAULT_MODEL:-}" ] && jq . "$CONFIG_FILE" > /dev/null 2>&1; then
  DESIRED_PRIMARY="mor-gateway/${EVERCLAW_DEFAULT_MODEL}"
  CURRENT_PRIMARY=$(jq -r '.agents.defaults.model.primary // empty' "$CONFIG_FILE" 2>/dev/null)
  if [ "$CURRENT_PRIMARY" != "$DESIRED_PRIMARY" ]; then
    TMP_CONFIG=$(mktemp)
    if jq --arg new "$DESIRED_PRIMARY" --arg old "$CURRENT_PRIMARY" '
      # Ensure agents.defaults.model structure exists
      .agents.defaults.model.fallbacks //= [] |
      # Move old primary to front of fallbacks (skip if empty/null)
      .agents.defaults.model.fallbacks = (
        [if ($old | length) > 0 then $old else empty end] +
        [.agents.defaults.model.fallbacks[] | select(. != null and . != "" and . != $old and . != $new)]
      ) |
      .agents.defaults.model.primary = $new
    ' "$CONFIG_FILE" > "$TMP_CONFIG" 2>/dev/null; then
      mv "$TMP_CONFIG" "$CONFIG_FILE"
      echo "🔄 Default model override: ${CURRENT_PRIMARY} → ${DESIRED_PRIMARY} (EVERCLAW_DEFAULT_MODEL)"
    else
      rm -f "$TMP_CONFIG"
    fi
  fi
fi

# ─── Security Tier: Apply exec approval settings ────────────────────────────
# Reads EVERCLAW_SECURITY_TIER env var (default: recommended).
# Writes tools.exec.ask + safeBins + strictInlineEval into openclaw.json.

SECURITY_TIER="${EVERCLAW_SECURITY_TIER:-recommended}"
TIER_SCRIPT="${SKILLS_DIR}/scripts/security-tier.mjs"

if [ -f "$TIER_SCRIPT" ]; then
  echo "🔒 Applying security tier: ${SECURITY_TIER}"
  node "$TIER_SCRIPT" --tier "$SECURITY_TIER" --apply --force 2>&1 | grep -E '✅|❌|⚠️|Tier|ask|safeBins' || true
else
  echo "ℹ️  Security tier script not found — using config defaults"
fi

# ─── Bonjour/mDNS Mitigation (OpenClaw v2026.4.24) ──────────────────────────
# OpenClaw v2026.4.24 ships a broken bonjour (mDNS/CIAO) plugin that throws
# unhandled promise rejections on macOS and headless Linux (Docker/VPS).
# This crashes WebSocket connections with ECONNRESET → 1006.
# Ref: https://github.com/openclaw/openclaw/issues/70232
#
# Mitigation: disable the bonjour plugin + clean corrupted plugin-runtime-deps
# before the gateway starts. This is safe — bonjour is only used for local
# network discovery and is not required for any inference or messaging.

echo "🔧 Applying Bonjour/mDNS mitigation (OpenClaw v2026.4.24)..."

# 1. Disable the bonjour plugin via config (prevents the crash entirely)
if jq . "$CONFIG_FILE" > /dev/null 2>&1; then
  # Fix: clean up incorrect gateway.plugins path from prior EverClaw builds.
  # Older entrypoints wrote bonjour config under gateway.plugins (wrong) instead
  # of plugins.entries (correct). The stale key causes "Unrecognized key: plugins"
  # on startup because gateway has additionalProperties: false.
  HAS_STALE_PATH=$(jq -r '.gateway.plugins // empty' "$CONFIG_FILE" 2>/dev/null)
  if [ -n "$HAS_STALE_PATH" ]; then
    TMP_CLEAN=$(mktemp)
    if jq 'del(.gateway.plugins)' "$CONFIG_FILE" > "$TMP_CLEAN" 2>/dev/null; then
      mv "$TMP_CLEAN" "$CONFIG_FILE"
      echo "   🧹 Removed stale gateway.plugins key (schema violation)"
    else
      rm -f "$TMP_CLEAN"
    fi
  fi

  BONJOUR_ENABLED_VALUE=$(jq -r '.plugins.entries.bonjour.enabled // "notset"' "$CONFIG_FILE" 2>/dev/null)
  if [ "$BONJOUR_ENABLED_VALUE" != "false" ]; then
    TMP_CONFIG=$(mktemp)
    if jq '.plugins.entries.bonjour.enabled = false' "$CONFIG_FILE" > "$TMP_CONFIG" 2>/dev/null; then
      mv "$TMP_CONFIG" "$CONFIG_FILE"
      echo "   ✅ Bonjour plugin disabled in config"
    else
      rm -f "$TMP_CONFIG"
      echo "   ⚠️  Could not disable bonjour via config — gateway may still crash"
    fi
  else
    echo "   ✅ Bonjour plugin already disabled"
  fi
fi

# 2. Clean stale plugin-runtime-deps (ENOTEMPTY fix)
#    Stale or half-written openclaw-* subdirectories from prior OpenClaw versions
#    can cause repeated ENOTEMPTY errors on startup. Remove any that don't
#    match the current OpenClaw version being run.
PLUGIN_DEPS_DIR="${OPENCLAW_HOME}/plugin-runtime-deps"
if [ -d "$PLUGIN_DEPS_DIR" ] && [ ! -L "$PLUGIN_DEPS_DIR" ]; then
  CURRENT_OC_VER=$(node -e "try{const v=require('/app/package.json').version;console.log(typeof v==='string'&&v?v:'')}catch(e){console.log('')}" 2>/dev/null)
  CLEANED=0
  while IFS= read -r STALE; do
    DIR_NAME=$(basename "$STALE")
    DIR_VER=${DIR_NAME#openclaw-}
    if [ -n "$CURRENT_OC_VER" ] && [ "$DIR_VER" != "$CURRENT_OC_VER" ]; then
      rm -rf "$STALE"
      CLEANED=$((CLEANED + 1))
    fi
  done < <(find "$PLUGIN_DEPS_DIR" -maxdepth 1 -name 'openclaw-*' -type d 2>/dev/null)
  if [ "$CLEANED" -gt 0 ]; then
    echo "   ✅ Cleaned $CLEANED stale plugin-runtime-deps (kept $CURRENT_OC_VER)"
  fi
fi

# ─── Start Morpheus Proxy (background, only if configured) ──────────────────

# Trap signals to clean up all children on exit
AUTH_PROXY_PID=""
cleanup() {
  echo ""
  echo "🛑 Shutting down..."
  if [ -n "${AUTH_PROXY_PID:-}" ]; then
    kill "$AUTH_PROXY_PID" 2>/dev/null || true
    wait "$AUTH_PROXY_PID" 2>/dev/null || true
    echo "   Auth proxy stopped"
  fi
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

# ─── Auth Proxy Mode (Privy JWT) ─────────────────────────────────────────────
# When PRIVY_APP_ID is set, the auth proxy handles external access on :18789
# and OpenClaw runs on :18790 (internal, localhost only) in trusted-proxy mode.
# When PRIVY_APP_ID is NOT set, OpenClaw runs directly on :18789 (legacy mode).

AUTH_PROXY_ENABLED=false
GATEWAY_PORT=18789

if [ -n "${PRIVY_APP_ID:-}" ] && [ -n "${PRIVY_VERIFICATION_KEY:-}" ] && [ -n "${OPENCLAW_OWNER_PRIVY_ID:-}" ]; then
  AUTH_PROXY_ENABLED=true
  GATEWAY_PORT=18790
  export OPENCLAW_INTERNAL_PORT=18790

  echo ""
  echo "🔒 Auth proxy mode enabled (Privy JWT)"
  echo "   External: Auth Proxy :18789 → OpenClaw :18790 (internal)"
  echo ""

  # Configure OpenClaw for trusted-proxy mode
  # The auth proxy injects x-forwarded-user after verifying the Privy JWT
  if jq . "$CONFIG_FILE" > /dev/null 2>&1; then
    TMP_CONFIG=$(mktemp)
    if jq '
      .gateway.port = 18790 |
      .gateway.bind = "loopback" |
      .gateway.auth.mode = "trusted-proxy" |
      .gateway.auth.trustedProxy.userHeader = "x-forwarded-user" |
      .gateway.auth.trustedProxy.allowLoopback = true |
      .gateway.trustedProxies = ["127.0.0.1"] |
      .gateway.controlUi.enabled = true |
      .gateway.controlUi.dangerouslyDisableDeviceAuth = true |
      .gateway.controlUi.allowInsecureAuth = true |
      .gateway.controlUi.dangerouslyAllowHostHeaderOriginFallback = true |
      # Remove token auth fields that conflict with trusted-proxy mode
      del(.gateway.auth.token)
    ' "$CONFIG_FILE" > "$TMP_CONFIG" 2>/dev/null; then
      mv "$TMP_CONFIG" "$CONFIG_FILE"
      echo "🔧 OpenClaw configured for trusted-proxy mode (port 18790, loopback only)"
    else
      rm -f "$TMP_CONFIG"
      echo "⚠️  Failed to configure trusted-proxy mode — auth proxy may not work"
    fi
  fi

  # Start the auth proxy
  AUTH_PROXY_SCRIPT="/opt/everclaw/auth-proxy/server.mjs"
  if [ -f "$AUTH_PROXY_SCRIPT" ]; then
    echo "🚀 Starting auth proxy on :18789..."
    node "$AUTH_PROXY_SCRIPT" &
    AUTH_PROXY_PID=$!

    # Health gate: wait for auth proxy to become ready before starting gateway
    # This ensures the gateway is never exposed without authentication
    echo "⏳ Waiting for auth proxy to become ready..."
    AUTH_PROXY_READY=false
    AUTH_PROXY_WAIT=0
    while [ $AUTH_PROXY_WAIT -lt 15 ]; do
      if curl -sf http://127.0.0.1:18789/health > /dev/null 2>&1; then
        AUTH_PROXY_READY=true
        break
      fi
      if ! kill -0 "$AUTH_PROXY_PID" 2>/dev/null; then
        echo "❌ Auth proxy exited during startup"
        break
      fi
      AUTH_PROXY_WAIT=$((AUTH_PROXY_WAIT + 1))
      sleep 1
    done

    if [ "$AUTH_PROXY_READY" = "true" ]; then
      echo "✅ Auth proxy ready"
    else
      echo "❌ Auth proxy failed to start within 15s"
      echo "   ABORTING: Will not start OpenClaw without authentication"
      echo "   Check PRIVY_APP_ID, PRIVY_VERIFICATION_KEY, and OPENCLAW_OWNER_PRIVY_ID"
      exit 1
    fi
  else
    echo "❌ Auth proxy script not found at $AUTH_PROXY_SCRIPT"
    echo "   ABORTING: Will not start OpenClaw without authentication"
    echo "   Rebuild the Docker image with the auth proxy included"
    exit 1
  fi
else
  if [ -n "${PRIVY_APP_ID:-}" ] || [ -n "${PRIVY_VERIFICATION_KEY:-}" ] || [ -n "${OPENCLAW_OWNER_PRIVY_ID:-}" ]; then
    echo "⚠️  Partial Privy configuration detected — all three required:"
    echo "   PRIVY_APP_ID, PRIVY_VERIFICATION_KEY, OPENCLAW_OWNER_PRIVY_ID"
    echo "   Starting without auth proxy (legacy mode)"
  fi
fi

# ─── CIG FQDN Pre-Detection ────────────────────────────────────────────────
# In CIG mode, the auth-proxy needs the container FQDN to mint CIG inference tokens.
# Buffer containers don't know their FQDN at provision time — it's auto-detected from
# the first external request's Host header. But OpenClaw makes its first inference call
# before any browser request arrives, causing "FQDN not yet detected" errors.
#
# Solution: If CONTAINER_FQDN is provided via env var, the auth-proxy uses it directly
# (CIG_CONFIG.fqdnLocked is set at startup). If not, we trigger FQDN self-detection by
# making a local request with the FQDN from the Manifest ingress hostname.
# The FQDN is typically available as CONTAINER_FQDN env var (set by provision-buffer).

if [ "$CIG_ENABLED" = "true" ]; then
  if [ -n "${CONTAINER_FQDN:-}" ]; then
    echo "🏷️  CIG FQDN pre-set via env: ${CONTAINER_FQDN}"
  else
    # FQDN not provided via env — wait for auto-detection via self-request
    # The auth-proxy auto-detects from Host header; we simulate an external request
    # by querying the auth-proxy health endpoint to confirm FQDN status.
    echo "⏳ Waiting for CIG FQDN auto-detection..."
    FQDN_WAIT=0
    FQDN_MAX_WAIT=30  # 30 seconds max
    while [ $FQDN_WAIT -lt $FQDN_MAX_WAIT ]; do
      HEALTH_RESP=$(curl -sf http://127.0.0.1:18789/health 2>/dev/null || echo '')
      if [ -n "$HEALTH_RESP" ]; then
        FQDN_DETECTED=$(echo "$HEALTH_RESP" | jq -r '.cig.detected // false' 2>/dev/null)
        FQDN_VALUE=$(echo "$HEALTH_RESP" | jq -r '.cig.fqdn // empty' 2>/dev/null)
        if [ "$FQDN_DETECTED" = "true" ] && [ -n "$FQDN_VALUE" ]; then
          echo "✅ CIG FQDN auto-detected: ${FQDN_VALUE}"
          break
        fi
      fi
      FQDN_WAIT=$((FQDN_WAIT + 1))
      sleep 1
    done

    if [ $FQDN_WAIT -ge $FQDN_MAX_WAIT ]; then
      echo "⚠️  CIG FQDN not detected within ${FQDN_MAX_WAIT}s — first inference may fail with 503"
      echo "   The FQDN will be auto-detected when the user opens the container URL in a browser."
      echo "   OpenClaw's model fallback chain will handle the 503 and retry."
    fi
  fi
fi

# ─── Start OpenClaw Gateway ─────────────────────────────────────────────────

if [ "$AUTH_PROXY_ENABLED" = "true" ]; then
  # In auth proxy mode, bind to localhost only (config sets gateway.bind=loopback)
  # Auth proxy on :18789 is the sole external entry point
  node /app/openclaw.mjs gateway --allow-unconfigured &
else
  node /app/openclaw.mjs gateway --allow-unconfigured --bind lan &
fi
GATEWAY_PID=$!

# ─── Health Gate: Wait for gateway readiness ─────────────────────────────────

echo "⏳ Waiting for gateway on port ${GATEWAY_PORT}..."
HEALTH_ATTEMPTS=0
MAX_ATTEMPTS=60
GATEWAY_ALIVE=true
GATEWAY_HEALTHY=false

while [ $HEALTH_ATTEMPTS -lt $MAX_ATTEMPTS ]; do
  if curl -sf http://127.0.0.1:${GATEWAY_PORT}/health > /dev/null 2>&1; then
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
  if [ "$AUTH_PROXY_ENABLED" = "true" ]; then
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║  ✅ EverClaw is ready! (Privy auth enabled)                     ║"
    echo "║                                                                 ║"
    echo "║  Dashboard:  Visit your container URL                          ║"
    echo "║  Auth:       Privy social login (Google, email, Apple)          ║"
    echo "║  Inference:  http://localhost:${EVERCLAW_PROXY_PORT:-8083}/v1"
    echo "║                                                                 ║"
    echo "║  Owner: ${OPENCLAW_OWNER_PRIVY_ID}"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo ""
    echo "🔒 Only the authenticated owner can access this agent."
    echo "   No credentials are stored externally — fully sovereign."
    echo ""
  else
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
    echo ""
  fi

  # First-run security guidance banner (shown once, suppressed by sentinel file)
  # Suppress in auth proxy mode — the proxy IS the authentication layer
  if [ ! -f "$FIRST_RUN_MARKER" ] && [ "$AUTH_PROXY_ENABLED" != "true" ]; then
    BANNER_PORT="${OPENCLAW_GATEWAY_PORT:-18789}"
    cat <<EOF
╔══════════════════════════════════════════════════════════════════╗
║  🔒 Security: Best Practices                                    ║
║                                                                 ║
║  For best security, access via http://localhost:${BANNER_PORT}
║  LAN access (e.g. http://192.168.x.x:${BANNER_PORT}) works but
║  is less secure — device auth requires HTTPS or localhost.
║                                                                 ║
║  For remote access, set up an HTTPS reverse proxy:              ║
║    • Caddy, Traefik, or Nginx with Let's Encrypt               ║
║    • SSH tunnel: ssh -NL ${BANNER_PORT}:127.0.0.1:${BANNER_PORT} user@host
║                                                                 ║
║  Docs: https://docs.openclaw.ai/gateway/security               ║
╚══════════════════════════════════════════════════════════════════╝
EOF
    if ! touch "$FIRST_RUN_MARKER" 2>/dev/null; then
      echo "⚠️  Could not create first-run marker — this banner may reappear" >&2
    fi
  fi

  if [ "$AUTH_PROXY_ENABLED" != "true" ]; then
    echo "⚠️  Do not expose to the internet without additional authentication"
    echo "   (reverse proxy, VPN, etc)."
    echo ""
  fi
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
