#!/bin/bash
# Gateway Guardian v2 — monitors OpenClaw gateway + inference health
#
# v1 only checked if the HTTP dashboard was up. But the real failure mode
# is when the gateway process is alive but ALL model providers are in cooldown
# (credits exhausted, billing errors cascading). The gateway returns 200 on its
# dashboard while the agent is effectively brain-dead.
#
# v2 Strategy:
#   1. HTTP probe — is the gateway process alive?
#   2. Inference probe — can any model provider actually respond?
#      Tries Venice, Morpheus proxy, and mor-gateway directly.
#   3. If gateway is up but no provider responds → escalating restart:
#      a. openclaw gateway restart (resets in-memory cooldown state)
#      b. Hard kill + launchd KeepAlive
#      c. launchctl kickstart
#      d. NUCLEAR: curl install.sh (full reinstall — the last resort)
#   4. Signal notification before nuclear restart
#
# Install: see templates/ai.openclaw.guardian.plist (every 2 minutes via launchd)
# Test:    bash ~/.openclaw/workspace/scripts/gateway-guardian.sh --verbose

# ─── Configuration ───────────────────────────────────────────────────────────
GATEWAY_PORT="${OPENCLAW_GATEWAY_PORT:-18789}"
GATEWAY_URL="http://127.0.0.1:${GATEWAY_PORT}/"
LAUNCHD_LABEL="ai.openclaw.gateway"
LOG_FILE="$HOME/.openclaw/logs/guardian.log"
STATE_FILE="$HOME/.openclaw/logs/guardian.state"
INFERENCE_STATE_FILE="$HOME/.openclaw/logs/guardian-inference.state"
PROBE_TIMEOUT=8
INFERENCE_TIMEOUT=15
FAIL_THRESHOLD=2           # consecutive HTTP failures before restart
INFERENCE_FAIL_THRESHOLD=3 # consecutive inference failures before escalation (~6 min)
MAX_LOG_LINES=1000
VERBOSE="${1:-}"

# Provider endpoints to probe (in order of preference)
# We only need ONE to succeed to consider inference "alive"
VENICE_API="https://api.venice.ai/api/v1/models"
MORPHEUS_PROXY="http://127.0.0.1:8083/health"
MOR_GATEWAY="https://api.mor.org/api/v1/models"

# Notification settings
OWNER_SIGNAL="+1XXXXXXXXXX"

# Install script URL for nuclear option
INSTALL_URL="https://clawd.bot/install.sh"

# ─── Helpers ─────────────────────────────────────────────────────────────────
log() {
  local msg="$(date '+%Y-%m-%d %H:%M:%S') [guardian] $1"
  echo "$msg" >> "$LOG_FILE"
  [[ "$VERBOSE" == "--verbose" ]] && echo "$msg"
}

mkdir -p "$(dirname "$LOG_FILE")"

# Trim log
if [[ -f "$LOG_FILE" ]] && [[ $(wc -l < "$LOG_FILE") -gt $MAX_LOG_LINES ]]; then
  tail -n $((MAX_LOG_LINES / 2)) "$LOG_FILE" > "${LOG_FILE}.tmp" && mv "${LOG_FILE}.tmp" "$LOG_FILE"
fi

# ─── Read state ──────────────────────────────────────────────────────────────
HTTP_FAIL_COUNT=0
[[ -f "$STATE_FILE" ]] && HTTP_FAIL_COUNT=$(cat "$STATE_FILE" 2>/dev/null || echo 0)

INFERENCE_FAIL_COUNT=0
[[ -f "$INFERENCE_STATE_FILE" ]] && INFERENCE_FAIL_COUNT=$(cat "$INFERENCE_STATE_FILE" 2>/dev/null || echo 0)

# ─── Restart functions ───────────────────────────────────────────────────────

do_graceful_restart() {
  log "Step 1: Graceful restart via openclaw CLI (resets in-memory cooldown state)..."
  if openclaw gateway restart 2>/dev/null; then
    sleep 10
    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time "$PROBE_TIMEOUT" "$GATEWAY_URL" 2>/dev/null || echo "000")
    if [[ "$http_code" != "000" ]]; then
      log "RECOVERED: Graceful restart succeeded (HTTP $http_code). Cooldown states cleared."
      echo "0" > "$INFERENCE_STATE_FILE"
      echo "0" > "$STATE_FILE"
      return 0
    fi
    log "Graceful restart: gateway didn't come back within timeout."
  else
    log "openclaw gateway restart command failed."
  fi
  return 1
}

do_hard_restart() {
  log "Step 2: Hard kill + launchd KeepAlive..."
  pkill -9 -f "openclaw.*gateway" 2>/dev/null || true

  sleep 12

  local http_code
  http_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time "$PROBE_TIMEOUT" "$GATEWAY_URL" 2>/dev/null || echo "000")
  if [[ "$http_code" != "000" ]]; then
    log "RECOVERED: Hard restart succeeded (HTTP $http_code)."
    echo "0" > "$INFERENCE_STATE_FILE"
    echo "0" > "$STATE_FILE"
    return 0
  fi
  log "Hard restart: gateway didn't come back via launchd."
  return 1
}

do_kickstart() {
  log "Step 3: launchctl kickstart..."
  launchctl kickstart -k "gui/$(id -u)/$LAUNCHD_LABEL" 2>/dev/null || true
  sleep 12

  local http_code
  http_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time "$PROBE_TIMEOUT" "$GATEWAY_URL" 2>/dev/null || echo "000")
  if [[ "$http_code" != "000" ]]; then
    log "RECOVERED: Kickstart succeeded (HTTP $http_code)."
    echo "0" > "$INFERENCE_STATE_FILE"
    echo "0" > "$STATE_FILE"
    return 0
  fi
  log "Kickstart: gateway didn't come back."
  return 1
}

do_nuclear_reinstall() {
  log "Step 4: NUCLEAR — full reinstall via $INSTALL_URL"
  log "This is the same command the user runs manually when all else fails."

  # Try to notify the owner before going nuclear.
  # Can't use openclaw message (agent may be dead). Try signal-cli directly.
  local signal_bin
  signal_bin=$(which signal-cli 2>/dev/null || echo "")
  if [[ -n "$signal_bin" ]]; then
    log "Notifying owner via Signal before nuclear restart..."
    "$signal_bin" -a "$OWNER_SIGNAL" send \
      -m "🚨 Gateway Guardian: All providers in cooldown for $((INFERENCE_FAIL_COUNT * 2))+ min. Executing nuclear reinstall now. Stand by." \
      "$OWNER_SIGNAL" 2>/dev/null || true
  fi

  # Nuclear option: reinstall OpenClaw
  # Reinstalls the binary, reloads launchd, restarts gateway → clears ALL cooldowns
  log "Executing: curl -fsSL $INSTALL_URL | bash"
  if curl -fsSL "$INSTALL_URL" | bash >> "$LOG_FILE" 2>&1; then
    sleep 15

    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time "$PROBE_TIMEOUT" "$GATEWAY_URL" 2>/dev/null || echo "000")
    if [[ "$http_code" != "000" ]]; then
      log "RECOVERED: Nuclear reinstall succeeded (HTTP $http_code). Cooldown states reset."
      echo "0" > "$INFERENCE_STATE_FILE"
      echo "0" > "$STATE_FILE"

      # Notify recovery
      if [[ -n "$signal_bin" ]]; then
        "$signal_bin" -a "$OWNER_SIGNAL" send \
          -m "✅ Gateway Guardian: Nuclear reinstall succeeded. Agent back online." \
          "$OWNER_SIGNAL" 2>/dev/null || true
      fi
      return 0
    fi
    log "Nuclear reinstall completed but gateway not responding yet."
  else
    log "Nuclear reinstall script failed."
  fi
  return 1
}

restart_all_steps() {
  do_graceful_restart && return 0
  do_hard_restart && return 0
  do_kickstart && return 0
  do_nuclear_reinstall && return 0

  log "CRITICAL: All restart attempts including nuclear reinstall FAILED."
  log "CRITICAL: Manual intervention required: curl -fsSL $INSTALL_URL | bash"
  return 1
}

# ─── Step 1: HTTP probe ─────────────────────────────────────────────────────
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time "$PROBE_TIMEOUT" "$GATEWAY_URL" 2>/dev/null || echo "000")

if [[ "$HTTP_CODE" == "000" || "$HTTP_CODE" == "" ]]; then
  # Gateway process is down
  HTTP_FAIL_COUNT=$((HTTP_FAIL_COUNT + 1))
  echo "$HTTP_FAIL_COUNT" > "$STATE_FILE"

  if [[ "$HTTP_FAIL_COUNT" -lt "$FAIL_THRESHOLD" ]]; then
    log "WARN: HTTP probe failed ($HTTP_FAIL_COUNT/$FAIL_THRESHOLD). Will retry next run."
    exit 0
  fi

  log "ALERT: Gateway process unresponsive ($HTTP_FAIL_COUNT consecutive HTTP failures). Restarting..."
  restart_all_steps
  exit $?
fi

# HTTP is OK — reset HTTP fail counter
if [[ "$HTTP_FAIL_COUNT" -gt 0 ]]; then
  log "OK: Gateway process recovered (HTTP $HTTP_CODE). Resetting HTTP fail counter."
fi
echo "0" > "$STATE_FILE"

# ─── Step 2: Inference probe ────────────────────────────────────────────────
# Gateway is up (HTTP 200). But can any model provider actually respond?
# We probe the providers directly: Venice API, Morpheus proxy, mor-gateway.
# If ANY provider responds, inference should work (OpenClaw can route to it).
# If ALL providers are down, the agent is brain-dead despite gateway being up.

INFERENCE_OK=false
PROVIDER_STATUS=""

# Probe 1: Venice API (primary provider)
VENICE_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time "$INFERENCE_TIMEOUT" "$VENICE_API" 2>/dev/null || echo "000")
if [[ "$VENICE_CODE" == "200" ]]; then
  INFERENCE_OK=true
  PROVIDER_STATUS="venice=ok"
else
  PROVIDER_STATUS="venice=$VENICE_CODE"
fi

# Probe 2: Morpheus local proxy (fallback provider)
if [[ "$INFERENCE_OK" != "true" ]]; then
  MORPHEUS_RESULT=$(curl -s --max-time "$INFERENCE_TIMEOUT" "$MORPHEUS_PROXY" 2>/dev/null || echo "")
  if echo "$MORPHEUS_RESULT" | grep -q '"status":"ok"'; then
    INFERENCE_OK=true
    PROVIDER_STATUS="$PROVIDER_STATUS,morpheus=ok"
  else
    PROVIDER_STATUS="$PROVIDER_STATUS,morpheus=down"
  fi
fi

# Probe 3: Morpheus API Gateway (last resort provider)
if [[ "$INFERENCE_OK" != "true" ]]; then
  GATEWAY_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time "$INFERENCE_TIMEOUT" "$MOR_GATEWAY" 2>/dev/null || echo "000")
  if [[ "$GATEWAY_CODE" == "200" || "$GATEWAY_CODE" == "401" ]]; then
    # 401 = gateway is up but needs auth — still means the provider is reachable
    INFERENCE_OK=true
    PROVIDER_STATUS="$PROVIDER_STATUS,mor-gateway=$GATEWAY_CODE"
  else
    PROVIDER_STATUS="$PROVIDER_STATUS,mor-gateway=$GATEWAY_CODE"
  fi
fi

# ─── Evaluate inference health ──────────────────────────────────────────────
if [[ "$INFERENCE_OK" == "true" ]]; then
  if [[ "$INFERENCE_FAIL_COUNT" -gt 0 ]]; then
    log "OK: Inference recovered ($PROVIDER_STATUS). Resetting inference fail counter."
  elif [[ "$VERBOSE" == "--verbose" ]]; then
    local_pid=$(pgrep -f "openclaw.*gateway" 2>/dev/null | head -1 || echo "?")
    log "OK: Fully healthy (PID=$local_pid, HTTP=$HTTP_CODE, $PROVIDER_STATUS)"
  fi
  echo "0" > "$INFERENCE_STATE_FILE"
  exit 0
fi

# ALL providers unreachable
INFERENCE_FAIL_COUNT=$((INFERENCE_FAIL_COUNT + 1))
echo "$INFERENCE_FAIL_COUNT" > "$INFERENCE_STATE_FILE"

if [[ "$INFERENCE_FAIL_COUNT" -lt "$INFERENCE_FAIL_THRESHOLD" ]]; then
  log "WARN: All providers unreachable ($PROVIDER_STATUS). Fail $INFERENCE_FAIL_COUNT/$INFERENCE_FAIL_THRESHOLD. Retrying in 2 min."
  exit 0
fi

# ─── All providers dead for too long — escalate ────────────────────────────
log "ALERT: All providers unreachable for $INFERENCE_FAIL_COUNT consecutive checks (~$((INFERENCE_FAIL_COUNT * 2)) min). Providers: $PROVIDER_STATUS. Escalating restart..."

# The key insight: restarting the gateway clears OpenClaw's in-memory cooldown state.
# Even if Venice credits are exhausted, the fallback chain (Morpheus, mor-gateway)
# might work after a fresh start without the cascading cooldown contamination.
restart_all_steps
exit $?
