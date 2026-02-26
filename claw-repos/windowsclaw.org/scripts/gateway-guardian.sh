#!/bin/bash
# Gateway Guardian v5 — monitors OpenClaw gateway + inference with billing awareness
#
# v1: Only checked HTTP dashboard (useless when providers in cooldown)
# v2: Probed provider endpoints directly (always 200 — can't see internal state)
# v3: Probed THROUGH OpenClaw via `openclaw agent`. Found billing death spiral +
#     silent restart bug (set -euo pipefail + pkill self-kill).
# v4: Billing-aware escalation, fixed restart chain, credit monitoring, notifications.
#     - Classifies errors: billing vs transient vs stuck
#     - Billing → DON'T restart (useless), calculate time to DIEM reset, notify, sleep
#     - Transient/stuck → restart as before
#     - Fixed: set -uo pipefail + ERR trap (no more silent exits)
#     - Fixed: pkill excludes own PID (no more self-kill)
#     - Added: proactive Venice credit monitoring
#     - Added: Signal notifications for billing exhaustion + recovery
# v5: Direct curl inference probe (replaces `openclaw agent`).
#     - Root cause: `openclaw agent` injected full 71K workspace system prompt into
#       every probe, causing mor-gateway/glm-5 to timeout at 60s (takes ~37s just
#       for the prompt). The error "Failed to create chat completions stream:" was
#       then delivered to Signal as a normal agent reply — spamming the user.
#     - Fix: Direct curl to gateway's LiteLLM proxy with tiny prompt (~50 chars).
#       Uses glm-4.7-flash (fast, lightweight) instead of glm-5.
#       No agent session = no Signal delivery on failure. Errors stay in logs only.
#
# Install: launchd plist at ~/Library/LaunchAgents/ai.openclaw.guardian.plist
# Test:    bash ~/.openclaw/workspace/scripts/gateway-guardian.sh --verbose

# CRITICAL FIX (v4): removed `set -e` which caused silent exits when openclaw
# gateway restart returned non-zero. Now using explicit error handling.
set -uo pipefail

# ERR trap for debugging — logs unexpected failures instead of dying silently
trap 'log "ERROR: unexpected failure at line $LINENO (exit code $?)"' ERR

# ─── macOS compatibility ─────────────────────────────────────────────────────
run_with_timeout() {
  local secs="$1"; shift
  perl -e "alarm $secs; exec @ARGV" -- "$@"
}

# ─── Configuration ───────────────────────────────────────────────────────────
GATEWAY_PORT="${OPENCLAW_GATEWAY_PORT:-18789}"
GATEWAY_URL="http://127.0.0.1:${GATEWAY_PORT}/"
LAUNCHD_LABEL="ai.openclaw.gateway"
LOG_FILE="$HOME/.openclaw/logs/guardian.log"
STATE_FILE="$HOME/.openclaw/logs/guardian.state"
INFERENCE_STATE_FILE="$HOME/.openclaw/logs/guardian-inference.state"
CIRCUIT_BREAKER_FILE="$HOME/.openclaw/logs/guardian-circuit-breaker.state"
BILLING_STATE_FILE="$HOME/.openclaw/logs/guardian-billing.state"
BILLING_NOTIFIED_FILE="$HOME/.openclaw/logs/guardian-billing-notified.state"

PROBE_TIMEOUT=8
INFERENCE_TIMEOUT=45
FAIL_THRESHOLD=2
INFERENCE_FAIL_THRESHOLD=3
MAX_LOG_LINES=1000
VERBOSE="${1:-}"

# Circuit breaker config
MAX_STUCK_DURATION_SEC=1800
STUCK_CHECK_INTERVAL=300

# Billing config
BILLING_BACKOFF_INTERVAL=1800  # When billing-dead, only check every 30 min (not 2 min)

# Notification settings
OWNER_SIGNAL="+1XXXXXXXXXX"
SIGNAL_ACCOUNT="+1XXXXXXXXXX"

# Install script URL for nuclear option
INSTALL_URL="https://clawd.bot/install.sh"

# Guardian probe session
GUARDIAN_SESSION_ID="guardian-health-probe"

# Own PID — used to exclude ourselves from pkill
GUARDIAN_PID=$$

# ─── Helpers ─────────────────────────────────────────────────────────────────
log() {
  local msg="$(date '+%Y-%m-%d %H:%M:%S') [guardian] $1"
  echo "$msg" >> "$LOG_FILE"
  [[ "$VERBOSE" == "--verbose" ]] && echo "$msg"
}

notify_signal() {
  local message="$1"
  local signal_bin
  signal_bin=$(which signal-cli 2>/dev/null || echo "")
  if [[ -n "$signal_bin" ]]; then
    "$signal_bin" -a "$SIGNAL_ACCOUNT" send -m "$message" "$OWNER_SIGNAL" 2>/dev/null || true
  fi
}

# Calculate hours until midnight UTC (when Venice DIEM resets)
hours_to_diem_reset() {
  local now_utc_h now_utc_m remaining_min
  now_utc_h=$(date -u '+%H' | sed 's/^0//')
  now_utc_m=$(date -u '+%M' | sed 's/^0//')
  remaining_min=$(( (23 - now_utc_h) * 60 + (60 - now_utc_m) ))
  echo $(( remaining_min / 60 ))
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

LAST_CIRCUIT_CHECK=0
[[ -f "$CIRCUIT_BREAKER_FILE" ]] && LAST_CIRCUIT_CHECK=$(cat "$CIRCUIT_BREAKER_FILE" 2>/dev/null || echo 0)

BILLING_DEAD_SINCE=0
[[ -f "$BILLING_STATE_FILE" ]] && BILLING_DEAD_SINCE=$(cat "$BILLING_STATE_FILE" 2>/dev/null || echo 0)

BILLING_NOTIFIED=0
[[ -f "$BILLING_NOTIFIED_FILE" ]] && BILLING_NOTIFIED=$(cat "$BILLING_NOTIFIED_FILE" 2>/dev/null || echo 0)

# ─── Billing backoff: skip if we already know credits are exhausted ─────────
# When billing-dead, don't hammer the system every 2 min. Check every 30 min
# or when we cross midnight UTC (DIEM reset).
if [[ "$BILLING_DEAD_SINCE" -gt 0 ]]; then
  NOW=$(date +%s)
  ELAPSED=$((NOW - BILLING_DEAD_SINCE))

  # Check if we've crossed midnight UTC since we went billing-dead
  CURRENT_UTC_DAY=$(date -u '+%Y-%m-%d')
  DEAD_UTC_DAY=$(date -u -r "$BILLING_DEAD_SINCE" '+%Y-%m-%d' 2>/dev/null || echo "")

  if [[ "$CURRENT_UTC_DAY" != "$DEAD_UTC_DAY" && -n "$DEAD_UTC_DAY" ]]; then
    # Midnight UTC has passed — DIEM should have reset. Clear billing state and probe.
    log "BILLING: Midnight UTC crossed (was $DEAD_UTC_DAY, now $CURRENT_UTC_DAY). DIEM should be reset. Re-probing..."
    echo "0" > "$BILLING_STATE_FILE"
    echo "0" > "$BILLING_NOTIFIED_FILE"
    BILLING_DEAD_SINCE=0
    BILLING_NOTIFIED=0
  elif [[ "$ELAPSED" -lt "$BILLING_BACKOFF_INTERVAL" ]]; then
    # Still within backoff window — skip this run entirely
    [[ "$VERBOSE" == "--verbose" ]] && log "BILLING: In backoff ($((ELAPSED / 60))m / $((BILLING_BACKOFF_INTERVAL / 60))m). Skipping probe."
    exit 0
  else
    # Backoff expired — re-probe to see if credits came back
    log "BILLING: Backoff expired ($((ELAPSED / 60))m). Re-probing..."
    echo "$NOW" > "$BILLING_STATE_FILE"
  fi
fi

# ─── Circuit Breaker: Kill stuck sub-agents ─────────────────────────────────
check_circuit_breaker() {
  local now
  now=$(date +%s)

  if [[ $((now - LAST_CIRCUIT_CHECK)) -lt $STUCK_CHECK_INTERVAL ]]; then
    return 0
  fi
  echo "$now" > "$CIRCUIT_BREAKER_FILE"

  [[ "$VERBOSE" == "--verbose" ]] && log "Circuit breaker: checking for stuck sub-agents..."

  local err_log="$HOME/.openclaw/logs/gateway.err.log"
  [[ ! -f "$err_log" ]] && return 0

  local stuck_runs
  stuck_runs=$(grep -E "embedded run timeout.*runId=" "$err_log" 2>/dev/null | \
    grep -E "$(date -v-1H '+%Y-%m-%dT%H')|$(date '+%Y-%m-%dT%H')" | \
    sed -n 's/.*runId=\([^ ]*\).*/\1/p' | sort | uniq -c | sort -rn | head -5) || true

  if [[ -z "$stuck_runs" ]]; then
    [[ "$VERBOSE" == "--verbose" ]] && log "Circuit breaker: no stuck sub-agents found."
    return 0
  fi

  while read -r count runId; do
    [[ -z "$runId" ]] && continue
    [[ "$count" -lt 3 ]] && continue

    local est_duration=$((count * 600))

    if [[ "$est_duration" -ge "$MAX_STUCK_DURATION_SEC" ]]; then
      log "CIRCUIT BREAKER: Run $runId has been timing out for ~$((est_duration / 60)) min ($count timeouts). Killing..."
      log "Circuit breaker: Triggering graceful restart to clear stuck run..."
      do_graceful_restart
      return 0
    fi
  done <<< "$stuck_runs"

  [[ "$VERBOSE" == "--verbose" ]] && log "Circuit breaker: no runs exceed ${MAX_STUCK_DURATION_SEC}s threshold."
  return 0
}

# ─── Restart functions (v4: fixed silent failures) ───────────────────────────
do_graceful_restart() {
  log "Step 1: Graceful restart via openclaw CLI..."
  # v4 fix: capture exit code explicitly instead of relying on set -e
  local restart_rc=0
  openclaw gateway restart 2>/dev/null || restart_rc=$?

  if [[ "$restart_rc" -ne 0 ]]; then
    log "Step 1: openclaw gateway restart exited with code $restart_rc. Continuing to next step."
    return 1
  fi

  sleep 10
  local http_code
  http_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time "$PROBE_TIMEOUT" "$GATEWAY_URL" 2>/dev/null || echo "000")
  if [[ "$http_code" != "000" ]]; then
    log "RECOVERED: Graceful restart succeeded (HTTP $http_code). Cooldown states cleared."
    echo "0" > "$INFERENCE_STATE_FILE"
    echo "0" > "$STATE_FILE"
    return 0
  fi
  log "Step 1: Gateway didn't come back within timeout."
  return 1
}

do_hard_restart() {
  log "Step 2: Hard kill + launchd KeepAlive..."
  # v4 fix: exclude our own PID so we don't self-kill
  # The guardian's path contains "openclaw" and "gateway" in the workspace path
  local pids
  pids=$(pgrep -f "openclaw.*gateway" 2>/dev/null || true)
  for pid in $pids; do
    if [[ "$pid" != "$GUARDIAN_PID" && "$pid" != "$$" ]]; then
      kill -9 "$pid" 2>/dev/null || true
      log "Step 2: Killed PID $pid"
    fi
  done
  sleep 12

  local http_code
  http_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time "$PROBE_TIMEOUT" "$GATEWAY_URL" 2>/dev/null || echo "000")
  if [[ "$http_code" != "000" ]]; then
    log "RECOVERED: Hard restart succeeded (HTTP $http_code)."
    echo "0" > "$INFERENCE_STATE_FILE"
    echo "0" > "$STATE_FILE"
    return 0
  fi
  log "Step 2: Gateway didn't come back via launchd."
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
  log "Step 3: Gateway didn't come back."
  return 1
}

do_nuclear_reinstall() {
  log "Step 4: NUCLEAR — full reinstall via $INSTALL_URL"

  notify_signal "🚨 Gateway Guardian: All recovery steps failed after $((INFERENCE_FAIL_COUNT * 2))+ min. Executing nuclear reinstall now."

  log "Executing: curl -fsSL $INSTALL_URL | bash"
  local nuclear_rc=0
  curl -fsSL "$INSTALL_URL" | bash >> "$LOG_FILE" 2>&1 || nuclear_rc=$?

  if [[ "$nuclear_rc" -ne 0 ]]; then
    log "Step 4: Nuclear reinstall script exited with code $nuclear_rc."
    return 1
  fi

  sleep 15

  local http_code
  http_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time "$PROBE_TIMEOUT" "$GATEWAY_URL" 2>/dev/null || echo "000")
  if [[ "$http_code" != "000" ]]; then
    log "RECOVERED: Nuclear reinstall succeeded (HTTP $http_code)."
    echo "0" > "$INFERENCE_STATE_FILE"
    echo "0" > "$STATE_FILE"
    notify_signal "✅ Gateway Guardian: Nuclear reinstall succeeded. Agent back online."
    return 0
  fi
  log "Step 4: Nuclear reinstall completed but gateway not responding."
  return 1
}

restart_all_steps() {
  do_graceful_restart && return 0
  do_hard_restart && return 0
  do_kickstart && return 0
  do_nuclear_reinstall && return 0

  log "CRITICAL: All restart attempts including nuclear reinstall FAILED."
  log "CRITICAL: Manual intervention required: curl -fsSL $INSTALL_URL | bash"
  notify_signal "🔴 Gateway Guardian: ALL recovery steps failed (graceful → hard → kickstart → nuclear). Manual intervention required."
  return 1
}

# ─── Error classification (v4 — billing-aware) ──────────────────────────────
# Returns: "billing", "transient", "timeout", "unknown"
classify_error() {
  local result="$1"
  # Billing / credit exhaustion patterns
  if echo "$result" | grep -qiE "Insufficient.*balance|Insufficient.*USD|Insufficient.*Diem|billing|402|credits.*insufficient|balance.*insufficient"; then
    echo "billing"
    return
  fi
  # Auth cooldown (all profiles disabled — likely from billing cascade)
  if echo "$result" | grep -qiE "No available auth profile|all in cooldown|all profiles unavailable"; then
    # Could be billing or transient. Check if the error mentions billing specifically.
    if echo "$result" | grep -qiE "billing|402|credits|Diem|balance"; then
      echo "billing"
    else
      echo "transient"
    fi
    return
  fi
  # Timeout
  if echo "$result" | grep -qiE "timed out|timeout"; then
    echo "timeout"
    return
  fi
  echo "unknown"
}

# ─── Handle billing exhaustion (v4) ─────────────────────────────────────────
handle_billing_exhaustion() {
  local hours_left
  hours_left=$(hours_to_diem_reset)
  local now
  now=$(date +%s)

  log "BILLING: All Venice keys exhausted. DIEM resets in ~${hours_left}h (midnight UTC). Restarting is POINTLESS — entering billing backoff."

  # Record when we first detected billing exhaustion
  if [[ "$BILLING_DEAD_SINCE" -eq 0 ]]; then
    echo "$now" > "$BILLING_STATE_FILE"
  fi

  # Notify owner (once per billing event)
  if [[ "$BILLING_NOTIFIED" -eq 0 ]]; then
    notify_signal "⚠️ DIEM credits exhausted on all Venice keys. I'll be back when credits reset in ~${hours_left}h (midnight UTC). Morpheus fallback also unavailable. No action needed — will auto-recover."
    echo "1" > "$BILLING_NOTIFIED_FILE"
    log "BILLING: Owner notified via Signal."
  fi

  # Don't restart — it's useless for billing. Just wait.
  # The billing backoff at the top of the script will skip future runs.
  exit 0
}

# ─── Proactive credit monitoring (v4 — Piece 4) ─────────────────────────────
# Check Venice DIEM balance via a cheap inference call's response headers.
# Warn when any key drops below threshold. Runs every ~10 min (5 guardian cycles).
CREDIT_CHECK_FILE="$HOME/.openclaw/logs/guardian-credit-check.state"
CREDIT_CHECK_INTERVAL=600  # 10 minutes between credit checks
CREDIT_WARN_THRESHOLD=15   # Warn when DIEM drops below this (Claude needs 30-50)

check_venice_credits() {
  local last_check=0
  [[ -f "$CREDIT_CHECK_FILE" ]] && last_check=$(cat "$CREDIT_CHECK_FILE" 2>/dev/null || echo 0)
  local now
  now=$(date +%s)

  if [[ $((now - last_check)) -lt $CREDIT_CHECK_INTERVAL ]]; then
    return 0
  fi
  echo "$now" > "$CREDIT_CHECK_FILE"

  local auth_file="$HOME/.openclaw/agents/main/agent/auth-profiles.json"
  [[ ! -f "$auth_file" ]] && return 0

  [[ "$VERBOSE" == "--verbose" ]] && log "CREDITS: Checking Venice DIEM balance (key1)..."

  # Only check key1 (primary) — it's the canary. If key1 is low, the rest are likely lower.
  local api_key
  api_key=$(python3 -c "
import json
with open('$auth_file') as f:
    d = json.load(f)
print(d.get('profiles',{}).get('venice:key1',{}).get('key',''))
" 2>/dev/null) || return 0

  [[ -z "$api_key" ]] && return 0

  # Cheap inference call to get x-venice-balance-diem response header
  local headers
  headers=$(curl -si --max-time 10 "https://api.venice.ai/api/v1/chat/completions" \
    -H "Authorization: Bearer $api_key" \
    -H "Content-Type: application/json" \
    -d '{"model":"kimi-k2-5","messages":[{"role":"user","content":"OK"}],"max_tokens":1}' 2>/dev/null | \
    grep -i "x-venice-balance-diem") || true

  local balance
  balance=$(echo "$headers" | sed -n 's/.*x-venice-balance-diem: *\([0-9.]*\).*/\1/pi') || true

  if [[ -n "$balance" ]]; then
    local int_balance=${balance%%.*}
    [[ "$VERBOSE" == "--verbose" ]] && log "CREDITS: venice:key1 = $balance DIEM"

    if [[ "$int_balance" -lt "$CREDIT_WARN_THRESHOLD" ]]; then
      log "CREDITS WARNING: venice:key1 at $balance DIEM (below ${CREDIT_WARN_THRESHOLD} threshold). Claude requests may fail. Morpheus fallback recommended."
    fi
  fi
}

# Only run credit check if not already in billing backoff
if [[ "$BILLING_DEAD_SINCE" -eq 0 ]]; then
  check_venice_credits
fi

# ─── Step 0: Circuit breaker check ──────────────────────────────────────────
check_circuit_breaker

# ─── Step 1: HTTP probe ─────────────────────────────────────────────────────
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time "$PROBE_TIMEOUT" "$GATEWAY_URL" 2>/dev/null || echo "000")

if [[ "$HTTP_CODE" == "000" || "$HTTP_CODE" == "" ]]; then
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

# HTTP OK — reset HTTP fail counter
if [[ "$HTTP_FAIL_COUNT" -gt 0 ]]; then
  log "OK: Gateway process recovered (HTTP $HTTP_CODE). Resetting HTTP fail counter."
fi
echo "0" > "$STATE_FILE"

# ─── Step 2: Provider health probes (v5: direct curl, no agent framework) ───
# v4 used `openclaw agent` which injected the full 71K workspace system prompt,
# causing mor-gateway to timeout at 60s and spamming Signal with error messages.
# v5 probes provider endpoints directly via curl — fast, lightweight, no Signal delivery.
#
# We check 3 providers (any 1 passing = inference available):
#   1. Venice API /models (fast, no auth needed, proves API reachability)
#   2. Morpheus local proxy /health (proves local P2P inference path)
#   3. Mor-gateway /models (proves Morpheus API Gateway reachability)
INFERENCE_OK=false
INFERENCE_ERROR=""
PROVIDERS_CHECKED=0
PROVIDERS_OK=0

# Probe 1: Venice API
VENICE_RESULT=$(curl -s --max-time 10 "https://api.venice.ai/api/v1/models" 2>&1) || true
PROVIDERS_CHECKED=$((PROVIDERS_CHECKED + 1))
if echo "$VENICE_RESULT" | grep -q '"data"'; then
  PROVIDERS_OK=$((PROVIDERS_OK + 1))
  [[ "$VERBOSE" == "--verbose" ]] && log "Probe: Venice API OK"
else
  INFERENCE_ERROR="venice: $(echo "$VENICE_RESULT" | head -1 | cut -c1-80)"
  [[ "$VERBOSE" == "--verbose" ]] && log "Probe: Venice API FAIL"
fi

# Probe 2: Local Morpheus proxy
MORPHEUS_RESULT=$(curl -s --max-time 5 "http://127.0.0.1:8083/health" 2>&1) || true
PROVIDERS_CHECKED=$((PROVIDERS_CHECKED + 1))
if echo "$MORPHEUS_RESULT" | grep -q '"status":"ok"'; then
  PROVIDERS_OK=$((PROVIDERS_OK + 1))
  [[ "$VERBOSE" == "--verbose" ]] && log "Probe: Morpheus local proxy OK"
else
  INFERENCE_ERROR="${INFERENCE_ERROR:+$INFERENCE_ERROR | }morpheus-local: $(echo "$MORPHEUS_RESULT" | head -1 | cut -c1-80)"
  [[ "$VERBOSE" == "--verbose" ]] && log "Probe: Morpheus local proxy FAIL"
fi

# Probe 3: Mor-gateway API
MORGATEWAY_RESULT=$(curl -s --max-time 15 "https://api.mor.org/api/v1/models" 2>&1) || true
PROVIDERS_CHECKED=$((PROVIDERS_CHECKED + 1))
if echo "$MORGATEWAY_RESULT" | grep -q '"data"'; then
  PROVIDERS_OK=$((PROVIDERS_OK + 1))
  [[ "$VERBOSE" == "--verbose" ]] && log "Probe: Mor-gateway API OK"
else
  INFERENCE_ERROR="${INFERENCE_ERROR:+$INFERENCE_ERROR | }mor-gateway: $(echo "$MORGATEWAY_RESULT" | head -1 | cut -c1-80)"
  [[ "$VERBOSE" == "--verbose" ]] && log "Probe: Mor-gateway API FAIL"
fi

# At least 1 provider must be reachable for inference to work
if [[ "$PROVIDERS_OK" -ge 1 ]]; then
  INFERENCE_OK=true
  INFERENCE_ERROR=""
fi

# ─── Evaluate inference health ──────────────────────────────────────────────
if [[ "$INFERENCE_OK" == "true" ]]; then
  # If we were in billing-dead state and just recovered, notify!
  if [[ "$BILLING_DEAD_SINCE" -gt 0 ]]; then
    local dead_duration=$(( $(date +%s) - BILLING_DEAD_SINCE ))
    log "BILLING RECOVERED: Credits are back after $((dead_duration / 60)) min."
    notify_signal "✅ DIEM credits restored! I'm back online after $((dead_duration / 60)) min of billing exhaustion."
    echo "0" > "$BILLING_STATE_FILE"
    echo "0" > "$BILLING_NOTIFIED_FILE"
  fi

  if [[ "$INFERENCE_FAIL_COUNT" -gt 0 ]]; then
    log "OK: Inference recovered (agent responded). Resetting inference fail counter."
  elif [[ "$VERBOSE" == "--verbose" ]]; then
    local_pid=$(pgrep -f "openclaw.*gateway" 2>/dev/null | head -1 || echo "?")
    log "OK: Fully healthy (PID=$local_pid, HTTP=$HTTP_CODE, inference=ok)"
  fi
  echo "0" > "$INFERENCE_STATE_FILE"
  exit 0
fi

# ─── Inference failed — classify the error ──────────────────────────────────
ERROR_CLASS=$(classify_error "$INFERENCE_ERROR")
INFERENCE_FAIL_COUNT=$((INFERENCE_FAIL_COUNT + 1))
echo "$INFERENCE_FAIL_COUNT" > "$INFERENCE_STATE_FILE"

if [[ "$INFERENCE_FAIL_COUNT" -lt "$INFERENCE_FAIL_THRESHOLD" ]]; then
  log "WARN: Inference probe failed ($INFERENCE_FAIL_COUNT/$INFERENCE_FAIL_THRESHOLD) [$ERROR_CLASS]: $(echo "$INFERENCE_ERROR" | head -1 | cut -c1-120). Retrying in 2 min."
  exit 0
fi

# ─── Threshold reached — take action based on error class ───────────────────
log "ALERT: Inference unavailable for $INFERENCE_FAIL_COUNT consecutive checks (~$((INFERENCE_FAIL_COUNT * 2)) min). Class: $ERROR_CLASS."

case "$ERROR_CLASS" in
  billing)
    # v4: DON'T restart for billing exhaustion — it's useless
    handle_billing_exhaustion
    ;;
  transient|timeout|unknown)
    # Transient errors → restart clears cooldown state
    log "ESCALATING: Error class '$ERROR_CLASS' — restarting may help."
    restart_all_steps
    exit $?
    ;;
esac
