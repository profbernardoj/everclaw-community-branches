#!/bin/bash
# Gateway Guardian v3 — monitors OpenClaw gateway + ACTUAL inference capability
#
# v1: Only checked if HTTP dashboard was up (useless when providers in cooldown)
# v2: Probed provider endpoints directly (Venice /models, Morpheus /health)
#     PROBLEM: Provider APIs always respond 200 — the issue is OpenClaw's internal
#     auth profiles being disabled/in-cooldown. v2 couldn't see that.
# v3: Probes THROUGH OpenClaw using `openclaw agent` with a throwaway session.
#     This tests the FULL stack: gateway → auth profile → provider → inference.
#     Also adds circuit breaker for stuck sub-agents burning credits.
#
# Install: launchd plist at ~/Library/LaunchAgents/ai.openclaw.guardian.plist
# Test:    bash ~/.openclaw/workspace/scripts/gateway-guardian.sh --verbose

set -euo pipefail

# ─── macOS compatibility ─────────────────────────────────────────────────────
# macOS lacks `timeout` and `gtimeout`. Use perl alarm as portable alternative.
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

PROBE_TIMEOUT=8
INFERENCE_TIMEOUT=45      # OpenClaw agent probe needs more time
FAIL_THRESHOLD=2          # consecutive HTTP failures before restart
INFERENCE_FAIL_THRESHOLD=3 # consecutive inference failures before escalation (~6 min)
MAX_LOG_LINES=1000
VERBOSE="${1:-}"

# Circuit breaker config
MAX_STUCK_DURATION_SEC=1800  # 30 minutes — kill sub-agents stuck longer than this
STUCK_CHECK_INTERVAL=300     # Only check for stuck agents every 5 min (not every 2 min run)

# Notification settings
OWNER_SIGNAL="+1XXXXXXXXXX"

# Install script URL for nuclear option
INSTALL_URL="https://clawd.bot/install.sh"

# Guardian probe session — isolated from main session to avoid pollution
GUARDIAN_SESSION_ID="guardian-health-probe"

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

LAST_CIRCUIT_CHECK=0
[[ -f "$CIRCUIT_BREAKER_FILE" ]] && LAST_CIRCUIT_CHECK=$(cat "$CIRCUIT_BREAKER_FILE" 2>/dev/null || echo 0)

# ─── Circuit Breaker: Kill stuck sub-agents ─────────────────────────────────
# Sub-agents that timeout repeatedly burn through API credits and auth profiles.
# If a sub-agent has been running for >30 min with repeated timeouts, kill it.
check_circuit_breaker() {
  local now
  now=$(date +%s)
  
  # Only run this check every 5 minutes (not every 2 min guardian run)
  if [[ $((now - LAST_CIRCUIT_CHECK)) -lt $STUCK_CHECK_INTERVAL ]]; then
    return 0
  fi
  echo "$now" > "$CIRCUIT_BREAKER_FILE"
  
  [[ "$VERBOSE" == "--verbose" ]] && log "Circuit breaker: checking for stuck sub-agents..."
  
  # Parse gateway error log for stuck runs
  # Pattern: repeated "embedded run timeout" for the same runId over >30 min
  local err_log="$HOME/.openclaw/logs/gateway.err.log"
  [[ ! -f "$err_log" ]] && return 0
  
  # Find runIds with timeout errors in the last hour
  local stuck_runs
  stuck_runs=$(grep -E "embedded run timeout.*runId=" "$err_log" 2>/dev/null | \
    grep -E "$(date -v-1H '+%Y-%m-%dT%H')|$(date '+%Y-%m-%dT%H')" | \
    sed -n 's/.*runId=\([^ ]*\).*/\1/p' | sort | uniq -c | sort -rn | head -5)
  
  if [[ -z "$stuck_runs" ]]; then
    [[ "$VERBOSE" == "--verbose" ]] && log "Circuit breaker: no stuck sub-agents found."
    return 0
  fi
  
  # Check each run with multiple timeouts
  while read -r count runId; do
    [[ -z "$runId" ]] && continue
    [[ "$count" -lt 3 ]] && continue  # Need at least 3 timeouts to consider stuck
    
    # Get timestamps of first and last timeout for this runId
    local first_timeout last_timeout
    first_timeout=$(grep "runId=$runId" "$err_log" | head -1 | cut -d' ' -f1 | cut -dT -f2 | cut -d. -f1)
    last_timeout=$(grep "runId=$runId" "$err_log" | tail -1 | cut -d' ' -f1 | cut -dT -f2 | cut -d. -f1)
    
    # Calculate duration (rough — just check if count * 10min > threshold)
    # Each timeout is ~10 min, so 3+ timeouts = 30+ min stuck
    local est_duration=$((count * 600))  # 10 min per timeout
    
    if [[ "$est_duration" -ge "$MAX_STUCK_DURATION_SEC" ]]; then
      log "CIRCUIT BREAKER: Run $runId has been timing out for ~$((est_duration / 60)) min ($count timeouts). Killing..."
      
      # Try to terminate the session via openclaw CLI
      # This is best-effort — the session might already be in a bad state
      if openclaw cron list --json 2>/dev/null | grep -q "$runId"; then
        log "Circuit breaker: Found as cron run, attempting to stop..."
        # Can't directly kill cron runs, but restarting gateway will clear them
      fi
      
      # The nuclear option for stuck runs: restart the gateway
      # This clears all in-memory state including stuck runs and cooldowns
      log "Circuit breaker: Triggering graceful restart to clear stuck run..."
      do_graceful_restart
      return 0
    fi
  done <<< "$stuck_runs"
  
  [[ "$VERBOSE" == "--verbose" ]] && log "Circuit breaker: no runs exceed ${MAX_STUCK_DURATION_SEC}s threshold."
  return 0
}

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

  # Notify owner before going nuclear
  local signal_bin
  signal_bin=$(which signal-cli 2>/dev/null || echo "")
  if [[ -n "$signal_bin" ]]; then
    log "Notifying owner via Signal before nuclear restart..."
    "$signal_bin" -a "$OWNER_SIGNAL" send \
      -m "🚨 Gateway Guardian: All providers in cooldown for $((INFERENCE_FAIL_COUNT * 2))+ min. Executing nuclear reinstall now." \
      "$OWNER_SIGNAL" 2>/dev/null || true
  fi

  log "Executing: curl -fsSL $INSTALL_URL | bash"
  if curl -fsSL "$INSTALL_URL" | bash >> "$LOG_FILE" 2>&1; then
    sleep 15

    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time "$PROBE_TIMEOUT" "$GATEWAY_URL" 2>/dev/null || echo "000")
    if [[ "$http_code" != "000" ]]; then
      log "RECOVERED: Nuclear reinstall succeeded (HTTP $http_code). Cooldown states reset."
      echo "0" > "$INFERENCE_STATE_FILE"
      echo "0" > "$STATE_FILE"

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

# HTTP is OK — reset HTTP fail counter
if [[ "$HTTP_FAIL_COUNT" -gt 0 ]]; then
  log "OK: Gateway process recovered (HTTP $HTTP_CODE). Resetting HTTP fail counter."
fi
echo "0" > "$STATE_FILE"

# ─── Step 2: Inference probe (v3 — through OpenClaw) ────────────────────────
# v2 probed raw provider URLs (Venice /models) — but those always return 200.
# The real failure is OpenClaw's internal auth profiles being disabled/cooldown.
# v3 probes THROUGH OpenClaw by running a lightweight agent request.
# This tests: gateway → auth selection → provider → inference → response.

INFERENCE_OK=false
INFERENCE_ERROR=""

# Use `openclaw agent` with a throwaway session to test the full inference stack.
# The --timeout flag limits how long we wait. If all providers are in cooldown,
# this will fail with "No available auth profile" or similar.
# We use glm-4.7-flash (cheapest model) to minimize cost.

# Use --thinking off to minimize cost. The agent will use whatever model is
# configured for the default fallback chain. The point is to test auth profiles.
AGENT_RESULT=$(run_with_timeout "$INFERENCE_TIMEOUT" openclaw agent \
  --session-id "$GUARDIAN_SESSION_ID" \
  --message "Reply with exactly one word: ALIVE" \
  --thinking off \
  --json 2>&1) || AGENT_RESULT=""

if echo "$AGENT_RESULT" | grep -qi "ALIVE"; then
  INFERENCE_OK=true
  INFERENCE_ERROR=""
elif echo "$AGENT_RESULT" | grep -qi "No available auth profile\|all in cooldown\|billing error\|credits"; then
  INFERENCE_ERROR="auth_cooldown"
elif echo "$AGENT_RESULT" | grep -qi "timed out\|timeout"; then
  INFERENCE_ERROR="timeout"
elif echo "$AGENT_RESULT" | grep -qi "error\|failed"; then
  INFERENCE_ERROR="error: $(echo "$AGENT_RESULT" | head -1 | cut -c1-100)"
else
  # Empty or unexpected result
  INFERENCE_ERROR="unknown: $(echo "$AGENT_RESULT" | head -1 | cut -c1-50)"
fi

# ─── Evaluate inference health ──────────────────────────────────────────────
if [[ "$INFERENCE_OK" == "true" ]]; then
  if [[ "$INFERENCE_FAIL_COUNT" -gt 0 ]]; then
    log "OK: Inference recovered (agent responded). Resetting inference fail counter."
  elif [[ "$VERBOSE" == "--verbose" ]]; then
    local_pid=$(pgrep -f "openclaw.*gateway" 2>/dev/null | head -1 || echo "?")
    log "OK: Fully healthy (PID=$local_pid, HTTP=$HTTP_CODE, inference=ok)"
  fi
  echo "0" > "$INFERENCE_STATE_FILE"
  exit 0
fi

# Inference failed
INFERENCE_FAIL_COUNT=$((INFERENCE_FAIL_COUNT + 1))
echo "$INFERENCE_FAIL_COUNT" > "$INFERENCE_STATE_FILE"

if [[ "$INFERENCE_FAIL_COUNT" -lt "$INFERENCE_FAIL_THRESHOLD" ]]; then
  log "WARN: Inference probe failed ($INFERENCE_FAIL_COUNT/$INFERENCE_FAIL_THRESHOLD): $INFERENCE_ERROR. Retrying in 2 min."
  exit 0
fi

# ─── Inference dead for too long — escalate ─────────────────────────────────
log "ALERT: Inference unavailable for $INFERENCE_FAIL_COUNT consecutive checks (~$((INFERENCE_FAIL_COUNT * 2)) min). Error: $INFERENCE_ERROR. Escalating..."

# Key insight: restarting the gateway clears OpenClaw's in-memory cooldown/disabled state.
# After restart, auth profiles reset and the agent can try providers fresh.
restart_all_steps
exit $?
