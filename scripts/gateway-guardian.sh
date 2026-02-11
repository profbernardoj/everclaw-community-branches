#!/bin/bash
# Gateway Guardian — monitors OpenClaw gateway and restarts if truly unresponsive
#
# Strategy: Simple HTTP probe only. If the dashboard responds, the gateway is alive.
# Avoids expensive RPC probes that can false-alarm under load.
#
# Three consecutive failures required before restart (avoids flapping).
#
# Install as system cron (every 2 minutes):
#   crontab -e
#   */2 * * * * /Users/bernardo/.openclaw/workspace/scripts/gateway-guardian.sh
#
# Test: bash ~/.openclaw/workspace/scripts/gateway-guardian.sh --verbose

GATEWAY_PORT="${OPENCLAW_GATEWAY_PORT:-18789}"
GATEWAY_URL="http://127.0.0.1:${GATEWAY_PORT}/"
LAUNCHD_LABEL="ai.openclaw.gateway"
LOG_FILE="$HOME/.openclaw/logs/guardian.log"
STATE_FILE="$HOME/.openclaw/logs/guardian.state"
PROBE_TIMEOUT=8
FAIL_THRESHOLD=2  # consecutive failures before restart
MAX_LOG_LINES=500
VERBOSE="${1:-}"

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

# Read consecutive failure count
FAIL_COUNT=0
[[ -f "$STATE_FILE" ]] && FAIL_COUNT=$(cat "$STATE_FILE" 2>/dev/null || echo 0)

# HTTP probe — the only check that matters
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time "$PROBE_TIMEOUT" "$GATEWAY_URL" 2>/dev/null || echo "000")

if [[ "$HTTP_CODE" != "000" && "$HTTP_CODE" != "" ]]; then
  # Gateway is responding
  if [[ "$FAIL_COUNT" -gt 0 ]]; then
    log "OK: Gateway recovered (HTTP $HTTP_CODE). Resetting fail counter."
  elif [[ "$VERBOSE" == "--verbose" ]]; then
    PID=$(launchctl list "$LAUNCHD_LABEL" 2>/dev/null | grep '"PID"' | sed 's/[^0-9]//g' || true)
    log "OK: Gateway healthy (PID=${PID:-?}, HTTP=$HTTP_CODE)"
  fi
  echo "0" > "$STATE_FILE"
  exit 0
fi

# Probe failed
FAIL_COUNT=$((FAIL_COUNT + 1))
echo "$FAIL_COUNT" > "$STATE_FILE"

if [[ "$FAIL_COUNT" -lt "$FAIL_THRESHOLD" ]]; then
  log "WARN: HTTP probe failed ($FAIL_COUNT/$FAIL_THRESHOLD). Will retry next run."
  exit 0
fi

# Threshold reached — restart
log "ALERT: Gateway unresponsive ($FAIL_COUNT consecutive failures). Restarting..."

# Step 1: Try graceful restart via openclaw
if openclaw gateway restart 2>/dev/null; then
  sleep 8
  VERIFY=$(curl -s -o /dev/null -w "%{http_code}" --max-time "$PROBE_TIMEOUT" "$GATEWAY_URL" 2>/dev/null || echo "000")
  if [[ "$VERIFY" != "000" ]]; then
    log "RECOVERED: Graceful restart succeeded (HTTP $VERIFY)."
    echo "0" > "$STATE_FILE"
    exit 0
  fi
fi

# Step 2: Hard kill + let launchd KeepAlive restart
log "Graceful restart failed. Hard killing gateway process..."
PID=$(launchctl list "$LAUNCHD_LABEL" 2>/dev/null | grep '"PID"' | sed 's/[^0-9]//g' || true)
if [[ -n "$PID" ]]; then
  kill -9 "$PID" 2>/dev/null || true
fi
# Also kill by pattern in case launchd tracking is stale
pkill -9 -f "openclaw.*gateway" 2>/dev/null || true

sleep 10

# Verify launchd restarted it
VERIFY=$(curl -s -o /dev/null -w "%{http_code}" --max-time "$PROBE_TIMEOUT" "$GATEWAY_URL" 2>/dev/null || echo "000")
if [[ "$VERIFY" != "000" ]]; then
  log "RECOVERED: Hard restart succeeded (HTTP $VERIFY)."
  echo "0" > "$STATE_FILE"
  exit 0
fi

# Step 3: Force launchctl kickstart
log "Launchd didn't auto-restart. Forcing kickstart..."
launchctl kickstart -k "gui/$(id -u)/$LAUNCHD_LABEL" 2>/dev/null || true
sleep 8

VERIFY=$(curl -s -o /dev/null -w "%{http_code}" --max-time "$PROBE_TIMEOUT" "$GATEWAY_URL" 2>/dev/null || echo "000")
if [[ "$VERIFY" != "000" ]]; then
  log "RECOVERED: Kickstart succeeded (HTTP $VERIFY)."
  echo "0" > "$STATE_FILE"
else
  log "CRITICAL: All restart attempts failed. Manual intervention needed."
fi
