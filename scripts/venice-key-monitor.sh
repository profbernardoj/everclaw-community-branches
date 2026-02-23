#!/bin/bash
# Venice Key Health Monitor v2.0
# Proactively checks DIEM balance on all Venice API keys.
# When a key hits 0 (or below threshold), disables it in auth-profiles.json
# so OpenClaw never tries it and immediately uses the next key.
#
# Design: Reads all venice:* profiles from auth-profiles.json, makes a cheap
# GLM-4.7-Flash inference call (1 token) per key, reads x-venice-balance-diem
# header, and disables depleted keys by writing disabledUntil/disabledReason.
#
# Usage:
#   bash venice-key-monitor.sh              # Check all keys, disable depleted
#   bash venice-key-monitor.sh --status     # Report balances without changes
#   bash venice-key-monitor.sh --verbose    # Detailed output
#   bash venice-key-monitor.sh --threshold 5  # Custom depletion threshold (default: 1)

set -uo pipefail

# ─── Configuration ───────────────────────────────────────────────────────────
AGENT_DIR="${OPENCLAW_AGENT_DIR:-$HOME/.openclaw/agents/main/agent}"
AUTH_PROFILES="$AGENT_DIR/auth-profiles.json"
VENICE_API="https://api.venice.ai/api/v1/chat/completions"
# GLM-4.7-Flash is cheapest: 0.125 DIEM/M input, 0.5 DIEM/M output
# A 1-token probe costs ~0.0001 DIEM
PROBE_MODEL="zai-org-glm-4.7-flash"
PROBE_TIMEOUT=15
DIEM_THRESHOLD="${DIEM_THRESHOLD:-1}"
LOG_FILE="$HOME/.openclaw/logs/venice-key-monitor.log"
STATE_FILE="$HOME/.openclaw/logs/venice-key-balances.json"

# Notification
OWNER_SIGNAL="${OWNER_SIGNAL:-+1XXXXXXXXXX}"

# Parse args
VERBOSE=""
STATUS_ONLY=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --verbose) VERBOSE=1; shift ;;
    --status) STATUS_ONLY=1; shift ;;
    --threshold) DIEM_THRESHOLD="$2"; shift 2 ;;
    *) shift ;;
  esac
done

# ─── Helpers ─────────────────────────────────────────────────────────────────
log() {
  local ts
  ts=$(date '+%Y-%m-%d %H:%M:%S')
  echo "$ts [venice-monitor] $*" >> "$LOG_FILE"
  [[ -n "$VERBOSE" ]] && echo "$ts [venice-monitor] $*"
}

ensure_log_dir() {
  mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
  mkdir -p "$(dirname "$STATE_FILE")" 2>/dev/null || true
}

# ─── Read Venice keys from auth-profiles.json ────────────────────────────────
get_venice_profiles() {
  python3 -c "
import json, sys
try:
    with open('$AUTH_PROFILES') as f:
        data = json.load(f)
    profiles = data.get('profiles', data)
    for pid, cred in profiles.items():
        if pid.startswith('venice:') and cred.get('type') == 'api_key':
            print(f\"{pid}|{cred['key']}\")
except Exception as e:
    print(f'ERROR|{e}', file=sys.stderr)
    sys.exit(1)
"
}

# ─── Probe a single key's DIEM balance ───────────────────────────────────────
probe_balance() {
  local key="$1"
  # Make a minimal inference call and capture response headers
  local body_file
  body_file=$(mktemp)
  local headers
  headers=$(curl -s -o "$body_file" -D - \
    --max-time "$PROBE_TIMEOUT" \
    "$VENICE_API" \
    -H "Authorization: Bearer $key" \
    -H "Content-Type: application/json" \
    -d "{\"model\":\"$PROBE_MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\".\"}],\"max_tokens\":1,\"stream\":false}" \
    2>/dev/null)

  local status
  status=$(echo "$headers" | head -1 | grep -oE '[0-9]{3}' | head -1)
  local body
  body=$(cat "$body_file" 2>/dev/null)
  rm -f "$body_file"

  # Check for 402 specifically — covers both balance depletion and per-key spend limits
  if [[ "$status" == "402" ]]; then
    # Distinguish between balance depletion and per-key spend limit
    if echo "$body" | grep -qi "spend limit"; then
      echo "0|402_SPEND_LIMIT"
    else
      echo "0|402"
    fi
    return 0
  fi

  # Extract balance from header (DIEM or USD — Venice uses both depending on account type)
  local balance
  balance=$(echo "$headers" | grep -i "x-venice-balance-diem" | sed 's/.*: *//' | tr -d '\r\n ')
  if [[ -z "$balance" ]]; then
    balance=$(echo "$headers" | grep -i "x-venice-balance-usd" | sed 's/.*: *//' | tr -d '\r\n ')
  fi

  if [[ -z "$balance" ]]; then
    echo "UNKNOWN|$status"
    return 1
  fi

  echo "$balance|$status"
  return 0
}

# ─── Disable a profile in auth-profiles.json ─────────────────────────────────
disable_profile() {
  local profile_id="$1"
  local balance="$2"
  local disable_until
  # Disable for 6 hours (matches billingMaxHours config)
  disable_until=$(python3 -c "import time; print(int((time.time() + 21600) * 1000))")

  python3 -c "
import json, sys, fcntl

path = '$AUTH_PROFILES'
profile_id = '$profile_id'
disable_until = $disable_until

with open(path, 'r+') as f:
    fcntl.flock(f, fcntl.LOCK_EX)
    data = json.load(f)

    # Initialize usageStats if needed
    if 'usageStats' not in data:
        data['usageStats'] = {}
    if profile_id not in data['usageStats']:
        data['usageStats'][profile_id] = {}

    stats = data['usageStats'][profile_id]
    stats['disabledUntil'] = disable_until
    stats['disabledReason'] = 'billing'

    # Track billing failure count
    if 'failureCounts' not in stats:
        stats['failureCounts'] = {}
    billing_count = stats['failureCounts'].get('billing', 0)
    stats['failureCounts']['billing'] = billing_count + 1
    stats['errorCount'] = stats.get('errorCount', 0) + 1
    
    import time
    stats['lastFailureAt'] = int(time.time() * 1000)

    f.seek(0)
    json.dump(data, f, indent=2)
    f.truncate()
    fcntl.flock(f, fcntl.LOCK_UN)

print(f'OK: {profile_id} disabled until {disable_until}')
" 2>&1
}

# ─── Re-enable a profile that has recovered ──────────────────────────────────
reenable_profile() {
  local profile_id="$1"

  python3 -c "
import json, sys, fcntl

path = '$AUTH_PROFILES'
profile_id = '$profile_id'

with open(path, 'r+') as f:
    fcntl.flock(f, fcntl.LOCK_EX)
    data = json.load(f)

    stats = data.get('usageStats', {}).get(profile_id, {})
    changed = False

    if stats.get('disabledReason') == 'billing' and stats.get('disabledUntil'):
        stats.pop('disabledUntil', None)
        stats.pop('disabledReason', None)
        stats['errorCount'] = 0
        if 'failureCounts' in stats:
            stats['failureCounts'].pop('billing', None)
        changed = True

    if changed:
        f.seek(0)
        json.dump(data, f, indent=2)
        f.truncate()
        print(f'OK: {profile_id} re-enabled')
    else:
        print(f'SKIP: {profile_id} not billing-disabled')

    fcntl.flock(f, fcntl.LOCK_UN)
" 2>&1
}

# ─── Save state for reporting ────────────────────────────────────────────────
save_state() {
  local json="$1"
  echo "$json" > "$STATE_FILE"
}

# ─── Main ────────────────────────────────────────────────────────────────────
main() {
  ensure_log_dir

  if [[ ! -f "$AUTH_PROFILES" ]]; then
    log "ERROR: auth-profiles.json not found at $AUTH_PROFILES"
    exit 1
  fi

  log "Starting Venice key health check (threshold: ${DIEM_THRESHOLD} DIEM)"

  local profiles
  profiles=$(get_venice_profiles)
  if [[ -z "$profiles" ]]; then
    log "No Venice profiles found"
    exit 0
  fi

  local total=0
  local depleted=0
  local healthy=0
  local errors=0
  local depleted_keys=""
  local recovered_keys=""
  local state_json="{"
  local first=1

  while IFS='|' read -r profile_id api_key; do
    total=$((total + 1))

    # Space probes by 2+ seconds (Venice rate limit)
    if [[ $total -gt 1 ]]; then
      sleep 2
    fi

    local result
    result=$(probe_balance "$api_key")
    local balance
    local status
    balance=$(echo "$result" | cut -d'|' -f1)
    status=$(echo "$result" | cut -d'|' -f2)

    # Build state JSON
    if [[ $first -eq 0 ]]; then state_json="$state_json,"; fi
    first=0

    if [[ "$balance" == "UNKNOWN" ]]; then
      log "WARN: Could not probe $profile_id (HTTP $status)"
      state_json="$state_json\"$profile_id\":{\"balance\":null,\"status\":$status,\"healthy\":null}"
      errors=$((errors + 1))
      continue
    fi

    local balance_float
    balance_float=$(echo "$balance" | sed 's/[^0-9.]//g')
    if [[ -z "$balance_float" ]]; then balance_float="0"; fi

    state_json="$state_json\"$profile_id\":{\"balance\":$balance_float,\"status\":$status,\"healthy\":"

    # Check if depleted
    local is_depleted
    is_depleted=$(python3 -c "print('yes' if float('$balance_float') < float('$DIEM_THRESHOLD') else 'no')")

    if [[ "$is_depleted" == "yes" ]]; then
      depleted=$((depleted + 1))
      state_json="${state_json}false}"
      if [[ "$status" == "402_SPEND_LIMIT" ]]; then
        log "SPEND_LIMIT: $profile_id — per-key DIEM spending limit reached (account may still have balance)"
      else
        log "DEPLETED: $profile_id — ${balance_float} DIEM (below threshold ${DIEM_THRESHOLD})"
      fi

      if [[ -z "$STATUS_ONLY" ]]; then
        local disable_result
        disable_result=$(disable_profile "$profile_id" "$balance_float")
        log "DISABLED: $disable_result"
        depleted_keys="${depleted_keys}${profile_id} (${balance_float} DIEM)\n"
      fi
    else
      healthy=$((healthy + 1))
      state_json="${state_json}true}"
      log "HEALTHY: $profile_id — ${balance_float} DIEM"

      # Check if this key was previously billing-disabled and has recovered
      if [[ -z "$STATUS_ONLY" ]]; then
        local reenable_result
        reenable_result=$(reenable_profile "$profile_id")
        if echo "$reenable_result" | grep -q "re-enabled"; then
          log "RECOVERED: $reenable_result"
          recovered_keys="${recovered_keys}${profile_id} (${balance_float} DIEM)\n"
        fi
      fi
    fi

  done <<< "$profiles"

  state_json="$state_json}"

  # Save state
  local timestamp
  timestamp=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
  local full_state="{\"timestamp\":\"$timestamp\",\"threshold\":$DIEM_THRESHOLD,\"total\":$total,\"healthy\":$healthy,\"depleted\":$depleted,\"errors\":$errors,\"keys\":$state_json}"
  save_state "$full_state"

  # Summary
  log "Complete: $total keys checked — $healthy healthy, $depleted depleted, $errors errors"

  # Output for cron/caller
  echo "$full_state"

  # Return non-zero if all keys depleted (for alerting)
  if [[ $healthy -eq 0 && $total -gt 0 ]]; then
    log "CRITICAL: All Venice keys depleted!"
    return 2
  fi

  return 0
}

main "$@"
