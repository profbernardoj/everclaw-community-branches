#!/bin/bash
# Venice 402 Reactive Watchdog v2.0
# Tails OpenClaw gateway logs for Venice billing errors (402 / "Insufficient USD
# or Diem balance") and immediately disables the offending key in auth-profiles.json.
#
# Problem: OpenClaw's billing error pattern matching checks for "insufficient balance"
# but Venice returns "Insufficient USD or Diem balance to complete request" — the words
# aren't adjacent, so the pattern fails. The error gets classified as "unknown" with a
# 60-second cooldown instead of a billing disable. After cooldown, the same empty key
# gets retried in a loop.
#
# Fix: This watchdog detects the Venice-specific error patterns and directly writes
# the billing disable to auth-profiles.json, forcing OpenClaw to rotate to the next key.
#
# Usage:
#   bash venice-402-watchdog.sh              # Run once (scan recent logs)
#   bash venice-402-watchdog.sh --daemon     # Run continuously (tail logs)
#   bash venice-402-watchdog.sh --verbose    # Detailed output
#
# Install as launchd:
#   See templates/ai.openclaw.venice-watchdog.plist

set -uo pipefail

# ─── Configuration ───────────────────────────────────────────────────────────
AGENT_DIR="${OPENCLAW_AGENT_DIR:-$HOME/.openclaw/agents/main/agent}"
AUTH_PROFILES="$AGENT_DIR/auth-profiles.json"
OPENCLAW_CONFIG="$HOME/.openclaw/openclaw.json"
LOG_DIR="$HOME/.openclaw/logs"
WATCHDOG_LOG="$LOG_DIR/venice-402-watchdog.log"
WATCHDOG_STATE="$LOG_DIR/venice-402-state.json"

# How far back to scan in one-shot mode (seconds)
SCAN_WINDOW=300

# Patterns that indicate Venice billing exhaustion
# These are the patterns OpenClaw MISSES
VENICE_402_PATTERNS=(
  "Insufficient USD or Diem balance"
  "Insufficient USD or DIEM balance"
  "insufficient usd or diem balance"
  "402.*Insufficient.*balance"
  "402.*Payment Required"
  "Insufficient.*Diem.*balance"
  "Insufficient.*USD.*balance"
  "DIEM spend limit exceeded"
  "diem spend limit exceeded"
  "API key DIEM spend limit"
  "reached its configured DIEM spending limit"
)

# Parse args
VERBOSE=""
DAEMON=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --verbose) VERBOSE=1; shift ;;
    --daemon) DAEMON=1; shift ;;
    *) shift ;;
  esac
done

# ─── Helpers ─────────────────────────────────────────────────────────────────
log() {
  local ts
  ts=$(date '+%Y-%m-%d %H:%M:%S')
  echo "$ts [402-watchdog] $*" >> "$WATCHDOG_LOG"
  [[ -n "$VERBOSE" ]] && echo "$ts [402-watchdog] $*"
}

ensure_dirs() {
  mkdir -p "$LOG_DIR" 2>/dev/null || true
}

# ─── Identify which Venice key was active when the error occurred ────────────
# Strategy: read auth-profiles.json usageStats, find the venice key with the
# most recent lastUsed timestamp that ISN'T already billing-disabled
identify_active_key() {
  python3 -c "
import json, sys, time

with open('$AUTH_PROFILES') as f:
    data = json.load(f)

profiles = data.get('profiles', data)
stats = data.get('usageStats', {})
now_ms = int(time.time() * 1000)

# Get all Venice profiles
venice_keys = []
for pid, cred in profiles.items():
    if not pid.startswith('venice:'):
        continue
    s = stats.get(pid, {})
    # Skip already billing-disabled keys
    disabled_until = s.get('disabledUntil', 0)
    if disabled_until and disabled_until > now_ms and s.get('disabledReason') == 'billing':
        continue
    last_used = s.get('lastUsed', 0)
    venice_keys.append((pid, last_used))

if not venice_keys:
    print('NONE')
    sys.exit(0)

# Sort by lastUsed descending — most recently used is most likely the offender
venice_keys.sort(key=lambda x: x[1], reverse=True)
print(venice_keys[0][0])
"
}

# ─── Disable the offending key ───────────────────────────────────────────────
disable_key() {
  local profile_id="$1"
  local reason="$2"

  python3 -c "
import json, sys, fcntl, time

path = '$AUTH_PROFILES'
profile_id = '$profile_id'
now_ms = int(time.time() * 1000)
# 6 hours disable (matches billingMaxHours)
disable_until = now_ms + (6 * 3600 * 1000)

with open(path, 'r+') as f:
    fcntl.flock(f, fcntl.LOCK_EX)
    data = json.load(f)

    if 'usageStats' not in data:
        data['usageStats'] = {}
    if profile_id not in data['usageStats']:
        data['usageStats'][profile_id] = {}

    stats = data['usageStats'][profile_id]

    # Check if already disabled
    existing_disabled = stats.get('disabledUntil', 0)
    if existing_disabled and existing_disabled > now_ms and stats.get('disabledReason') == 'billing':
        print(f'ALREADY_DISABLED:{profile_id}')
        fcntl.flock(f, fcntl.LOCK_UN)
        sys.exit(0)

    stats['disabledUntil'] = disable_until
    stats['disabledReason'] = 'billing'
    stats['lastFailureAt'] = now_ms
    stats['errorCount'] = stats.get('errorCount', 0) + 1

    if 'failureCounts' not in stats:
        stats['failureCounts'] = {}
    stats['failureCounts']['billing'] = stats['failureCounts'].get('billing', 0) + 1

    # Also set cooldownUntil to ensure OpenClaw doesn't try it
    stats['cooldownUntil'] = disable_until

    f.seek(0)
    json.dump(data, f, indent=2)
    f.truncate()
    fcntl.flock(f, fcntl.LOCK_UN)

print(f'DISABLED:{profile_id}:until:{disable_until}')
" 2>&1
}

# ─── Find the next healthy key and set it as lastGood ────────────────────────
promote_next_key() {
  python3 -c "
import json, sys, time

with open('$OPENCLAW_CONFIG') as f:
    config = json.load(f)

with open('$AUTH_PROFILES') as f:
    auth_data = json.load(f)

now_ms = int(time.time() * 1000)
stats = auth_data.get('usageStats', {})
order = config.get('auth', {}).get('order', {}).get('venice', [])

if not order:
    # Fall back to all venice profiles in definition order
    profiles = auth_data.get('profiles', auth_data)
    order = [pid for pid in profiles if pid.startswith('venice:')]

# Find first key that's not disabled
next_key = None
for pid in order:
    s = stats.get(pid, {})
    disabled_until = s.get('disabledUntil', 0)
    if disabled_until and disabled_until > now_ms:
        continue
    next_key = pid
    break

if next_key:
    print(f'NEXT:{next_key}')
else:
    print('ALL_DEPLETED')
" 2>&1
}

# ─── Update state file ──────────────────────────────────────────────────────
update_state() {
  local action="$1"
  local profile="$2"
  local next_key="$3"
  local timestamp
  timestamp=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

  cat > "$WATCHDOG_STATE" << EOF
{
  "lastAction": "$action",
  "lastProfile": "$profile",
  "nextKey": "$next_key",
  "timestamp": "$timestamp"
}
EOF
}

# ─── Build grep pattern from VENICE_402_PATTERNS ─────────────────────────────
build_grep_pattern() {
  local pattern=""
  for p in "${VENICE_402_PATTERNS[@]}"; do
    if [[ -n "$pattern" ]]; then
      pattern="$pattern|$p"
    else
      pattern="$p"
    fi
  done
  echo "$pattern"
}

# ─── Scan gateway logs for RECENT Venice 402 errors ──────────────────────────
scan_logs() {
  local pattern
  pattern=$(build_grep_pattern)

  # Find gateway log files
  local log_files=()
  for f in "$LOG_DIR"/gateway*.log "$LOG_DIR"/openclaw*.log "$HOME"/.openclaw/gateway*.log; do
    [[ -f "$f" ]] && log_files+=("$f")
  done
  for f in "$LOG_DIR"/daemon*.log; do
    [[ -f "$f" ]] && log_files+=("$f")
  done

  if [[ ${#log_files[@]} -eq 0 ]]; then
    return 1
  fi

  # Calculate cutoff timestamp (only match entries within SCAN_WINDOW)
  local cutoff_epoch
  cutoff_epoch=$(( $(date +%s) - SCAN_WINDOW ))
  # Format as ISO-ish for comparison: "2026-02-23T00:50"
  local cutoff_iso
  cutoff_iso=$(date -u -r "$cutoff_epoch" '+%Y-%m-%dT%H:%M' 2>/dev/null || date -u -d "@$cutoff_epoch" '+%Y-%m-%dT%H:%M' 2>/dev/null || echo "")

  local found=0
  for f in "${log_files[@]}"; do
    # Grep for pattern, then filter by recency
    grep -iE "$pattern" "$f" 2>/dev/null | tail -20 | while read -r line; do
      # Extract timestamp from log line (handles both ISO and local formats)
      local line_ts
      line_ts=$(echo "$line" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}' | head -1)

      if [[ -z "$line_ts" ]]; then
        # No parseable timestamp — skip (can't verify recency)
        continue
      fi

      # Simple string comparison works for ISO timestamps
      if [[ -n "$cutoff_iso" && "$line_ts" > "$cutoff_iso" || "$line_ts" == "$cutoff_iso" ]]; then
        log "DETECTED Venice 402 in $f: $(echo "$line" | head -c 200)"
        found=1
      fi
    done
  done

  return $found
}

# ─── Check auth-profiles.json directly for recent unknown failures ───────────
# This is the more reliable detection method — it doesn't depend on log files
check_recent_failures() {
  python3 -c "
import json, sys, time

with open('$AUTH_PROFILES') as f:
    data = json.load(f)

now_ms = int(time.time() * 1000)
scan_window_ms = $SCAN_WINDOW * 1000
stats = data.get('usageStats', {})

# Look for Venice keys with recent failures that aren't properly billing-disabled
suspect_keys = []
for pid, s in stats.items():
    if not pid.startswith('venice:'):
        continue

    last_failure = s.get('lastFailureAt', 0)
    if not last_failure or (now_ms - last_failure) > scan_window_ms:
        continue

    disabled_until = s.get('disabledUntil', 0)
    disabled_reason = s.get('disabledReason', '')

    # Key has recent failures but is NOT properly billing-disabled
    # This means OpenClaw classified it as something other than billing
    error_count = s.get('errorCount', 0)
    cooldown_until = s.get('cooldownUntil', 0)
    billing_failures = s.get('failureCounts', {}).get('billing', 0)

    # Suspect: has errors, has short cooldown (not billing-length), no billing disable
    if error_count > 0:
        is_billing_disabled = (disabled_until and disabled_until > now_ms and disabled_reason == 'billing')
        has_short_cooldown = (cooldown_until and cooldown_until > now_ms and (cooldown_until - now_ms) < 600000)  # < 10 min
        rapid_failures = error_count >= 2 and (now_ms - last_failure) < 120000  # 2+ fails in 2 min

        if not is_billing_disabled and (has_short_cooldown or rapid_failures):
            suspect_keys.append({
                'id': pid,
                'errors': error_count,
                'lastFailure': last_failure,
                'cooldownUntil': cooldown_until,
                'billingFailures': billing_failures
            })

if suspect_keys:
    for k in suspect_keys:
        print(f\"SUSPECT:{k['id']}:errors={k['errors']}:billing={k['billingFailures']}\")
else:
    print('CLEAN')
" 2>&1
}

# ─── Handle a detected billing error ────────────────────────────────────────
handle_billing_error() {
  local source="$1"  # "log_scan" or "failure_check" or "probe"

  log "Billing error detected via $source"

  # Identify the most likely offending key
  local active_key
  active_key=$(identify_active_key)

  if [[ "$active_key" == "NONE" ]]; then
    log "CRITICAL: All Venice keys already disabled — nothing to rotate"
    update_state "all_depleted" "none" "none"
    return 2
  fi

  log "Disabling offending key: $active_key"
  local disable_result
  disable_result=$(disable_key "$active_key" "$source")

  if echo "$disable_result" | grep -q "ALREADY_DISABLED"; then
    log "Key $active_key was already disabled"
    return 0
  fi

  log "Result: $disable_result"

  # Find and report the next key
  local next
  next=$(promote_next_key)
  log "Next key: $next"

  if echo "$next" | grep -q "ALL_DEPLETED"; then
    log "CRITICAL: All Venice keys now depleted after disabling $active_key"
    update_state "all_depleted" "$active_key" "none"
    return 2
  fi

  local next_key
  next_key=$(echo "$next" | cut -d: -f2-)
  update_state "disabled" "$active_key" "$next_key"

  log "Rotation complete: $active_key → $next_key"
  return 0
}

# ─── One-shot scan mode ─────────────────────────────────────────────────────
run_once() {
  ensure_dirs
  log "Running one-shot scan (window: ${SCAN_WINDOW}s)"

  # ONLY method: Check auth-profiles for suspect failures (rapid errors without billing-disable)
  # Log scanning was removed — gateway logs accumulate old 402 errors that cause false positives.
  # The auth-profiles method is reliable: it detects keys with recent rapid failures that
  # OpenClaw classified as "unknown" instead of "billing" (the exact bug we're fixing).
  local suspects
  suspects=$(check_recent_failures)

  if echo "$suspects" | grep -q "^SUSPECT:"; then
    log "Found suspect Venice failures in auth-profiles"
    echo "$suspects" | grep "^SUSPECT:" | while read -r line; do
      log "  $line"
    done
    handle_billing_error "failure_check"
    return $?
  fi

  log "No Venice 402 errors detected"
  echo '{"status":"clean","timestamp":"'"$(date -u '+%Y-%m-%dT%H:%M:%SZ')"'"}'
  return 0
}

# ─── Daemon mode: watch auth-profiles.json for changes ──────────────────────
run_daemon() {
  ensure_dirs
  log "Starting daemon mode — watching for Venice billing errors"

  local last_check=0
  local check_interval=30  # Check every 30 seconds

  while true; do
    local now
    now=$(date +%s)

    if (( now - last_check >= check_interval )); then
      last_check=$now

      # Check for suspect failures
      local suspects
      suspects=$(check_recent_failures 2>/dev/null)

      if echo "$suspects" | grep -q "^SUSPECT:"; then
        log "DAEMON: Detected suspect Venice failures"
        handle_billing_error "daemon_watch"
      fi
    fi

    sleep 5
  done
}

# ─── Main ────────────────────────────────────────────────────────────────────
if [[ -n "$DAEMON" ]]; then
  run_daemon
else
  run_once
fi
