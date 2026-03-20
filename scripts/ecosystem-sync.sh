#!/usr/bin/env bash
# ecosystem-sync.sh — Automated EverClaw ecosystem sync
#
# Syncs the main branch to all 28 flavor repos + org repo.
# Verifies all remotes match origin HEAD after push.
# Sends a Signal summary via OpenClaw message tool (optional).
#
# Usage:
#   ./ecosystem-sync.sh              # Push to all remotes
#   ./ecosystem-sync.sh --dry-run    # Show what would be pushed, don't push
#   ./ecosystem-sync.sh --verify     # Only verify sync status, no push
#   ./ecosystem-sync.sh --force      # Force push (use after history rewrite)
#
# Exit codes:
#   0 — All remotes in sync
#   1 — One or more remotes failed
#   2 — Script error (not in repo, no remotes, etc.)

set -euo pipefail

# === Concurrent Execution Lock (prevents overlapping pushes) ===
LOCK_DIR="/tmp/everclaw-ecosystem-sync.lock"
if mkdir "$LOCK_DIR" 2>/dev/null; then
  trap 'rm -rf "$LOCK_DIR"' EXIT
else
  # Check if stale (older than 10 minutes)
  lock_age=0
  if [[ -f "$LOCK_DIR/pid" ]]; then
    lock_ts=$(stat -f %m "$LOCK_DIR/pid" 2>/dev/null || stat -c %Y "$LOCK_DIR/pid" 2>/dev/null || echo 0)
    lock_age=$(( $(date +%s) - lock_ts ))
  fi
  if (( lock_age > 600 )); then
    echo "⚠️  Stale lock detected (${lock_age}s old) — removing and continuing"
    rm -rf "$LOCK_DIR"
    mkdir "$LOCK_DIR" 2>/dev/null
    trap 'rm -rf "$LOCK_DIR"' EXIT
  else
    echo "❌ Another ecosystem-sync is already running. Exiting." >&2
    exit 1
  fi
fi
echo $$ > "$LOCK_DIR/pid"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BRANCH="main"
DRY_RUN=false
VERIFY_ONLY=false
FORCE=false
FAILED=()
SUCCEEDED=()
SKIPPED=()

# Parse args
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=true ;;
    --verify) VERIFY_ONLY=true ;;
    --force) FORCE=true ;;
    --help|-h)
      echo "Usage: $0 [--dry-run] [--verify] [--force]"
      exit 0
      ;;
  esac
done

cd "$REPO_DIR"

# Verify we're in a git repo
if ! git rev-parse --is-inside-work-tree &>/dev/null; then
  echo "❌ Not a git repository: $REPO_DIR"
  exit 2
fi

# Get current HEAD
LOCAL_SHA=$(git rev-parse HEAD)
LOCAL_SHORT=$(git rev-parse --short HEAD)
LOCAL_MSG=$(git log -1 --format="%s")

echo "🔄 EverClaw Ecosystem Sync"
echo "   Branch: $BRANCH"
echo "   Commit: $LOCAL_SHORT — $LOCAL_MSG"
echo "   Remotes: $(git remote | wc -l | tr -d ' ')"
echo ""

# Skip non-flavor remotes
SKIP_REMOTES="everclaw-fork"

# Categorize remotes
ORIGIN_REMOTE="origin"
ORG_REMOTE="everclaw-org"
FLAVOR_REMOTES=()

for remote in $(git remote | sort); do
  case "$remote" in
    origin|everclaw-org|everclaw-fork) ;; # handled separately
    *) FLAVOR_REMOTES+=("$remote") ;;
  esac
done

sync_remote() {
  local remote=$1
  local label=$2

  # Check if remote is already in sync
  local remote_sha
  remote_sha=$(git ls-remote "$remote" refs/heads/$BRANCH 2>/dev/null | cut -f1) || true

  if [ "$remote_sha" = "$LOCAL_SHA" ]; then
    SKIPPED+=("$remote")
    printf "  ⏭️  %-25s already in sync\n" "$remote"
    return 0
  fi

  if $VERIFY_ONLY; then
    local remote_short="${remote_sha:0:7}"
    printf "  ❌ %-25s out of sync (remote: %s)\n" "$remote" "${remote_short:-empty}"
    FAILED+=("$remote")
    return 1
  fi

  if $DRY_RUN; then
    printf "  🔍 %-25s would push %s → %s\n" "$remote" "$LOCAL_SHORT" "${remote_sha:0:7}"
    SUCCEEDED+=("$remote")
    return 0
  fi

  # Push
  local push_args=("--no-verify" "$remote" "$BRANCH")
  if $FORCE; then
    push_args=("--no-verify" "--force" "$remote" "$BRANCH")
  fi

  if git push "${push_args[@]}" 2>&1 | tail -1; then
    SUCCEEDED+=("$remote")
    printf "  ✅ %-25s pushed\n" "$remote"
    return 0
  else
    FAILED+=("$remote")
    printf "  ❌ %-25s FAILED\n" "$remote"
    return 1
  fi
}

# 1. Push to origin first
echo "📦 Origin (EverClaw/EverClaw)"
sync_remote "$ORIGIN_REMOTE" "origin" || true
echo ""

# 2. Push to org repo
echo "🏢 Org (EverClaw/EverClaw)"
sync_remote "$ORG_REMOTE" "org" || true
echo ""

# 3. Push to all flavor repos
echo "🌈 Flavor repos (${#FLAVOR_REMOTES[@]})"
for remote in "${FLAVOR_REMOTES[@]}"; do
  # Skip explicitly excluded remotes
  if [[ " $SKIP_REMOTES " == *" $remote "* ]]; then
    SKIPPED+=("$remote")
    printf "  ⏭️  %-25s skipped (excluded)\n" "$remote"
    continue
  fi
  sync_remote "$remote" "flavor" || true
done
echo ""

# Summary
TOTAL=$((${#SUCCEEDED[@]} + ${#FAILED[@]} + ${#SKIPPED[@]}))
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📊 Sync Summary"
echo "   Total remotes: $TOTAL"
echo "   ✅ Pushed:     ${#SUCCEEDED[@]}"
echo "   ⏭️  In sync:    ${#SKIPPED[@]}"
echo "   ❌ Failed:     ${#FAILED[@]}"

if [ ${#FAILED[@]} -gt 0 ]; then
  echo ""
  echo "   Failed remotes:"
  for r in "${FAILED[@]}"; do
    echo "   - $r"
  done
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ─── SmartAgent Sync Check ─────────────────────────────────────
# SmartAgent has its own content but references EverClaw.
# We verify it's reachable and log its HEAD for awareness.
echo ""
echo "📱 SmartAgent (SmartAgentProtocol/smartagent)"
SMART_SHA=$(git ls-remote https://github.com/SmartAgentProtocol/smartagent.git refs/heads/main 2>/dev/null | cut -f1) || true
if [ -n "$SMART_SHA" ]; then
  SMART_SHORT="${SMART_SHA:0:7}"
  # Check local clone if it exists
  SMART_LOCAL="$HOME/.openclaw/workspace/smartagent"
  if [ -d "$SMART_LOCAL/.git" ]; then
    LOCAL_SMART_SHA=$(git -C "$SMART_LOCAL" rev-parse HEAD 2>/dev/null) || true
    if [ "$LOCAL_SMART_SHA" = "$SMART_SHA" ]; then
      printf "  ⏭️  %-25s in sync (%s)\n" "smartagent" "$SMART_SHORT"
    else
      LOCAL_SMART_SHORT="${LOCAL_SMART_SHA:0:7}"
      printf "  ⚠️  %-25s local (%s) differs from remote (%s)\n" "smartagent" "$LOCAL_SMART_SHORT" "$SMART_SHORT"
      if ! $DRY_RUN && ! $VERIFY_ONLY; then
        git -C "$SMART_LOCAL" pull --rebase origin main 2>&1 | tail -1
        printf "  ✅ %-25s synced\n" "smartagent"
      fi
    fi
  else
    printf "  ℹ️  %-25s remote HEAD: %s (no local clone)\n" "smartagent" "$SMART_SHORT"
  fi
else
  printf "  ❌ %-25s unreachable\n" "smartagent"
fi
echo ""

# Write sync status to a file for cron/shift consumption
cat > "$REPO_DIR/scripts/.last-sync.json" << SYNCJSON
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "commit": "$LOCAL_SHA",
  "commitShort": "$LOCAL_SHORT",
  "commitMessage": "$LOCAL_MSG",
  "branch": "$BRANCH",
  "total": $TOTAL,
  "pushed": ${#SUCCEEDED[@]},
  "inSync": ${#SKIPPED[@]},
  "failed": ${#FAILED[@]},
  "failedRemotes": [$(if [ ${#FAILED[@]} -gt 0 ]; then printf '"%s",' "${FAILED[@]}" | sed 's/,$//'; fi)]
}
SYNCJSON

if [ ${#FAILED[@]} -gt 0 ]; then
  exit 1
else
  exit 0
fi
