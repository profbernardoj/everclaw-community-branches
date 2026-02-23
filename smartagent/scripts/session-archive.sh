#!/bin/bash
# session-archive.sh — Smart session archiver for OpenClaw
#
# Moves old session .jsonl files to archive/ when the sessions directory
# exceeds a configurable size threshold. Prevents the OpenClaw dashboard
# from choking on large session histories.
#
# Usage:
#   bash session-archive.sh              # Archive if over threshold
#   bash session-archive.sh --check      # Check size without archiving
#   bash session-archive.sh --force      # Archive regardless of size
#   bash session-archive.sh --verbose    # Show detailed output
#
# Environment:
#   ARCHIVE_THRESHOLD_MB  — trigger threshold in MB (default: 10)
#   SESSIONS_DIR          — sessions directory (default: ~/.openclaw/agents/main/sessions)
#   KEEP_RECENT           — number of most-recent sessions to keep (default: 5)

set -uo pipefail

# --- Configuration ---
ARCHIVE_THRESHOLD_MB="${ARCHIVE_THRESHOLD_MB:-10}"
SESSIONS_DIR="${SESSIONS_DIR:-$HOME/.openclaw/agents/main/sessions}"
ARCHIVE_DIR="$SESSIONS_DIR/archive"
KEEP_RECENT="${KEEP_RECENT:-5}"

# --- Flags ---
CHECK_ONLY=false
FORCE=false
VERBOSE=false

for arg in "$@"; do
  case "$arg" in
    --check)   CHECK_ONLY=true ;;
    --force)   FORCE=true ;;
    --verbose) VERBOSE=true ;;
    --help|-h)
      echo "Usage: session-archive.sh [--check] [--force] [--verbose]"
      echo ""
      echo "Smart session archiver — moves old sessions to archive/ when"
      echo "the sessions directory exceeds the size threshold."
      echo ""
      echo "Options:"
      echo "  --check    Report size and status without archiving"
      echo "  --force    Archive regardless of current size"
      echo "  --verbose  Show detailed output"
      echo ""
      echo "Environment:"
      echo "  ARCHIVE_THRESHOLD_MB  Threshold in MB (default: 10)"
      echo "  SESSIONS_DIR          Sessions path (default: ~/.openclaw/agents/main/sessions)"
      echo "  KEEP_RECENT           Recent sessions to keep (default: 5)"
      exit 0
      ;;
  esac
done

log() { echo "[session-archive] $*"; }
vlog() { $VERBOSE && echo "[session-archive] $*"; }

# --- Validate ---
if [[ ! -d "$SESSIONS_DIR" ]]; then
  log "ERROR: Sessions directory not found: $SESSIONS_DIR"
  exit 1
fi

# --- Measure current size (excluding archive/) ---
# Sum only top-level files, not the archive subdirectory
SIZE_KB=0
while IFS= read -r fsize; do
  SIZE_KB=$((SIZE_KB + fsize))
done < <(find "$SESSIONS_DIR" -maxdepth 1 -type f -exec du -sk {} + 2>/dev/null | awk '{print $1}')
SIZE_MB=$(echo "scale=1; $SIZE_KB / 1024" | bc)
THRESHOLD_KB=$((ARCHIVE_THRESHOLD_MB * 1024))

# Count session files (exclude archive/, sessions.json, and other non-session files)
TOTAL_SESSIONS=$(find "$SESSIONS_DIR" -maxdepth 1 -name "*.jsonl" 2>/dev/null | wc -l | tr -d ' ')

log "Sessions directory: ${SIZE_MB}MB (${TOTAL_SESSIONS} sessions)"
log "Threshold: ${ARCHIVE_THRESHOLD_MB}MB"

if $CHECK_ONLY; then
  if [[ "$SIZE_KB" -ge "$THRESHOLD_KB" ]]; then
    log "⚠️  OVER THRESHOLD — archiving recommended"
    exit 1  # Non-zero = over threshold (useful for scripting)
  else
    HEADROOM=$(echo "scale=1; $ARCHIVE_THRESHOLD_MB - $SIZE_MB" | bc)
    log "✅ Under threshold (${HEADROOM}MB headroom)"
    exit 0
  fi
fi

# --- Decide whether to archive ---
if ! $FORCE && [[ "$SIZE_KB" -lt "$THRESHOLD_KB" ]]; then
  log "✅ Under threshold — nothing to archive"
  exit 0
fi

if $FORCE; then
  log "🔧 Force mode — archiving regardless of size"
fi

# --- Identify active sessions to protect ---
# Read session IDs from sessions.json (the index file)
ACTIVE_IDS=()
if [[ -f "$SESSIONS_DIR/sessions.json" ]]; then
  # Extract sessionId values from the JSON index
  while IFS= read -r sid; do
    ACTIVE_IDS+=("$sid")
  done < <(grep -o '"sessionId"[[:space:]]*:[[:space:]]*"[^"]*"' "$SESSIONS_DIR/sessions.json" 2>/dev/null | sed 's/.*"sessionId"[[:space:]]*:[[:space:]]*"//;s/"//')
  vlog "Active sessions from index: ${#ACTIVE_IDS[@]}"
fi

# Also protect the guardian health probe
PROTECTED_FILES=("guardian-health-probe.jsonl")
for aid in "${ACTIVE_IDS[@]}"; do
  PROTECTED_FILES+=("${aid}.jsonl")
done

# --- Build list of archivable sessions sorted by modification time (oldest first) ---
CANDIDATES=()
while IFS= read -r filepath; do
  filename=$(basename "$filepath")
  
  # Check if protected
  protected=false
  for pf in "${PROTECTED_FILES[@]}"; do
    if [[ "$filename" == "$pf" ]]; then
      protected=true
      break
    fi
  done
  
  if ! $protected; then
    CANDIDATES+=("$filepath")
  fi
done < <(find "$SESSIONS_DIR" -maxdepth 1 -name "*.jsonl" -print0 2>/dev/null | xargs -0 ls -t 2>/dev/null | tail -r 2>/dev/null || find "$SESSIONS_DIR" -maxdepth 1 -name "*.jsonl" -printf '%T@ %p\n' 2>/dev/null | sort -n | awk '{print $2}')

# Fallback: if the above sorting failed, just use find order
if [[ ${#CANDIDATES[@]} -eq 0 ]]; then
  while IFS= read -r filepath; do
    filename=$(basename "$filepath")
    protected=false
    for pf in "${PROTECTED_FILES[@]}"; do
      if [[ "$filename" == "$pf" ]]; then
        protected=true
        break
      fi
    done
    if ! $protected; then
      CANDIDATES+=("$filepath")
    fi
  done < <(find "$SESSIONS_DIR" -maxdepth 1 -name "*.jsonl" 2>/dev/null)
fi

CANDIDATE_COUNT=${#CANDIDATES[@]}
vlog "Archivable candidates: $CANDIDATE_COUNT"

# Keep KEEP_RECENT most recent sessions
if [[ "$CANDIDATE_COUNT" -le "$KEEP_RECENT" ]]; then
  log "Only $CANDIDATE_COUNT archivable sessions (keeping $KEEP_RECENT) — nothing to move"
  exit 0
fi

# Sort candidates by mtime (oldest first) on macOS
SORTED_CANDIDATES=()
while IFS= read -r f; do
  SORTED_CANDIDATES+=("$f")
done < <(
  for f in "${CANDIDATES[@]}"; do
    echo "$(stat -f '%m' "$f" 2>/dev/null || stat -c '%Y' "$f" 2>/dev/null || echo 0) $f"
  done | sort -n | awk '{print $2}'
)

# Archive all but the KEEP_RECENT newest
TO_ARCHIVE_COUNT=$((${#SORTED_CANDIDATES[@]} - KEEP_RECENT))
if [[ "$TO_ARCHIVE_COUNT" -le 0 ]]; then
  log "Nothing to archive after keeping $KEEP_RECENT recent sessions"
  exit 0
fi

# --- Archive ---
mkdir -p "$ARCHIVE_DIR"

MOVED=0
FREED_KB=0

for ((i = 0; i < TO_ARCHIVE_COUNT; i++)); do
  filepath="${SORTED_CANDIDATES[$i]}"
  filename=$(basename "$filepath")
  filesize_kb=$(du -sk "$filepath" 2>/dev/null | awk '{print $1}')
  
  if mv "$filepath" "$ARCHIVE_DIR/$filename" 2>/dev/null; then
    MOVED=$((MOVED + 1))
    FREED_KB=$((FREED_KB + filesize_kb))
    vlog "  Archived: $filename (${filesize_kb}KB)"
  else
    log "  WARNING: Failed to move $filename"
  fi
done

FREED_MB=$(echo "scale=1; $FREED_KB / 1024" | bc)
NEW_SIZE_KB=$((SIZE_KB - FREED_KB))
NEW_SIZE_MB=$(echo "scale=1; $NEW_SIZE_KB / 1024" | bc)

log "✅ Archived $MOVED sessions (freed ${FREED_MB}MB)"
log "   Sessions directory: ${SIZE_MB}MB → ${NEW_SIZE_MB}MB"
log "   Remaining active sessions: $((CANDIDATE_COUNT - MOVED + ${#ACTIVE_IDS[@]}))"

# --- Output JSON summary for cron consumption ---
cat <<EOF
{"archived":$MOVED,"freedMB":$FREED_MB,"beforeMB":$SIZE_MB,"afterMB":$NEW_SIZE_MB,"threshold":$ARCHIVE_THRESHOLD_MB}
EOF
