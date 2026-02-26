#!/usr/bin/env bash
# filter-repo-pii.sh — Rewrite git history to permanently remove PII from all affected repos
# Uses git-filter-repo to strip sensitive strings from entire history
# Usage: bash filter-repo-pii.sh [--dry-run]
set -uo pipefail

DRY_RUN=false
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=true

WORK_DIR="/tmp/pii-filter-batch"
mkdir -p "$WORK_DIR"
cd "$WORK_DIR"

# Sensitive strings to scrub from all history
# Format: literal string → replacement
cat > "$WORK_DIR/replacements.txt" << 'EOF'
VENICE-INFERENCE-KEY-REDACTED==>VENICE-INFERENCE-KEY-REDACTED
VENICE-INFERENCE-KEY-REDACTED==>VENICE-INFERENCE-KEY-REDACTED
+1XXXXXXXXXX==>+1XXXXXXXXXX
5129488566==>XXXXXXXXXX
sk-REDACTED==>sk-REDACTED
192.168.1.217==>YOUR_LOCAL_IP
~/.openclaw==>~/.openclaw
~==>~
EverClaw Contributor==>EverClaw Contributor
default==>default
EOF

# Paths to completely remove from history
cat > "$WORK_DIR/paths-to-remove.txt" << 'EOF'
verified-bundle.json
memory/daily/
memory/reference/family-reminders.md
memory/reference/school-calendar.md
EOF

# All affected repos — profbernardoj repos that had PII
PROF_REPOS=(
  androidclaw.org
  appleclaw.org
  arbclaw.com
  basedclaw.org
  bitcoinclaw.ai
  bookingclaw.org
  briefingclaw.com
  deepseekclaw.org
  emailclaw.org
  ethereumclaw.com
  everclaw
  everclaw-community-branches
  everclaw-fork
  familyclaw.org
  familyofficeclaw.com
  friendclaw.xyz
  glmclaw.com
  grokclaw.xyz
  homeclaw.org
  installopenclaw.xyz
  investclaw.ai
  kimiclaw.co
  linuxclaw.com
  llamaclaw.org
  minimaxclaw.com
  morpheusclaw.com
  officeclaw.ai
  officeclaw.org
  solanaclaw.xyz
  travelclaw.org
  vcclaw.org
  windowsclaw.org
)

# Other orgs
OTHER_REPOS=(
  "EverClaw/EverClaw"
  "SmartAgentProtocol/smartagent"
)

TOTAL=$(( ${#PROF_REPOS[@]} + ${#OTHER_REPOS[@]} ))
FIXED=0
SKIPPED=0
FAILED=0

echo "============================================"
echo "GIT HISTORY REWRITE — PII Scrub"
echo "Dry run: $DRY_RUN"
echo "Repos: $TOTAL"
echo "Working dir: $WORK_DIR"
echo "============================================"
echo ""

filter_repo() {
  local clone_url="$1"
  local label="$2"
  local dir="$3"

  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "[$((FIXED + SKIPPED + FAILED + 1))/$TOTAL] $label"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  # Full clone (not shallow — filter-repo needs full history)
  rm -rf "$dir"
  if ! git clone "$clone_url" "$dir" 2>/dev/null; then
    echo "  ⚠️  SKIP — clone failed"
    ((SKIPPED++))
    echo ""
    return
  fi

  cd "$dir"

  echo "  🔧 Rewriting history..."

  if [ "$DRY_RUN" = true ]; then
    echo "  📋 DRY RUN — would rewrite history"
    ((FIXED++))
    cd "$WORK_DIR"
    echo ""
    return
  fi

  # Run git-filter-repo with blob replacements
  git filter-repo \
    --replace-text "$WORK_DIR/replacements.txt" \
    --path-glob 'verified-bundle.json' --invert-paths \
    --force 2>&1 | tail -3

  # Re-add remote (filter-repo removes it)
  git remote add origin "$clone_url"

  # Force push all branches
  if git push origin --all --force 2>&1; then
    echo "  ✅ Force pushed successfully"
    # Also push tags if any
    git push origin --tags --force 2>/dev/null || true
    ((FIXED++))
  else
    echo "  ❌ Force push FAILED"
    ((FAILED++))
  fi

  cd "$WORK_DIR"
  echo ""
}

# Process profbernardoj repos
for repo in "${PROF_REPOS[@]}"; do
  filter_repo "https://github.com/profbernardoj/${repo}.git" "profbernardoj/$repo" "filter-$repo"
done

# Process other org repos
for repo in "${OTHER_REPOS[@]}"; do
  dir="filter-$(echo "$repo" | tr '/' '-')"
  filter_repo "https://github.com/${repo}.git" "$repo" "$dir"
done

echo "============================================"
echo "RESULTS"
echo "============================================"
echo "  Rewritten: $FIXED"
echo "  Skipped:   $SKIPPED"
echo "  Failed:    $FAILED"
echo "  Total:     $TOTAL"
echo "============================================"

if [ "$DRY_RUN" = true ]; then
  echo ""
  echo "This was a DRY RUN. Re-run without --dry-run to apply."
fi
