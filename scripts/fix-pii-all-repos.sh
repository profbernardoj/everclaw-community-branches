#!/usr/bin/env bash
# fix-pii-all-repos.sh — Batch PII remediation for all EverClaw flavor repos
# Fixes: Venice API key, Signal phone, verified-bundle.json, default, America/Chicago
# Usage: bash fix-pii-all-repos.sh [--dry-run]
set -uo pipefail

DRY_RUN=false
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=true

WORK_DIR="/tmp/pii-fix-batch"
COMMIT_MSG="fix: remove PII — API key, phone number, system dump, timezone hardcodes, personal refs"
PHONE="5129488566"
PHONE_FULL="+1XXXXXXXXXX"
OLD_VENICE_KEY="VENICE-INFERENCE-KEY-REDACTED"

# All 28 flavor repos + extras under profbernardoj
REPOS=(
  androidclaw.org
  appleclaw.org
  arbclaw.com
  baseclaw.ai
  basedclaw.org
  bitcoinclaw.ai
  bookingclaw.org
  briefingclaw.com
  deepseekclaw.org
  emailclaw.org
  ethereumclaw.com
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
  myai.capital
  officeclaw.ai
  officeclaw.org
  solanaclaw.xyz
  travelclaw.org
  vcclaw.org
  windowsclaw.org
)

mkdir -p "$WORK_DIR"
cd "$WORK_DIR"

TOTAL=${#REPOS[@]}
FIXED=0
SKIPPED=0
FAILED=0
CLEAN=0

echo "============================================"
echo "PII Batch Fix — $TOTAL repos"
echo "Dry run: $DRY_RUN"
echo "Working dir: $WORK_DIR"
echo "============================================"
echo ""

for repo in "${REPOS[@]}"; do
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "[$((FIXED + SKIPPED + FAILED + CLEAN + 1))/$TOTAL] $repo"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  # Clone fresh
  rm -rf "$repo"
  if ! git clone --depth 1 "https://github.com/profbernardoj/${repo}.git" "$repo" 2>/dev/null; then
    echo "  ⚠️  SKIP — repo not found or not accessible"
    ((SKIPPED++))
    echo ""
    continue
  fi

  cd "$repo"
  CHANGES=0

  # --- FIX 1: Venice API key in generate-logos.sh ---
  if grep -rq "$OLD_VENICE_KEY" . 2>/dev/null; then
    echo "  🔧 Fixing Venice API key..."
    find . -type f \( -name "*.sh" -o -name "*.json" -o -name "*.md" -o -name "*.js" -o -name "*.mjs" \) \
      -exec grep -l "$OLD_VENICE_KEY" {} \; 2>/dev/null | while read -r f; do
      sed -i '' "s|$OLD_VENICE_KEY|VENICE-INFERENCE-KEY-REDACTED|g" "$f"
      echo "    ✓ $f"
    done
    # Also fix generate-logos.sh to use env var pattern if it has a hardcoded key
    if [ -f "branding/generate-logos.sh" ]; then
      sed -i '' 's|^VENICE_KEY="VENICE-INFERENCE-KEY-REDACTED[^"]*"|VENICE_KEY="${VENICE_API_KEY:?Set VENICE_API_KEY env var}"|' "branding/generate-logos.sh"
      echo "    ✓ branding/generate-logos.sh → env var pattern"
    fi
    ((CHANGES++))
  fi

  # --- FIX 2: Signal phone number ---
  if grep -rq "$PHONE" . 2>/dev/null; then
    echo "  🔧 Fixing Signal phone number..."
    find . -type f \( -name "*.sh" -o -name "*.md" -o -name "*.json" -o -name "*.js" \) \
      -exec grep -l "$PHONE" {} \; 2>/dev/null | while read -r f; do
      # In gateway-guardian.sh: replace the full number with placeholder
      sed -i '' "s|\"$PHONE_FULL\"|\"$PHONE_FULL\"|g; s|$PHONE_FULL|+1XXXXXXXXXX|g" "$f"
      # Also catch without + prefix
      sed -i '' "s|$PHONE|XXXXXXXXXX|g" "$f"
      echo "    ✓ $f"
    done
    ((CHANGES++))
  fi

  # --- FIX 3: verified-bundle.json ---
  if [ -f "verified-bundle.json" ]; then
    echo "  🔧 Removing verified-bundle.json..."
    rm -f "verified-bundle.json"
    git rm -f "verified-bundle.json" 2>/dev/null || true
    echo "    ✓ deleted"
    ((CHANGES++))
  fi

  # --- FIX 4: ~ paths (in any remaining files) ---
  if grep -rq "~" . --include="*.sh" --include="*.json" --include="*.md" --include="*.js" --include="*.mjs" 2>/dev/null; then
    echo "  🔧 Fixing ~ paths..."
    find . -type f \( -name "*.sh" -o -name "*.json" -o -name "*.md" -o -name "*.js" -o -name "*.mjs" \) \
      -exec grep -l "~" {} \; 2>/dev/null | while read -r f; do
      # In generate-logos.sh: replace hardcoded output dir
      if [[ "$f" == *"generate-logos.sh"* ]]; then
        sed -i '' 's|OUTPUT_DIR="~/[^"]*"|OUTPUT_DIR="${SCRIPT_DIR}/../flavor-logos"|' "$f"
      fi
      echo "    ✓ $f"
    done
    ((CHANGES++))
  fi

  # --- FIX 5: default ---
  if grep -rq "default" . 2>/dev/null; then
    echo "  🔧 Fixing personal name reference..."
    find . -type f -name "*.js" -exec grep -l "default" {} \; 2>/dev/null | while read -r f; do
      sed -i '' "s|default|default|g" "$f"
      echo "    ✓ $f"
    done
    ((CHANGES++))
  fi

  # --- FIX 6: America/Chicago → placeholder ---
  if grep -rq "America/Chicago" . --include="*.md" --include="*.js" --include="*.mjs" --include="*.json" 2>/dev/null; then
    echo "  🔧 Fixing hardcoded timezone..."
    find . -type f \( -name "*.md" -o -name "*.js" -o -name "*.mjs" -o -name "*.json" \) \
      -exec grep -l "America/Chicago" {} \; 2>/dev/null | while read -r f; do
      sed -i '' 's|America/Chicago|YOUR_TIMEZONE|g' "$f"
      echo "    ✓ $f"
    done
    ((CHANGES++))
  fi

  # --- FIX 7: Local IP addresses ---
  if grep -rq "192\.168\." . --include="*.json" --include="*.md" --include="*.sh" 2>/dev/null; then
    echo "  🔧 Fixing local IP addresses..."
    find . -type f \( -name "*.json" -o -name "*.md" -o -name "*.sh" \) \
      -exec grep -l "192\.168\." {} \; 2>/dev/null | while read -r f; do
      sed -i '' -E 's|192\.168\.[0-9]+\.[0-9]+|YOUR_LOCAL_IP|g' "$f"
      echo "    ✓ $f"
    done
    ((CHANGES++))
  fi

  # --- Commit & Push ---
  if [ "$CHANGES" -gt 0 ]; then
    echo ""
    # Verify no PII remains
    REMAINING=$(grep -rn "$PHONE\|$OLD_VENICE_KEY\|~\|default" . \
      --include="*.sh" --include="*.json" --include="*.md" --include="*.js" --include="*.mjs" 2>/dev/null | wc -l | tr -d ' ')

    if [ "$REMAINING" -gt 0 ]; then
      echo "  ⚠️  WARNING: $REMAINING PII references still remain!"
      grep -rn "$PHONE\|$OLD_VENICE_KEY\|~\|default" . \
        --include="*.sh" --include="*.json" --include="*.md" --include="*.js" --include="*.mjs" 2>/dev/null | head -5
    fi

    if [ "$DRY_RUN" = true ]; then
      echo "  📋 DRY RUN — would commit $CHANGES fix categories"
      ((FIXED++))
    else
      git add -A
      git commit -m "$COMMIT_MSG" 2>/dev/null || {
        echo "  ℹ️  Nothing to commit (maybe already clean)"
        ((CLEAN++))
        cd "$WORK_DIR"
        continue
      }
      if git push origin main 2>/dev/null || git push origin master 2>/dev/null; then
        echo "  ✅ Pushed successfully"
        ((FIXED++))
      else
        echo "  ❌ Push failed!"
        ((FAILED++))
      fi
    fi
  else
    echo "  ✅ Already clean — no PII found"
    ((CLEAN++))
  fi

  cd "$WORK_DIR"
  echo ""
done

echo "============================================"
echo "RESULTS"
echo "============================================"
echo "  Fixed:   $FIXED"
echo "  Clean:   $CLEAN"
echo "  Skipped: $SKIPPED"
echo "  Failed:  $FAILED"
echo "  Total:   $TOTAL"
echo "============================================"

if [ "$DRY_RUN" = true ]; then
  echo ""
  echo "This was a DRY RUN. Re-run without --dry-run to apply fixes."
fi
