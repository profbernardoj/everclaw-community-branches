#!/usr/bin/env bash
# pre-push V2 — Global git pre-push hook for PII Guard
# Part of EverClaw Security V2
# Install: git config --global core.hooksPath <path-to-git-hooks-dir>
set -euo pipefail

find_patterns_file() {
  local candidates=(
    "${PII_PATTERNS_FILE:-}"
    "$HOME/.openclaw/workspace/.pii-patterns.json"
    "./.pii-patterns.json"
  )
  for f in "${candidates[@]}"; do
    [[ -n "$f" && -f "$f" ]] && echo "$f" && return 0
  done
  return 1
}

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BOLD='\033[1m'
NC='\033[0m'

PATTERNS_FILE=$(find_patterns_file) || { exit 0; }

if ! command -v jq &>/dev/null; then
  echo -e "${YELLOW}⚠ PII Guard: jq not installed — skipping${NC}"
  exit 0
fi

# Build user-defined patterns
build_user_patterns() {
  local result=""
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    local escaped
    escaped=$(printf '%s' "$line" | sed 's/[.[\*^$()+?{|]/\\&/g')
    [[ -n "$result" ]] && result="$result|$escaped" || result="$escaped"
  done < <(jq -r '
    (.names // [])[], (.first_names // [])[], (.emails // [])[], (.phones // [])[],
    (.wallets // [])[], (.organizations // [])[], (.people // [])[],
    (.websites // [])[], (.keywords // [])[], (.location_signals // [])[]
  ' "$PATTERNS_FILE" 2>/dev/null)
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    [[ -n "$result" ]] && result="$result|$line" || result="$line"
  done < <(jq -r '(.regex // [])[]' "$PATTERNS_FILE" 2>/dev/null)
  echo "$result"
}

# Build built-in detection patterns
build_builtin_patterns() {
  local patterns=(
    'VENICE-INFERENCE-KEY-[A-Za-z0-9_-]{20,}'
    'sk-[A-Za-z0-9.]{20,}'
    'ghp_[A-Za-z0-9]{36}'
    'gho_[A-Za-z0-9]{36}'
    'github_pat_[A-Za-z0-9_]{82}'
    'AKIA[0-9A-Z]{16}'
    'sk_live_[A-Za-z0-9]{24,}'
    'xox[baprs]-[A-Za-z0-9-]{10,}'
    '/Users/[A-Za-z][A-Za-z0-9_-]+/'
    '/home/[A-Za-z][A-Za-z0-9_-]+/'
    '192\.168\.[0-9]{1,3}\.[0-9]{1,3}'
    '10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
  )
  local result=""
  for p in "${patterns[@]}"; do
    [[ -n "$result" ]] && result="$result|$p" || result="$p"
  done
  echo "$result"
}

# False positive filter
is_false_positive() {
  local line="$1"
  echo "$line" | grep -qiE "YOUR_KEY_HERE|YOUR_PRIMARY|placeholder|example|XXXXXXXXXX|YOUR_LOCAL_IP|YOUR_TIMEZONE|192\.168\.x\.x|template|sk-abcdef|sk-test_|sk_test_|REDACTED" && return 0
  echo "$line" | grep -qiE "172\.17\.0\.1|host\.docker\.internal|10\.0\.0\.1[^0-9]|127\.0\.0\.1" && return 0
  echo "$line" | grep -qiE "192\.168\.(x|X|0)\.|(x|X)\.(x|X)" && return 0
  return 1
}

USER_PATTERN=$(build_user_patterns)
BUILTIN_PATTERN=$(build_builtin_patterns)

if [[ -n "$USER_PATTERN" && -n "$BUILTIN_PATTERN" ]]; then
  GREP_PATTERN="$USER_PATTERN|$BUILTIN_PATTERN"
elif [[ -n "$USER_PATTERN" ]]; then
  GREP_PATTERN="$USER_PATTERN"
elif [[ -n "$BUILTIN_PATTERN" ]]; then
  GREP_PATTERN="$BUILTIN_PATTERN"
else
  exit 0
fi

ZERO="0000000000000000000000000000000000000000"
found_pii=0
violations=""

while read -r local_ref local_sha remote_ref remote_sha; do
  [[ "$local_sha" == "$ZERO" ]] && continue

  if [[ "$remote_sha" == "$ZERO" ]]; then
    raw_matches=$(git diff --cached "$local_sha" 2>/dev/null | grep -inE "$GREP_PATTERN" 2>/dev/null || true)
  else
    raw_matches=$(git diff "$remote_sha" "$local_sha" 2>/dev/null | grep -inE "$GREP_PATTERN" 2>/dev/null || true)
  fi

  if [[ -n "$raw_matches" ]]; then
    # Filter false positives
    while IFS= read -r line; do
      if ! is_false_positive "$line"; then
        found_pii=1
        violations+="$line"$'\n'
      fi
    done <<< "$raw_matches"
  fi
done

if [[ $found_pii -eq 1 ]]; then
  echo ""
  echo -e "${RED}${BOLD}🚫 PII GUARD V2: Push blocked — personal data detected!${NC}"
  echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo ""
  echo -e "${YELLOW}The following lines contain protected personal information:${NC}"
  echo ""
  echo "$violations" | head -30
  [[ $(echo "$violations" | wc -l) -gt 30 ]] && echo -e "${YELLOW}... and more (showing first 30)${NC}"
  echo ""
  echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "Patterns file: ${PATTERNS_FILE}"
  echo -e "To bypass (USE WITH CAUTION): git push ${BOLD}--no-verify${NC}"
  echo ""
  exit 1
fi

echo -e "${GREEN}✓ PII Guard: scan clean — no personal data detected${NC}"
exit 0
