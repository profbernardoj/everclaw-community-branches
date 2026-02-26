#!/usr/bin/env bash
# pii-scan.sh V2 — Scan files, directories, text, or git history for PII patterns
# Part of EverClaw PII Guard V2
#
# Usage:
#   pii-scan.sh <file_or_directory>       Scan file(s)
#   pii-scan.sh --text "string"           Scan a string
#   echo "content" | pii-scan.sh -        Scan stdin
#   pii-scan.sh --history [<repo_path>]   Scan full git history
#   pii-scan.sh --repo-scan <repo_path>   Deep scan: current files + history + blocked paths
#
# Exit codes: 0 = clean, 1 = PII found, 2 = error
set -uo pipefail

VERSION="2.0.0"

# ─── Config / Paths ──────────────────────────────────────────────────
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
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

PATTERNS_FILE=$(find_patterns_file) || {
  echo -e "${RED}Error: .pii-patterns.json not found.${NC}" >&2
  echo -e "Run the setup script first: bash security/pii-guard/setup.sh" >&2
  exit 2
}

if ! command -v jq &>/dev/null; then
  echo -e "${RED}Error: jq required (brew install jq / apt install jq)${NC}" >&2
  exit 2
fi

# ─── Pattern Builder ─────────────────────────────────────────────────

# Build user-defined patterns from JSON
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
  # Regex patterns (added raw)
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    [[ -n "$result" ]] && result="$result|$line" || result="$line"
  done < <(jq -r '(.regex // [])[]' "$PATTERNS_FILE" 2>/dev/null)
  echo "$result"
}

# Build built-in detection patterns (generic, not user-specific)
build_builtin_patterns() {
  local result=""
  local patterns=()

  # API key formats — common providers
  patterns+=(
    'VENICE-INFERENCE-KEY-[A-Za-z0-9_-]{20,}'   # Venice AI
    'sk-[A-Za-z0-9.]{20,}'                       # OpenAI / Morpheus Gateway
    'ghp_[A-Za-z0-9]{36}'                         # GitHub personal access token
    'gho_[A-Za-z0-9]{36}'                         # GitHub OAuth token
    'github_pat_[A-Za-z0-9_]{82}'                 # GitHub fine-grained PAT
    'AKIA[0-9A-Z]{16}'                            # AWS access key
    'sk_live_[A-Za-z0-9]{24,}'                    # Stripe live key
    'sk_test_[A-Za-z0-9]{24,}'                    # Stripe test key
    'xox[baprs]-[A-Za-z0-9-]{10,}'               # Slack tokens
    'EAACEdEose0cBA[A-Za-z0-9]+'                  # Facebook access token
  )

  # Home directory paths
  patterns+=(
    '/Users/[A-Za-z][A-Za-z0-9_-]+/'             # macOS home dirs
    '/home/[A-Za-z][A-Za-z0-9_-]+/'              # Linux home dirs
    'C:\\Users\\[A-Za-z][A-Za-z0-9_-]+'          # Windows home dirs
  )

  # Private IP addresses (RFC1918) — real IPs, not template placeholders
  patterns+=(
    '192\.168\.[0-9]{1,3}\.[0-9]{1,3}'           # Class C private
    '10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'    # Class A private
    '172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}'  # Class B private
  )

  # SSN (US)
  patterns+=(
    '[0-9]{3}-[0-9]{2}-[0-9]{4}'                 # SSN format
  )

  for p in "${patterns[@]}"; do
    [[ -n "$result" ]] && result="$result|$p" || result="$p"
  done
  echo "$result"
}

# ─── Blocked Files / Paths ───────────────────────────────────────────

# Check for files that should never be in a repo
check_blocked_paths() {
  local dir="$1"
  local found=0

  # Built-in blocked filenames
  local blocked_files=(
    "verified-bundle.json"
    ".env"
    ".env.local"
    ".env.production"
    "secrets.json"
    "credentials.json"
    ".pii-patterns.json"
  )

  # User-configured blocked paths
  local user_blocked=()
  while IFS= read -r line; do
    [[ -n "$line" ]] && user_blocked+=("$line")
  done < <(jq -r '(.blocked_paths // [])[]' "$PATTERNS_FILE" 2>/dev/null)

  for bf in "${blocked_files[@]}"; do
    local hits
    hits=$(find "$dir" -name "$bf" -not -path '*/.git/*' 2>/dev/null)
    if [[ -n "$hits" ]]; then
      echo -e "  ${RED}🚫 Blocked file:${NC} $bf"
      echo "$hits" | sed 's/^/    /'
      found=1
    fi
  done

  for bp in "${user_blocked[@]}"; do
    local hits
    hits=$(find "$dir" -path "*/$bp*" -not -path '*/.git/*' 2>/dev/null)
    if [[ -n "$hits" ]]; then
      echo -e "  ${RED}🚫 Blocked path:${NC} $bp"
      echo "$hits" | head -5 | sed 's/^/    /'
      found=1
    fi
  done

  return $found
}

# Check git history for blocked filenames that were ever committed
check_history_blocked_paths() {
  local dir="$1"
  local found=0

  local blocked_files=("verified-bundle.json" ".env" ".env.local" ".env.production" "secrets.json" "credentials.json" ".pii-patterns.json")

  cd "$dir"
  for bf in "${blocked_files[@]}"; do
    if git log --all --diff-filter=A --name-only --format='' 2>/dev/null | grep -q "$bf"; then
      echo -e "  ${RED}🚫 Blocked file in history:${NC} $bf (was committed at some point)"
      found=1
    fi
  done

  return $found
}

# ─── Exclusion Helpers ───────────────────────────────────────────────

# Lines to exclude from builtin pattern matches (template/example content)
is_false_positive() {
  local line="$1"
  # Template placeholders
  echo "$line" | grep -qiE "YOUR_KEY_HERE|YOUR_PRIMARY|YOUR_SECOND|placeholder|example|XXXXXXXXXX|YOUR_LOCAL_IP|YOUR_TIMEZONE|192\.168\.x\.x|template|REDACTED" && return 0
  # Test files with fake tokens
  echo "$line" | grep -qiE "sk-abcdef|sk-test_|sk_test_" && return 0
  # Documentation examples
  echo "$line" | grep -qiE "123 Main St|Jane Doe|John Doe|user@example" && return 0
  # Docker standard IPs and well-known infrastructure IPs
  echo "$line" | grep -qiE "172\.17\.0\.1|host\.docker\.internal|10\.0\.0\.1[^0-9]|127\.0\.0\.1" && return 0
  # Localhost / loopback / template subnet references
  echo "$line" | grep -qiE "192\.168\.(x|X|0)\.|(x|X)\.(x|X)" && return 0
  # Container / Docker paths (not personal home dirs)
  echo "$line" | grep -qiE "/home/node/|/home/claw/|/home/user/" && return 0
  # Documentation example IPs (x.x.x.100 pattern commonly used in docs)
  echo "$line" | grep -qiE "192\.168\.[0-9]+\.100[^0-9]|your.*proxy.*host|# your" && return 0
  return 1
}

# ─── Identify Category ──────────────────────────────────────────────

identify_category() {
  local match="$1"
  for cat in names first_names emails phones wallets organizations people websites keywords location_signals; do
    if jq -r "(.${cat} // [])[]" "$PATTERNS_FILE" 2>/dev/null | grep -qiF "$match"; then
      echo "$cat"
      return
    fi
  done
  # Check built-in categories
  if echo "$match" | grep -qE "VENICE-INFERENCE-KEY|sk-[A-Za-z0-9]|ghp_|gho_|AKIA|sk_live|xox"; then
    echo "api_key"
  elif echo "$match" | grep -qE "/Users/|/home/|C:\\\\Users"; then
    echo "filesystem_path"
  elif echo "$match" | grep -qE "^192\.168\.|^10\.|^172\.(1[6-9]|2[0-9]|3[01])\."; then
    echo "private_ip"
  elif echo "$match" | grep -qE "^[0-9]{3}-[0-9]{2}-[0-9]{4}$"; then
    echo "ssn"
  else
    echo "pattern"
  fi
}

# ─── Scanners ────────────────────────────────────────────────────────

USER_PATTERN=$(build_user_patterns)
BUILTIN_PATTERN=$(build_builtin_patterns)

# Combined pattern
if [[ -n "$USER_PATTERN" && -n "$BUILTIN_PATTERN" ]]; then
  FULL_PATTERN="$USER_PATTERN|$BUILTIN_PATTERN"
elif [[ -n "$USER_PATTERN" ]]; then
  FULL_PATTERN="$USER_PATTERN"
elif [[ -n "$BUILTIN_PATTERN" ]]; then
  FULL_PATTERN="$BUILTIN_PATTERN"
else
  echo -e "${GREEN}✓ PII Guard V2: no patterns configured${NC}"
  exit 0
fi

scan_content() {
  local source_label="$1"
  local content="$2"
  local matches
  matches=$(echo "$content" | grep -inE "$FULL_PATTERN" 2>/dev/null || true)

  if [[ -z "$matches" ]]; then
    return 0
  fi

  # Filter false positives
  local real_matches=""
  while IFS= read -r line; do
    if ! is_false_positive "$line"; then
      real_matches+="$line"$'\n'
    fi
  done <<< "$matches"

  # Trim trailing newline
  real_matches=$(echo -n "$real_matches" | sed '/^$/d')

  if [[ -z "$real_matches" ]]; then
    return 0
  fi

  echo -e "${RED}${BOLD}🚫 PII GUARD V2: Personal data detected!${NC}"
  echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "${YELLOW}Source: ${source_label}${NC}"
  echo ""

  local count=0
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    count=$((count + 1))
    [[ $count -gt 30 ]] && echo -e "${YELLOW}... truncated (showing first 30)${NC}" && break
    echo -e "  ${line}"
  done <<< "$real_matches"

  echo ""
  echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  return 1
}

# Scan git history for PII in all past commits
scan_history() {
  local repo_dir="${1:-.}"
  cd "$repo_dir"

  if ! git rev-parse --git-dir &>/dev/null; then
    echo -e "${RED}Error: not a git repository${NC}" >&2
    return 2
  fi

  echo -e "${CYAN}${BOLD}🔍 PII Guard V2 — History Scan${NC}"
  echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "  Repo: $(git remote get-url origin 2>/dev/null || echo 'local')"
  echo -e "  Commits: $(git rev-list --all --count 2>/dev/null || echo '?')"
  echo ""

  local found=0

  # Check all blobs in history for pattern matches
  echo -e "  ${CYAN}Scanning commit diffs...${NC}"
  local history_matches
  history_matches=$(git log --all -p --format="COMMIT:%H %s" 2>/dev/null | grep -inE "$FULL_PATTERN" 2>/dev/null | head -50 || true)

  if [[ -n "$history_matches" ]]; then
    # Filter false positives
    local real_hits=""
    while IFS= read -r line; do
      if ! is_false_positive "$line"; then
        real_hits+="$line"$'\n'
      fi
    done <<< "$history_matches"
    real_hits=$(echo -n "$real_hits" | sed '/^$/d')

    if [[ -n "$real_hits" ]]; then
      echo -e "  ${RED}🔴 PII found in git history:${NC}"
      echo "$real_hits" | head -20 | sed 's/^/    /'
      [[ $(echo "$real_hits" | wc -l) -gt 20 ]] && echo -e "    ${YELLOW}... and more${NC}"
      found=1
    fi
  fi

  # Check for blocked files in history
  check_history_blocked_paths "$repo_dir" || found=1

  echo ""
  if [[ $found -eq 0 ]]; then
    echo -e "  ${GREEN}✅ History clean — no PII found${NC}"
  else
    echo -e "  ${RED}⚠️  PII exists in git history — consider git filter-repo to scrub${NC}"
  fi

  return $found
}

# Deep repo scan: current files + blocked paths + history
scan_repo_deep() {
  local repo_dir="${1:-.}"
  local found=0

  echo -e "${CYAN}${BOLD}🔍 PII Guard V2 — Deep Repo Scan${NC}"
  echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "  Path: $repo_dir"
  echo ""

  # Phase 1: Blocked paths
  echo -e "  ${CYAN}[1/3] Checking blocked files/paths...${NC}"
  if ! check_blocked_paths "$repo_dir"; then
    found=1
  else
    echo -e "  ${GREEN}✓${NC} No blocked files"
  fi
  echo ""

  # Phase 2: Current content scan
  echo -e "  ${CYAN}[2/3] Scanning current files...${NC}"
  local file_count=0
  local hit_count=0
  while IFS= read -r -d '' f; do
    if file -b --mime-type "$f" 2>/dev/null | grep -q "^text/"; then
      file_count=$((file_count + 1))
      local content
      content=$(cat "$f")
      if ! scan_content "$f" "$content" 2>/dev/null; then
        hit_count=$((hit_count + 1))
        found=1
      fi
    fi
  done < <(find "$repo_dir" -type f -not -path '*/.git/*' -not -name '*.png' -not -name '*.jpg' -not -name '*.jpeg' -not -name '*.gif' -not -name '*.ico' -not -name '*.woff*' -not -name '*.woff2' -print0 2>/dev/null)

  if [[ $hit_count -eq 0 ]]; then
    echo -e "  ${GREEN}✓${NC} $file_count files scanned — clean"
  else
    echo -e "  ${RED}✗${NC} $hit_count/$file_count files have PII"
  fi
  echo ""

  # Phase 3: Git history
  echo -e "  ${CYAN}[3/3] Scanning git history...${NC}"
  if ! scan_history "$repo_dir" 2>/dev/null; then
    found=1
  fi

  echo ""
  echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  if [[ $found -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}✅ Deep scan passed — no PII detected${NC}"
  else
    echo -e "${RED}${BOLD}🚫 PII detected — review findings above${NC}"
  fi

  return $found
}

# ─── Main ────────────────────────────────────────────────────────────

found_any=0

case "${1:-}" in
  --version|-v)
    echo "PII Guard V2 — v$VERSION"
    exit 0
    ;;
  --text)
    shift
    scan_content "text input" "$*" || found_any=1
    ;;
  -)
    content=$(cat)
    scan_content "stdin" "$content" || found_any=1
    ;;
  --history)
    shift
    scan_history "${1:-.}" || found_any=1
    ;;
  --repo-scan|--deep)
    shift
    scan_repo_deep "${1:-.}" || found_any=1
    ;;
  --help|-h)
    echo "PII Guard V2 Scanner — EverClaw Security (v$VERSION)"
    echo ""
    echo "Usage:"
    echo "  pii-scan.sh <file_or_dir>           Scan files for PII"
    echo "  pii-scan.sh --text \"string\"          Scan a string"
    echo "  echo \"content\" | pii-scan.sh -       Scan stdin"
    echo "  pii-scan.sh --history [<repo>]       Scan git history for PII"
    echo "  pii-scan.sh --repo-scan [<repo>]     Deep scan: files + history + blocked paths"
    echo "  pii-scan.sh --version                Show version"
    echo ""
    echo "Exit codes: 0=clean, 1=PII found, 2=error"
    echo "Patterns: $PATTERNS_FILE"
    echo ""
    echo "V2 features:"
    echo "  • Built-in API key detection (Venice, OpenAI, GitHub, AWS, Stripe, Slack)"
    echo "  • Filesystem path detection (/Users/*, /home/*)"
    echo "  • Private IP detection (RFC1918)"
    echo "  • Blocked file/path enforcement"
    echo "  • Git history scanning"
    echo "  • False positive filtering"
    echo "  • first_names + location_signals categories"
    exit 0
    ;;
  "")
    echo "PII Guard V2 Scanner — EverClaw Security (v$VERSION)"
    echo "Run: pii-scan.sh --help"
    exit 2
    ;;
  *)
    for target in "$@"; do
      if [[ -d "$target" ]]; then
        while IFS= read -r -d '' f; do
          if file -b --mime-type "$f" 2>/dev/null | grep -q "^text/"; then
            content=$(cat "$f")
            scan_content "$f" "$content" || found_any=1
          fi
        done < <(find "$target" -type f -not -path '*/.git/*' -not -name '*.png' -not -name '*.jpg' -not -name '*.jpeg' -not -name '*.gif' -not -name '*.ico' -not -name '*.woff*' -print0 2>/dev/null)
      elif [[ -f "$target" ]]; then
        content=$(cat "$target")
        scan_content "$target" "$content" || found_any=1
      else
        echo -e "${YELLOW}Warning: $target not found, skipping${NC}" >&2
      fi
    done
    ;;
esac

if [[ $found_any -eq 0 ]]; then
  echo -e "${GREEN}✓ PII Guard V2: scan clean — no personal data detected${NC}"
  exit 0
else
  exit 1
fi
