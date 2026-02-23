#!/usr/bin/env bash
set -uo pipefail

# Memory Upgrade — Organize
# Sorts loose memory files into a clean directory structure.
# Only moves files at the root of memory/ — never touches files already in subdirs.

# Colors
if [ -t 1 ] && command -v tput >/dev/null 2>&1; then
  GREEN=$(tput setaf 2)
  YELLOW=$(tput setaf 3)
  BOLD=$(tput bold)
  RESET=$(tput sgr0)
else
  GREEN="" YELLOW="" BOLD="" RESET=""
fi

# Find workspace
WORKSPACE="${OPENCLAW_WORKSPACE_DIR:-${HOME}/.openclaw/workspace}"
MEMORY_DIR="${WORKSPACE}/memory"

if [ ! -d "$MEMORY_DIR" ]; then
  echo "No memory/ directory found at $MEMORY_DIR"
  echo "Nothing to organize."
  exit 0
fi

echo "${BOLD}Memory Organize${RESET}"
echo "==============="
echo "Workspace: $WORKSPACE"
echo "Memory dir: $MEMORY_DIR"
echo ""

cd "$MEMORY_DIR"

# Create directories
for dir in daily projects marketing campaigns reference insights goals relationships; do
  mkdir -p "$dir"
done

MOVED=0
SKIPPED=0

move_file() {
  local file="$1"
  local dest="$2"
  if [ -f "$file" ]; then
    mkdir -p "$(dirname "$dest")"
    mv "$file" "$dest"
    echo "  ${file} → ${dest}"
    MOVED=$((MOVED + 1))
  fi
}

# --- Daily notes (date-stamped files) ---
echo "${BOLD}Daily notes:${RESET}"
for f in [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]*.md; do
  [ -f "$f" ] || continue
  move_file "$f" "daily/$f"
done

# --- Marketing files ---
echo "${BOLD}Marketing:${RESET}"
for f in *-marketing-stage*.md *-marketing-plan*.md; do
  [ -f "$f" ] || continue
  move_file "$f" "marketing/$f"
done

# --- Campaign files ---
echo "${BOLD}Campaigns:${RESET}"
for f in *-viral-*.md *-launch-campaign*.md *-quiz-*.md; do
  [ -f "$f" ] || continue
  move_file "$f" "campaigns/$f"
done

# --- Reference files ---
echo "${BOLD}Reference:${RESET}"
for f in school-calendar*.md family-reminders*.md *-lessons-learned*.md; do
  [ -f "$f" ] || continue
  move_file "$f" "reference/$f"
done

# --- Revenue/strategy files → projects ---
echo "${BOLD}Projects:${RESET}"
for f in *-negotiation*.md *-bom-*.md *-support-bot*.md *-flavors-strategy*.md *-key-issuance*.md *-revenue-models*.md; do
  [ -f "$f" ] || continue
  move_file "$f" "projects/$f"
done

echo ""
echo "${GREEN}${BOLD}Done.${RESET} Moved ${MOVED} files."

# Count what's left at root
REMAINING=$(find . -maxdepth 1 -name "*.md" -type f | wc -l | tr -d ' ')
if [ "$REMAINING" -gt 0 ]; then
  echo "${YELLOW}${REMAINING} files remain at memory/ root (review manually).${RESET}"
  find . -maxdepth 1 -name "*.md" -type f | sort | sed 's|^./|  |'
fi
