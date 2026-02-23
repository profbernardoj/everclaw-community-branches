#!/usr/bin/env bash
set -uo pipefail

# Memory Upgrade — Tag
# Adds YAML frontmatter to untagged memory files.
# Skips files that already have frontmatter (start with ---).

# Colors
if [ -t 1 ] && command -v tput >/dev/null 2>&1; then
  GREEN=$(tput setaf 2)
  BOLD=$(tput bold)
  RESET=$(tput sgr0)
else
  GREEN="" BOLD="" RESET=""
fi

WORKSPACE="${OPENCLAW_WORKSPACE_DIR:-${HOME}/.openclaw/workspace}"
MEMORY_DIR="${WORKSPACE}/memory"

if [ ! -d "$MEMORY_DIR" ]; then
  echo "No memory/ directory found."
  exit 0
fi

echo "${BOLD}Memory Tag${RESET}"
echo "=========="
echo ""

TAGGED=0
SKIPPED=0

add_frontmatter() {
  local file="$1"
  local frontmatter="$2"

  # Skip if already has frontmatter
  if head -1 "$file" | grep -q "^---"; then
    SKIPPED=$((SKIPPED + 1))
    return
  fi

  # Prepend frontmatter
  local tmpfile="${file}.tmp.$$"
  printf '%s\n' "$frontmatter" | cat - "$file" > "$tmpfile" && mv "$tmpfile" "$file"
  TAGGED=$((TAGGED + 1))
}

# --- Daily notes ---
DAILY_COUNT=0
if [ -d "$MEMORY_DIR/daily" ]; then
  for f in "$MEMORY_DIR"/daily/*.md; do
    [ -f "$f" ] || continue
    basename_f=$(basename "$f" .md)
    # Extract date from filename (first 10 chars: YYYY-MM-DD)
    file_date="${basename_f:0:10}"
    add_frontmatter "$f" "---
tags: [daily, session-log]
date: ${file_date}
---"
    DAILY_COUNT=$((DAILY_COUNT + 1))
  done
  echo "Daily notes: ${DAILY_COUNT} processed"
fi

# --- Marketing ---
MKT_COUNT=0
if [ -d "$MEMORY_DIR/marketing" ]; then
  for f in "$MEMORY_DIR"/marketing/*.md; do
    [ -f "$f" ] || continue
    # Extract flavor name from filename
    basename_f=$(basename "$f" .md)
    flavor=$(echo "$basename_f" | sed 's/-marketing-stage[0-9]*//' | sed 's/-marketing-plan//')
    add_frontmatter "$f" "---
tags: [marketing, flavor, ${flavor}]
status: complete
---"
    MKT_COUNT=$((MKT_COUNT + 1))
  done
  echo "Marketing: ${MKT_COUNT} processed"
fi

# --- Campaigns ---
CAMP_COUNT=0
if [ -d "$MEMORY_DIR/campaigns" ]; then
  for f in "$MEMORY_DIR"/campaigns/*.md; do
    [ -f "$f" ] || continue
    add_frontmatter "$f" "---
tags: [campaign, marketing, launch]
status: complete
---"
    CAMP_COUNT=$((CAMP_COUNT + 1))
  done
  echo "Campaigns: ${CAMP_COUNT} processed"
fi

# --- Goals ---
GOAL_COUNT=0
if [ -d "$MEMORY_DIR/goals" ]; then
  for f in "$MEMORY_DIR"/goals/*.md; do
    [ -f "$f" ] || continue
    goal=$(basename "$f" .md)
    add_frontmatter "$f" "---
tags: [goal, ${goal}]
status: active
---"
    GOAL_COUNT=$((GOAL_COUNT + 1))
  done
  echo "Goals: ${GOAL_COUNT} processed"
fi

# --- Projects ---
PROJ_COUNT=0
if [ -d "$MEMORY_DIR/projects" ]; then
  for f in $(find "$MEMORY_DIR/projects" -name "*.md" -type f); do
    [ -f "$f" ] || continue
    # Get project name from parent directory
    project=$(basename "$(dirname "$f")")
    if [ "$project" = "projects" ]; then
      project=$(basename "$f" .md)
    fi
    add_frontmatter "$f" "---
tags: [project, ${project}]
status: active
---"
    PROJ_COUNT=$((PROJ_COUNT + 1))
  done
  echo "Projects: ${PROJ_COUNT} processed"
fi

# --- Reference ---
REF_COUNT=0
if [ -d "$MEMORY_DIR/reference" ]; then
  for f in "$MEMORY_DIR"/reference/*.md; do
    [ -f "$f" ] || continue
    topic=$(basename "$f" .md)
    add_frontmatter "$f" "---
tags: [reference, ${topic}]
status: active
---"
    REF_COUNT=$((REF_COUNT + 1))
  done
  echo "Reference: ${REF_COUNT} processed"
fi

# --- Insights ---
INS_COUNT=0
if [ -d "$MEMORY_DIR/insights" ]; then
  for f in "$MEMORY_DIR"/insights/*.md; do
    [ -f "$f" ] || continue
    topic=$(basename "$f" .md)
    add_frontmatter "$f" "---
tags: [insight, ${topic}]
status: active
---"
    INS_COUNT=$((INS_COUNT + 1))
  done
  echo "Insights: ${INS_COUNT} processed"
fi

echo ""
echo "${GREEN}${BOLD}Done.${RESET} Tagged: ${TAGGED} | Already tagged: ${SKIPPED}"
