#!/usr/bin/env bash
# PII Guard Setup — EverClaw Security
# Interactive setup for personal data leak prevention
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$HOME/.openclaw/workspace"
PATTERNS_FILE="$WORKSPACE/.pii-patterns.json"
TEMPLATE="$SCRIPT_DIR/pii-patterns.template.json"
HOOKS_DIR="$WORKSPACE/scripts/git-hooks"
SCAN_SCRIPT="$SCRIPT_DIR/pii-scan.sh"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo ""
echo -e "${BOLD}🛡️  PII Guard Setup — EverClaw Security${NC}"
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Step 1: Check dependencies
echo -e "${CYAN}[1/4] Checking dependencies...${NC}"
if command -v jq &>/dev/null; then
  echo -e "  ${GREEN}✓${NC} jq installed"
else
  echo -e "  ${YELLOW}⚠ jq not found — installing...${NC}"
  if command -v brew &>/dev/null; then
    brew install jq
  elif command -v apt-get &>/dev/null; then
    sudo apt-get install -y jq
  else
    echo "  Please install jq manually: https://stedolan.github.io/jq/"
    exit 1
  fi
fi

# Step 2: Create patterns file from template
echo -e "${CYAN}[2/4] Setting up patterns file...${NC}"
if [[ -f "$PATTERNS_FILE" ]]; then
  echo -e "  ${GREEN}✓${NC} Patterns file already exists at $PATTERNS_FILE"
  echo -e "  ${YELLOW}Skipping — edit manually if needed${NC}"
else
  if [[ -f "$TEMPLATE" ]]; then
    cp "$TEMPLATE" "$PATTERNS_FILE"
    echo -e "  ${GREEN}✓${NC} Created $PATTERNS_FILE from template"
    echo -e "  ${YELLOW}⚡ IMPORTANT: Edit this file with YOUR personal data to protect${NC}"
    echo -e "     nano $PATTERNS_FILE"
  else
    echo -e "  ${YELLOW}Template not found — creating minimal patterns file${NC}"
    cat > "$PATTERNS_FILE" << 'MINTEMPLATE'
{
  "version": 1,
  "description": "PII patterns — NEVER commit this file",
  "names": [],
  "emails": [],
  "phones": [],
  "wallets": [],
  "organizations": [],
  "people": [],
  "websites": [],
  "keywords": [],
  "regex": [
    "\\b\\d{3}-\\d{2}-\\d{4}\\b"
  ]
}
MINTEMPLATE
    echo -e "  ${GREEN}✓${NC} Created minimal patterns file"
    echo -e "  ${YELLOW}⚡ IMPORTANT: Add your protected data to $PATTERNS_FILE${NC}"
  fi
fi

# Step 3: Install global git hook
echo -e "${CYAN}[3/4] Installing global git pre-push hook...${NC}"
mkdir -p "$HOOKS_DIR"

# Copy hook from skill directory
cp "$SCRIPT_DIR/pre-push" "$HOOKS_DIR/pre-push"
chmod +x "$HOOKS_DIR/pre-push"

# Copy scanner to scripts
mkdir -p "$WORKSPACE/scripts"
cp "$SCAN_SCRIPT" "$WORKSPACE/scripts/pii-scan.sh"
chmod +x "$WORKSPACE/scripts/pii-scan.sh"

# Set global hooks path
CURRENT_HOOKS=$(git config --global core.hooksPath 2>/dev/null || echo "")
if [[ "$CURRENT_HOOKS" == "$HOOKS_DIR" ]]; then
  echo -e "  ${GREEN}✓${NC} Global hooks already configured"
else
  if [[ -n "$CURRENT_HOOKS" ]]; then
    echo -e "  ${YELLOW}Note: Existing hooks path: $CURRENT_HOOKS${NC}"
    echo -e "  ${YELLOW}Updating to: $HOOKS_DIR${NC}"
  fi
  git config --global core.hooksPath "$HOOKS_DIR"
  echo -e "  ${GREEN}✓${NC} Global git hooks installed at $HOOKS_DIR"
fi

# Step 4: Update .gitignore
echo -e "${CYAN}[4/4] Updating .gitignore...${NC}"
if [[ -f "$WORKSPACE/.gitignore" ]]; then
  if grep -q "pii-patterns" "$WORKSPACE/.gitignore" 2>/dev/null; then
    echo -e "  ${GREEN}✓${NC} .pii-patterns.json already in .gitignore"
  else
    echo ".pii-patterns.json" >> "$WORKSPACE/.gitignore"
    echo -e "  ${GREEN}✓${NC} Added .pii-patterns.json to .gitignore"
  fi
else
  echo ".pii-patterns.json" > "$WORKSPACE/.gitignore"
  echo -e "  ${GREEN}✓${NC} Created .gitignore with .pii-patterns.json"
fi

echo ""
echo -e "${GREEN}${BOLD}✅ PII Guard installed successfully!${NC}"
echo ""
echo -e "Next steps:"
echo -e "  1. Edit your patterns:  ${BOLD}nano $PATTERNS_FILE${NC}"
echo -e "  2. Test the scanner:    ${BOLD}$WORKSPACE/scripts/pii-scan.sh --text \"your name here\"${NC}"
echo -e "  3. Push with confidence — the hook will catch any leaks"
echo ""
echo -e "Every ${BOLD}git push${NC} on this machine now runs through PII Guard."
echo -e "Your agent will also scan before emails, GitHub posts, and other external actions."
echo ""
