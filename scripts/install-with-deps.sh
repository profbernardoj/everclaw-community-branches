#!/bin/bash
#
# EverClaw Installer with Dependency Detection
# 
# This script checks for required dependencies and guides users through
# installing them before proceeding with the EverClaw setup.
#
# Usage:
#   curl -fsSL https://get.everclaw.xyz | bash
#   # or
#   bash scripts/install-with-deps.sh
#
# Options:
#   --auto-install    Automatically install missing dependencies without prompting
#   --check-only      Only check dependencies, don't install EverClaw
#   --skip-openclaw   Skip OpenClaw installation check (for existing installations)
#
# Requirements:
#   - macOS or Linux
#   - curl (for downloading)
#   - git (for cloning)
#   - node + npm (for bootstrap scripts)
#   - OpenClaw (the agent runtime)
#

set -e

# ─── Colors ──────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# ─── Parse Arguments ─────────────────────────────────────────────

AUTO_INSTALL=false
CHECK_ONLY=false
SKIP_OPENCLAW=false

for arg in "$@"; do
  case $arg in
    --auto-install)
      AUTO_INSTALL=true
      shift
      ;;
    --check-only)
      CHECK_ONLY=true
      shift
      ;;
    --skip-openclaw)
      SKIP_OPENCLAW=true
      shift
      ;;
    --help)
      echo "EverClaw Installer with Dependency Detection"
      echo ""
      echo "Usage: bash install-with-deps.sh [options]"
      echo ""
      echo "Options:"
      echo "  --auto-install    Automatically install missing dependencies"
      echo "  --check-only      Only check dependencies, don't install EverClaw"
      echo "  --skip-openclaw   Skip OpenClaw check (for existing installations)"
      echo "  --help            Show this help message"
      exit 0
      ;;
    *)
      echo -e "${RED}Unknown option: $arg${NC}"
      exit 1
      ;;
  esac
done

# ─── Banner ──────────────────────────────────────────────────────

echo ""
echo -e "${CYAN}♾️  EverClaw Installer${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${BOLD}Own your inference. Forever.${NC}"
echo ""

# ─── OS Detection ────────────────────────────────────────────────

OS=$(uname -s)
ARCH=$(uname -m)

case "$OS" in
  Darwin)
    PLATFORM="macOS"
    PACKAGE_MANAGER="brew"
    ;;
  Linux)
    PLATFORM="Linux"
    if command -v apt-get &>/dev/null; then
      PACKAGE_MANAGER="apt"
    elif command -v dnf &>/dev/null; then
      PACKAGE_MANAGER="dnf"
    elif command -v yum &>/dev/null; then
      PACKAGE_MANAGER="yum"
    elif command -v pacman &>/dev/null; then
      PACKAGE_MANAGER="pacman"
    else
      PACKAGE_MANAGER="unknown"
    fi
    ;;
  *)
    echo -e "${RED}✗ Unsupported OS: $OS${NC}"
    echo "  EverClaw requires macOS or Linux."
    exit 1
    ;;
esac

echo -e "Platform: ${GREEN}$PLATFORM${NC} (${ARCH})"
echo ""

# ─── Dependency Checking ──────────────────────────────────────────

# Dependencies to check (in order)
# Format: name:command:description:install_cmd

echo -e "${BOLD}Checking dependencies...${NC}"
echo ""

MISSING=""
MISSING_COUNT=0

check_dep() {
  local name="$1"
  local cmd="$2"
  local desc="$3"
  local install="$4"
  
  if command -v "$cmd" &>/dev/null; then
    local version=""
    case $cmd in
      node)  version=" ($(node --version 2>/dev/null || echo 'unknown'))" ;;
      npm)   version=" ($(npm --version 2>/dev/null | head -1 || echo 'unknown'))" ;;
      git)   version=" ($(git --version 2>/dev/null | awk '{print $3}' || echo 'unknown'))" ;;
      brew)  version=" ($(brew --version 2>/dev/null | head -1 | awk '{print $2}' || echo 'unknown'))" ;;
    esac
    echo -e "  ${GREEN}✓${NC} ${name}${version}${desc:+ - $desc}"
    return 0
  else
    echo -e "  ${RED}✗${NC} ${name} ${YELLOW}(missing)${NC}${desc:+ - $desc}"
    MISSING="$MISSING:$name:$install"
    MISSING_COUNT=$((MISSING_COUNT + 1))
    return 1
  fi
}

# Check core dependencies
check_dep "curl" "curl" "HTTP client for downloads" "comes with macOS/Linux"
check_dep "git" "git" "Version control" "brew install git"
check_dep "Node.js" "node" "JavaScript runtime (v18+)" "brew install node"
check_dep "npm" "npm" "Node package manager" "comes with Node.js"

# Check Homebrew on macOS
if [[ "$OS" == "Darwin" ]]; then
  check_dep "Homebrew" "brew" "Package manager" '/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"'
fi

# Check OpenClaw (unless skipped)
if [[ "$SKIP_OPENCLAW" != true ]]; then
  check_dep "OpenClaw" "openclaw" "Agent runtime" "curl -fsSL https://get.openclaw.ai | bash"
fi

echo ""

# ─── Handle Missing Dependencies ──────────────────────────────────

if [[ $MISSING_COUNT -gt 0 ]]; then
  echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "${YELLOW}Missing dependencies: $MISSING_COUNT${NC}"
  echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo ""
  
  # Print install instructions
  echo -e "${BOLD}To install missing dependencies:${NC}"
  echo ""
  
  # Parse MISSING string and print instructions
  IFS=':' read -ra PARTS <<< "$MISSING"
  i=0
  while [[ $i -lt ${#PARTS[@]} ]]; do
    if [[ $((i % 2)) -eq 0 ]] && [[ -n "${PARTS[$i]}" ]]; then
      local dep_name="${PARTS[$i]}"
      local dep_install="${PARTS[$((i+1))]}"
      echo -e "  ${CYAN}$dep_name${NC}"
      if [[ -n "$dep_install" ]] && [[ "$dep_install" != "comes with"* ]]; then
        echo -e "    $dep_install"
      fi
      echo ""
    fi
    i=$((i + 1))
  done
  
  # Auto-install or prompt
  if [[ "$AUTO_INSTALL" == true ]]; then
    echo -e "${CYAN}Auto-installing missing dependencies...${NC}"
    echo ""
    install_dependencies
  elif [[ "$CHECK_ONLY" == true ]]; then
    echo -e "${YELLOW}Run without --check-only to install EverClaw${NC}"
    exit 1
  else
    echo -e "${BOLD}Would you like to install missing dependencies automatically?${NC}"
    read -p "  [y/N] " -n 1 -r
    echo ""
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
      install_dependencies
    else
      echo ""
      echo -e "${YELLOW}Please install the missing dependencies and re-run this script.${NC}"
      echo -e "${YELLOW}Quick install:${NC}"
      echo ""
      if [[ "$OS" == "Darwin" ]]; then
        echo "  # Install Homebrew (if needed)"
        echo '  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"'
        echo ""
      fi
      echo "  # Install Node.js"
      echo "  brew install node"
      echo ""
      if [[ "$SKIP_OPENCLAW" != true ]]; then
        echo "  # Install OpenClaw"
        echo "  curl -fsSL https://get.openclaw.ai | bash"
      fi
      echo ""
      exit 1
    fi
  fi
fi

# ─── Install Dependencies Function ─────────────────────────────────

install_dependencies() {
  # Parse MISSING and install each
  IFS=':' read -ra PARTS <<< "$MISSING"
  i=0
  while [[ $i -lt ${#PARTS[@]} ]]; do
    if [[ $((i % 2)) -eq 0 ]] && [[ -n "${PARTS[$i]}" ]]; then
      local dep_name="${PARTS[$i]}"
      
      echo -e "${CYAN}Installing $dep_name...${NC}"
      
      case "$dep_name" in
        "Homebrew")
          /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
          # Add to PATH for current session
          if [[ -f "/opt/homebrew/bin/brew" ]]; then
            eval "$(/opt/homebrew/bin/brew shellenv)"
          elif [[ -f "/usr/local/bin/brew" ]]; then
            eval "$(/usr/local/bin/brew shellenv)"
          fi
          ;;
          
        "git")
          if [[ "$OS" == "Darwin" ]]; then
            brew install git
          elif [[ "$PACKAGE_MANAGER" == "apt" ]]; then
            sudo apt-get update && sudo apt-get install -y git
          elif [[ "$PACKAGE_MANAGER" == "dnf" ]]; then
            sudo dnf install -y git
          elif [[ "$PACKAGE_MANAGER" == "yum" ]]; then
            sudo yum install -y git
          elif [[ "$PACKAGE_MANAGER" == "pacman" ]]; then
            sudo pacman -S --noconfirm git
          fi
          ;;
          
        "Node.js"|"npm")
          if [[ "$OS" == "Darwin" ]]; then
            brew install node
          elif [[ "$PACKAGE_MANAGER" == "apt" ]]; then
            curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
            sudo apt-get install -y nodejs
          elif [[ "$PACKAGE_MANAGER" == "dnf" ]]; then
            sudo dnf install -y nodejs
          elif [[ "$PACKAGE_MANAGER" == "yum" ]]; then
            sudo yum install -y nodejs
          elif [[ "$PACKAGE_MANAGER" == "pacman" ]]; then
            sudo pacman -S --noconfirm nodejs npm
          fi
          ;;
          
        "OpenClaw")
          curl -fsSL https://get.openclaw.ai | bash
          ;;
          
        *)
          echo -e "${YELLOW}Cannot auto-install $dep_name. Please install manually.${NC}"
          ;;
      esac
    fi
    i=$((i + 2))
  done
  
  echo ""
  echo -e "${GREEN}✓ Dependencies installed${NC}"
  echo ""
  
  # Re-check
  echo -e "${BOLD}Verifying installation...${NC}"
  MISSING=""
  MISSING_COUNT=0
  check_dep "curl" "curl" "HTTP client" ""
  check_dep "git" "git" "Version control" ""
  check_dep "Node.js" "node" "JavaScript runtime" ""
  check_dep "npm" "npm" "Node package manager" ""
  if [[ "$OS" == "Darwin" ]]; then
    check_dep "Homebrew" "brew" "Package manager" ""
  fi
  if [[ "$SKIP_OPENCLAW" != true ]]; then
    check_dep "OpenClaw" "openclaw" "Agent runtime" ""
  fi
  echo ""
  
  if [[ $MISSING_COUNT -gt 0 ]]; then
    echo -e "${RED}Some dependencies could not be installed automatically.${NC}"
    echo -e "${YELLOW}Please install them manually and re-run this script.${NC}"
    exit 1
  fi
}

# ─── Check Only Mode ───────────────────────────────────────────────

if [[ "$CHECK_ONLY" == true ]]; then
  echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "${GREEN}✓ All dependencies satisfied!${NC}"
  echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo ""
  echo "Run without --check-only to install EverClaw."
  exit 0
fi

# ─── All Dependencies Satisfied ────────────────────────────────────

echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}✓ All dependencies satisfied!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# ─── Install EverClaw ──────────────────────────────────────────────

echo -e "${BOLD}Installing EverClaw...${NC}"
echo ""

INSTALL_DIR="$HOME/.openclaw/workspace/skills/everclaw"

# Check if already installed
if [[ -d "$INSTALL_DIR" ]]; then
  echo -e "${YELLOW}EverClaw is already installed at $INSTALL_DIR${NC}"
  read -p "  Update to latest version? [y/N] " -n 1 -r
  echo ""
  
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${CYAN}Updating EverClaw...${NC}"
    cd "$INSTALL_DIR"
    git pull origin main
    npm install --production
    echo -e "${GREEN}✓ EverClaw updated${NC}"
  else
    echo -e "${YELLOW}Skipping update${NC}"
  fi
else
  echo -e "${CYAN}Cloning EverClaw skill...${NC}"
  mkdir -p "$HOME/.openclaw/workspace/skills"
  cd "$HOME/.openclaw/workspace/skills"
  
  git clone https://github.com/profbernardoj/everclaw.git everclaw
  cd everclaw
  
  echo -e "${CYAN}Installing dependencies...${NC}"
  npm install --production 2>/dev/null || {
    echo -e "${YELLOW}npm install failed, but continuing...${NC}"
  }
  
  echo -e "${GREEN}✓ EverClaw installed${NC}"
fi

echo ""

# ─── Bootstrap API Key ─────────────────────────────────────────────

echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}Bootstrap: GLM-5 Starter Key${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

if [[ -f "$HOME/.openclaw/.bootstrap-key" ]]; then
  echo -e "${GREEN}✓ Bootstrap key already configured${NC}"
else
  echo "Getting your starter key for GLM-5 inference..."
  echo ""
  
  if command -v node &>/dev/null; then
    if [[ -f "$INSTALL_DIR/scripts/bootstrap-everclaw.mjs" ]]; then
      cd "$INSTALL_DIR"
      node scripts/bootstrap-everclaw.mjs --setup || {
        echo -e "${YELLOW}Could not reach EverClaw key server.${NC}"
        echo "  Run manually later: node scripts/bootstrap-everclaw.mjs"
      }
    fi
  fi
fi

echo ""

# ─── Install Morpheus Proxy-Router (Optional) ──────────────────────

echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}Morpheus Proxy-Router (Optional)${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "The Morpheus proxy-router enables local P2P inference."
echo "This is optional — the API Gateway (with your starter key)"
echo "provides immediate access to GLM-5 without additional setup."
echo ""
read -p "Install Morpheus proxy-router? [y/N] " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
  # Run the existing install.sh for the proxy-router
  if [[ -f "$INSTALL_DIR/scripts/install.sh" ]]; then
    bash "$INSTALL_DIR/scripts/install.sh"
  fi
fi

echo ""

# ─── Success ───────────────────────────────────────────────────────

echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}✓ EverClaw Setup Complete!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${BOLD}Next steps:${NC}"
echo ""
echo "  1. Restart OpenClaw:"
echo "     ${CYAN}openclaw gateway restart${NC}"
echo ""
echo "  2. Test your setup:"
echo "     ${CYAN}node ~/.openclaw/workspace/skills/everclaw/scripts/bootstrap-everclaw.mjs --test${NC}"
echo ""
echo "  3. Get your own API key (optional):"
echo "     ${CYAN}https://app.mor.org${NC}"
echo ""
echo -e "${BOLD}Your GLM-5 starter key provides:${NC}"
echo "  • 1,000 requests per day"
echo "  • 30-day auto-renewal"
echo "  • Access to GLM-5 via Morpheus Gateway"
echo ""
echo -e "${CYAN}♾️  Own your inference. Forever.${NC}"
echo ""