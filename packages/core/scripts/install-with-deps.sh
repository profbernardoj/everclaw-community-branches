#!/bin/bash
#
# EverClaw Installer — Zero-Prompt Auto-Install
#
# One command. Zero prompts. Working agent.
#
#   curl -fsSL https://get.everclaw.xyz | bash
#
# Detects OS and hardware, installs all dependencies automatically.
# Every component auto-installs or auto-skips based on hardware detection.
#
# Options:
#   --check-only      Show what would happen, don't install anything
#   --skip-openclaw   Skip OpenClaw installation check
#   --skip-ollama     Skip local Ollama installation
#   --skip-proxy      Skip Morpheus proxy-router installation
#   --auto-install    Legacy flag (now default behavior)
#
# Requirements:
#   - macOS or Linux
#   - Internet connection
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

# ─── State Variables ─────────────────────────────────────────────

CHECK_ONLY=false
SKIP_OPENCLAW=false
SKIP_OLLAMA=false
FORCE_OLLAMA=false
SKIP_PROXY=false

# Hardware detection results (set by detect_hardware)
TOTAL_RAM_MB=0
AVAILABLE_RAM_MB=0
DISK_FREE_MB=0
GPU_TYPE="none"

# Dependency tracking
MISSING_DEPS=()
MISSING_COUNT=0

# ─── Parse Arguments ─────────────────────────────────────────────

for arg in "$@"; do
  case $arg in
    --auto-install)
      # Legacy flag — auto-install is now default. No-op.
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
    --skip-ollama)
      SKIP_OLLAMA=true
      shift
      ;;
    --ollama-already-installed)
      FORCE_OLLAMA=true
      shift
      ;;
    --skip-proxy)
      SKIP_PROXY=true
      shift
      ;;
    --help)
      echo "EverClaw Installer — Zero-Prompt Auto-Install"
      echo ""
      echo "Usage:"
      echo "  curl -fsSL https://get.everclaw.xyz | bash"
      echo "  bash scripts/install-with-deps.sh [options]"
      echo ""
      echo "Options:"
      echo "  --check-only      Show what would happen, don't install"
      echo "  --skip-openclaw   Skip OpenClaw installation check"
      echo "  --skip-ollama              Skip local Ollama installation"
      echo "  --ollama-already-installed  Mark Ollama as installed (skip detection)"
      echo "  --skip-proxy               Skip Morpheus proxy-router installation"
      echo "  --auto-install    Legacy flag (now default behavior)"
      echo "  --help            Show this help message"
      exit 0
      ;;
    *)
      echo -e "${RED}Unknown option: $arg${NC}"
      exit 1
      ;;
  esac
done

# ─── Logging Helpers ─────────────────────────────────────────────

log()      { echo -e "  $1"; }
log_ok()   { echo -e "  ${GREEN}✓${NC} $1"; }
log_warn() { echo -e "  ${YELLOW}⚠${NC}  $1"; }
log_err()  { echo -e "  ${RED}✗${NC} $1"; }
log_skip() { echo -e "  ${YELLOW}→${NC} Skipping $1"; }

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
  MINGW*|MSYS*|CYGWIN*)
    log_err "Unsupported OS: $OS"
    log "EverClaw requires macOS or Linux."
    log "Windows (Git Bash / MSYS / Cygwin) is not supported."
    log "Please install WSL 2 and run the installer inside WSL:"
    log "  → https://learn.microsoft.com/en-us/windows/wsl/install"
    exit 1
    ;;
  *)
    log_err "Unsupported OS: $OS"
    log "EverClaw requires macOS or Linux."
    exit 1
    ;;
esac

log "Platform:     ${PLATFORM} (${ARCH})"

# ─── Hardware Detection ─────────────────────────────────────────
# Detects RAM, disk, GPU for downstream gating (proxy-router, Ollama).
# Patterns reused from setup-ollama.sh.

detect_hardware() {
  # --- RAM ---
  if [[ "$OS" == "Darwin" ]]; then
    TOTAL_RAM_MB=$(/usr/sbin/sysctl -n hw.memsize 2>/dev/null | awk '{print int($1 / 1048576)}') || TOTAL_RAM_MB=0
    local page_size
    page_size=$(/usr/sbin/sysctl -n hw.pagesize 2>/dev/null || echo "4096")
    local vm_stats
    vm_stats=$(/usr/bin/vm_stat 2>/dev/null || echo "")
    if [[ -n "$vm_stats" ]]; then
      local pages_free pages_inactive
      pages_free=$(echo "$vm_stats" | grep "Pages free" | awk '{print $3}' | tr -d '.')
      pages_inactive=$(echo "$vm_stats" | grep "Pages inactive" | awk '{print $3}' | tr -d '.')
      pages_free=${pages_free:-0}
      pages_inactive=${pages_inactive:-0}
      AVAILABLE_RAM_MB=$(( (pages_free + pages_inactive) * page_size / 1048576 ))
    else
      AVAILABLE_RAM_MB=$((TOTAL_RAM_MB / 2))
    fi
  else
    TOTAL_RAM_MB=$(awk '/MemTotal/ {print int($2 / 1024)}' /proc/meminfo 2>/dev/null) || TOTAL_RAM_MB=0
    AVAILABLE_RAM_MB=$(awk '/MemAvailable/ {print int($2 / 1024)}' /proc/meminfo 2>/dev/null) || AVAILABLE_RAM_MB=0
    if [[ -z "$AVAILABLE_RAM_MB" || "$AVAILABLE_RAM_MB" == "0" ]]; then
      local free_kb buffers_kb cached_kb
      free_kb=$(awk '/MemFree/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
      buffers_kb=$(awk '/Buffers/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
      cached_kb=$(awk '/^Cached/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
      AVAILABLE_RAM_MB=$(( (free_kb + buffers_kb + cached_kb) / 1024 ))
    fi
  fi

  # --- Disk free (home partition) ---
  DISK_FREE_MB=$(df -m "$HOME" 2>/dev/null | tail -1 | awk '{print $4}') || DISK_FREE_MB=0

  # --- GPU ---
  GPU_TYPE="none"
  if [[ "$OS" == "Darwin" ]]; then
    local cpu_brand
    cpu_brand=$(/usr/sbin/sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "")
    if echo "$cpu_brand" | grep -qi "apple"; then
      GPU_TYPE="metal"
    fi
  else
    if command -v nvidia-smi &>/dev/null; then
      GPU_TYPE="nvidia"
    elif command -v rocm-smi &>/dev/null; then
      GPU_TYPE="amd"
    fi
  fi

  # Print summary
  local total_gb disk_gb
  total_gb=$(awk "BEGIN {printf \"%.1f\", ${TOTAL_RAM_MB:-0}/1024}")
  disk_gb=$(awk "BEGIN {printf \"%.1f\", ${DISK_FREE_MB:-0}/1024}")
  log "RAM:          ${total_gb} GB total"
  log "Disk free:    ${disk_gb} GB"
  log "GPU:          ${GPU_TYPE}"
}

echo -e "${BOLD}Detecting hardware...${NC}"
detect_hardware
echo ""

# ─── Global Variables ─────────────────────────────────────────────
BREW_CMD=""

# ─── Install‑time Verification Helper ───────────────────────────────
# Once an item is installed, verify it actually worked.
verify_installed() {
  local name="$1"
  local cmd="$2"
  
  if command -v "$cmd" &>/dev/null; then
    local version=""
    case $cmd in
      node)  version=" ($(node --version 2>/dev/null || echo 'unknown'))" ;;
      npm)   version=" ($(npm --version 2>/dev/null | head -1 || echo 'unknown'))" ;;
      git)   version=" ($(git --version 2>/dev/null | awk '{print $3}' || echo 'unknown'))" ;;
      brew)  version=" ($(brew --version 2>/dev/null | head -1 | awk '{print $2}' || echo 'unknown'))" ;;
      openclaw) version=" ($(openclaw --version 2>/dev/null | head -1 || echo 'unknown'))" ;;
    esac
    log_ok "${name}${version}"
    return 0
  else
    log_err "${name} (install failed)"
    return 1
  fi
}

# ─── Admin Pre‑Check (macOS) ───────────────────────────────────────
# Detect non‑admin accounts and warn, but continue with nvm fallback.
is_macos_admin() {
  [[ "$OS" != "Darwin" ]] && return 0
  # Check admin group (handles localized "administradores" etc.)
  if id -Gn 2>/dev/null | grep -qiE '\b(admin|administradores|administrator)\b'; then
    return 0
  fi
  # Check for password‑less sudo access
  sudo -n true 2>/dev/null && return 0
  return 1
}

# ─── Commit PATH changes permanently ───────────────────────────────
persist_brew_path() {
  [[ "$OS" != "Darwin" || -z "$BREW_CMD" ]] && return 0
  
  # Find shell profile file
  local profile_file="$HOME/.zprofile"
  [[ "${SHELL##*/}" == "bash" ]] && profile_file="$HOME/.bash_profile"
  [[ ! -f "$profile_file" ]] && profile_file="$HOME/.profile"
  
  # Append brew shellenv if not already present
  local brew_env_line="eval \"\$($BREW_CMD shellenv)\""
  if ! grep -Fxq "$brew_env_line" "$profile_file" 2>/dev/null; then
    echo "" >> "$profile_file"
    echo "$brew_env_line" >> "$profile_file"
    log_ok "Homebrew PATH persisted to $profile_file"
    log "  Restart Terminal or run: source $profile_file"
  fi
}

# ─── Reload PATH for current session ───────────────────────────────
reload_brew_path() {
  if [[ -n "$BREW_CMD" ]] && [[ -f "$BREW_CMD" ]]; then
    eval "$("$BREW_CMD" shellenv)" 2>/dev/null
    hash -r
  fi
}

# ─── Fallback: nvm for Node.js (no admin required) ───────────────────
use_nvm_for_node() {
  [[ "$OS" != "Darwin" ]] && return 1
  
  log "Homebrew unavailable → falling back to nvm (no admin required)..."
  
  # Install nvm if not present
  if [[ ! -s "$HOME/.nvm/nvm.sh" ]]; then
    curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash 2>&1 | tail -5
  fi
  
  # Load nvm
  export NVM_DIR="$HOME/.nvm"
  [ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
  
  # Install latest LTS (future‑proof)
  log "Installing Node.js via nvm..."
  nvm install --lts && nvm use --lts
  
  # Refresh PATH for current script session
  export PATH="$NVM_DIR/versions/node/$(nvm current)/bin:$PATH"
  hash -r
  
  if command -v node &>/dev/null && command -v npm &>/dev/null; then
    log_ok "Node.js & npm installed via nvm"
    return 0
  else
    log_err "nvm failed to install Node.js"
    return 1
  fi
}

# ─── macOS Admin Check (soft warning + nvm fallback) ────────────────
if [[ "$OS" == "Darwin" ]] && ! is_macos_admin; then
  log_warn "User '$USER' does not have administrator rights"
  log "  Homebrew requires admin rights → will use nvm fallback for Node.js"
  log "  (Optional) System Settings → Users & Groups → Allow user to administer this computer"
  echo ""
fi

# ─── Dependency Checking ──────────────────────────────────────────

check_dep() {
  local name="$1"
  local cmd="$2"

  if command -v "$cmd" &>/dev/null; then
    local version=""
    case $cmd in
      node)  version=" ($(node --version 2>/dev/null || echo 'unknown'))" ;;
      npm)   version=" ($(npm --version 2>/dev/null | head -1 || echo 'unknown'))" ;;
      git)   version=" ($(git --version 2>/dev/null | awk '{print $3}' || echo 'unknown'))" ;;
      brew)  version=" ($(brew --version 2>/dev/null | head -1 | awk '{print $2}' || echo 'unknown'))" ;;
      openclaw) version=" ($(openclaw --version 2>/dev/null | head -1 || echo 'unknown'))" ;;
    esac
    log_ok "${name}${version}"
    return 0
  else
    log_err "${name} ${YELLOW}(missing)${NC}"
    MISSING_DEPS+=("$name")
    MISSING_COUNT=$((MISSING_COUNT + 1))
    return 1
  fi
}

echo -e "${BOLD}Checking dependencies...${NC}"
echo ""

# Homebrew first on macOS (needed to install others)
if [[ "$OS" == "Darwin" ]]; then
  check_dep "Homebrew" "brew" || true
fi

check_dep "curl" "curl" || true
check_dep "git" "git" || true
check_dep "Node.js" "node" || true
check_dep "npm" "npm" || true

if [[ "$SKIP_OPENCLAW" != true ]]; then
  check_dep "OpenClaw" "openclaw" || true
fi

echo ""

# ─── Auto-Install Missing Dependencies ──────────────────────────

install_dep() {
  local name="$1"

  echo -e "  ${CYAN}Installing ${name}...${NC}"

  case "$name" in
    Homebrew)
      NONINTERACTIVE=1 /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" </dev/null
      
      # Detect where brew was installed
      if [[ -f "/opt/homebrew/bin/brew" ]]; then
        BREW_CMD="/opt/homebrew/bin/brew"
      elif [[ -f "/usr/local/bin/brew" ]]; then
        BREW_CMD="/usr/local/bin/brew"
      else
        log_err "Homebrew install failed"
        log "  Manual install: https://brew.sh"
        return 1
      fi
      
      # Immediately reload PATH for current session
      reload_brew_path
      
      # Verify and persist
      if verify_installed "Homebrew" "brew"; then
        persist_brew_path
        return 0
      else
        return 1
      fi
      ;;

    curl)
      case "$PACKAGE_MANAGER" in
        apt)    sudo apt-get update -qq && sudo apt-get install -y -qq curl ;;
        dnf)    sudo dnf install -y -q curl ;;
        yum)    sudo yum install -y -q curl ;;
        pacman) sudo pacman -S --noconfirm curl ;;
        *)      log_warn "Cannot auto-install curl on this system"; return 1 ;;
      esac
      verify_installed "curl" "curl" || return 1
      ;;

    git)
      if [[ "$OS" == "Darwin" ]]; then
        if [[ -n "$BREW_CMD" ]]; then
          "$BREW_CMD" install git 2>&1 | tail -3
          verify_installed "git" "git" || return 1
        else
          log_err "Git install skipped (no Homebrew on this Mac)"
          log "  Install Xcode Command Line Tools: xcode-select --install"
          return 1
        fi
      else
        case "$PACKAGE_MANAGER" in
          apt)    sudo apt-get update -qq && sudo apt-get install -y -qq git ;;
          dnf)    sudo dnf install -y -q git ;;
          yum)    sudo yum install -y -q git ;;
          pacman) sudo pacman -S --noconfirm git ;;
          *)      log_warn "Cannot auto-install git on this system"; return 1 ;;
        esac
        verify_installed "git" "git" || return 1
      fi
      ;;

    "Node.js")
      if [[ "$OS" == "Darwin" ]]; then
        if [[ -n "$BREW_CMD" ]] && is_macos_admin; then
          # Try Homebrew (admin available)
          "$BREW_CMD" install node 2>&1 | tail -3
          sleep 1
          reload_brew_path
          if ! verify_installed "Node.js" "node" 2>/dev/null; then
            use_nvm_for_node || return 1
          fi
        else
          # Non‑admin or Homebrew failed — use nvm
          use_nvm_for_node || return 1
        fi
      else
        # Linux
        case "$PACKAGE_MANAGER" in
          apt)
            curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
            sudo apt-get install -y -qq nodejs
            ;;
          dnf)    sudo dnf install -y -q nodejs ;;
          yum)    sudo yum install -y -q nodejs ;;
          pacman) sudo pacman -S --noconfirm nodejs npm ;;
          *)      log_warn "Cannot auto-install Node.js on this system"; return 1 ;;
        esac
        verify_installed "Node.js" "node"
      fi
      ;;

    npm)
      # npm comes with Node.js — just verify
      if verify_installed "npm" "npm" 2>/dev/null; then
        return 0
      fi
      # On Linux, npm might need separate install
      case "$PACKAGE_MANAGER" in
        apt)    sudo apt-get install -y -qq npm ;;
        dnf)    sudo dnf install -y -q npm ;;
        yum)    sudo yum install -y -q npm ;;
        pacman) sudo pacman -S --noconfirm npm ;;
        *)      log_warn "Cannot auto-install npm on this system"; return 1 ;;
      esac
      verify_installed "npm" "npm" || return 1
      ;;

    OpenClaw)
      if command -v npm &>/dev/null; then
        npm install -g openclaw@latest 2>&1 | tail -3
        verify_installed "OpenClaw" "openclaw" || return 1
      else
        log_err "npm not found — cannot install OpenClaw"
        return 1
      fi
      ;;

    *)
      log_warn "Cannot auto-install ${name}"
      return 1
      ;;
  esac
}

if [[ $MISSING_COUNT -gt 0 ]]; then
  if [[ "$CHECK_ONLY" == true ]]; then
    echo -e "${YELLOW}Missing ${MISSING_COUNT} dependencies. Run without --check-only to auto-install.${NC}"
    echo ""
  else
    echo -e "${CYAN}Auto-installing ${MISSING_COUNT} missing dependencies...${NC}"
    echo ""

    for dep in "${MISSING_DEPS[@]}"; do
      install_dep "$dep" || {
        log_err "Failed to install ${dep}"
        echo ""
        echo -e "${RED}Could not auto-install ${dep}.${NC}"
        echo "  Please install it manually and re-run this script."
        exit 1
      }
    done

    # Re-verify
    echo ""
    echo -e "${BOLD}Verifying installation...${NC}"
    MISSING_DEPS=()
    MISSING_COUNT=0
    if [[ "$OS" == "Darwin" ]]; then
      check_dep "Homebrew" "brew" || true
    fi
    check_dep "curl" "curl" || true
    check_dep "git" "git" || true
    check_dep "Node.js" "node" || true
    check_dep "npm" "npm" || true
    if [[ "$SKIP_OPENCLAW" != true ]]; then
      check_dep "OpenClaw" "openclaw" || true
    fi
    echo ""

    if [[ $MISSING_COUNT -gt 0 ]]; then
      log_err "Some dependencies could not be installed automatically."
      log "Please install them manually and re-run this script."
      exit 1
    fi
  fi
fi

# ─── Check Only Mode ───────────────────────────────────────────────

if [[ "$CHECK_ONLY" == true ]]; then
  echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "${GREEN}✓ Dependency check complete${NC}"
  echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo ""

  # Show what would happen for optional components
  echo -e "${BOLD}Optional components:${NC}"
  echo ""

  # Proxy-router gating
  if [[ "$SKIP_PROXY" == true ]]; then
    log_skip "Morpheus proxy-router (--skip-proxy)"
  elif [[ -f "$HOME/morpheus/proxy-router" ]]; then
    log_ok "Morpheus proxy-router (already installed)"
  elif [[ "${DISK_FREE_MB:-0}" -ge 2048 ]]; then
    log "Morpheus proxy-router: ${GREEN}would install${NC} (${DISK_FREE_MB} MB free ≥ 2048 MB)"
  else
    log "Morpheus proxy-router: ${YELLOW}would skip${NC} (${DISK_FREE_MB} MB free < 2048 MB)"
  fi

  # Ollama gating
  if [[ "$SKIP_OLLAMA" == true ]]; then
    log_skip "Local Ollama (--skip-ollama)"
  elif command -v ollama &>/dev/null; then
    log_ok "Local Ollama (already installed)"
  elif [[ "${DISK_FREE_MB:-0}" -ge 5120 && "${TOTAL_RAM_MB:-0}" -ge 2048 ]]; then
    log "Local Ollama: ${GREEN}would install${NC} (${DISK_FREE_MB} MB disk, ${TOTAL_RAM_MB} MB RAM)"
  else
    log "Local Ollama: ${YELLOW}would skip${NC} (needs ≥5 GB disk + ≥2 GB RAM)"
  fi

  echo ""
  echo "Run without --check-only to install EverClaw."
  exit 0
fi

# ─── All Dependencies Satisfied ────────────────────────────────────

echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}✓ All dependencies satisfied!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# ─── Install OpenClaw (if missing) ─────────────────────────────────
# OpenClaw may have been installed by the dep check above, but if
# --skip-openclaw was used and it's not present, install it now.
# This is the agent runtime — everything else depends on it.

if [[ "$SKIP_OPENCLAW" != true ]] && ! command -v openclaw &>/dev/null; then
  echo -e "${BOLD}Installing OpenClaw...${NC}"
  npm install -g openclaw@latest || {
    log_warn "OpenClaw auto-install failed"
    log "Install manually: npm install -g openclaw@latest"
    log "Then re-run this script with --skip-openclaw"
  }
  echo ""
fi

# ─── Install EverClaw ──────────────────────────────────────────────

echo -e "${BOLD}Installing EverClaw...${NC}"
echo ""

INSTALL_DIR="$HOME/.openclaw/workspace/skills/everclaw"

if [[ -d "$INSTALL_DIR/.git" ]]; then
  # Already installed — auto-update (no prompt)
  log_ok "EverClaw already installed at $INSTALL_DIR"
  log "Updating to latest..."
  cd "$INSTALL_DIR"
  git pull origin main 2>/dev/null || {
    log_warn "git pull failed (offline or no remote). Continuing with existing version."
  }
  npm install --production 2>/dev/null || true
  log_ok "EverClaw up to date"
else
  # Fresh install
  log "Cloning EverClaw skill..."
  mkdir -p "$HOME/.openclaw/workspace/skills"
  cd "$HOME/.openclaw/workspace/skills"

  git clone --quiet https://github.com/profbernardoj/morpheus-skill.git everclaw || {
    log_err "Failed to clone EverClaw repository"
    log "Check your internet connection and try again."
    exit 1
  }
  cd everclaw

  log "Installing Node.js dependencies..."
  npm install --production 2>/dev/null || {
    log_warn "npm install failed, but continuing..."
  }

  log_ok "EverClaw installed"
fi

# Resolve scripts directory — supports both monorepo (packages/core/scripts/)
# and composed flavor repos (scripts/ at root). Must run AFTER clone/update.
if [[ -d "$INSTALL_DIR/packages/core/scripts" ]]; then
  SCRIPTS_DIR="$INSTALL_DIR/packages/core/scripts"
else
  SCRIPTS_DIR="$INSTALL_DIR/scripts"
fi

echo ""

# ─── Bootstrap API Key (Auto) ──────────────────────────────────────

echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}Bootstrap: GLM-5 Starter Key${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

if [[ -f "$HOME/.openclaw/.bootstrap-key" ]]; then
  log_ok "Bootstrap key already configured"
else
  log "Getting your starter key for GLM-5 inference..."

  if command -v node &>/dev/null && [[ -f "$SCRIPTS_DIR/bootstrap-everclaw.mjs" ]]; then
    cd "$INSTALL_DIR"
    node "$SCRIPTS_DIR/bootstrap-everclaw.mjs" --setup 2>/dev/null || {
      log_warn "Could not reach EverClaw key server (not fatal)"
      log "  The agent will still work via local Ollama fallback."
      log "  Run manually later: node $SCRIPTS_DIR/bootstrap-everclaw.mjs --setup"
    }
  else
    log_warn "Node.js or bootstrap script not available — skipping key setup"
  fi
fi

echo ""

# ─── Install Morpheus Proxy-Router (Auto, Hardware-Gated) ──────────
# Gate: ≥2 GB disk free → auto-install
# Skip if: --skip-proxy, or ~/morpheus/proxy-router already exists

echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}Morpheus Proxy-Router${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

PROXY_INSTALLED=false

if [[ "$SKIP_PROXY" == true ]]; then
  log_skip "Morpheus proxy-router (--skip-proxy)"
elif [[ -f "$HOME/morpheus/proxy-router" ]]; then
  log_ok "Morpheus proxy-router already installed"
  PROXY_INSTALLED=true
elif [[ "${DISK_FREE_MB:-0}" -ge 2048 ]]; then
  log "Disk: ${DISK_FREE_MB} MB free ≥ 2048 MB threshold"
  log "Auto-installing Morpheus proxy-router..."
  echo ""

  if [[ -f "$SCRIPTS_DIR/install.sh" ]]; then
    bash "$SCRIPTS_DIR/install.sh" && PROXY_INSTALLED=true || {
      log_warn "Proxy-router install failed (not fatal)"
      log "  The API Gateway provides inference without it."
      log "  Retry later: bash $SCRIPTS_DIR/install.sh"
    }
  else
    log_warn "install.sh not found at $SCRIPTS_DIR/install.sh"
  fi
else
  log "Disk: ${DISK_FREE_MB} MB free < 2048 MB threshold"
  log_skip "Morpheus proxy-router (insufficient disk space)"
  log "  The API Gateway provides inference without it."
fi

echo ""

# ─── Install Ollama Local Fallback (Auto, Hardware-Gated) ──────────
# Gate: ≥5 GB disk free AND ≥2 GB RAM → auto-install via setup-ollama.sh
# Skip if: --skip-ollama, or already installed + configured

echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}Local Ollama Fallback${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

OLLAMA_INSTALLED=false

# detect_ollama — check multiple install methods (PATH, Homebrew, DMG, running server)
detect_ollama() {
  if command -v ollama &>/dev/null; then
    log_ok "Ollama detected (binary in PATH)"
    return 0
  elif [[ -x /opt/homebrew/bin/ollama ]]; then
    log_ok "Ollama detected via Homebrew (/opt/homebrew/bin)"
    return 0
  elif [[ -x /usr/local/bin/ollama ]]; then
    log_ok "Ollama detected at /usr/local/bin"
    return 0
  elif [[ -d /Applications/Ollama.app ]]; then
    log_ok "Ollama.app detected (DMG install)"
    return 0
  elif curl -sf --max-time 2 http://127.0.0.1:11434/api/version &>/dev/null; then
    log_ok "Ollama server running on port 11434"
    return 0
  else
    return 1
  fi
}

if [[ "$SKIP_OLLAMA" == true ]]; then
  log_skip "Local Ollama (--skip-ollama)"
elif [[ "$FORCE_OLLAMA" == true ]]; then
  log_ok "Ollama marked as installed (--ollama-already-installed)"
  OLLAMA_INSTALLED=true
elif detect_ollama; then
  # Ollama found — check if it's configured in OpenClaw
  local_config="$HOME/.openclaw/openclaw.json"
  if [[ -f "$local_config" ]] && command -v jq &>/dev/null && jq -e '.models.providers.ollama' "$local_config" >/dev/null 2>&1; then
    log "Already configured in OpenClaw"
  else
    log "Ollama installed but not yet configured in OpenClaw"
    log "Running setup-ollama.sh to configure..."
    if [[ -f "$SCRIPTS_DIR/setup-ollama.sh" ]]; then
      bash "$SCRIPTS_DIR/setup-ollama.sh" --apply 2>&1 | tail -20 || {
        log_warn "Ollama configuration failed (not fatal)"
      }
    fi
  fi
  OLLAMA_INSTALLED=true
elif [[ "${DISK_FREE_MB:-0}" -ge 5120 && "${TOTAL_RAM_MB:-0}" -ge 2048 ]]; then
  log "Disk: ${DISK_FREE_MB} MB free ≥ 5120 MB threshold"
  log "RAM:  ${TOTAL_RAM_MB} MB total ≥ 2048 MB threshold"
  log "Auto-installing Ollama local fallback..."
  echo ""

  if [[ -f "$SCRIPTS_DIR/setup-ollama.sh" ]]; then
    bash "$SCRIPTS_DIR/setup-ollama.sh" --apply 2>&1 | tail -30 && OLLAMA_INSTALLED=true || {
      log_warn "Ollama setup failed (not fatal)"
      log "  Cloud inference via Gateway + proxy-router still works."
      log "  Retry later: bash $SCRIPTS_DIR/setup-ollama.sh --apply"
    }
  else
    log_warn "setup-ollama.sh not found at $SCRIPTS_DIR/"
  fi
else
  disk_short=""
  ram_short=""
  [[ "${DISK_FREE_MB:-0}" -lt 5120 ]] && disk_short="disk ${DISK_FREE_MB} MB < 5120 MB"
  [[ "${TOTAL_RAM_MB:-0}" -lt 2048 ]] && ram_short="RAM ${TOTAL_RAM_MB} MB < 2048 MB"
  log_skip "Local Ollama (${disk_short}${disk_short:+, }${ram_short})"
  log "  Cloud inference via Gateway still works without local fallback."
fi

echo ""

# ─── Config Merge + Gateway Restart ────────────────────────────────
# Run setup.mjs to merge Morpheus providers into openclaw.json and restart.

echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}Configuring OpenClaw${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

CONFIG_MERGED=false

if command -v node &>/dev/null && [[ -f "$SCRIPTS_DIR/setup.mjs" ]]; then
  log "Merging Morpheus providers into OpenClaw config..."
  cd "$INSTALL_DIR"
  node "$SCRIPTS_DIR/setup.mjs" --apply --restart 2>&1 | tail -15 && CONFIG_MERGED=true || {
    log_warn "Config merge or gateway restart failed"
    log "  Run manually: node $SCRIPTS_DIR/setup.mjs --apply --restart"
  }
else
  log_warn "setup.mjs not found — skipping config merge"
  log "  Run manually: node $SCRIPTS_DIR/setup.mjs --apply --restart"
fi

# ─── Ollama API Migration ─────────────────────────────────────────
# Fix existing configs where ollama has api:"openai-completions" instead
# of api:"ollama". Without this, ollama requests may route through the
# previous provider's HTTP client in the fallback chain.
# See: https://github.com/openclaw/openclaw/issues/45369

local_config="$HOME/.openclaw/openclaw.json"
if [[ -f "$local_config" ]] && command -v jq &>/dev/null; then
  ollama_api=$(jq -r '.models.providers.ollama.api // ""' "$local_config" 2>/dev/null) || ollama_api=""
  if [[ "$ollama_api" == "openai-completions" ]]; then
    log "Migrating ollama config: api \"openai-completions\" → \"ollama\"..."
    cp "$local_config" "${local_config}.bak.$(date +%s)"
    tmp_config=$(jq '
      .models.providers.ollama.api = "ollama" |
      if .models.providers.ollama.models then
        .models.providers.ollama.models |= map(
          if .api == "openai-completions" then del(.api) else . end
        )
      else . end
    ' "$local_config")
    echo "$tmp_config" | jq '.' > "$local_config" && \
      log_ok "Ollama API type migrated — fallback routing fixed" || \
      log_warn "Ollama migration failed (not fatal)"
  fi
fi

echo ""

# ─── Open Dashboard (best effort) ─────────────────────────────────
# If we have a local OpenClaw web UI URL, open it. Non-fatal.

DASHBOARD_URL="http://localhost:18789"

open_dashboard() {
  if [[ "$OS" == "Darwin" ]]; then
    open "$DASHBOARD_URL" 2>/dev/null && return 0
  elif command -v xdg-open &>/dev/null; then
    xdg-open "$DASHBOARD_URL" 2>/dev/null && return 0
  fi
  return 1
}

if [[ "$CONFIG_MERGED" == true ]]; then
  # Give gateway a moment to come up after restart
  sleep 2
  if open_dashboard; then
    log_ok "Dashboard opened: ${DASHBOARD_URL}"
  fi
fi

# ─── Success Banner ────────────────────────────────────────────────

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  ♾️  EverClaw Setup Complete!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${BOLD}  Installed components:${NC}"
echo ""

# Core (always)
log_ok "EverClaw skill"
log_ok "GLM-5 bootstrap key (1,000 req/day, 30-day renewal)"

# Conditional
if [[ "$PROXY_INSTALLED" == true ]]; then
  log_ok "Morpheus proxy-router (local P2P inference)"
else
  log "  ─  Morpheus proxy-router (skipped)"
fi

if [[ "$OLLAMA_INSTALLED" == true ]]; then
  log_ok "Local Ollama fallback (zero-network last resort)"
else
  log "  ─  Local Ollama (skipped)"
fi

if [[ "$CONFIG_MERGED" == true ]]; then
  log_ok "OpenClaw config merged + gateway restarted"
else
  log "  ─  Config merge (manual step needed)"
fi

echo ""
echo -e "${BOLD}  Inference chain:${NC}"
echo ""

# Build the chain description based on what was installed
CHAIN="GLM-5 (Morpheus Gateway)"
[[ "$PROXY_INSTALLED" == true ]] && CHAIN="${CHAIN} → Morpheus P2P"
[[ "$OLLAMA_INSTALLED" == true ]] && CHAIN="${CHAIN} → Local Ollama"
log "${CHAIN}"

echo ""

if [[ "$CONFIG_MERGED" != true ]]; then
  echo -e "${BOLD}  Manual steps needed:${NC}"
  echo ""
  log "1. Merge config:  node $SCRIPTS_DIR/setup.mjs --apply"
  log "2. Restart:       openclaw gateway restart"
  echo ""
fi

# --- Optional: Agent-Chat XMTP Daemon ---
AGENT_CHAT_SKILL="$INSTALL_DIR/skills/agent-chat"
if [[ -d "$AGENT_CHAT_SKILL" ]] && [[ -f "$AGENT_CHAT_SKILL/daemon.mjs" ]] && [[ -f "$SCRIPTS_DIR/setup-agent-chat.sh" ]]; then
  echo ""
  log "💬 Setting up agent-chat XMTP daemon..."
  bash "$SCRIPTS_DIR/setup-agent-chat.sh" --skip-deps 2>&1 | tail -10 || {
    log_warn "Agent-chat daemon setup had issues — not critical"
    log "      Run manually: bash $SCRIPTS_DIR/setup-agent-chat.sh"
  }
fi

echo -e "${BOLD}  Useful commands:${NC}"
echo ""
log "Test inference:   node $SCRIPTS_DIR/bootstrap-everclaw.mjs --test"
log "Check status:     bash $SCRIPTS_DIR/diagnose.sh"
log "Get your own key: https://app.mor.org"

echo ""
echo -e "${BOLD}✅ EverClaw successfully installed to:${NC}"
log "$INSTALL_DIR"
echo ""

echo -e "${BOLD}  Import your existing inference key:${NC}"
echo ""
echo "  1. Recommended (easiest):"
echo "     cd \"$INSTALL_DIR\""
echo "     npm run bootstrap -- --key sk-XXXXXXXXXXXXXXXX"
echo ""
echo "  2. Absolute path (works from anywhere):"
echo "     node \"$SCRIPTS_DIR/bootstrap-gateway.mjs\" --key sk-XXXXXXXXXXXXXXXX"
echo ""
echo "  3. With environment variable (works from anywhere):"
echo "     EVERCLAW_KEY=sk-XXXXXXXXXXXXXXXX node \"$SCRIPTS_DIR/bootstrap-gateway.mjs\""

echo ""
echo -e "${CYAN}  ♾️  Own your inference. Forever.${NC}"
echo ""
