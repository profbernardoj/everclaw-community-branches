#!/bin/bash
# Buddy Bots Installer — https://buddybots.org
#
# One command to set up agent-to-agent social coordination:
#   curl -fsSL https://buddybots.org/install.sh | bash
#
# What this does:
#   1. Checks/installs Node.js 22+
#   2. Installs OpenClaw (the AI agent framework)
#   3. Installs EverClaw (decentralized inference via Morpheus)
#   4. Bootstraps decentralized inference (Morpheus API Gateway)
#   5. Configures Buddy Bots workspace (SOUL.md, USER.md, AGENTS.md)
#   6. Starts the agent and opens WebChat
#
# Requirements: macOS 12+ or Linux (x86_64/arm64), ~500MB disk, internet

set -euo pipefail

# ─── Configuration ───────────────────────────────────────────────────────────
BUDDYBOTS_VERSION="0.1.0"
NODE_MIN_VERSION="22"
EVERCLAW_REPO="https://github.com/profbernardoj/morpheus-skill.git"
WORKSPACE="${OPENCLAW_WORKSPACE:-$HOME/.openclaw/workspace}"
SKILL_DIR="$WORKSPACE/skills/everclaw"
BUDDYBOTS_DIR="$WORKSPACE/skills/buddy-bots"
TEMPLATES_URL="https://raw.githubusercontent.com/EverClaw/buddybots.org/main/templates"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ─── Helpers ─────────────────────────────────────────────────────────────────
log()  { echo -e "${GREEN}[buddy-bots]${NC} $1"; }
warn() { echo -e "${YELLOW}[buddy-bots]${NC} ⚠️  $1"; }
err()  { echo -e "${RED}[buddy-bots]${NC} ❌ $1"; }
info() { echo -e "${BLUE}[buddy-bots]${NC} $1"; }
bold() { echo -e "${BOLD}$1${NC}"; }

banner() {
  echo ""
  echo -e "${CYAN}"
  echo "  ╔═══════════════════════════════════════════════╗"
  echo "  ║                                               ║"
  echo "  ║   🤝 Buddy Bots v${BUDDYBOTS_VERSION}                       ║"
  echo "  ║   Agent-to-Agent Social Coordination          ║"
  echo "  ║                                               ║"
  echo "  ║   Powered by EverClaw + OpenClaw + XMTP       ║"
  echo "  ║                                               ║"
  echo "  ╚═══════════════════════════════════════════════╝"
  echo -e "${NC}"
  echo ""
}

check_os() {
  local os
  os="$(uname -s)"
  case "$os" in
    Darwin) OS="macos" ;;
    Linux)  OS="linux" ;;
    MINGW*|MSYS*|CYGWIN*)
      err "Windows (Git Bash / MSYS / Cygwin) is not supported."
      err "Please install WSL 2 and run the installer inside WSL:"
      info "  https://learn.microsoft.com/en-us/windows/wsl/install"
      exit 1 ;;
    *)
      err "Unsupported OS: $os"
      err "Buddy Bots supports macOS and Linux."
      exit 1 ;;
  esac

  local arch
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) ;; # supported
    arm64|aarch64) ;; # supported
    *)
      err "Unsupported architecture: $arch"
      exit 1 ;;
  esac

  log "Detected: $OS ($arch)"
}

# ─── Prerequisite Checks ─────────────────────────────────────────────────────
check_dependencies() {
  for cmd in curl git; do
    if ! command -v "$cmd" &>/dev/null; then
      err "$cmd is required but not installed."
      err "Install: brew install $cmd (macOS) or apt install $cmd (Linux)"
      exit 1
    fi
  done
}

# ─── Step 1: Node.js ────────────────────────────────────────────────────────
check_node() {
  log "Checking for Node.js ${NODE_MIN_VERSION}+..."

  if command -v node &>/dev/null; then
    local node_version
    node_version=$(node -e 'console.log(parseInt(process.versions.node,10))' 2>/dev/null || echo 0)
    if (( node_version >= NODE_MIN_VERSION )); then
      log "Node.js v$(node -v | sed 's/v//') ✓"
      return 0
    else
      warn "Node.js v$(node -v | sed 's/v//') found, but v${NODE_MIN_VERSION}+ required."
    fi
  fi

  install_node
}

install_node() {
  log "Installing Node.js ${NODE_MIN_VERSION}..."

  # Try fnm first (fast, Rust-based)
  if command -v fnm &>/dev/null; then
    fnm install "$NODE_MIN_VERSION"
    fnm use "$NODE_MIN_VERSION"
    eval "$(fnm env --use-on-cd)"
    return
  fi

  # Try nvm
  if command -v nvm &>/dev/null || [[ -f "$HOME/.nvm/nvm.sh" ]]; then
    [[ -f "$HOME/.nvm/nvm.sh" ]] && source "$HOME/.nvm/nvm.sh"
    nvm install "$NODE_MIN_VERSION" && nvm use "$NODE_MIN_VERSION"
    hash -r
    return
  fi

  # Install fnm + Node
  log "Installing fnm (Node version manager)..."
  if [[ "$OS" == "macos" ]] && command -v brew &>/dev/null; then
    brew install fnm
  else
    curl -fsSL https://fnm.vercel.app/install | bash -s -- --skip-shell
    export PATH="$HOME/.local/share/fnm:$PATH"
    eval "$(fnm env)"
  fi

  fnm install "$NODE_MIN_VERSION"
  fnm use "$NODE_MIN_VERSION"

  # Add to shell config
  local shell_config=""
  if [[ -f "$HOME/.zshrc" ]]; then
    shell_config="$HOME/.zshrc"
  elif [[ -f "$HOME/.bashrc" ]]; then
    shell_config="$HOME/.bashrc"
  fi

  if [[ -n "$shell_config" ]]; then
    if ! grep -q "fnm env" "$shell_config" 2>/dev/null; then
      echo 'eval "$(fnm env --use-on-cd --shell '"$(basename "$SHELL")"')"' >> "$shell_config"
      log "Added fnm to $shell_config"
    fi
  fi

  log "Node.js $(node -v) installed ✓"
}

# ─── Step 2: OpenClaw ───────────────────────────────────────────────────────
check_openclaw() {
  log "Checking for OpenClaw..."

  if command -v openclaw &>/dev/null; then
    local version
    version="$(openclaw --version 2>/dev/null | head -1 || echo "unknown")"
    log "OpenClaw $version ✓"
    return 0
  fi

  install_openclaw
}

install_openclaw() {
  log "Installing OpenClaw..."

  if curl -fsSL https://openclaw.ai/install.sh | bash; then
    log "OpenClaw installed ✓"
  else
    warn "Official installer failed, trying npm..."
    npm install -g openclaw
    log "OpenClaw installed via npm ✓"
  fi
}

# ─── Step 3: EverClaw ───────────────────────────────────────────────────────
install_everclaw() {
  log "Installing EverClaw (decentralized inference)..."

  if [[ -d "$SKILL_DIR/.git" ]]; then
    log "EverClaw already installed, updating..."
    (cd "$SKILL_DIR" && git pull --quiet) || warn "EverClaw update failed (not critical)"
    log "EverClaw updated ✓"
    return
  fi

  if command -v clawhub &>/dev/null; then
    clawhub install everclaw-inference 2>/dev/null || {
      warn "ClawHub install failed, falling back to git..."
      mkdir -p "$(dirname "$SKILL_DIR")"
      git clone --quiet "$EVERCLAW_REPO" "$SKILL_DIR"
    }
  else
    mkdir -p "$(dirname "$SKILL_DIR")"
    git clone --quiet "$EVERCLAW_REPO" "$SKILL_DIR"
  fi

  log "EverClaw installed ✓"
}

# ─── Step 4: Bootstrap Decentralized Inference ───────────────────────────────
bootstrap_inference() {
  log "Bootstrapping decentralized inference via Morpheus..."

  local bootstrap_script="$SKILL_DIR/scripts/bootstrap-gateway.mjs"

  if [[ -f "$bootstrap_script" ]]; then
    if node "$bootstrap_script" 2>/dev/null; then
      log "Decentralized inference configured ✓"
      return 0
    else
      warn "Gateway bootstrap had issues"
    fi
  fi

  configure_defaults
}

configure_defaults() {
  local config_file="${OPENCLAW_CONFIG_DIR:-$HOME/.openclaw}/openclaw.json"
  mkdir -p "$(dirname "$config_file")"

  if [[ -f "$config_file" ]]; then
    info "openclaw.json already exists, preserving..."
    return
  fi

  mkdir -p "$HOME/.openclaw"
  cat > "$config_file" << 'CONF'
{
  "models": {
    "mode": "merge",
    "providers": {
      "mor-gateway": {
        "baseUrl": "https://api.mor.org/api/v1",
        "api": "openai-completions",
        "models": [
          { "id": "kimi-k2.5", "reasoning": false, "contextWindow": 131072, "maxTokens": 8192 },
          { "id": "glm-4.7-flash", "reasoning": false, "contextWindow": 131072, "maxTokens": 8192 }
        ]
      }
    }
  },
  "agents": {
    "defaults": {
      "model": {
        "primary": "mor-gateway/kimi-k2.5",
        "fallbacks": ["mor-gateway/glm-4.7-flash"]
      },
      "timeoutSeconds": 300
    }
  }
}
CONF

  log "Default config written ✓"
}

# ─── Step 5: Configure Buddy Bots Workspace ─────────────────────────────────
configure_workspace() {
  log "Configuring Buddy Bots workspace..."

  mkdir -p "$WORKSPACE/memory"

  # Apply Buddy Bots templates (SOUL.md, USER.md, AGENTS.md)
  local files=("SOUL.md" "USER.md" "AGENTS.md")

  for file in "${files[@]}"; do
    if [[ ! -f "$WORKSPACE/$file" ]]; then
      if curl -fsSL "${TEMPLATES_URL}/${file}" -o "$WORKSPACE/$file" 2>/dev/null; then
        log "  Applied template: $file"
      else
        warn "  Could not download $file template"
      fi
    else
      info "  $file already exists, skipping"
    fi
  done

  # Create workspace essentials if missing
  for file in TOOLS.md HEARTBEAT.md IDENTITY.md; do
    if [[ ! -f "$WORKSPACE/$file" ]]; then
      touch "$WORKSPACE/$file"
      log "  Created $file"
    fi
  done

  log "Workspace configured ✓"
}

# ─── Step 6: Start Agent ─────────────────────────────────────────────────────
start_agent() {
  log "Starting Buddy Bots..."

  if openclaw gateway status &>/dev/null 2>&1; then
    info "Gateway already running"
  else
    openclaw gateway start 2>/dev/null || {
      warn "Could not start gateway automatically"
      info "Run manually: openclaw gateway start"
      return 1
    }
  fi

  log "Gateway started ✓"
  return 0
}

open_webchat() {
  sleep 2

  local webchat_url
  webchat_url="$(openclaw webchat url 2>/dev/null || echo "")"

  if [[ -z "$webchat_url" ]]; then
    webchat_url="http://localhost:4200"
  fi

  echo ""
  bold "  ┌─────────────────────────────────────────────┐"
  bold "  │                                             │"
  bold "  │   🤝 Buddy Bots is ready!                   │"
  bold "  │                                             │"
  bold "  │   WebChat: ${webchat_url}            │"
  bold "  │                                             │"
  bold "  │   Your bot uses Morpheus decentralized      │"
  bold "  │   inference — no API key needed.            │"
  bold "  │                                             │"
  bold "  │   Create a group chat and add friends       │"
  bold "  │   to get started!                           │"
  bold "  │                                             │"
  bold "  └─────────────────────────────────────────────┘"
  echo ""

  if [[ "$OS" == "macos" ]]; then
    open "$webchat_url" 2>/dev/null || true
  elif command -v xdg-open &>/dev/null; then
    xdg-open "$webchat_url" 2>/dev/null || true
  fi

  info "To stop: openclaw gateway stop"
  info "To restart: openclaw gateway restart"
  info ""
  info "Next steps:"
  info "  • Create a group chat on Signal, WhatsApp, or Telegram"
  info "  • Add your friends — each gets their own buddy bot"
  info "  • Bots coordinate over XMTP to plan activities"
  info ""
  info "Docs: https://buddybots.org"
  info "GitHub: https://github.com/EverClaw/buddybots.org"
}

# ─── Main ────────────────────────────────────────────────────────────────────
main() {
  banner
  check_os
  check_dependencies

  echo ""
  log "Step 1/6: Node.js"
  check_node

  echo ""
  log "Step 2/6: OpenClaw"
  check_openclaw

  echo ""
  log "Step 3/6: EverClaw"
  install_everclaw

  echo ""
  log "Step 4/6: Decentralized Inference"
  bootstrap_inference

  echo ""
  log "Step 5/6: Buddy Bots Workspace"
  configure_workspace

  echo ""
  log "Step 6/6: Launch"
  if start_agent; then
    open_webchat
  else
    echo ""
    bold "  Buddy Bots is installed! Start it with:"
    bold "    openclaw gateway start"
    echo ""
  fi
}

main "$@"
