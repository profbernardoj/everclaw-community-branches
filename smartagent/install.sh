#!/bin/bash
# SmartAgent Installer — https://smartagent.org
#
# One command to a personal AI agent with free inference:
#   curl -fsSL https://smartagent.org/install.sh | bash
#
# What this does:
#   1. Checks/installs Node.js 22+
#   2. Installs OpenClaw (the AI agent framework)
#   3. Installs Everclaw (decentralized inference via Morpheus)
#   4. Bootstraps free inference (Morpheus API Gateway — no API key needed)
#   5. Pre-configures your agent with sensible defaults
#   6. Starts the agent and opens WebChat in your browser
#
# Requirements: macOS 12+ or Linux (x86_64/arm64), ~500MB disk, internet

set -euo pipefail

# ─── Configuration ───────────────────────────────────────────────────────────
SMARTAGENT_VERSION="0.1.0"
OPENCLAW_MIN_VERSION="2026.2"
NODE_MIN_VERSION="22"
EVERCLAW_REPO="https://github.com/profbernardoj/everclaw.git"
SMARTAGENT_REPO="https://github.com/SmartAgentProtocol/smartagent.git"
WORKSPACE="${OPENCLAW_WORKSPACE:-$HOME/.openclaw/workspace}"
SKILL_DIR="$WORKSPACE/skills/everclaw"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ─── Helpers ─────────────────────────────────────────────────────────────────
log()  { echo -e "${GREEN}[smartagent]${NC} $1"; }
warn() { echo -e "${YELLOW}[smartagent]${NC} ⚠️  $1"; }
err()  { echo -e "${RED}[smartagent]${NC} ❌ $1"; }
info() { echo -e "${BLUE}[smartagent]${NC} $1"; }
bold() { echo -e "${BOLD}$1${NC}"; }

banner() {
  echo ""
  echo -e "${CYAN}"
  echo "  ╔═══════════════════════════════════════════════╗"
  echo "  ║                                               ║"
  echo "  ║   🤖 SmartAgent v${SMARTAGENT_VERSION}                      ║"
  echo "  ║   Your Personal AI Agent                      ║"
  echo "  ║                                               ║"
  echo "  ║   Powered by OpenClaw + Morpheus              ║"
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
    *)
      err "Unsupported OS: $os"
      err "SmartAgent supports macOS and Linux."
      exit 1
      ;;
  esac

  local arch
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) ARCH="x64" ;;
    arm64|aarch64) ARCH="arm64" ;;
    *)
      err "Unsupported architecture: $arch"
      exit 1
      ;;
  esac

  log "Detected: $OS ($arch)"
}

# ─── Step 1: Node.js ────────────────────────────────────────────────────────
check_node() {
  log "Checking for Node.js ${NODE_MIN_VERSION}+..."

  if command -v node &>/dev/null; then
    local node_version
    node_version="$(node -v | sed 's/v//' | cut -d. -f1)"
    if [[ "$node_version" -ge "$NODE_MIN_VERSION" ]]; then
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
    fnm install "$NODE_MIN_VERSION" && fnm use "$NODE_MIN_VERSION"
    return
  fi

  # Try nvm
  if command -v nvm &>/dev/null || [[ -f "$HOME/.nvm/nvm.sh" ]]; then
    [[ -f "$HOME/.nvm/nvm.sh" ]] && source "$HOME/.nvm/nvm.sh"
    nvm install "$NODE_MIN_VERSION" && nvm use "$NODE_MIN_VERSION"
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
  local shell_config
  if [[ -f "$HOME/.zshrc" ]]; then
    shell_config="$HOME/.zshrc"
  elif [[ -f "$HOME/.bashrc" ]]; then
    shell_config="$HOME/.bashrc"
  fi

  if [[ -n "${shell_config:-}" ]]; then
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

  # Use OpenClaw's official installer (handles npm + binary)
  if curl -fsSL https://clawd.bot/install.sh | bash; then
    log "OpenClaw installed ✓"
  else
    # Fallback to npm
    warn "Official installer failed, trying npm..."
    npm install -g openclaw
    log "OpenClaw installed via npm ✓"
  fi
}

# ─── Step 3: Everclaw ───────────────────────────────────────────────────────
install_everclaw() {
  log "Installing Everclaw (decentralized inference)..."

  if [[ -d "$SKILL_DIR/.git" ]]; then
    log "Everclaw already installed, updating..."
    cd "$SKILL_DIR" && git pull --quiet
    log "Everclaw updated ✓"
    return
  fi

  # Check for ClawHub collision
  if [[ -d "$SKILL_DIR" ]]; then
    if grep -q "Everclaw Vault\|everclaw.chong-eae.workers.dev" "$SKILL_DIR/SKILL.md" 2>/dev/null; then
      warn "ClawHub collision detected — removing 'Everclaw Vault' imposter..."
      rm -rf "$SKILL_DIR"
    fi
  fi

  # Install via ClawHub or git
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

  log "Everclaw installed ✓"
}

# ─── Step 4: Bootstrap Free Inference ────────────────────────────────────────
bootstrap_inference() {
  log "Bootstrapping free inference via Morpheus API Gateway..."

  local bootstrap_script="$SKILL_DIR/scripts/bootstrap-gateway.mjs"

  if [[ -f "$bootstrap_script" ]]; then
    if node "$bootstrap_script" 2>/dev/null; then
      log "Free inference configured ✓"
      log "Using: mor-gateway/kimi-k2.5 (free, no API key needed)"
      return 0
    else
      warn "Gateway bootstrap script returned an error"
    fi
  else
    warn "Bootstrap script not found, configuring manually..."
  fi

  # Manual fallback: write a minimal config
  configure_smartagent_defaults
}

# ─── Step 5: Configure Workspace ─────────────────────────────────────────────
configure_workspace() {
  log "Configuring SmartAgent workspace..."

  mkdir -p "$WORKSPACE/memory"

  # Download SmartAgent workspace files (AGENTS.md, SOUL.md, etc.)
  local config_url="https://raw.githubusercontent.com/SmartAgentProtocol/smartagent/main/config"
  local files=("AGENTS.md" "SOUL.md" "BOOTSTRAP.md" "TOOLS.md" "USER.md" "IDENTITY.md" "HEARTBEAT.md")

  for file in "${files[@]}"; do
    if [[ ! -f "$WORKSPACE/$file" ]]; then
      if curl -fsSL "$config_url/$file" -o "$WORKSPACE/$file" 2>/dev/null; then
        log "  Created $file"
      else
        warn "  Could not download $file (will use OpenClaw defaults)"
      fi
    else
      info "  $file already exists, skipping"
    fi
  done

  log "Workspace configured ✓"
}

configure_smartagent_defaults() {
  # Write a minimal openclaw.json with Morpheus API Gateway
  local config_file="$HOME/.openclaw/openclaw.json"

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
      }
    }
  }
}
CONF

  log "Default config written ✓"
}

# ─── Step 6: Start Agent ─────────────────────────────────────────────────────
start_agent() {
  log "Starting SmartAgent..."

  # Check if gateway is already running
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
  # Give the gateway a moment to initialize
  sleep 2

  local webchat_url
  webchat_url="$(openclaw webchat url 2>/dev/null || echo "")"

  if [[ -z "$webchat_url" ]]; then
    webchat_url="http://localhost:4200"
  fi

  echo ""
  bold "  ┌─────────────────────────────────────────────┐"
  bold "  │                                             │"
  bold "  │   🎉 SmartAgent is ready!                   │"
  bold "  │                                             │"
  bold "  │   WebChat: ${webchat_url}            │"
  bold "  │                                             │"
  bold "  │   Your agent is using free Morpheus          │"
  bold "  │   inference — no API key needed.             │"
  bold "  │                                             │"
  bold "  │   Say hello to get started!                  │"
  bold "  │                                             │"
  bold "  └─────────────────────────────────────────────┘"
  echo ""

  # Open in browser
  if [[ "$OS" == "macos" ]]; then
    open "$webchat_url" 2>/dev/null || true
  elif command -v xdg-open &>/dev/null; then
    xdg-open "$webchat_url" 2>/dev/null || true
  fi

  info "To stop: openclaw gateway stop"
  info "To restart: openclaw gateway restart"
  info "Logs: openclaw gateway logs"
  echo ""
  info "Next steps:"
  info "  • Get your own API key at https://app.mor.org"
  info "  • Add Venice for premium models (Claude, GPT)"
  info "  • Stake MOR for self-sovereign inference"
  info ""
  info "Docs: https://smartagent.org"
  info "GitHub: https://github.com/SmartAgentProtocol/smartagent"
}

# ─── Main ────────────────────────────────────────────────────────────────────
main() {
  banner
  check_os

  echo ""
  log "Step 1/6: Node.js"
  check_node

  echo ""
  log "Step 2/6: OpenClaw"
  check_openclaw

  echo ""
  log "Step 3/6: Everclaw"
  install_everclaw

  echo ""
  log "Step 4/6: Free Inference"
  bootstrap_inference

  echo ""
  log "Step 5/6: Workspace"
  configure_workspace

  echo ""
  log "Step 6/6: Launch"
  if start_agent; then
    open_webchat
  else
    echo ""
    bold "  SmartAgent is installed! Start it with:"
    bold "    openclaw gateway start"
    echo ""
  fi
}

main "$@"
