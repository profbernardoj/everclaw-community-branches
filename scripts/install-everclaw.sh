#!/bin/bash
# install-everclaw.sh — Safe Everclaw installer with collision protection
#
# Handles all installation paths:
#   - Fresh install (git clone)
#   - Update existing git install (git pull)
#   - Detect and warn about ClawHub name collision
#   - Post-install: router, proxy, guardian setup
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/profbernardoj/everclaw/main/scripts/install-everclaw.sh | bash
#   # or
#   bash skills/everclaw/scripts/install-everclaw.sh

set -euo pipefail

# ─── Configuration ───────────────────────────────────────────────────────────
REPO_URL="https://github.com/profbernardoj/everclaw.git"
SKILL_DIR="${OPENCLAW_WORKSPACE:-$HOME/.openclaw/workspace}/skills/everclaw"
SKILL_NAME="everclaw"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log()  { echo -e "${GREEN}[everclaw]${NC} $1"; }
warn() { echo -e "${YELLOW}[everclaw]${NC} ⚠️  $1"; }
err()  { echo -e "${RED}[everclaw]${NC} ❌ $1"; }
info() { echo -e "${BLUE}[everclaw]${NC} $1"; }

# ─── Collision Detection ────────────────────────────────────────────────────
check_for_collision() {
  if [[ -d "$SKILL_DIR" ]]; then
    # Check if it's our skill or the ClawHub imposter
    if [[ -f "$SKILL_DIR/.clawhub/origin.json" ]]; then
      local slug
      slug=$(python3 -c "import json; print(json.load(open('$SKILL_DIR/.clawhub/origin.json')).get('slug',''))" 2>/dev/null || echo "")
      
      if [[ "$slug" == "everclaw" ]]; then
        # Check if it's the ClawHub "Everclaw Vault" (not our skill)
        if grep -q "Everclaw Vault\|everclaw.chong-eae.workers.dev\|encrypted cloud memory" "$SKILL_DIR/SKILL.md" 2>/dev/null; then
          err "COLLISION DETECTED!"
          err ""
          err "The directory $SKILL_DIR contains 'Everclaw Vault' — a DIFFERENT"
          err "product from ClawHub that shares the 'everclaw' name."
          err ""
          err "Everclaw Vault = encrypted cloud memory backup"
          err "Everclaw (ours) = Morpheus decentralized AI inference"
          err ""
          warn "To fix this:"
          warn "  1. Remove the imposter:  rm -rf $SKILL_DIR"
          warn "  2. Re-run this installer: bash install-everclaw.sh"
          err ""
          err "Your runtime infrastructure (~/morpheus/, guardian, proxy) is NOT affected."
          exit 1
        fi
      fi
    fi
    
    # Check if it's a git repo (our install method)
    if [[ -d "$SKILL_DIR/.git" ]]; then
      return 0  # It's our git-based install
    fi
    
    # It exists but isn't a git repo and isn't ClawHub — might be manual copy
    if grep -q "Morpheus\|mor\.org\|proxy-router\|MOR token" "$SKILL_DIR/SKILL.md" 2>/dev/null; then
      return 0  # Looks like our skill, just not a git repo
    fi
    
    # Unknown skill in our directory
    warn "Directory $SKILL_DIR exists but doesn't appear to be Everclaw (Morpheus inference)."
    warn "Contents may be from a different 'everclaw' package."
    echo ""
    read -p "Remove and reinstall? (y/N) " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
      rm -rf "$SKILL_DIR"
    else
      err "Aborted. Remove the directory manually and re-run."
      exit 1
    fi
  fi
}

# ─── Install / Update ───────────────────────────────────────────────────────
install_or_update() {
  if [[ -d "$SKILL_DIR/.git" ]]; then
    # Existing git install → pull updates
    log "Existing Everclaw installation found. Updating via git pull..."
    cd "$SKILL_DIR"
    
    local current_tag
    current_tag=$(git describe --tags --abbrev=0 2>/dev/null || echo "unknown")
    
    git fetch origin 2>/dev/null
    git pull origin main 2>/dev/null
    
    local new_tag
    new_tag=$(git describe --tags --abbrev=0 2>/dev/null || echo "unknown")
    
    if [[ "$current_tag" != "$new_tag" ]]; then
      log "Updated: $current_tag → $new_tag"
    else
      log "Already up to date ($new_tag)"
    fi
  else
    # Fresh install → clone
    log "Installing Everclaw from GitHub..."
    mkdir -p "$(dirname "$SKILL_DIR")"
    git clone "$REPO_URL" "$SKILL_DIR" 2>/dev/null
    
    local tag
    tag=$(cd "$SKILL_DIR" && git describe --tags --abbrev=0 2>/dev/null || echo "unknown")
    log "Installed Everclaw $tag"
  fi
}

# ─── Post-Install ────────────────────────────────────────────────────────────
validate_config() {
  local openclaw_config="${OPENCLAW_WORKSPACE:-$HOME/.openclaw}/openclaw.json"
  
  if [[ ! -f "$openclaw_config" ]]; then
    return  # No config yet — that's fine for fresh installs
  fi

  # Check for "everclaw/" provider prefix — the #1 misconfiguration
  local bad_provider
  bad_provider=$(python3 -c "
import json
try:
    c = json.load(open('$openclaw_config'))
    bad = []
    p = c.get('agents',{}).get('defaults',{}).get('model',{}).get('primary','')
    if p.startswith('everclaw/'): bad.append(p)
    for f in c.get('agents',{}).get('defaults',{}).get('model',{}).get('fallbacks',[]):
        if f.startswith('everclaw/'): bad.append(f)
    if 'everclaw' in c.get('models',{}).get('providers',{}): bad.append('provider:everclaw')
    print(' '.join(bad))
except: pass
" 2>/dev/null)

  if [[ -n "$bad_provider" ]]; then
    echo ""
    warn "═══════════════════════════════════════════════════"
    warn "  MISCONFIGURATION: 'everclaw/' is not a provider!"
    warn "═══════════════════════════════════════════════════"
    echo ""
    err "Your openclaw.json uses 'everclaw/' as a model prefix."
    err "Everclaw is a SKILL (tooling), not an inference provider."
    err "This routes requests to Venice → billing errors."
    echo ""
    log "Fix: change your model to one of these:"
    echo "  • mor-gateway/kimi-k2.5  — Morpheus API Gateway (easiest)"
    echo "  • morpheus/kimi-k2.5     — Local Morpheus P2P (needs router)"
    echo ""
    log "Quick fix:"
    echo "  node $SKILL_DIR/scripts/bootstrap-gateway.mjs"
    echo "  openclaw gateway restart"
    echo ""
  fi
}

post_install() {
  local version
  version=$(grep "^version:" "$SKILL_DIR/SKILL.md" | head -1 | awk '{print $2}' || echo "?")
  
  # Validate config before showing success
  validate_config

  echo ""
  log "╔══════════════════════════════════════════════════╗"
  log "║  ♾️  Everclaw v${version} installed                  ║"
  log "╚══════════════════════════════════════════════════╝"
  echo ""
  info "Next steps:"
  echo "  1. Install the Morpheus router:"
  echo "     bash $SKILL_DIR/scripts/install.sh"
  echo ""
  echo "  2. Install the proxy + guardian:"
  echo "     bash $SKILL_DIR/scripts/install-proxy.sh"
  echo ""
  echo "  3. Create your wallet:"
  echo "     node $SKILL_DIR/scripts/everclaw-wallet.mjs setup"
  echo ""
  echo "  4. Or bootstrap with free inference (no wallet needed):"
  echo "     node $SKILL_DIR/scripts/bootstrap-gateway.mjs"
  echo ""
  warn "IMPORTANT: Valid model prefixes are 'morpheus/' or 'mor-gateway/'"
  warn "  NOT 'everclaw/' — that will route to Venice instead of Morpheus."
  echo ""
  warn "DO NOT run 'clawhub update everclaw' — a different product"
  warn "uses the same name on ClawHub. Updates come from GitHub:"
  warn "  cd $SKILL_DIR && git pull"
  echo ""
}

# ─── Version Check ───────────────────────────────────────────────────────────
check_version() {
  if [[ "${1:-}" == "--check" || "${1:-}" == "--version" ]]; then
    local local_version="unknown"
    local remote_version="unknown"
    
    if [[ -f "$SKILL_DIR/SKILL.md" ]]; then
      local_version=$(grep "^version:" "$SKILL_DIR/SKILL.md" | head -1 | awk '{print $2}')
    fi
    
    remote_version=$(curl -s "https://api.github.com/repos/profbernardoj/everclaw/releases/latest" 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin).get('tag_name','unknown'))" 2>/dev/null || echo "unknown")
    
    echo "Local:  v${local_version}"
    echo "Latest: ${remote_version}"
    
    if [[ "v${local_version}" == "${remote_version}" ]]; then
      log "Up to date."
    else
      warn "Update available. Run: cd $SKILL_DIR && git pull"
    fi
    exit 0
  fi
}

# ─── Main ────────────────────────────────────────────────────────────────────
check_version "$@"
check_for_collision
install_or_update
post_install
