#!/bin/bash
# diagnose.sh — Everclaw Health Diagnostic
#
# Step 1: Config checks (no network, no processes, pure file parsing)
# Step 2: Infrastructure checks (TODO — network, processes, inference)
#
# Usage:
#   bash skills/everclaw/scripts/diagnose.sh            # All checks
#   bash skills/everclaw/scripts/diagnose.sh --config    # Config only
#   bash skills/everclaw/scripts/diagnose.sh --infra     # Infra only (Step 2)
#   bash skills/everclaw/scripts/diagnose.sh --quick     # Both, skip inference test
#
# Exit codes: 0 = all pass, 1 = failures found, 2 = warnings only

set -uo pipefail

# ─── Configuration ───────────────────────────────────────────────────────────
OPENCLAW_DIR="${OPENCLAW_DIR:-$HOME/.openclaw}"
OPENCLAW_CONFIG="$OPENCLAW_DIR/openclaw.json"
AUTH_PROFILES="$OPENCLAW_DIR/agents/main/agent/auth-profiles.json"
MORPHEUS_DIR="${MORPHEUS_DIR:-$HOME/morpheus}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

# Counters
PASS=0
WARN=0
FAIL=0

# ─── Output Helpers ──────────────────────────────────────────────────────────
pass() { echo -e "  ${GREEN}✅${NC} $1"; ((PASS++)); }
warn() { echo -e "  ${YELLOW}⚠️${NC}  $1"; ((WARN++)); }
fail() { echo -e "  ${RED}❌${NC} $1"; ((FAIL++)); }
fix()  { echo -e "     ${BLUE}→${NC} $1"; }
info() { echo -e "     ${NC}$1"; }

# ─── Parse Mode ──────────────────────────────────────────────────────────────
MODE="all"
QUICK=false
for arg in "$@"; do
  case "$arg" in
    --config) MODE="config" ;;
    --infra)  MODE="infra" ;;
    --quick)  QUICK=true ;;
    --help|-h)
      echo "Usage: bash diagnose.sh [--config|--infra|--quick]"
      echo "  --config  Config checks only (no network)"
      echo "  --infra   Infrastructure checks only (Step 2)"
      echo "  --quick   Both groups, skip inference test"
      exit 0
      ;;
  esac
done

# ─── Banner ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}♾️  Everclaw Diagnostic${NC}"
echo "─────────────────────────────────────"

# ═════════════════════════════════════════════════════════════════════════════
# GROUP A — Config & Routing (no network needed)
# ═════════════════════════════════════════════════════════════════════════════
run_config_checks() {
  echo ""
  echo -e "${BOLD}Config & Routing${NC}"
  echo ""

  # A1: Does openclaw.json exist?
  if [[ ! -f "$OPENCLAW_CONFIG" ]]; then
    fail "openclaw.json not found at $OPENCLAW_CONFIG"
    fix "Run: openclaw onboard"
    return
  fi
  pass "openclaw.json exists"

  # Validate JSON
  if ! python3 -c "import json; json.load(open('$OPENCLAW_CONFIG'))" 2>/dev/null; then
    fail "openclaw.json is not valid JSON"
    fix "Check for syntax errors: python3 -m json.tool $OPENCLAW_CONFIG"
    return
  fi

  # A2: Check for 'everclaw/' provider prefix
  local everclaw_refs
  everclaw_refs=$(python3 -c "
import json
c = json.load(open('$OPENCLAW_CONFIG'))
bad = []
p = c.get('agents',{}).get('defaults',{}).get('model',{}).get('primary','')
if p.startswith('everclaw/'): bad.append('primary: ' + p)
for f in c.get('agents',{}).get('defaults',{}).get('model',{}).get('fallbacks',[]):
    if f.startswith('everclaw/'): bad.append('fallback: ' + f)
if 'everclaw' in c.get('models',{}).get('providers',{}):
    bad.append('provider named \"everclaw\"')
print('\n'.join(bad))
" 2>/dev/null)

  if [[ -n "$everclaw_refs" ]]; then
    fail "'everclaw/' used as provider prefix (this is a skill, not a provider)"
    while IFS= read -r line; do
      info "  $line"
    done <<< "$everclaw_refs"
    fix "Change to mor-gateway/kimi-k2.5 or morpheus/kimi-k2.5"
    fix "Auto-fix: node scripts/bootstrap-gateway.mjs"
  else
    pass "No 'everclaw/' provider prefix"
  fi

  # A3: Is morpheus or mor-gateway registered as a provider?
  local providers
  providers=$(python3 -c "
import json
c = json.load(open('$OPENCLAW_CONFIG'))
ps = list(c.get('models',{}).get('providers',{}).keys())
morpheus = [p for p in ps if p in ('morpheus','mor-gateway')]
print(' '.join(morpheus) if morpheus else '')
" 2>/dev/null)

  if [[ -n "$providers" ]]; then
    pass "Morpheus provider(s) configured: $providers"
  else
    fail "No Morpheus provider (morpheus or mor-gateway) in config"
    fix "Run: node scripts/bootstrap-gateway.mjs"
  fi

  # A4: Is a Morpheus model in the fallback chain?
  local fallback_info
  fallback_info=$(python3 -c "
import json
c = json.load(open('$OPENCLAW_CONFIG'))
model = c.get('agents',{}).get('defaults',{}).get('model',{})
primary = model.get('primary','')
fallbacks = model.get('fallbacks',[])
chain = [primary] + fallbacks
morpheus_in_chain = [m for m in chain if m.startswith('morpheus/') or m.startswith('mor-gateway/')]
if morpheus_in_chain:
    print('OK|' + ', '.join(morpheus_in_chain))
else:
    print('MISSING|chain: ' + ' → '.join(chain) if chain else 'MISSING|no chain')
" 2>/dev/null)

  local fb_status="${fallback_info%%|*}"
  local fb_detail="${fallback_info#*|}"

  if [[ "$fb_status" == "OK" ]]; then
    pass "Morpheus in model chain: $fb_detail"
  else
    fail "No Morpheus model in primary/fallback chain"
    info "  Current $fb_detail"
    fix "Add morpheus/kimi-k2.5 or mor-gateway/kimi-k2.5 to fallbacks"
  fi

  # A5: Do auth profiles exist for configured providers?
  if [[ -f "$AUTH_PROFILES" ]]; then
    local auth_check
    auth_check=$(python3 -c "
import json
config = json.load(open('$OPENCLAW_CONFIG'))
providers = list(config.get('models',{}).get('providers',{}).keys())

try:
    auth = json.load(open('$AUTH_PROFILES'))
    profiles = auth.get('profiles', auth)  # handle both formats
    auth_providers = set()
    for k, v in profiles.items():
        prov = v.get('provider', k.split(':')[0])
        auth_providers.add(prov)
except:
    auth_providers = set()

missing = [p for p in providers if p not in auth_providers]
if missing:
    print('MISSING|' + ', '.join(missing))
else:
    print('OK|' + str(len(providers)) + ' providers covered')
" 2>/dev/null)

    local auth_status="${auth_check%%|*}"
    local auth_detail="${auth_check#*|}"

    if [[ "$auth_status" == "OK" ]]; then
      pass "Auth profiles cover all providers ($auth_detail)"
    else
      warn "Missing auth profiles for: $auth_detail"
      fix "Add keys to $AUTH_PROFILES"
    fi
  else
    warn "Auth profiles file not found"
    fix "Expected at $AUTH_PROFILES"
  fi

  # A6: Are any Morpheus models set to reasoning: true?
  local reasoning_check
  reasoning_check=$(python3 -c "
import json
c = json.load(open('$OPENCLAW_CONFIG'))
bad = []
for pname in ('morpheus', 'mor-gateway'):
    prov = c.get('models',{}).get('providers',{}).get(pname,{})
    for m in prov.get('models',[]):
        if m.get('reasoning') is True:
            bad.append(pname + '/' + m.get('id','?'))
print('\n'.join(bad))
" 2>/dev/null)

  if [[ -n "$reasoning_check" ]]; then
    fail "Morpheus models with reasoning: true (causes HTTP 400)"
    while IFS= read -r line; do
      info "  $line"
    done <<< "$reasoning_check"
    fix "Set \"reasoning\": false for all Morpheus/mor-gateway models"
  else
    pass "No Morpheus models with reasoning: true"
  fi

  # A7: Does the primary model reference a valid provider?
  local primary_check
  primary_check=$(python3 -c "
import json
c = json.load(open('$OPENCLAW_CONFIG'))
primary = c.get('agents',{}).get('defaults',{}).get('model',{}).get('primary','')
if '/' not in primary:
    print('BAD|No provider prefix in primary: ' + primary)
else:
    provider = primary.split('/')[0]
    custom = list(c.get('models',{}).get('providers',{}).keys())
    # Built-in providers that don't need models.providers entry
    builtins = ['openai','anthropic','google','google-vertex','xai','groq',
                'cerebras','mistral','openrouter','github-copilot','venice',
                'ollama','vllm','huggingface','moonshot','zai','opencode',
                'openai-codex','google-antigravity','google-gemini-cli',
                'qwen-portal','synthetic','kimi-coding',
                'vercel-ai-gateway','minimax']
    if provider in custom or provider in builtins:
        print('OK|' + primary)
    else:
        print('BAD|Provider \"' + provider + '\" not found (not built-in, not in models.providers)')
" 2>/dev/null)

  local prim_status="${primary_check%%|*}"
  local prim_detail="${primary_check#*|}"

  if [[ "$prim_status" == "OK" ]]; then
    pass "Primary model valid: $prim_detail"
  else
    fail "$prim_detail"
    fix "Check provider name or add it to models.providers in openclaw.json"
  fi
}

# ═════════════════════════════════════════════════════════════════════════════
# GROUP B — Infrastructure & Connectivity (Step 2 — placeholder)
# ═════════════════════════════════════════════════════════════════════════════
run_infra_checks() {
  echo ""
  echo -e "${BOLD}Infrastructure & Connectivity${NC}"
  echo ""
  echo -e "  ${YELLOW}⏳${NC} Step 2 not yet implemented — coming in next release"
  echo "     Will check: proxy-router, proxy, sessions, MOR balance,"
  echo "     launchd services, gateway status, and live inference."
}

# ─── Run ─────────────────────────────────────────────────────────────────────
if [[ "$MODE" == "config" || "$MODE" == "all" ]]; then
  run_config_checks
fi

if [[ "$MODE" == "infra" || "$MODE" == "all" ]]; then
  run_infra_checks
fi

# ─── Summary ─────────────────────────────────────────────────────────────────
echo ""
echo "─────────────────────────────────────"
TOTAL=$((PASS + WARN + FAIL))
echo -e "${BOLD}Results:${NC} ${GREEN}${PASS} passed${NC}, ${YELLOW}${WARN} warnings${NC}, ${RED}${FAIL} failures${NC} (${TOTAL} checks)"

if [[ "$FAIL" -gt 0 ]]; then
  echo -e "${RED}${BOLD}Action required — fix the failures above.${NC}"
  exit 1
elif [[ "$WARN" -gt 0 ]]; then
  echo -e "${YELLOW}Mostly healthy — review warnings above.${NC}"
  exit 2
else
  echo -e "${GREEN}${BOLD}All clear! ✨${NC}"
  exit 0
fi
