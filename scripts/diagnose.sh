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
# GROUP B — Infrastructure & Connectivity
# ═════════════════════════════════════════════════════════════════════════════
run_infra_checks() {
  echo ""
  echo -e "${BOLD}Infrastructure & Connectivity${NC}"
  echo ""

  # B1: Is the proxy-router process running? (port 8082)
  local router_health
  local cookie_pass=""
  if [[ -f "$MORPHEUS_DIR/.cookie" ]]; then
    cookie_pass=$(cut -d: -f2 < "$MORPHEUS_DIR/.cookie" 2>/dev/null)
  fi

  if [[ -n "$cookie_pass" ]]; then
    router_health=$(curl -s --max-time 5 -u "admin:$cookie_pass" http://localhost:8082/healthcheck 2>/dev/null || echo "")
  else
    router_health=$(curl -s --max-time 5 http://localhost:8082/healthcheck 2>/dev/null || echo "")
  fi

  if echo "$router_health" | grep -q '"healthy"' 2>/dev/null; then
    local router_uptime
    router_uptime=$(echo "$router_health" | python3 -c "import json,sys; print(json.load(sys.stdin).get('Uptime','?'))" 2>/dev/null || echo "?")
    pass "Proxy-router healthy (port 8082, uptime $router_uptime)"
  else
    fail "Proxy-router not responding (port 8082)"
    if pgrep -f proxy-router >/dev/null 2>&1; then
      info "  Process is running but not responding on HTTP"
      fix "Check logs: tail ~/morpheus/data/logs/router-stdout.log"
    else
      fix "Start it: launchctl load ~/Library/LaunchAgents/com.morpheus.router.plist"
      fix "Or manually: cd ~/morpheus && bash mor-launch-headless.sh"
    fi
  fi

  # B2: Is the JS proxy running? (port 8083)
  local proxy_health
  proxy_health=$(curl -s --max-time 5 http://127.0.0.1:8083/health 2>/dev/null || echo "")

  if echo "$proxy_health" | grep -q '"ok"' 2>/dev/null; then
    pass "Morpheus proxy healthy (port 8083)"
  else
    fail "Morpheus proxy not responding (port 8083)"
    if pgrep -f morpheus-proxy >/dev/null 2>&1; then
      fix "Process running but not healthy — check ~/morpheus/proxy/proxy.log"
    else
      fix "Start it: launchctl load ~/Library/LaunchAgents/com.morpheus.proxy.plist"
    fi
  fi

  # B3: Does the proxy have active blockchain sessions?
  # B4: Are sessions expiring soon?
  if [[ -n "$proxy_health" ]] && echo "$proxy_health" | grep -q '"ok"' 2>/dev/null; then
    local session_info
    session_info=$(echo "$proxy_health" | python3 -c "
import json, sys
from datetime import datetime, timezone
d = json.load(sys.stdin)
sessions = d.get('activeSessions', [])
if not sessions:
    print('NONE|0')
else:
    active = [s for s in sessions if s.get('active')]
    soonest_h = 999
    soonest_model = ''
    for s in active:
        exp = s.get('expiresAt','')
        if exp:
            try:
                exp_dt = datetime.fromisoformat(exp.replace('Z','+00:00'))
                now = datetime.now(timezone.utc)
                hours_left = (exp_dt - now).total_seconds() / 3600
                if hours_left < soonest_h:
                    soonest_h = hours_left
                    soonest_model = s.get('model','?')
            except: pass
    if soonest_h == 999:
        soonest_h = -1
    print(f'OK|{len(active)}|{soonest_h:.1f}|{soonest_model}')
" 2>/dev/null)

    local sess_status="${session_info%%|*}"
    local sess_rest="${session_info#*|}"

    if [[ "$sess_status" == "NONE" ]]; then
      fail "No active blockchain sessions"
      fix "Open one: bash scripts/session.sh open kimi-k2.5 604800"
      fix "Or send any request — proxy auto-opens sessions on demand"
    else
      local sess_count="${sess_rest%%|*}"
      sess_rest="${sess_rest#*|}"
      local hours_left="${sess_rest%%|*}"
      local soonest_model="${sess_rest#*|}"
      local hours_int="${hours_left%%.*}"

      pass "$sess_count active session(s)"

      if (( hours_int < 2 )); then
        warn "Session for $soonest_model expires in ${hours_left}h"
        fix "Renew: bash scripts/session.sh open $soonest_model 604800"
      elif (( hours_int < 24 )); then
        pass "Nearest expiry: ${hours_left}h ($soonest_model)"
      else
        pass "Nearest expiry: ${hours_left}h ($soonest_model) — plenty of time"
      fi
    fi
  fi

  # B5: MOR wallet balance
  if [[ -n "$cookie_pass" ]] && echo "$router_health" | grep -q '"healthy"' 2>/dev/null; then
    local balance_json
    balance_json=$(curl -s --max-time 5 -u "admin:$cookie_pass" http://localhost:8082/blockchain/balance 2>/dev/null || echo "")

    if [[ -n "$balance_json" ]]; then
      local balance_info
      balance_info=$(echo "$balance_json" | python3 -c "
import json, sys
d = json.load(sys.stdin)
mor_wei = int(d.get('mor', '0'))
eth_wei = int(d.get('eth', '0'))
mor = mor_wei / 1e18
eth = eth_wei / 1e18
if mor < 1:
    print(f'LOW|{mor:.2f} MOR, {eth:.6f} ETH')
elif eth < 0.0001:
    print(f'LOW_GAS|{mor:.2f} MOR, {eth:.6f} ETH')
else:
    print(f'OK|{mor:.2f} MOR, {eth:.6f} ETH')
" 2>/dev/null)

      local bal_status="${balance_info%%|*}"
      local bal_detail="${balance_info#*|}"

      case "$bal_status" in
        OK)
          pass "Wallet balance: $bal_detail"
          ;;
        LOW)
          warn "Low MOR balance: $bal_detail"
          fix "Need MOR to open sessions. Swap: bash scripts/swap.sh eth 0.01"
          ;;
        LOW_GAS)
          warn "Low ETH (gas): $bal_detail"
          fix "Need ETH on Base for transaction fees"
          ;;
      esac
    fi
  fi

  # B6: Is the Morpheus API Gateway reachable?
  local gw_status
  gw_status=$(curl -s --max-time 10 -o /dev/null -w "%{http_code}" https://api.mor.org/api/v1/models 2>/dev/null || echo "000")

  if [[ "$gw_status" == "200" || "$gw_status" == "401" || "$gw_status" == "403" ]]; then
    pass "Morpheus API Gateway reachable (api.mor.org → HTTP $gw_status)"
  elif [[ "$gw_status" == "000" ]]; then
    warn "Cannot reach Morpheus API Gateway (network issue or DNS)"
    fix "Check internet connection. Try: curl https://api.mor.org/api/v1/models"
  else
    warn "Morpheus API Gateway returned HTTP $gw_status"
    fix "Gateway may be down. Check: https://mor.org"
  fi

  # B7: Live inference test (skip with --quick)
  if [[ "$QUICK" == true ]]; then
    echo ""
    info "  Skipping inference test (--quick mode)"
  else
    echo ""
    echo -e "  ${BLUE}🔬${NC} Testing live inference (morpheus/kimi-k2.5)..."

    local infer_result
    infer_result=$(curl -s --max-time 60 http://127.0.0.1:8083/v1/chat/completions \
      -H "Content-Type: application/json" \
      -H "Authorization: Bearer morpheus-local" \
      -d '{"model":"kimi-k2.5","messages":[{"role":"user","content":"Reply with exactly: DIAG_OK"}],"stream":false,"max_tokens":50}' 2>/dev/null || echo "")

    if echo "$infer_result" | grep -q "DIAG_OK" 2>/dev/null; then
      pass "Live inference working — Kimi K2.5 responded via Morpheus P2P"
    elif echo "$infer_result" | grep -q '"choices"' 2>/dev/null; then
      pass "Live inference working — got response (model may not have followed instruction exactly)"
    elif echo "$infer_result" | grep -q "billing\|Insufficient\|402" 2>/dev/null; then
      fail "Inference returned billing error — this shouldn't happen on Morpheus"
      fix "Requests may be routing to Venice. Run: bash scripts/diagnose.sh --config"
    elif echo "$infer_result" | grep -q "session" 2>/dev/null; then
      warn "Inference failed — possible session issue"
      fix "Try opening a fresh session: bash scripts/session.sh open kimi-k2.5 604800"
    elif [[ -z "$infer_result" ]]; then
      fail "Inference test timed out (60s) — proxy may be stuck"
      fix "Check proxy logs: tail ~/morpheus/proxy/proxy.log"
      fix "Check router logs: tail ~/morpheus/data/logs/router-stdout.log"
    else
      fail "Inference test failed"
      info "  Response: $(echo "$infer_result" | head -c 200)"
      fix "Check proxy and router logs"
    fi
  fi

  # B8: Are launchd services loaded? (macOS only)
  if [[ "$(uname)" == "Darwin" ]]; then
    echo ""
    local services=("com.morpheus.router" "com.morpheus.proxy" "ai.openclaw.guardian")
    local svc_names=("Proxy-router" "Morpheus proxy" "Gateway Guardian")
    local all_loaded=true

    for i in "${!services[@]}"; do
      local svc="${services[$i]}"
      local name="${svc_names[$i]}"

      if launchctl list 2>/dev/null | grep -q "$svc"; then
        local pid
        pid=$(launchctl list 2>/dev/null | grep "$svc" | awk '{print $1}')
        if [[ "$pid" == "-" || -z "$pid" ]]; then
          warn "$name ($svc) loaded but not running"
          fix "Check: launchctl kickstart gui/$(id -u)/$svc"
        else
          pass "$name ($svc) running (PID $pid)"
        fi
      else
        local plist="$HOME/Library/LaunchAgents/${svc}.plist"
        if [[ -f "$plist" ]]; then
          warn "$name ($svc) plist exists but not loaded"
          fix "Load: launchctl load $plist"
        else
          warn "$name ($svc) not installed"
          fix "Run: bash skills/everclaw/scripts/install-proxy.sh"
        fi
        all_loaded=false
      fi
    done
  fi

  # B9: Is the OpenClaw gateway running?
  local gw_port="${OPENCLAW_GATEWAY_PORT:-18789}"
  local gw_http
  gw_http=$(curl -s --max-time 3 -o /dev/null -w "%{http_code}" "http://127.0.0.1:${gw_port}/" 2>/dev/null || echo "000")

  if [[ "$gw_http" != "000" ]]; then
    pass "OpenClaw gateway responding (port $gw_port)"
  else
    fail "OpenClaw gateway not responding (port $gw_port)"
    fix "Start it: openclaw gateway start"
  fi
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
