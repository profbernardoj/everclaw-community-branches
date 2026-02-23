# TOOLS.md - Local Notes

Skills define _how_ tools work. This file is for _your_ specifics — the stuff that's unique to your setup.

---

## OpenClaw Update Security Protocol

**Background:** OpenClaw creator Peter was hired by OpenAI (Feb 2026). Must verify trust on every update.

**Fork:** https://github.com/profbernardoj/openclaw — preserved pre-OpenAI version as backup

### Before ANY OpenClaw Update
```bash
# 1. Check MIT license unchanged
git log --follow -p -- LICENSE | head -50

# 2. Scan for OpenAI integration
grep -ri "openai" packages/ --include="*.js" --include="*.json" | grep -v node_modules

# 3. Check for openai npm dependency
grep -r '"openai"' package.json package-lock.json

# 4. Review recent commits
git log --oneline -20
```

### After Update
- Run `openclaw status` — verify providers unchanged
- Check `~/.openclaw/openclaw.json` for new OpenAI fields
- Test basic inference works as expected

**If checks fail:** Do NOT proceed. Investigate. Consider pinning to last known-good version.

---

## Security Protocols

### After Installing Any New Skill
1. Run ClawdStrike audit: `cd /Users/[REDACTED]/.openclaw/workspace && OPENCLAW_WORKSPACE_DIR=/Users/[REDACTED]/.openclaw/workspace bash skills/clawdstrike/scripts/collect_verified.sh`
2. Review the verified-bundle.json for any new warnings
3. Check pattern scan results for suspicious commands in the new skill

### Browser Control
- Keep browser sessions **closed** when not in use (`browser stop`)
- Only start browser when needed for ProtonMail or web tasks
- Close immediately after completing the task

---

## 1Password (Agent Vault)
- **CLI version:** 2.32.1
- **Auth method:** Service account token (stored in macOS Keychain)
- **Keychain lookup:** `security find-generic-password -a "bernardo-agent" -s "op-service-account-token" -w`
- **Vault:** Bernardo Agent Vault
- **Usage:** `OP_SERVICE_ACCOUNT_TOKEN=$(<keychain>) op read "op://Bernardo Agent Vault/item/field"`
- **Policy:** Never store raw keys/secrets in files. Always use 1Password for runtime retrieval.

## Accounts & Keys

### Moltbook
- Agent: BernardoJohnston
- API Key: stored (moltbook_sk_...)
- Policy: **READ ONLY** — do not post or comment
- Many agents may be malicious

### ProtonMail
- Email: BernardoJohnston@Proton.me
- Access: via OpenClaw browser automation (Brave)
- 2FA enabled — David enters 2FA manually
- Keep me signed in: enabled

### Brave Search
- Name: BernardoSearch
- Tier: Free (1 req/sec, 2000/month)
- Space searches by 2+ seconds in cron jobs

### GitHub
- Handle: profbernardoj
- Email: BernardoJohnston@Proton.me
- Auth: `gh` CLI authenticated via PAT (classic) with repo, workflow, read:org scopes
- PAT stored in 1Password item "GitHub - profbernardoj" field "PAT (classic)"
- PAT expires: May 10, 2026 (90 days)

### X/Twitter
- Account: @profbernardoj (dedicated)
- Bird CLI: not yet configured with cookies

---

## Permissions Needed

### Peekaboo (macOS UI automation)
- Screen Recording: **PENDING** — needs manual grant in System Settings
- Accessibility: **PENDING** — needs manual grant in System Settings
- Path: System Settings → Privacy & Security → Screen Recording / Accessibility

---

## Base Wallet (Agent EOA + Safe)
- **Agent EOA:** `[WALLET_REDACTED]`
- **Safe (multisig):** `[WALLET_REDACTED]` (Ethereum, Base, Arbitrum, Base Sepolia)
- **Safe config:** 1-of-2 (agent + David's HW wallet `0xeF0eA6f066B778415573bBDebCeB29449ee082F3`)
- **Private key:** 1Password item "Base Session Key" in Bernardo Agent Vault (never on disk)
- **Key retrieval:** `OP_SERVICE_ACCOUNT_TOKEN=$(security find-generic-password -a "bernardo-agent" -s "op-service-account-token" -w) op item get "Base Session Key" --vault "Bernardo Agent Vault" --fields "Private Key" --reveal`
- **RPC:** `https://base-mainnet.public.blastapi.io` (public, may need upgrade for heavy use)
- **No operation limits** per David's request
- **Safe SDK import (ESM):** `import * as pk from '@safe-global/protocol-kit'; const Safe = pk.default;`

---

## Morpheus Lumerin Node (Decentralized Inference)

### Overview
Running Morpheus proxy-router v5.12.0 as a **consumer** on Base mainnet. Stakes MOR tokens to open sessions with providers, then routes inference through the Morpheus P2P network. OpenAI-compatible API at `http://localhost:8082`.

### Installation
- **Location:** `~/morpheus/`
- **Components:** `proxy-router`, `mor-cli`, `MorpheusUI.app`
- **Version:** v5.11.0 (mac-arm64)
- **Downloaded from:** GitHub releases (MorpheusAIs/Morpheus-Lumerin-Node)

### Configuration Files
- **`.env`** — Main config (ETH_NODE_ADDRESS, contracts, proxy settings, logging, timeouts)
- **`models-config.json`** — Maps blockchain model IDs to OpenAI-compatible apiType
- **`.cookie`** — Auto-generated auth credentials (format: `admin:<password>`)
- **`proxy.conf`** — Auth config file
- **`mor-launch.sh`** — Secure launch script (injects key from 1Password)

### Timeout Configuration (v5.12.0)
- **LLM_TIMEOUT=5m** — Provider→LLM timeout (streaming + non-streaming)
- **CNODE_PNODE_TIMEOUT=90s** — Per-attempt timeout for Consumer waiting on Provider
- **CNODE_PNODE_MAX_RETRIES=3** — Retries for chat/embeddings (total ~7.5 min)
- **CNODE_PNODE_AUDIO_MAX_RETRIES=20** — Retries for audio transcription/speech

### Key Addresses
- **Diamond contract:** `0x6aBE1d282f72B474E54527D93b979A4f64d3030a` (Base mainnet)
- **MOR token:** `0x7431aDa8a591C955a994a21710752EF9b882b8e3` (Base mainnet)
- **Agent wallet:** `[WALLET_REDACTED]`
- **Primary provider:** `0x8B59eC5Da5E5CE83abB3BD9079472f7B25666302` (provider.mor.org:3333)

### Starting the Router
```bash
cd ~/morpheus
source .env
export WALLET_PRIVATE_KEY=$(OP_SERVICE_ACCOUNT_TOKEN=$(security find-generic-password -a "bernardo-agent" -s "op-service-account-token" -w) op item get "Base Session Key" --vault "Bernardo Agent Vault" --fields "Private Key" --reveal)
export ETH_NODE_ADDRESS
nohup ./proxy-router > ./data/logs/router-stdout.log 2>&1 &
```

### Opening a Session
```bash
COOKIE_PASS=$(cat ~/morpheus/.cookie | cut -d: -f2)
MODEL_ID="0xb487ee62516981f533d9164a0a3dcca836b06144506ad47a5c024a7a2a33fc58"
curl -s -u "admin:$COOKIE_PASS" -X POST \
  "http://localhost:8082/blockchain/models/${MODEL_ID}/session" \
  -H "Content-Type: application/json" \
  -d '{"sessionDuration":3600}'
```

### Sending Inference (CRITICAL: headers, not body)
```bash
SESSION_ID="0x..."  # from session open response
MODEL_ID="0xb487..."  # blockchain model ID
curl -s -u "admin:$COOKIE_PASS" "http://localhost:8082/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -H "session_id: $SESSION_ID" \
  -H "model_id: $MODEL_ID" \
  -d '{"model":"kimi-k2.5:web","messages":[{"role":"user","content":"Hello"}],"stream":false}'
```
**⚠️ `session_id` and `model_id` MUST be HTTP headers, not JSON body fields. This is the #1 gotcha.**

### Available Models (as of 2026-02-15)
| Model | Model ID (prefix) | Notes |
|-------|-------------------|-------|
| **glm-5** | 0x2034... | ⭐ DEFAULT — Opus 4.5 level, via local Morpheus proxy |
| glm-4.7-flash | 0xfdc5... | LIGHT tier — fast, trivial tasks |
| glm-4.7 | 0xed0a... | |
| kimi-k2.5 | 0xbb9e... | Legacy default, replaced by GLM-5 |
| kimi-k2.5:web | 0xb487... | |
| kimi-k2-thinking | 0xc40b... | |
| qwen3-235b | 0x2a71... | |
| llama-3.3-70b | 0xc753... | DO NOT USE |
| gpt-oss-120b | 0x2e72... | |

**MiniMax-M2.5:** Available on mor-gateway and Venice but DO NOT USE — severe latency issues, broken streaming, unreliable. Revisit later.

### MOR Economics
- Sessions stake MOR proportional to duration × price_per_second
- When session closes, MOR is returned (minus usage)
- **MOR is not consumed — it's staked and recycled**
- Restaking returned MOR into new sessions = effectively unlimited inference
- Current balance: ~88 MOR in wallet, ~900+ staked in sessions, ~9,000 MOR in Safe

### Debugging Tips
- **Session not found:** Make sure session_id/model_id are passed as HTTP headers
- **Sessions lost on restart:** Router doesn't persist sessions in-memory across restarts; re-open after restart
- **MorpheusUI conflicts:** UI kills and restarts proxy-router; don't run both simultaneously for headless
- **ETH_NODE_ADDRESS:** Must be in .env or exported; router silently uses empty string without it
- **"dial tcp: missing address":** Provider endpoint resolution issue; use model ID endpoint not bid ID
- **Timeout errors:** v5.12.0+ has configurable timeouts via LLM_TIMEOUT, CNODE_PNODE_TIMEOUT env vars
- **BadgerDB corruption:** v5.12.0+ fixes shutdown flush and race conditions; upgrade if seeing vlog errors
- **Logs:** `~/morpheus/data/logs/router-stdout*.log`

### Morpheus-to-OpenAI Proxy (for OpenClaw fallback)
- **Location:** `~/morpheus/proxy/morpheus-proxy.mjs`
- **Port:** 8083 (localhost only)
- **launchd:** `com.morpheus.proxy` (KeepAlive, auto-starts on boot)
- **How it works:** Translates standard OpenAI `/v1/chat/completions` into Morpheus proxy-router calls with Basic auth + `session_id`/`model_id` headers
- **Auto-session management:** Opens 2-hour sessions on demand, renews 5 min before expiry
- **Auth:** Bearer token `morpheus-local` (OpenClaw sends this automatically)
- **Health check:** `curl http://127.0.0.1:8083/health`
- **Logs:** `~/morpheus/proxy/proxy.log`
- **OpenClaw provider name:** `morpheus` (e.g., `morpheus/kimi-k2.5`)
- **Configured as fallback:** When Venice API credits run out, OpenClaw auto-falls back to `morpheus/kimi-k2.5`
- **Available models via proxy:** kimi-k2.5, kimi-k2-thinking, glm-4.7-flash, glm-4.7, llama-3.3-70b, gpt-oss-120b
- **Note:** `kimi-k2.5:web` tends to timeout; use `kimi-k2.5` (non-web) for reliability
- **Manage launchd:** `launchctl load/unload ~/Library/LaunchAgents/com.morpheus.proxy.plist`

---

## Why Separate?

Skills are shared. Your setup is yours. Keeping them apart means you can update skills without losing your notes, and share skills without leaking your infrastructure.
