---
name: everclaw
version: 0.2.0
description: Unlimited AI inference for OpenClaw agents via the Morpheus decentralized network. Stake MOR tokens, access Kimi K2.5 and 10+ models, and never run out of inference by recycling staked MOR. Includes OpenAI-compatible proxy with auto-session management and Gateway Guardian watchdog.
homepage: https://everclaw.com
metadata:
  openclaw:
    emoji: "♾️"
    requires:
      bins: ["curl", "op", "node"]
    tags: ["inference", "everclaw", "morpheus", "mor", "decentralized", "ai", "blockchain", "base", "unlimited", "fallback", "guardian"]
---

# ♾️ Everclaw — Unlimited Decentralized AI Inference

*Powered by [Morpheus AI](https://mor.org)*

Access Kimi K2.5, Qwen3, GLM-4, Llama 3.3, and 10+ models with effectively unlimited inference. Everclaw connects your OpenClaw agent to the Morpheus P2P network — stake MOR tokens, open sessions, and recycle your stake for inference that never runs out.

## How It Works

1. **Get MOR tokens** on Base — swap from ETH/USDC via Uniswap or Aerodrome (see below)
2. You run a **proxy-router** (Morpheus Lumerin Node) locally as a consumer
3. The router connects to Base mainnet and discovers model providers
4. You **stake MOR tokens** to open a session with a provider (MOR is locked, not spent)
5. You send inference requests to `http://localhost:8082/v1/chat/completions`
6. When the session ends, your **MOR is returned** (minus tiny usage fees)
7. Re-stake the returned MOR into new sessions → effectively unlimited inference

## Getting MOR Tokens

You need MOR on Base to stake for inference. If you already have ETH, USDC, or USDT on Base:

```bash
# Swap ETH for MOR
bash skills/everclaw/scripts/swap.sh eth 0.01

# Swap USDC for MOR
bash skills/everclaw/scripts/swap.sh usdc 50
```

Or swap manually on a DEX:
- **Uniswap:** [MOR/ETH on Base](https://app.uniswap.org/explore/tokens/base/0x7431ada8a591c955a994a21710752ef9b882b8e3)
- **Aerodrome:** [MOR swap on Base](https://aerodrome.finance/swap?from=eth&to=0x7431ada8a591c955a994a21710752ef9b882b8e3)

Don't have anything on Base yet? Buy ETH on Coinbase, withdraw to Base, then swap to MOR. See `references/acquiring-mor.md` for the full guide.

**How much do you need?** MOR is staked, not spent — you get it back. 50-100 MOR is enough for daily use. 0.005 ETH covers months of Base gas fees.

## Architecture

```
Agent → proxy-router (localhost:8082) → Morpheus P2P Network → Provider → Model
                ↓
         Base Mainnet (MOR staking, session management)
```

---

## 1. Installation

Run the install script:

```bash
bash skills/everclaw/scripts/install.sh
```

This downloads the latest proxy-router release for your OS/arch, extracts it to `~/morpheus/`, and creates initial config files.

### Manual Installation

1. Go to [Morpheus-Lumerin-Node releases](https://github.com/MorpheusAIs/Morpheus-Lumerin-Node/releases)
2. Download the release for your platform (e.g., `mor-launch-darwin-arm64.zip`)
3. Extract to `~/morpheus/`
4. On macOS: `xattr -cr ~/morpheus/`

### Required Files

After installation, `~/morpheus/` should contain:

| File | Purpose |
|------|---------|
| `proxy-router` | The main binary |
| `.env` | Configuration (RPC, contracts, ports) |
| `models-config.json` | Maps blockchain model IDs to API types |
| `.cookie` | Auto-generated auth credentials |

---

## 2. Configuration

### .env File

The `.env` file configures the proxy-router for consumer mode on Base mainnet. Critical variables:

```bash
# RPC endpoint — MUST be set or router silently fails
ETH_NODE_ADDRESS=https://base-mainnet.public.blastapi.io
ETH_NODE_CHAIN_ID=8453

# Contract addresses (Base mainnet)
DIAMOND_CONTRACT_ADDRESS=0x6aBE1d282f72B474E54527D93b979A4f64d3030a
MOR_TOKEN_ADDRESS=0x7431aDa8a591C955a994a21710752EF9b882b8e3

# Wallet key — leave blank, inject at runtime via 1Password
WALLET_PRIVATE_KEY=

# Proxy settings
PROXY_ADDRESS=0.0.0.0:3333
PROXY_STORAGE_PATH=./data/badger/
PROXY_STORE_CHAT_CONTEXT=true
PROXY_FORWARD_CHAT_CONTEXT=true
MODELS_CONFIG_PATH=./models-config.json

# Web API
WEB_ADDRESS=0.0.0.0:8082
WEB_PUBLIC_URL=http://localhost:8082

# Auth
AUTH_CONFIG_FILE_PATH=./proxy.conf
COOKIE_FILE_PATH=./.cookie

# Logging
LOG_COLOR=true
LOG_LEVEL_APP=info
LOG_FOLDER_PATH=./data/logs
ENVIRONMENT=production
```

⚠️ **`ETH_NODE_ADDRESS` MUST be set.** The router silently connects to an empty string without it and all blockchain operations fail. Also **`MODELS_CONFIG_PATH`** must point to your models-config.json.

### models-config.json

⚠️ **This file is required.** Without it, chat completions fail with `"api adapter not found"`.

```json
{
  "$schema": "./internal/config/models-config-schema.json",
  "models": [
    {
      "modelId": "0xb487ee62516981f533d9164a0a3dcca836b06144506ad47a5c024a7a2a33fc58",
      "modelName": "kimi-k2.5:web",
      "apiType": "openai",
      "apiUrl": ""
    },
    {
      "modelId": "0xbb9e920d94ad3fa2861e1e209d0a969dbe9e1af1cf1ad95c49f76d7b63d32d93",
      "modelName": "kimi-k2.5",
      "apiType": "openai",
      "apiUrl": ""
    }
  ]
}
```

⚠️ **Note the format:** The JSON uses a `"models"` array with `"modelId"` / `"modelName"` / `"apiType"` / `"apiUrl"` fields. The `apiUrl` is left empty — the router resolves provider endpoints from the blockchain. Add entries for every model you want to use. See `references/models.md` for the full list.

---

## 3. Starting the Router

### Secure Launch (1Password)

The proxy-router needs your wallet private key. **Never store it on disk.** Inject it at runtime from 1Password:

```bash
bash skills/everclaw/scripts/start.sh
```

Or manually:

```bash
cd ~/morpheus
source .env

# Retrieve private key from 1Password (never touches disk)
export WALLET_PRIVATE_KEY=$(
  OP_SERVICE_ACCOUNT_TOKEN=$(security find-generic-password -a "YOUR_KEYCHAIN_ACCOUNT" -s "op-service-account-token" -w) \
  op item get "YOUR_ITEM_NAME" --vault "YOUR_VAULT_NAME" --fields "Private Key" --reveal
)

export ETH_NODE_ADDRESS
nohup ./proxy-router > ./data/logs/router-stdout.log 2>&1 &
```

### Health Check

Wait a few seconds, then verify:

```bash
COOKIE_PASS=$(cat ~/morpheus/.cookie | cut -d: -f2)
curl -s -u "admin:$COOKIE_PASS" http://localhost:8082/healthcheck
```

Expected: HTTP 200.

### Stopping

```bash
bash skills/everclaw/scripts/stop.sh
```

Or: `pkill -f proxy-router`

---

## 4. MOR Allowance

Before opening sessions, approve the Diamond contract to transfer MOR on your behalf:

```bash
COOKIE_PASS=$(cat ~/morpheus/.cookie | cut -d: -f2)

curl -s -u "admin:$COOKIE_PASS" -X POST \
  "http://localhost:8082/blockchain/approve?spender=0x6aBE1d282f72B474E54527D93b979A4f64d3030a&amount=1000000000000000000000"
```

⚠️ **The `/blockchain/approve` endpoint uses query parameters**, not a JSON body. The `amount` is in wei (1000000000000000000 = 1 MOR). Approve a large amount so you don't need to re-approve frequently.

---

## 5. Opening Sessions

Open a session by **model ID** (not bid ID):

```bash
MODEL_ID="0xb487ee62516981f533d9164a0a3dcca836b06144506ad47a5c024a7a2a33fc58"

curl -s -u "admin:$COOKIE_PASS" -X POST \
  "http://localhost:8082/blockchain/models/${MODEL_ID}/session" \
  -H "Content-Type: application/json" \
  -d '{"sessionDuration": 3600}'
```

⚠️ **Always use the model ID endpoint**, not the bid ID. Using a bid ID results in `"dial tcp: missing address"`.

### Session Duration

- Duration is in **seconds**: 3600 = 1 hour, 86400 = 1 day
- **Two blockchain transactions** occur: approve transfer + open session
- MOR is **staked** (locked) for the session duration
- When the session closes, MOR is **returned** to your wallet

### Response

The response includes a `sessionId` (hex string). Save this — you need it for inference.

### Using the Script

```bash
# Open a 1-hour session for kimi-k2.5:web
bash skills/everclaw/scripts/session.sh open kimi-k2.5:web 3600

# List active sessions
bash skills/everclaw/scripts/session.sh list

# Close a session
bash skills/everclaw/scripts/session.sh close 0xSESSION_ID_HERE
```

---

## 6. Sending Inference

### ⚠️ THE #1 GOTCHA: Headers, Not Body

`session_id` and `model_id` are **HTTP headers**, not JSON body fields. This is the single most common mistake.

**CORRECT:**

```bash
curl -s -u "admin:$COOKIE_PASS" "http://localhost:8082/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -H "session_id: 0xYOUR_SESSION_ID" \
  -H "model_id: 0xYOUR_MODEL_ID" \
  -d '{
    "model": "kimi-k2.5:web",
    "messages": [{"role": "user", "content": "Hello, world!"}],
    "stream": false
  }'
```

**WRONG (will fail with "session not found"):**

```bash
# DON'T DO THIS
curl -s ... -d '{
  "model": "kimi-k2.5:web",
  "session_id": "0x...",   # WRONG — not a body field
  "model_id": "0x...",     # WRONG — not a body field
  "messages": [...]
}'
```

### Using the Chat Script

```bash
bash skills/everclaw/scripts/chat.sh kimi-k2.5:web "What is the meaning of life?"
```

### Streaming

Set `"stream": true` in the request body. The response will be Server-Sent Events (SSE).

---

## 7. Closing Sessions

Close a session to reclaim your staked MOR:

```bash
curl -s -u "admin:$COOKIE_PASS" -X POST \
  "http://localhost:8082/blockchain/sessions/0xSESSION_ID/close"
```

Or use the script:

```bash
bash skills/everclaw/scripts/session.sh close 0xSESSION_ID
```

⚠️ MOR staked in a session is returned when the session closes. Close sessions you're not using to free up MOR for new sessions.

---

## 8. Session Management

### Sessions Are Ephemeral

⚠️ **Sessions are NOT persisted across router restarts.** If you restart the proxy-router, you must re-open sessions. The blockchain still has the session, but the router's in-memory state is lost.

### Monitoring

```bash
# Check balance (MOR + ETH)
bash skills/everclaw/scripts/balance.sh

# List sessions
bash skills/everclaw/scripts/session.sh list
```

### Session Lifecycle

1. **Open** → MOR is staked, session is active
2. **Active** → Send inference requests using session_id header
3. **Expired** → Session duration elapsed; MOR returned automatically
4. **Closed** → Manually closed; MOR returned immediately

### Re-opening After Restart

After restarting the router:

```bash
# Wait for health check
sleep 5

# Re-open sessions for models you need
bash skills/everclaw/scripts/session.sh open kimi-k2.5:web 3600
```

---

## 9. Checking Balances

```bash
COOKIE_PASS=$(cat ~/morpheus/.cookie | cut -d: -f2)

# MOR and ETH balance
curl -s -u "admin:$COOKIE_PASS" http://localhost:8082/blockchain/balance | jq .

# Active sessions
curl -s -u "admin:$COOKIE_PASS" http://localhost:8082/blockchain/sessions | jq .

# Available models
curl -s -u "admin:$COOKIE_PASS" http://localhost:8082/blockchain/models | jq .
```

---

## 10. Troubleshooting

See `references/troubleshooting.md` for a complete guide. Quick hits:

| Error | Fix |
|-------|-----|
| `session not found` | Use session_id/model_id as HTTP **headers**, not body fields |
| `dial tcp: missing address` | Open session by **model ID**, not bid ID |
| `api adapter not found` | Add the model to `models-config.json` |
| `ERC20: transfer amount exceeds balance` | Close old sessions to free staked MOR |
| Sessions gone after restart | Normal — re-open sessions after restart |
| MorpheusUI conflicts | Don't run MorpheusUI and headless router simultaneously |

---

## Key Contract Addresses (Base Mainnet)

| Contract | Address |
|----------|---------|
| Diamond | `0x6aBE1d282f72B474E54527D93b979A4f64d3030a` |
| MOR Token | `0x7431aDa8a591C955a994a21710752EF9b882b8e3` |

## Quick Reference

| Action | Command |
|--------|---------|
| Install | `bash skills/everclaw/scripts/install.sh` |
| Start | `bash skills/everclaw/scripts/start.sh` |
| Stop | `bash skills/everclaw/scripts/stop.sh` |
| Swap ETH→MOR | `bash skills/everclaw/scripts/swap.sh eth 0.01` |
| Swap USDC→MOR | `bash skills/everclaw/scripts/swap.sh usdc 50` |
| Open session | `bash skills/everclaw/scripts/session.sh open <model> [duration]` |
| Close session | `bash skills/everclaw/scripts/session.sh close <session_id>` |
| List sessions | `bash skills/everclaw/scripts/session.sh list` |
| Send prompt | `bash skills/everclaw/scripts/chat.sh <model> "prompt"` |
| Check balance | `bash skills/everclaw/scripts/balance.sh` |

---

## 11. OpenAI-Compatible Proxy (v0.2)

The Morpheus proxy-router requires custom auth (Basic auth via `.cookie`) and custom HTTP headers (`session_id`, `model_id`) that standard OpenAI clients don't support. Everclaw includes a lightweight proxy that bridges this gap.

### What It Does

```
OpenClaw/any client → morpheus-proxy (port 8083) → proxy-router (port 8082) → Morpheus P2P → Provider
```

- Accepts standard OpenAI `/v1/chat/completions` requests
- **Auto-opens** blockchain sessions on demand (no manual session management)
- **Auto-renews** sessions before expiry (default: 1 hour before)
- Injects Basic auth + `session_id`/`model_id` headers automatically
- Exposes `/health`, `/v1/models`, `/v1/chat/completions`

### Installation

```bash
bash skills/everclaw/scripts/install-proxy.sh
```

This installs:
- `morpheus-proxy.mjs` → `~/morpheus/proxy/`
- `gateway-guardian.sh` → `~/.openclaw/workspace/scripts/`
- launchd plists for both (macOS, auto-start on boot)

### Configuration

Environment variables (all optional, sane defaults):

| Variable | Default | Description |
|----------|---------|-------------|
| `MORPHEUS_PROXY_PORT` | `8083` | Port the proxy listens on |
| `MORPHEUS_ROUTER_URL` | `http://localhost:8082` | Proxy-router URL |
| `MORPHEUS_COOKIE_PATH` | `~/morpheus/.cookie` | Path to auth cookie |
| `MORPHEUS_SESSION_DURATION` | `604800` (7 days) | Session duration in seconds |
| `MORPHEUS_RENEW_BEFORE` | `3600` (1 hour) | Renew session this many seconds before expiry |
| `MORPHEUS_PROXY_API_KEY` | `morpheus-local` | Bearer token for proxy auth |

### Session Duration

Sessions stake MOR tokens for their duration. Longer sessions = more MOR locked but fewer blockchain transactions:

| Duration | MOR Staked (approx) | Transactions |
|----------|--------------------:|:-------------|
| 1 hour | ~11 MOR | Every hour |
| 1 day | ~274 MOR | Daily |
| 7 days | ~1,915 MOR | Weekly |

MOR is **returned** when the session closes or expires. The proxy auto-renews before expiry, so you get continuous inference with minimal staking overhead.

### Health Check

```bash
curl http://127.0.0.1:8083/health
```

### Available Models

```bash
curl http://127.0.0.1:8083/v1/models
```

### Direct Usage (without OpenClaw)

```bash
curl http://127.0.0.1:8083/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer morpheus-local" \
  -d '{
    "model": "kimi-k2.5",
    "messages": [{"role": "user", "content": "Hello!"}],
    "stream": false
  }'
```

### Reliability Notes

- **`kimi-k2.5`** (non-web) is the most reliable model — recommended as primary fallback
- **`kimi-k2.5:web`** (web search variant) tends to timeout on P2P routing — avoid for fallback use
- Provider connection resets are transient — retries usually succeed
- The proxy itself runs as a KeepAlive launchd service — auto-restarts if it crashes

---

## 12. OpenClaw Integration (v0.2)

Configure OpenClaw to use Morpheus as a **fallback provider** so your agent keeps running when primary API credits run out.

### Step 1: Add Morpheus Provider

Add to your `openclaw.json` via config patch or manual edit:

```json5
{
  "models": {
    "providers": {
      "morpheus": {
        "baseUrl": "http://127.0.0.1:8083/v1",
        "apiKey": "morpheus-local",
        "api": "openai-completions",
        "models": [
          {
            "id": "kimi-k2.5",
            "name": "Kimi K2.5 (via Morpheus)",
            "reasoning": true,
            "input": ["text"],
            "cost": { "input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0 },
            "contextWindow": 131072,
            "maxTokens": 8192
          },
          {
            "id": "kimi-k2-thinking",
            "name": "Kimi K2 Thinking (via Morpheus)",
            "reasoning": true,
            "input": ["text"],
            "cost": { "input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0 },
            "contextWindow": 131072,
            "maxTokens": 8192
          },
          {
            "id": "glm-4.7-flash",
            "name": "GLM 4.7 Flash (via Morpheus)",
            "reasoning": false,
            "input": ["text"],
            "cost": { "input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0 },
            "contextWindow": 131072,
            "maxTokens": 8192
          }
        ]
      }
    }
  }
}
```

### Step 2: Set as Fallback

```json5
{
  "agents": {
    "defaults": {
      "model": {
        "primary": "venice/claude-opus-4-6",
        "fallbacks": ["morpheus/kimi-k2.5"]
      },
      "models": {
        "morpheus/kimi-k2.5": { "alias": "Kimi K2.5 (Morpheus)" },
        "morpheus/kimi-k2-thinking": { "alias": "Kimi K2 Thinking (Morpheus)" },
        "morpheus/glm-4.7-flash": { "alias": "GLM 4.7 Flash (Morpheus)" }
      }
    }
  }
}
```

### Step 3: Add Auth Profile

Add to `~/.openclaw/agents/main/agent/auth-profiles.json`:

```json
{
  "morpheus:default": {
    "type": "api_key",
    "provider": "morpheus",
    "key": "morpheus-local"
  }
}
```

And in `openclaw.json` under `auth.profiles`:

```json5
{
  "auth": {
    "profiles": {
      "morpheus:default": {
        "provider": "morpheus",
        "mode": "api_key"
      }
    }
  }
}
```

### Failover Behavior

When your primary provider (e.g., Venice) returns billing/credit errors:
1. OpenClaw marks the profile as **disabled** (5h backoff)
2. Falls back to `morpheus/kimi-k2.5`
3. The proxy auto-opens a 7-day Morpheus session (if none exists)
4. Inference routes through the Morpheus P2P network
5. When primary credits refill, OpenClaw switches back automatically

---

## 13. Gateway Guardian (v0.2)

A watchdog that monitors the OpenClaw gateway and restarts it if unresponsive. Runs every 2 minutes via launchd.

### How It Works

1. **HTTP probe** against `http://127.0.0.1:18789/`
2. **2 consecutive failures** required before restart (prevents flapping)
3. Three-stage restart:
   - `openclaw gateway restart` (graceful)
   - Hard kill → launchd KeepAlive restarts (force)
   - `launchctl kickstart` (nuclear option)
4. Logs everything to `~/.openclaw/logs/guardian.log`

### Installation

Included in `install-proxy.sh`, or manually:

```bash
cp skills/everclaw/scripts/gateway-guardian.sh ~/.openclaw/workspace/scripts/
chmod +x ~/.openclaw/workspace/scripts/gateway-guardian.sh

# Install launchd plist (macOS)
# See templates/ai.openclaw.guardian.plist
```

### Manual Test

```bash
bash ~/.openclaw/workspace/scripts/gateway-guardian.sh --verbose
```

### Logs

```bash
tail -f ~/.openclaw/logs/guardian.log
```

### Configuration

Edit variables at the top of `gateway-guardian.sh`:

| Variable | Default | Description |
|----------|---------|-------------|
| `GATEWAY_PORT` | `18789` | Gateway port to probe |
| `PROBE_TIMEOUT` | `8` | HTTP timeout in seconds |
| `FAIL_THRESHOLD` | `2` | Consecutive failures before restart |
| `MAX_LOG_LINES` | `500` | Log file rotation threshold |

---

## Quick Reference (v0.2)

| Action | Command |
|--------|---------|
| Install router | `bash skills/everclaw/scripts/install.sh` |
| Install proxy + guardian | `bash skills/everclaw/scripts/install-proxy.sh` |
| Start router | `bash skills/everclaw/scripts/start.sh` |
| Stop router | `bash skills/everclaw/scripts/stop.sh` |
| Swap ETH→MOR | `bash skills/everclaw/scripts/swap.sh eth 0.01` |
| Swap USDC→MOR | `bash skills/everclaw/scripts/swap.sh usdc 50` |
| Open session | `bash skills/everclaw/scripts/session.sh open <model> [duration]` |
| Close session | `bash skills/everclaw/scripts/session.sh close <session_id>` |
| List sessions | `bash skills/everclaw/scripts/session.sh list` |
| Send prompt | `bash skills/everclaw/scripts/chat.sh <model> "prompt"` |
| Check balance | `bash skills/everclaw/scripts/balance.sh` |
| Proxy health | `curl http://127.0.0.1:8083/health` |
| Guardian test | `bash scripts/gateway-guardian.sh --verbose` |
| Guardian logs | `tail -f ~/.openclaw/logs/guardian.log` |

## References

- `references/acquiring-mor.md` — How to get MOR tokens (exchanges, bridges, swaps)
- `references/models.md` — Available models and their blockchain IDs
- `references/api.md` — Complete proxy-router API reference
- `references/economics.md` — How MOR staking economics work
- `references/troubleshooting.md` — Common errors and solutions
