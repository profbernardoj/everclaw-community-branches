---
name: everclaw
version: 0.6.0
description: AI inference you own, forever powering your OpenClaw agents via the Morpheus decentralized network. Stake MOR tokens, access Kimi K2.5 and 10+ models, and maintain persistent inference by recycling staked MOR. Includes OpenAI-compatible proxy with auto-session management, automatic retry with fresh sessions, OpenAI-compatible error classification to prevent cooldown cascades, Gateway Guardian watchdog, bundled security skills, and zero-dependency wallet management via macOS Keychain.
homepage: https://everclaw.com
metadata:
  openclaw:
    emoji: "♾️"
    requires:
      bins: ["curl", "node"]
    tags: ["inference", "everclaw", "morpheus", "mor", "decentralized", "ai", "blockchain", "base", "persistent", "fallback", "guardian", "security"]
---

# ♾️ Everclaw — AI Inference You Own, Forever Powering Your OpenClaw Agents

*Powered by [Morpheus AI](https://mor.org)*

Access Kimi K2.5, Qwen3, GLM-4, Llama 3.3, and 10+ models with inference you own. Everclaw connects your OpenClaw agent to the Morpheus P2P network — stake MOR tokens, open sessions, and recycle your stake for persistent, self-sovereign access to AI.

## How It Works

1. **Get MOR tokens** on Base — swap from ETH/USDC via Uniswap or Aerodrome (see below)
2. You run a **proxy-router** (Morpheus Lumerin Node) locally as a consumer
3. The router connects to Base mainnet and discovers model providers
4. You **stake MOR tokens** to open a session with a provider (MOR is locked, not spent)
5. You send inference requests to `http://localhost:8082/v1/chat/completions`
6. When the session ends, your **MOR is returned** (minus tiny usage fees)
7. Re-stake the returned MOR into new sessions → persistent inference you own

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

## 11. Wallet Management (v0.4)

Everclaw v0.4 includes a self-contained wallet manager that eliminates all external account dependencies. No 1Password, no Foundry, no Safe Wallet — just macOS Keychain and Node.js (already bundled with OpenClaw).

### Setup (One Command)

```bash
node skills/everclaw/scripts/everclaw-wallet.mjs setup
```

This generates a new Ethereum wallet and stores the private key in your macOS Keychain (encrypted at rest, protected by your login password / Touch ID).

### Import Existing Key

```bash
node skills/everclaw/scripts/everclaw-wallet.mjs import-key 0xYOUR_PRIVATE_KEY
```

### Check Balances

```bash
node skills/everclaw/scripts/everclaw-wallet.mjs balance
```

Shows ETH, MOR, USDC balances and MOR allowance for the Diamond contract.

### Swap ETH/USDC for MOR

```bash
# Swap 0.05 ETH for MOR
node skills/everclaw/scripts/everclaw-wallet.mjs swap eth 0.05

# Swap 50 USDC for MOR
node skills/everclaw/scripts/everclaw-wallet.mjs swap usdc 50
```

Executes onchain swaps via Uniswap V3 on Base. No external tools required — uses viem (bundled with OpenClaw).

### Approve MOR for Staking

```bash
node skills/everclaw/scripts/everclaw-wallet.mjs approve
```

Approves the Morpheus Diamond contract to use your MOR for session staking.

### Security Model

- Private key stored in **macOS Keychain** (encrypted at rest)
- Protected by your **login password / Touch ID**
- Key is **injected at runtime** and immediately unset from environment
- Key is **never written to disk** as a plaintext file
- For advanced users: 1Password is supported as a fallback (backward compatible)

### Full Command Reference

| Command | Description |
|---------|-------------|
| `setup` | Generate wallet, store in Keychain |
| `address` | Show wallet address |
| `balance` | Show ETH, MOR, USDC balances |
| `swap eth <amount>` | Swap ETH → MOR via Uniswap V3 |
| `swap usdc <amount>` | Swap USDC → MOR via Uniswap V3 |
| `approve [amount]` | Approve MOR for Morpheus staking |
| `export-key` | Print private key (use with caution) |
| `import-key <0xkey>` | Import existing private key |

---

## 12. OpenAI-Compatible Proxy (v0.2)

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

### Proxy Resilience (v0.5)

v0.5 adds three critical improvements to the proxy that prevent prolonged outages caused by **cooldown cascades** — where both primary and fallback providers become unavailable simultaneously.

#### Problem: Cooldown Cascades

When a primary provider (e.g., Venice) returns a billing error, OpenClaw's failover engine marks that provider as "in cooldown." If the Morpheus proxy also returns errors that OpenClaw misclassifies as billing errors, **both providers enter cooldown** and the agent goes completely offline — sometimes for 6+ hours.

#### Fix 1: OpenAI-Compatible Error Classification

The proxy now returns errors in the exact format OpenAI uses, with proper `type` and `code` fields:

```json
{
  "error": {
    "message": "Morpheus session unavailable: ...",
    "type": "server_error",
    "code": "morpheus_session_error",
    "param": null
  }
}
```

**Key distinction:** All Morpheus infrastructure errors are typed as `"server_error"` — never `"billing"` or `"rate_limit_error"`. This ensures OpenClaw treats them as transient failures and retries appropriately, instead of putting the provider into extended cooldown.

Error codes returned by the proxy:

| Code | Meaning |
|------|---------|
| `morpheus_session_error` | Failed to open or refresh a blockchain session |
| `morpheus_inference_error` | Provider returned an error during inference |
| `morpheus_upstream_error` | Connection error to the proxy-router |
| `timeout` | Inference request exceeded the time limit |
| `model_not_found` | Requested model not in MODEL_MAP |

#### Fix 2: Automatic Session Retry

When the proxy-router returns a session-related error (expired, invalid, not found, closed), the proxy now:

1. **Invalidates** the cached session
2. **Opens a fresh** blockchain session
3. **Retries** the inference request once

This handles the common case where the proxy-router restarts and loses its in-memory session state, or when a long-running session expires mid-request.

#### Fix 3: Multi-Tier Fallback Chain

Configure OpenClaw with multiple fallback models across providers:

```json5
{
  "agents": {
    "defaults": {
      "model": {
        "primary": "venice/claude-opus-4-6",
        "fallbacks": [
          "venice/claude-opus-45",    // Try different Venice model first
          "venice/kimi-k2-5",         // Try yet another Venice model
          "morpheus/kimi-k2.5"        // Last resort: decentralized inference
        ]
      }
    }
  }
}
```

This way, if the primary model has billing issues, OpenClaw tries other models on the same provider (which may have separate rate limits) before falling back to Morpheus. The cascade is:

1. **venice/claude-opus-4-6** (primary) → billing error
2. **venice/claude-opus-45** (fallback 1) → tries a different model on Venice
3. **venice/kimi-k2-5** (fallback 2) → tries open-source model on Venice
4. **morpheus/kimi-k2.5** (fallback 3) → decentralized inference, always available if MOR is staked

---

## 13. OpenClaw Integration (v0.2)

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

Configure a multi-tier fallback chain (recommended since v0.5):

```json5
{
  "agents": {
    "defaults": {
      "model": {
        "primary": "venice/claude-opus-4-6",
        "fallbacks": [
          "venice/claude-opus-45",   // Different model, same provider
          "venice/kimi-k2-5",        // Open-source model, same provider
          "morpheus/kimi-k2.5"       // Decentralized fallback
        ]
      },
      "models": {
        "venice/claude-opus-45": { "alias": "Claude Opus 4.5" },
        "venice/kimi-k2-5": { "alias": "Kimi K2.5" },
        "morpheus/kimi-k2.5": { "alias": "Kimi K2.5 (Morpheus)" },
        "morpheus/kimi-k2-thinking": { "alias": "Kimi K2 Thinking (Morpheus)" },
        "morpheus/glm-4.7-flash": { "alias": "GLM 4.7 Flash (Morpheus)" }
      }
    }
  }
}
```

⚠️ **Why multi-tier?** A single fallback creates a single point of failure. If both the primary provider and the single fallback enter cooldown simultaneously (e.g., billing error triggers cooldown on both), your agent goes offline. Multiple fallback tiers across different models and providers ensure at least one path remains available.

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
1. OpenClaw marks the primary model's profile as **in cooldown**
2. Tries fallback 1 (`venice/claude-opus-45`) — different model, same provider
3. If that also fails, tries fallback 2 (`venice/kimi-k2-5`) — open-source model
4. If all Venice models fail, falls back to `morpheus/kimi-k2.5`
5. The proxy auto-opens a 7-day Morpheus session (if none exists)
6. Inference routes through the Morpheus P2P network
7. When primary credits refill, OpenClaw switches back automatically

**v0.5 improvement:** The Morpheus proxy now returns `"server_error"` type errors (not billing errors), so OpenClaw won't put the Morpheus provider into extended cooldown due to transient infrastructure issues. If a Morpheus session expires mid-request, the proxy automatically opens a fresh session and retries once.

---

## 14. Gateway Guardian (v0.2)

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

## Quick Reference (v0.6)

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
| Scan a skill | `node security/skillguard/src/cli.js scan <path>` |
| Batch scan | `node security/skillguard/src/cli.js batch <dir>` |
| Security audit | `bash security/clawdstrike/scripts/collect_verified.sh` |
| Detect injection | `python3 security/prompt-guard/scripts/detect.py "text"` |

---

## 15. Security Skills (v0.3)

Everclaw agents handle MOR tokens and private keys — making them high-value targets. v0.3 bundles four security skills to defend against supply chain attacks, prompt injection, credential theft, and configuration exposure.

### 🔍 SkillGuard — Pre-Install Skill Scanner

Scans AgentSkill packages for malicious patterns before you install them. Detects credential theft, code injection, prompt manipulation, data exfiltration, and evasion techniques.

```bash
# Scan a skill directory
node security/skillguard/src/cli.js scan <path>

# Batch scan all installed skills
node security/skillguard/src/cli.js batch <directory>

# Scan a ClawHub skill by slug
node security/skillguard/src/cli.js scan-hub <slug>
```

**Score interpretation:**
- 80-100 ✅ LOW risk — safe to install
- 50-79 ⚠️ MEDIUM — review before installing
- 20-49 🟠 HIGH — significant concerns
- 0-19 🔴 CRITICAL — do NOT install

**When to use:** Before installing any skill from ClawHub or untrusted sources. Run batch scans periodically to audit all installed skills.

Full docs: `security/skillguard/SKILL.md`

### 🔒 ClawdStrike — Config & Exposure Audits

Security audit and threat model for OpenClaw gateway hosts. Verifies configuration, network exposure, installed skills/plugins, and filesystem hygiene. Produces an OK/VULNERABLE report with evidence and remediation steps.

```bash
# Run a full audit
cd security/clawdstrike && \
  OPENCLAW_WORKSPACE_DIR=$HOME/.openclaw/workspace \
  bash scripts/collect_verified.sh
```

**What it checks:**
- Gateway bind address and auth configuration
- Channel exposure (Signal, Telegram, Discord, etc.)
- Installed skills and plugins for known vulnerabilities
- Filesystem permissions and sensitive file access
- Network exposure and firewall rules
- OpenClaw version and known CVEs

**When to use:** After initial setup, after installing new skills, and periodically (weekly recommended).

Full docs: `security/clawdstrike/SKILL.md`

### 🧱 PromptGuard — Prompt Injection Defense

Advanced prompt injection defense system with multi-language detection (EN/KO/JA/ZH), severity scoring, automatic logging, and configurable security policies. Connects to the HiveFence distributed threat intelligence network.

```bash
# Analyze a message for injection attempts
python3 security/prompt-guard/scripts/detect.py "suspicious message here"

# Run audit on prompt injection logs
python3 security/prompt-guard/scripts/audit.py

# Analyze historical logs
python3 security/prompt-guard/scripts/analyze_log.py
```

**Detection categories:**
- Direct injection (instruction overrides, role manipulation)
- Indirect injection (data exfiltration, hidden instructions)
- Jailbreak attempts (DAN mode, filter bypasses)
- Multi-language attacks (cross-language injection)

**When to use:** In group chats, when processing untrusted input, when agents interact with external data sources.

Full docs: `security/prompt-guard/SKILL.md`

### 💰 Bagman — Secure Key Management

Secure key management for AI agents handling private keys, API secrets, and wallet credentials. Covers secure storage patterns, session keys, leak prevention, prompt injection defense specific to financial operations, and MetaMask Delegation Framework (EIP-7710) integration.

**Key principles:**
- **Never store keys on disk** — use 1Password `op run` for runtime injection
- **Session keys** — generate ephemeral keys with limited permissions
- **Delegation Framework** — grant agents scoped authority without exposing master keys
- **Leak prevention** — patterns to detect and block secret exposure

**Reference docs:**
- `security/bagman/references/secure-storage.md` — Storage patterns
- `security/bagman/references/session-keys.md` — Session key architecture
- `security/bagman/references/delegation-framework.md` — EIP-7710 integration
- `security/bagman/references/leak-prevention.md` — Leak detection rules
- `security/bagman/references/prompt-injection-defense.md` — Financial-specific injection defense

**When to use:** Whenever an agent handles private keys, wallet credentials, or API secrets — which Everclaw agents always do.

Full docs: `security/bagman/SKILL.md`

### Security Recommendations

For Everclaw agents handling MOR tokens:

1. **Before installing any new skill:** Run SkillGuard scan
2. **After setup and periodically:** Run ClawdStrike audit
3. **In group chats or with untrusted input:** Enable PromptGuard detection
4. **Always:** Follow Bagman patterns for key management (1Password, session keys, no keys on disk)

---

## 16. Model Router (v0.6)

A lightweight, local prompt classifier that routes requests to the cheapest capable model. Runs in <1ms with zero external API calls.

### Tiers

| Tier | Primary Model | Fallback | Use Case |
|------|--------------|----------|----------|
| **LIGHT** | `morpheus/glm-4.7-flash` | `morpheus/kimi-k2.5` | Cron jobs, heartbeats, simple Q&A, status checks |
| **STANDARD** | `morpheus/kimi-k2.5` | `venice/kimi-k2-5` | Research, drafting, summaries, most sub-agent tasks |
| **HEAVY** | `venice/claude-opus-4-6` | `venice/claude-opus-45` | Complex reasoning, architecture, formal proofs, strategy |

All LIGHT and STANDARD tier models run through Morpheus (free via staked MOR). Only HEAVY tier uses Venice (premium).

### How Scoring Works

The router scores prompts across 13 weighted dimensions:

| Dimension | Weight | What It Detects |
|-----------|--------|----------------|
| `reasoningMarkers` | 0.20 | "prove", "theorem", "step by step", "chain of thought" |
| `codePresence` | 0.14 | `function`, `class`, `import`, backticks, "refactor" |
| `synthesis` | 0.11 | "summarize", "compare", "draft", "analyze", "review" |
| `technicalTerms` | 0.10 | "algorithm", "architecture", "smart contract", "consensus" |
| `multiStepPatterns` | 0.10 | "first...then", "step 1", numbered lists |
| `simpleIndicators` | 0.08 | "what is", "hello", "weather" (negative score → pushes toward LIGHT) |
| `agenticTask` | 0.06 | "edit", "deploy", "install", "debug", "fix" |
| `creativeMarkers` | 0.04 | "story", "poem", "brainstorm" |
| `questionComplexity` | 0.04 | Multiple question marks |
| `tokenCount` | 0.04 | Short prompts skew LIGHT, long prompts skew HEAVY |
| `constraintCount` | 0.04 | "at most", "at least", "maximum", "budget" |
| `domainSpecificity` | 0.04 | "quantum", "zero-knowledge", "genomics" |
| `outputFormat` | 0.03 | "json", "yaml", "table", "csv" |

**Special override:** 2+ reasoning keywords in the user prompt → force HEAVY at 88%+ confidence. This prevents accidental cheap routing of genuinely hard problems.

**Ambiguous prompts** (low confidence) default to STANDARD — the safe middle ground.

### CLI Usage

```bash
# Test routing for a prompt
node scripts/router.mjs "What is 2+2?"
# → LIGHT (morpheus/glm-4.7-flash)

node scripts/router.mjs "Summarize the meeting notes and draft a follow-up"
# → STANDARD (morpheus/kimi-k2.5)

node scripts/router.mjs "Design a distributed consensus algorithm and prove its correctness"
# → HEAVY (venice/claude-opus-4-6)

# JSON output for programmatic use
node scripts/router.mjs --json "Build a React component"

# Pipe from stdin
echo '{"prompt":"hello","system":"You are helpful"}' | node scripts/router.mjs --stdin
```

### Programmatic Usage

```javascript
import { route, classify } from './scripts/router.mjs';

const decision = route("Check the weather in Austin");
// {
//   tier: "LIGHT",
//   model: "morpheus/glm-4.7-flash",
//   fallback: "morpheus/kimi-k2.5",
//   confidence: 0.87,
//   score: -0.10,
//   signals: ["short (7 tok)", "simple (weather)"],
//   reasoning: "score=-0.100 → LIGHT"
// }
```

### Applying to Cron Jobs

Set the `model` field on cron job payloads to route to cheaper models:

```json5
{
  "payload": {
    "kind": "agentTurn",
    "model": "morpheus/kimi-k2.5",   // STANDARD tier — free via Morpheus
    "message": "Compile a morning briefing...",
    "timeoutSeconds": 300
  }
}
```

For truly simple cron jobs (health checks, pings, status queries):

```json5
{
  "payload": {
    "kind": "agentTurn",
    "model": "morpheus/glm-4.7-flash",  // LIGHT tier — fastest, free
    "message": "Check proxy health and report any issues",
    "timeoutSeconds": 60
  }
}
```

### Applying to Sub-Agent Spawns

```javascript
// Simple research task → STANDARD
sessions_spawn({ task: "Search for X news", model: "morpheus/kimi-k2.5" });

// Quick lookup → LIGHT
sessions_spawn({ task: "What's the weather?", model: "morpheus/glm-4.7-flash" });

// Complex analysis → let it use the default (HEAVY / Claude 4.6)
sessions_spawn({ task: "Design the x402 payment integration..." });
```

### Cost Impact

With the router in place, only complex reasoning tasks in the main session use premium models. All background work (cron jobs, sub-agents, heartbeats) runs on free Morpheus inference:

| Before | After |
|--------|-------|
| All cron jobs → Claude 4.6 (premium) | Cron jobs → Kimi K2.5 / GLM Flash (free) |
| All sub-agents → Claude 4.6 (premium) | Sub-agents → Kimi K2.5 (free) unless complex |
| Main session → Claude 4.6 | Main session → Claude 4.6 (unchanged) |

---

## References

- `references/acquiring-mor.md` — How to get MOR tokens (exchanges, bridges, swaps)
- `references/models.md` — Available models and their blockchain IDs
- `references/api.md` — Complete proxy-router API reference
- `references/economics.md` — How MOR staking economics work
- `references/troubleshooting.md` — Common errors and solutions
- `security/skillguard/SKILL.md` — SkillGuard full documentation
- `security/clawdstrike/SKILL.md` — ClawdStrike full documentation
- `security/prompt-guard/SKILL.md` — PromptGuard full documentation
- `security/bagman/SKILL.md` — Bagman full documentation
