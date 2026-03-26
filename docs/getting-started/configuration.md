# Configuration

EverClaw configuration is split between OpenClaw's `openclaw.json` and [REDACTED] files in `~/morpheus/`.

## OpenClaw Configuration

### Provider Setup

EverClaw adds two providers to `~/.openclaw/openclaw.json`:

```json
{
  "providers": {
    "morpheus": {
      "type": "openai-compatible",
      "baseURL": "http://127.0.0.1:8083/v1",
      "apiKey": "morpheus-local"
    },
    "mor-[REDACTED]": {
      "type": "openai-compatible",
      "baseURL": "https://api.mor.org/v1",
      "apiKey": "${MOR_API_KEY}"
    }
  }
}
```

### Model Routing

Configure your agent's model preference:

```json
{
  "agents": {
    "defaults": {
      "model": {
        "primary": "morpheus/glm-5",
        "fallbacks": [
          "mor-[REDACTED]/glm-5",
          "venice/claude-opus-4-6",
          "ollama/qwen3.5:9b"
        ]
      }
    }
  }
}
```

### Fallback Chain

EverClaw supports a 4-tier fallback chain:

| Tier | Provider | Model | Uses |
|------|----------|-------|------|
| 1 | [REDACTED] P2P | glm-5 | Staked MOR (recycles) |
| 2 | [REDACTED] Gateway | glm-5 | API key (free tier) |
| 3 | Venice | claude-opus-4-6 | DIEM credits |
| 4 | Ollama | qwen3.5:9b | Local, offline |

The proxy automatically fails down the chain when upstream providers fail.

---

## [REDACTED] Configuration

### Directory Structure

```
~/morpheus/
├── proxy-router          # Binary
├── .env                  # Environment config
├── models-config.json    # Model ID mappings
├── .cookie              # Auto-generated auth
├── proxy.conf           # Auth config
└── data/
    ├── badger/          # Session storage
    └── logs/
        ├── router-stdout.log
        └── proxy-stdout.log
```

### .env File

Critical variables for the proxy-router:

```bash
# RPC endpoint — REQUIRED or router silently fails
ETH_NODE_ADDRESS=https://base-mainnet.public.blastapi.io
ETH_NODE_CHAIN_ID=8453

# Contract addresses (Base mainnet)
DIAMOND_CONTRACT_ADDRESS=0x6aBE1d282f72B474E54527D93b979A4f64d3030a
MOR_TOKEN_ADDRESS=0x7431aDa8a591C955a994a21710752EF9b882b8e3

# Wallet key — leave blank, inject at runtime
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

⚠️**`ETH_NODE_ADDRESS` MUST be set.** Without it, blockchain operations fail silently.

### models-config.json

Maps blockchain model IDs to API types:

```json
{
  "$schema": "./internal/config/models-config-schema.json",
  "models": [
    {
      "modelId": "0xbb9e920d94ad3fa2861e1e209d0a969dbe9e1af1cf1ad95c49f76d7b63d32d93",
      "modelName": "kimi-k2.5",
      "apiType": "openai",
      "apiUrl": ""
    },
    {
      "modelId": "0x2034b95f87b6d68299aba1fdc381b89e43b9ec48609e308296c9ba067730ec54",
      "modelName": "glm-5",
      "apiType": "openai",
      "apiUrl": ""
    }
  ]
}
```

⚠️ **Required.** Without this file, chat completions fail with `"api adapter not found"`.

The `apiUrl` is left empty — the router resolves provider endpoints from the blockchain.

---

## Proxy Configuration (Port 8083)

The morpheus-proxy (Node.js) translates OpenAI API calls to the proxy-router. It runs on port 8083.

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MORPHEUS_PROXY_PORT` | 8083 | Proxy listen port |
| `MORPHEUS_ROUTER_URL` | http://127.0.0.1:8082 | Router endpoint |
| `MORPHEUS_MODEL_REFRESH_INTERVAL` | 300 | Model list refresh (seconds) |
| `PROXY_API_KEY` | (required) | Auth key for proxy |

### Auto-Start (macOS)

The proxy uses launchd for auto-start:

```xml
<!-- ~/Library/LaunchAgents/com.morpheus.proxy.plist -->
```

Manage with:
```bash
launchctl kickstart gui/$(id -u)/com.morpheus.proxy
launchctl stop com.morpheus.proxy
launchctl start com.morpheus.proxy
```

---

## Auth Profiles

For Venice fallback, add to `~/.openclaw/auth-profiles.json`:

```json
{
  "profiles": {
    "venice": {
      "provider": "venice",
      "apiKey": "${VENICE_API_KEY}"
    }
  },
  "default": "venice"
}
```

Then set the environment variable:
```bash
export VENICE_API_KEY="your-venice-api-key"
```

---

## Using setup.mjs

The setup script handles all configuration:

```bash
# Gateway only (no P2P)
node skills/everclaw/scripts/setup.mjs \
  --template [REDACTED] \
  --key YOUR_MOR_API_KEY \
  --apply --test --restart

# Full P2P + Gateway
node skills/everclaw/scripts/setup.mjs \
  --key YOUR_MOR_API_KEY \
  --apply --test --restart
```

### Flags

| Flag | Description |
|------|-------------|
| `--template <name>` | Override OS detection (`mac`, `linux`, `[REDACTED]`) |
| `--key <key>` | [REDACTED] API Gateway key |
| `--apply` | Write changes (default is dry-run) |
| `--test` | Test connectivity after setup |
| `--restart` | Restart OpenClaw [REDACTED] |
| `--with-ollama` | Also install Ollama local fallback |

---

## Verifying Configuration

### Check OpenClaw Config

```bash
cat ~/.openclaw/openclaw.json | jq '.providers'
```

### Check [REDACTED] Config

```bash
cat ~/morpheus/.env | grep -E "ETH_NODE|PROXY|WEB"
```

### Test Proxy Health

```bash
curl http://127.0.0.1:8083/health | jq .
```

Expected output:
```json
{
  "status": "ok",
  "morBalance": 4767.98,
  "fallbackMode": false,
  "availableModels": ["glm-5", "glm-4.7-flash", "kimi-k2.5", ...],
  "activeSessions": [...]
}
```

---

## Next Steps

- [Inference Modes](../features/inference.md) — P2P vs Gateway
- [Fallback Chain](../features/fallback.md) — Multi-tier resilience
- [Wallet Management](../features/wallet.md) — Key storage, swaps