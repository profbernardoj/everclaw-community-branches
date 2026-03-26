# Inference

EverClaw provides three inference modes with a 4-tier fallback chain for resilience.

## Inference Modes

### Mode 1: Gateway Only (Easiest)

No wallet, no MOR tokens. Just a free API key from [app.mor.org](https://app.mor.org).

| Aspect | Details |
|--------|---------|
| **Setup** | 5 minutes |
| **Cost** | Free tier: 1,000 requests/day |
| **Models** | GLM-5, GLM-4.7 Flash, Kimi K2.5 |
| **Privacy** | Requests via [REDACTED] Gateway servers |
| **Persistence** | Stateless (no sessions) |

```bash
curl https://api.mor.org/v1/chat/completions \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"glm-5","messages":[{"role":"user","content":"Hello"}]}'
```

**Best for:** Quick testing, low-volume use, no crypto setup.

### Mode 2: P2P + Gateway (Recommended)

Full decentralized inference with staked MOR tokens.

| Aspect | Details |
|--------|---------|
| **Setup** | 15-30 minutes |
| **Cost** | Stake MOR (tokens recycle) + ETH for gas |
| **Models** | 40+ models including GLM-5, Kimi K2.5 Thinking |
| **Privacy** | Direct provider connection (no intermediary) |
| **Persistence** | Sessions up to 24 hours |

```bash
curl http://127.0.0.1:8083/v1/chat/completions \
  -H "Authorization: Bearer morpheus-local" \
  -H "Content-Type: application/json" \
  -d '{"model":"glm-5","messages":[{"role":"user","content":"Hello"}]}'
```

**Best for:** Daily use, privacy-conscious users, high-volume workloads.

### Mode 3: Local Fallback (Offline)

Ollama running locally for disconnected operation.

| Aspect | Details |
|--------|---------|
| **Setup** | Automated via `setup-ollama.sh` |
| **Cost** | Free (uses your hardware) |
| **Models** | Qwen3.5 family (0.8B-35B) |
| **Privacy** | Fully local |
| **Persistence** | No sessions needed |

```bash
curl http://127.0.0.1:11434/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"qwen3.5:9b","messages":[{"role":"user","content":"Hello"}]}'
```

**Best for:** Offline operation, last-resort fallback, air-gapped setups.

---

## Fallback Chain

EverClaw automatically falls back when upstream providers fail:

```
1. [REDACTED] P2P (port 8083)
   └─ Falls back on: session expired, no MOR, provider error
       └─ 2. [REDACTED] Gateway (api.mor.org)
           └─ Falls back on: rate limit, API error
               └─ 3. Venice API (api.venice.ai)
                   └─ Falls back on: DIEM exhausted, 402 error
                       └─ 4. Ollama Local (port 11434)
                           └─ Last resort: offline, all else failed
```

### Configuring Fallback

In `openclaw.json`:

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

---

## P2P Sessions

P2P inference requires a session — a temporary contract with a model provider.

### Session Lifecycle

```
1. Approve MOR spending (one-time)
   └─ Diamond contract gets allowance
2. Open session
   └─ MOR is staked (locked) for duration
3. Send inference requests
   └─ Model responses via provider
4. Session expires or closes
   └─ MOR is returned (minus tiny fees)
```

### Opening Sessions

```bash
# Via script
node skills/everclaw/scripts/session.sh open glm-5 86400

# Via API
MODEL_ID="0x2034b95f87b6d68299aba1fdc381b89e43b9ec48609e308296c9ba067730ec54"
curl -u "admin:$COOKIE_PASS" -X POST \
  "http://localhost:8082/blockchain/models/${MODEL_ID}/session" \
  -H "Content-Type: application/json" \
  -d '{"sessionDuration": 86400}'
```

### Session Duration

| Duration | MOR Staked | Gas Cost |
|----------|------------|----------|
| 1 hour | ~50 MOR | ~0.001 ETH |
| 24 hours | ~500-1000 MOR | ~0.001 ETH |
| 7 days | ~4000 MOR | ~0.001 ETH |

**Note:** MOR is returned when the session closes. Only ETH gas is consumed.

### Session Management

```bash
# List active sessions
node skills/everclaw/scripts/session.sh list

# Check session status
curl http://127.0.0.1:8083/health | jq '.activeSessions'

# Close a session (returns MOR)
node skills/everclaw/scripts/session.sh close 0xSESSION_ID
```

---

## Available Models

### P2P Models(40+)

| Model | Type | P2P | Gateway |
|-------|------|-----|---------|
| `glm-5` | Reasoning | ✅ | ✅ |
| `glm-5:web` | Web search | ✅ | ✅ |
| `glm-4.7` | General | ✅ | ✅ |
| `glm-4.7-flash` | Fast | ✅ | ✅ |
| `glm-4.7-thinking` | Extended thinking | ✅ | ❌ |
| `kimi-k2.5` | General | ✅ | ✅ |
| `kimi-k2.5:web` | Web search | ✅ | ✅ |
| `kimi-k2-thinking` | Reasoning | ✅ | ❌ |
| `qwen3-235b` | Large | ✅ | ❌ |
| `llama-3.3-70b` | General | ✅ | ❌ |
| `mistral-31-24b` | Fast | ✅ | ❌ |

[→ Full model list](../reference/models.md)

### Checking Available Models

```bash
# Via proxy (P2P)
curl http://127.0.0.1:8083/v1/models | jq '.data[].id'

# Via router (raw blockchain data)
curl -u "admin:$COOKIE_PASS" http://localhost:8082/blockchain/models | jq '.models[].Name'
```

---

## Sending Inference

### Via OpenAI-Compatible Proxy

The proxy at port 8083 handles sessions automatically:

```bash
curl http://127.0.0.1:8083/v1/chat/completions \
  -H "Authorization: Bearer morpheus-local" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "glm-5",
    "messages": [
      {"role": "system", "content": "You are a helpful assistant."},
      {"role": "user", "content": "What is 2+2?"}
    ],
    "stream": false
  }'
```

### Streaming Responses

```bash
curl http://127.0.0.1:8083/v1/chat/completions \
  -H "Authorization: Bearer morpheus-local" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "glm-5",
    "messages": [{"role": "user", "content": "Write a poem"}],
    "stream": true
  }'
```

### Via Script

```bash
node skills/everclaw/scripts/chat.sh glm-5 "What is the meaning of life?"
```

---

## Proxy Auto-Management

The morpheus-proxy handles:

| Feature | Description |
|---------|-------------|
| **Session auto-open** | Opens session when needed |
| **Session auto-renew** | Renews before expiry |
| **Model discovery** | Refreshes available models every 5 min |
| **Fallback routing** | Falls back to Gateway on P2P failure |
| **Auth injection** | Adds required headers automatically |

### Proxy Health Check

```bash
curl http://127.0.0.1:8083/health | jq .
```

Response:
```json
{
  "status": "ok",
  "morBalance": 4767.98,
  "fallbackMode": false,
  "consecutiveFailures": 0,
  "availableModels": ["glm-5", "glm-4.7-flash", ...],
  "activeSessions": [
    {
      "model": "glm-5",
      "sessionId": "0x...",
      "expiresAt": "2026-03-16T15:55:09.634Z",
      "active": true
    }
  ]
}
```

### Fallback Mode

When P2P fails, the proxy enters "fallback mode" and routes via Gateway:

```json
{
  "fallbackMode": true,
  "fallbackReason": "No active session for glm-5"
}
```

---

## Common Issues

### "session not found"

Make sure you're using the proxy (port 8083), not the router (port 8082). The proxy handles sessions automatically.

### "api adapter not found"

Add the model to `~/morpheus/models-config.json`:

```json
{
  "models": [
    {
      "modelId": "0x...",
      "modelName": "model-name",
      "apiType": "openai",
      "apiUrl": ""
    }
  ]
}
```

[→ Full troubleshooting guide](../operations/troubleshooting.md)

---

## Next Steps

- [Wallet Management](wallet.md) — MOR tokens, staking, swaps
- [Fallback Chain](fallback.md) — Multi-tier resilience
- [API Reference](../reference/api.md) — OpenAI-compatible endpoints