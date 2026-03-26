# API Reference

Complete API reference for the [REDACTED] proxy-router and OpenAI-compatible proxy.

## Endpoints Overview

| Service | Port | Purpose |
|---------|------|---------|
| **Proxy Router** | 8082 | Blockchain operations, sessions |
| **OpenAI Proxy** | 8083 | OpenAI-compatible inference |

---

## Proxy Router (Port 8082)

**Base URL:** `http://localhost:8082`
**Auth:** Basic auth using credentials from `~/morpheus/.cookie`
**Swagger:** `http://localhost:8082/swagger/index.html`

### Authentication

```bash
COOKIE_PASS=$(cat ~/morpheus/.cookie | cut -d: -f2)
curl -s -u "admin:$COOKIE_PASS" http://localhost:8082/...
```

---

### Health Check

#### GET /healthcheck

Check if the proxy-router is running.

```bash
curl -s -u "admin:$COOKIE_PASS" http://localhost:8082/healthcheck
```

**Response:** HTTP 200 if healthy.

---

### Blockchain Endpoints

#### GET /blockchain/balance

Returns MOR and ETH balance for the configured wallet.

```bash
curl -s -u "admin:$COOKIE_PASS" http://localhost:8082/blockchain/balance | jq .
```

**Response:**
```json
{
  "mor": "88000000000000000000",
  "eth": "50000000000000000"
}
```

Values are in wei (18 decimals). Divide by 10^18 for human-readable.

---

#### POST /blockchain/approve

Approve the Diamond contract to transfer MOR tokens.

⚠️ **Uses query parameters, not JSON body.**

```bash
curl -s -u "admin:$COOKIE_PASS" -X POST \
  "http://localhost:8082/blockchain/approve?spender=0x6aBE1d282f72B474E54527D93b979A4f64d3030a&amount=1000000000000000000000"
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `spender` | address | Diamond contract address |
| `amount` | uint256 | Amount in wei (1000 MOR = 1000000000000000000000) |

---

#### GET /blockchain/allowance

Check current MOR allowance for a spender.

```bash
curl -s -u "admin:$COOKIE_PASS" \
  "http://localhost:8082/blockchain/allowance?spender=0x6aBE1d282f72B474E54527D93b979A4f64d3030a"
```

---

#### GET /blockchain/models

List all available models on the [REDACTED] network.

```bash
curl -s -u "admin:$COOKIE_PASS" http://localhost:8082/blockchain/models | jq '.models[].Name' | sort
```

---

#### POST /blockchain/models/{id}/session

Open a new inference session.

⚠️ **Use the model ID, not a bid ID.**

```bash
curl -s -u "admin:$COOKIE_PASS" -X POST \
  "http://localhost:8082/blockchain/models/0xMODEL_ID/session" \
  -H "Content-Type: application/json" \
  -d '{"sessionDuration": 86400}'
```

| Field | Type | Description |
|-------|------|-------------|
| `sessionDuration` | integer | Duration in seconds (86400 = 1 day) |

**Response:**
```json
{
  "sessionId": "0xabcdef1234567890...",
  "txHash": "0x..."
}
```

---

#### GET /blockchain/sessions

List all active sessions.

```bash
curl -s -u "admin:$COOKIE_PASS" http://localhost:8082/blockchain/sessions | jq .
```

---

#### POST /blockchain/sessions/{id}/close

Close an active session and reclaim staked MOR.

```bash
curl -s -u "admin:$COOKIE_PASS" -X POST \
  "http://localhost:8082/blockchain/sessions/0xSESSION_ID/close"
```

---

### Inference Endpoints

#### POST /v1/chat/completions

Send a chat completion request through an active session.

⚠️ **CRITICAL: `session_id` and `model_id` must be HTTP headers, not JSON body fields.**

```bash
curl -s -u "admin:$COOKIE_PASS" "http://localhost:8082/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -H "session_id: 0xYOUR_SESSION_ID" \
  -H "model_id: 0xYOUR_MODEL_ID" \
  -d '{
    "model": "kimi-k2.5",
    "messages": [{"role": "user", "content": "Hello!"}],
    "stream": false
  }'
```

**Required Headers:**

| Header | Description |
|--------|-------------|
| `session_id` | Active session ID (hex) |
| `model_id` | Blockchain model ID (hex) |

**Body Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `model` | string | Yes | Model name |
| `messages` | array | Yes | Chat messages |
| `stream` | boolean | No | Enable SSE streaming |
| `temperature` | float | No | Sampling temperature |
| `max_tokens` | integer | No | Max tokens to generate |

---

## OpenAI-Compatible Proxy (Port 8083)

**Base URL:** `http://localhost:8083/v1`
**Auth:** Bearer token `morpheus-local`

The proxy automatically handles session management — no session_id or model_id headers needed.

### GET /health

Health check with MOR balance and session status.

```bash
curl -s http://localhost:8083/health | jq .
```

**Response:**
```json
{
  "status": "ok",
  "morBalance": 4767.98,
  "fallbackMode": false,
  "consecutiveFailures": 0,
  "availableModels": ["glm-5", "glm-4.7-flash", ...],
  "activeSessions": [...]
}
```

---

### GET /v1/models

List available models.

```bash
curl -s http://localhost:8083/v1/models | jq '.data[].id'
```

---

### POST /v1/chat/completions

Send a chat completion request (OpenAI-compatible).

```bash
curl -s http://localhost:8083/v1/chat/completions \
  -H "Authorization: Bearer morpheus-local" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "glm-5",
    "messages": [{"role": "user", "content": "Hello!"}],
    "stream": false
  }'
```

**No session management needed** — the proxy handles it automatically.

---

## Common Patterns

### Full Workflow (Router)

```bash
COOKIE_PASS=$(cat ~/morpheus/.cookie | cut -d: -f2)
MODEL_ID="0xbb9eaf3df30bbada0a6e3bdf3c836c792e3be34a64e68832874bbf0de7351e43"

# 1. Check balance
curl -s -u "admin:$COOKIE_PASS" http://localhost:8082/blockchain/balance | jq .

# 2. Approve MOR
curl -s -u "admin:$COOKIE_PASS" -X POST \
  "http://localhost:8082/blockchain/approve?spender=0x6aBE1d282f72B474E54527D93b979A4f64d3030a&amount=1000000000000000000000"

# 3. Open session
SESSION_ID=$(curl -s -u "admin:$COOKIE_PASS" -X POST \
  "http://localhost:8082/blockchain/models/${MODEL_ID}/session" \
  -H "Content-Type: application/json" \
  -d '{"sessionDuration":86400}' | jq -r '.sessionId')

# 4. Send inference
curl -s -u "admin:$COOKIE_PASS" "http://localhost:8082/v1/chat/completions" \
  -H "session_id: $SESSION_ID" \
  -H "model_id: $MODEL_ID" \
  -d '{"model":"kimi-k2.5","messages":[{"role":"user","content":"Hello"}]}'

# 5. Close session
curl -s -u "admin:$COOKIE_PASS" -X POST \
  "http://localhost:8082/blockchain/sessions/${SESSION_ID}/close"
```

### Simple Inference (Proxy)

```bash
curl http://localhost:8083/v1/chat/completions \
  -H "Authorization: Bearer morpheus-local" \
  -H "Content-Type: application/json" \
  -d '{"model":"glm-5","messages":[{"role":"user","content":"Hello"}]}'
```

---

## Next Steps

- [Models Reference](./models.md) — Available models and model IDs
- [Contracts Reference](./contracts.md) — Contract addresses