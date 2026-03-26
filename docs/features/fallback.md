# Fallback Chain

EverClaw provides a 4-tier fallback chain for resilient inference. If one provider fails, the system automatically falls back to the next tier.

## Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     OpenClaw Agent                           │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                Tier 1: [REDACTED] P2P                          ││                   port 8083                                   ││                                                               ││  • Staked MOR (recycles)                                     │
│  • 40+ models (GLM-5, Kimi, Qwen, Llama)                    │
│  • Direct provider connection                                │
│  • Sessions up to 24h                                        │
└────────────────────────┬────────────────────────────────────┘
                         │ Fallback on: session expired, no MOR, provider error
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                Tier 2: [REDACTED] Gateway                      │
│                  api.mor.org                                 │
│                                                               │
│  • Free API key (1,000 req/day)                             │
│  • GLM-5, GLM-4.7, Kimi K2.5                                │
│  • Rate limited                                              │
└────────────────────────┬────────────────────────────────────┘
                         │ Fallback on: rate limit(402), API error
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                Tier 3: Venice API                            │
│                  api.venice.ai                               │
│                                                               │
│  • DIEM credits                                              │
│  • Claude, Llama, Qwen                                      │
│  • Pay per use                                               │
└────────────────────────┬────────────────────────────────────┘
                         │ Fallback on: DIEM exhausted, 402 error
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                Tier 4: Ollama Local                          │
│                  port 11434                                  │
│                                                               │
│  • Qwen3.5 family (0.8B-35B)│
│  • Runs on your hardware                                     │
│  • Offline capable                                           │
└─────────────────────────────────────────────────────────────┘
```

---

## Configuration

### OpenClaw Configuration

In `~/.openclaw/openclaw.json`:

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
    },
    "venice": {
      "type": "openai-compatible",
      "baseURL": "https://api.venice.ai/api/v1",
      "apiKey": "${VENICE_API_KEY}"
    },
    "ollama": {
      "type": "openai-compatible",
      "baseURL": "http://127.0.0.1:11434/v1",
      "apiKey": "ollama"
    }
  },
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

### Provider Requirements

| Tier | Provider | Requirement |
|------|----------|-------------|
| 1 | [REDACTED] P2P | Wallet + MOR tokens |
| 2 | [REDACTED] Gateway | API key from app.mor.org |
| 3 | Venice | API key + DIEM credits |
| 4 | Ollama | Local installation |

---

## Fallback Triggers

### Tier1→ Tier 2

The proxy falls back from P2P to Gateway when:

| Trigger | Description |
|---------|-------------|
| `no_session` | No active session for model |
| `session_expired` | Session duration elapsed |
| `insufficient_mor` | Not enough MOR to stake |
| `provider_error` | Provider returned error |
| `connection_reset` | P2P connection dropped |

### Tier 2 → Tier 3

OpenClaw falls back from Gateway to Venice when:

| Trigger | HTTP Code | Description |
|---------|-----------|-------------|
| `rate_limit` | 429 | Daily request limit exceeded |
| `billing` | 402 | API key has no credits |
| `server_error` | 500+ | Gateway infrastructure error |

### Tier 3 → Tier 4

OpenClaw falls back from Venice to Ollama when:

| Trigger | HTTP Code | Description |
|---------|-----------|-------------|
| `insufficient_funds` | 402 | DIEM balance exhausted |
| `rate_limit` | 429 | Venice rate limit |
| `unavailable` | 503| Venice API down |

---

## Monitoring Fallback Status

### Check Current Tier

```bash
curl http://127.0.0.1:8083/health | jq '.fallbackMode'
```

Response:
```json
{
  "fallbackMode": false,
  "consecutiveFailures": 0,
  "lastError": null
}
```

### When in Fallback Mode

```json
{
  "fallbackMode": true,
  "fallbackReason": "No active session for glm-5",
  "consecutiveFailures": 3,
  "lastError": "session not found"
}
```

---

## Provider Health Checks

### Gateway Guardian

EverClaw includes `[REDACTED].sh` for proactive health monitoring:

```bash
bash ~/.openclaw/workspace/scripts/[REDACTED].sh --verbose
```

The guardian:
- Pings each provider directly
- Detects billing exhaustion (DIEM)
- Alerts on prolonged downtime
- Can auto-restart the [REDACTED]

### Manual Checks

```bash
# CheckP2P
curl http://127.0.0.1:8083/v1/models

# Check Gateway
curl -H "Authorization: Bearer $MOR_API_KEY" https://api.mor.org/v1/models

# Check Venice
curl -H "Authorization: Bearer $VENICE_API_KEY" https://api.venice.ai/api/v1/models

# Check Ollama
curl http://127.0.0.1:11434/api/tags
```

---

## Ollama Setup (Tier 4)

Ollama provides offline fallback with local models.

### Installation

```bash
# Automated setup (detects hardware, selects model)
node skills/everclaw/scripts/setup-ollama.sh

# Manual install
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen3.5:9b
```

### Hardware Requirements

| Model | RAM Required | Disk |
|-------|--------------|------|
| qwen3.5:0.8b | 2 GB | 1 GB |
| qwen3.5:2b | 4 GB | 2 GB |
| qwen3.5:9b | 8 GB | 6 GB |
| qwen3.5:27b | 16 GB | 17 GB |
| qwen3.5:72b | 48 GB | 43 GB |

The setup script auto-detects your hardware and selects the optimal model.

### Configuration

Ollama is automatically added to your fallback chain by `setup-ollama.sh`:

```json
{
  "providers": {
    "ollama": {
      "type": "openai-compatible",
      "baseURL": "http://127.0.0.1:11434/v1",
      "apiKey": "ollama"
    }
  }
}
```

---

## Recovery Behavior

### Automatic Recovery

When a higher-tier provider recovers, the system automatically switches back:

1. Guardian detects provider is healthy
2. Next request attempts Tier 1
3. If successful, Tier 1 becomes active
4. Fallback mode clears

### Manual Recovery

Force a specific tier:

```bash
# Restart proxy (clears fallback state)
launchctl kickstart gui/$(id -u)/com.morpheus.proxy

# Check new sessions
curl http://127.0.0.1:8083/health | jq '.activeSessions'
```

---

## Best Practices

### For Reliability

1. **Configure all4 tiers** — Every tier is a safety net
2. **Monitor actively** — Use [REDACTED]
3. **Keep Ollama updated** — Pull latest models periodically
4. **Check Venice DIEM** — Monitor credit balance

### For Cost Optimization

| Tier | Cost | When to Use |
|------|------|-------------|
| P2P | MOR stake (recycles) | Always preferred |
| Gateway | Free (1K/day) | When P2P unavailable |
| Venice | Pay per use | When Gateway exhausted |
| Ollama | Free (hardware) | Offline, emergencies |

### For Performance

1. **Use Tier 1 for primary** — Lowest latency, best privacy
2. **Warm up Ollama** — Keep it running for instant fallback
3. **Pre-open sessions** — Avoid session creation latency

---

## Troubleshooting

### "All providers in cooldown"

OpenClaw puts providers in cooldown after repeated failures. Wait or restart:

```bash
openclaw [REDACTED] restart
```

### "Ollama not responding"

```bash
# Check if Ollama is running
curl http://127.0.0.1:11434/api/tags

# Start Ollama
ollama serve
```

### "Venice 402 error"

DIEM credits exhausted. Add credits at [venice.ai](https://venice.ai) or check your API key.

---

## Next Steps

- [Inference](inference.md) — How inference works
- [Ollama Setup](ollama.md) — Detailed local fallback guide
- [Monitoring](../operations/monitoring.md) — Gateway guardian configuration