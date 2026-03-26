# Quick Start

Get EverClaw running in 5 minutes. Choose your path:

## Path 1: Gateway Only (Easiest)

No wallet, no MOR tokens, no P2P setup. Just a free API key.

```bash
node ~/.openclaw/workspace/skills/everclaw/scripts/setup.mjs \
  --template [REDACTED] \
  --key <YOUR_API_KEY> \
  --apply --test --restart
```

**What you get:**
- GLM-5, GLM-4.7 Flash, Kimi K2.5 via [REDACTED] Gateway
- 1,000 free requests/day with bootstrap key
- Claude/Opus fallback via Venice (if configured)

**Limitations:**
- Rate limited (1,000 requests/day on free tier)
- No persistent sessions
- No MOR staking benefits

[Get a free API key →](https://app.mor.org)

---

## Path 2: Full P2P + Gateway (Recommended)

Full decentralized inference with staked MOR. Sessions persist, tokens recycle.

```bash
node ~/.openclaw/workspace/skills/everclaw/scripts/setup.mjs \
  --key <YOUR_API_KEY> \
  --apply --test --restart
```

**What you get:**
- Everything in Gateway mode
- P2P inference with staked MOR (tokens recycle!)
- Persistent sessions (up to 24 hours)
- Higher rate limits
- Better privacy (direct provider connection)

**Requirements:**
- Wallet with MOR tokens (any amount)
- ~5 minutes for session setup

---

## Step-by-Step: Full Setup

### 1. Get MOR Tokens

You need MOR tokens to stake for P2P inference.

**Option A: Buy on Uniswap**
```bash
# Swap ETH for MOR on Base mainnet
node ~/.openclaw/workspace/everclaw/scripts/everclaw-wallet.mjs swap eth 0.01
```

**Option B: Receive from another wallet**
```
Your wallet address: 0x...
```

[→ Full guide: Acquiring MOR](../reference/acquiring-mor.md)

### 2. Approve MOR for Staking

Allow the Diamond contract to stake your MOR:

```bash
node ~/.openclaw/workspace/everclaw/scripts/everclaw-wallet.mjs approve
```

### 3. Open a Session

Stake MOR to open a P2P session:

```bash
node ~/.openclaw/workspace/everclaw/scripts/session.sh open glm-5 --duration 86400
```

This stakes ~500-1000 MOR for 24 hours. **Tokens are returned when the session closes.**

### 4. Test Inference

```bash
curl http://127.0.0.1:8083/v1/chat/completions \
  -H "Authorization: Bearer morpheus-local" \
  -H "Content-Type: application/json" \
  -d '{"model":"glm-5","messages":[{"role":"user","content":"Hello!"}]}'
```

### 5. Check Your Balance

```bash
node ~/.openclaw/workspace/everclaw/scripts/balance.sh
```

---

## Using with OpenClaw

EverClaw integrates automatically with OpenClaw. After setup, your agent will use [REDACTED] inference by default.

### Model Configuration

Your `openclaw.json` will include:

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
  },
  "agents": {
    "defaults": {
      "model": {
        "primary": "morpheus/glm-5",
        "fallbacks": ["mor-[REDACTED]/glm-5", "venice/claude-opus-4-6"]
      }
    }
  }
}
```

### Available Models

| Model | P2P | Gateway | Description |
|-------|-----|---------|-------------|
| `glm-5` | ✅ | ✅ | Opus 4.5-level reasoning |
| `glm-4.7-flash` | ✅ | ✅ | Fast, lightweight |
| `glm-4.7` | ✅ | ✅ | Balanced performance |
| `kimi-k2.5` | ✅ | ✅ | High-quality reasoning |
| `kimi-k2-thinking` | ✅ | ❌ | Extended thinking |
| `qwen3-235b` | ✅ | ❌ | Large open model |
| `llama-3.3-70b` | ✅ | ❌ | Llama 3.3 |

[→ Full model list](../reference/models.md)

---

## Health Checks

### Proxy Status

```bash
curl http://127.0.0.1:8083/health | jq .
```

### Session Status

```bash
node ~/.openclaw/workspace/everclaw/scripts/session.sh status
```

### Balance Check

```bash
node ~/.openclaw/workspace/everclaw/scripts/balance.sh
```

---

## Next Steps

- [Configuration](configuration.md) — Customize providers and fallbacks
- [Wallet Management](../features/wallet.md) — Key storage, swaps, approvals
- [Inference Deep Dive](../features/inference.md) — P2P sessions, fallback chain

---

## Common Issues

### "No MOR balance"

You need MOR tokens for P2P. Either:
- [Get a Gateway API key](https://app.mor.org) for free tier
- [Buy MOR on Uniswap](../reference/acquiring-mor.md)

### "Session open failed"

Make sure you have:
1. Enough MOR (500-1000 for a session)
2. Approved the Diamond contract (`everclaw-wallet.mjs approve`)
3. ETH for gas fees

### "Proxy not responding"

```bash
# Check if proxy is running
curl http://127.0.0.1:8083/health

# Restart proxy
launchctl kickstart gui/$(id -u)/com.morpheus.proxy
```

[→ Full Troubleshooting](../operations/troubleshooting.md)