# Fix: Alex's Morpheus Inference Setup

## Problem Diagnosis

Alex's agent shows `model: everclaw/kimi-k2.5:web` — but **there is no provider called `everclaw` in OpenClaw**. Everclaw is a *skill* (tooling), not a provider. OpenClaw routes model requests by provider name (`provider/model`), so:

- `venice/kimi-k2-5` → routes to Venice API (needs DIEM credits)
- `morpheus/kimi-k2.5` → routes to local Morpheus proxy-router (needs MOR staked)
- `mor-gateway/kimi-k2.5` → routes to Morpheus API Gateway at api.mor.org (free beta)
- `everclaw/kimi-k2.5:web` → **no matching provider** → falls through to default (Venice) → billing error

## Root Cause Chain

1. Alex installed Everclaw and staked 2 MOR to open a Morpheus session ✅
2. But his OpenClaw config has the model as `everclaw/kimi-k2.5:web` ❌
3. OpenClaw doesn't recognize `everclaw` as a provider → routes to Venice
4. Venice has no DIEM credits → billing error
5. MOR is staked on-chain but never used because requests never reach the proxy-router

## Immediate Fix (Morpheus API Gateway — easiest)

Alex already has an API key (`sk-cAMdd6...`). The fastest fix is to use the hosted Morpheus API Gateway, which requires no local infrastructure:

### Step 1: Add `mor-gateway` provider to openclaw.json

```json
{
  "models": {
    "mode": "merge",
    "providers": {
      "mor-gateway": {
        "baseUrl": "https://api.mor.org/api/v1",
        "apiKey": "sk-cAMdd6.fb74c58ab9ea8089317fc43213bea8d531aebd37531bfc665d36a864e057a776",
        "api": "openai-completions",
        "models": [
          {
            "id": "kimi-k2.5",
            "name": "Kimi K2.5 (Morpheus Gateway)",
            "reasoning": false,
            "input": ["text"],
            "cost": { "input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0 },
            "contextWindow": 131072,
            "maxTokens": 8192
          },
          {
            "id": "kimi-k2.5:web",
            "name": "Kimi K2.5 Web (Morpheus Gateway)",
            "reasoning": false,
            "input": ["text"],
            "cost": { "input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0 },
            "contextWindow": 131072,
            "maxTokens": 8192
          },
          {
            "id": "glm-4.7-flash",
            "name": "GLM 4.7 Flash (Morpheus Gateway)",
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

### Step 2: Change the model

```json
{
  "agents": {
    "defaults": {
      "model": {
        "primary": "mor-gateway/kimi-k2.5"
      }
    }
  }
}
```

### Step 3: Restart OpenClaw

```bash
openclaw gateway restart
```

That's it — his agent should now route through Morpheus directly, bypassing Venice entirely. The staked MOR handles the inference cost on-chain.

## Better Fix (Local Proxy-Router — for power users)

If Alex wants maximum reliability and is running the full Morpheus Lumerin Node:

### Add `morpheus` provider

```json
{
  "models": {
    "mode": "merge",
    "providers": {
      "morpheus": {
        "baseUrl": "http://127.0.0.1:8083/v1",
        "apiKey": "morpheus-local",
        "api": "openai-completions",
        "models": [
          {
            "id": "kimi-k2.5",
            "name": "Kimi K2.5 (Morpheus P2P)",
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

### Set model

```json
{
  "agents": {
    "defaults": {
      "model": {
        "primary": "morpheus/kimi-k2.5"
      }
    }
  }
}
```

## What Everclaw v0.9.5 Should Fix

1. **The install script should auto-configure the provider correctly** — `morpheus` or `mor-gateway`, NOT `everclaw`
2. **SKILL.md should explicitly warn** that `everclaw/` is not a valid provider prefix
3. **The bootstrap script should validate** the model name format before writing config
4. **Add a diagnostic command** (`bash scripts/diagnose.sh`) that checks:
   - Is the provider name correct in openclaw.json?
   - Is the proxy-router running?
   - Are there active blockchain sessions?
   - Can we reach the model endpoint?

## Alex's MOR Status

- Wallet: `0xBDC1526a7B36CD93dc6D47716a2ad3d0f3696395`
- Staked: 2 MOR (auto-transaction on chat start)
- This is correct — MOR is staked on-chain, sessions should be open
- The staking works fine; the problem is purely the OpenClaw provider routing
