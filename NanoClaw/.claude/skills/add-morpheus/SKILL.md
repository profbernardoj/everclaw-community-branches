# Add Morpheus — Decentralized Inference for NanoClaw

## What This Does

Connects NanoClaw to the EverClaw proxy for decentralized AI inference via the Morpheus network.
The proxy runs on the host machine and is reachable from Docker containers.

## When To Use

Use `/add-morpheus` to:
- Enable hybrid mode (Claude orchestration + Morpheus inference)
- Check proxy health
- Switch default inference model

## Setup

The EverClaw proxy must be running on the host (installed via `setup.sh`).

### Environment Variables

Add to the NanoClaw container environment:

```env
MORPHEUS_API_BASE=http://host.docker.internal:8083/v1
MORPHEUS_API_KEY=morpheus-local
MORPHEUS_DEFAULT_MODEL=glm-5
```

On Linux (native Docker), replace `host.docker.internal` with `172.17.0.1`.

### Docker Compose

If NanoClaw uses Docker Compose, add `extra_hosts` to ensure the alias resolves:

```yaml
services:
  nanoclaw:
    extra_hosts:
      - "host.docker.internal:host-gateway"
    environment:
      - MORPHEUS_API_BASE=http://host.docker.internal:8083/v1
      - MORPHEUS_API_KEY=morpheus-local
```

## Available Models

| Model | Use Case |
|-------|----------|
| `glm-5` | Complex reasoning, coding, analysis (Opus 4.5-level) |
| `glm-4.7-flash` | Fast responses, lightweight tasks |
| `kimi-k2.5` | General purpose |
| `qwen3-235b` | Large context, multilingual |

## Health Check

From inside the container:
```bash
curl -sf http://host.docker.internal:8083/health
```

From the host:
```bash
curl -sf http://127.0.0.1:8083/health
```

## Hybrid Routing Strategy

- **Use Claude for:** orchestration, swarm coordination, complex multi-step tool use
- **Use Morpheus for:** text generation, summarization, research, sub-agent tasks
- Model selection is by name — pass `glm-5` or `glm-4.7-flash` as the model parameter

## Staking for Unlimited Inference

```bash
cd ~/.everclaw
node scripts/everclaw-wallet.mjs setup
node scripts/everclaw-wallet.mjs stake
```

MOR tokens are staked, not spent — returned when sessions close. Stake once, use forever.
