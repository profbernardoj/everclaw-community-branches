# pico-everclaw — EverClaw for PicoClaw

Decentralized Morpheus inference for your [PicoClaw](https://github.com/pico-claw) edge device agent.

**Designed for tiny hardware:** PicoClaw runs on $10 RISC-V boards, Raspberry Pi, Termux, and Docker. The EverClaw proxy runs as a separate Node.js sidecar and provides OpenAI-compatible inference to PicoClaw via standard HTTP.

## Architecture

```
PicoClaw (<10 MB RAM) → EverClaw Proxy (Node.js, port 8083) → Morpheus P2P → AI Model
```

> **Note:** The Node.js proxy needs ~80 MB RAM. On extremely constrained devices ($10 RISC-V), you may want to run the proxy on a separate host (e.g., Raspberry Pi 4 or any server) and point PicoClaw at it over the network.

## Quick Start

### 1. Install (on the proxy host)

```bash
bash setup.sh
```

### 2. Configure PicoClaw

The setup script merges Morpheus models into your `~/.picoclaw/config.json`. If PicoClaw runs on a different device, set the proxy host:

```bash
# Same device
PROXY_HOST=127.0.0.1

# Separate device (e.g., proxy on a Pi 4, PicoClaw on a $10 board)
PROXY_HOST=192.168.1.100
```

### 3. Verify

```bash
curl http://${PROXY_HOST:-127.0.0.1}:8083/health
picoclaw agent -m "Hello from Morpheus"
```

## Available Models

| Model | Best For | Tier |
|-------|----------|------|
| `glm-5` | Complex reasoning, coding (default) | HEAVY |
| `glm-4.7-flash` | Fast responses, simple tasks | LIGHT |
| `kimi-k2.5` | General purpose | STANDARD |
| `qwen3-235b` | Large context, multilingual | STANDARD |

## What's Included

| Path | Purpose |
|------|---------|
| `setup.sh` | Installs proxy, merges config, starts services |
| `config.patch.json` | Model entries to merge into PicoClaw config |
| `workspace/skills/enable-morpheus/` | PicoClaw skill for runtime control |
| `examples/` | Config snippets for various deployment scenarios |

## Deployment Scenarios

### Same Device (Pi 4+, decent Linux box)
Both PicoClaw and the proxy run locally. Default config works.

### Split Deployment (tiny board + proxy host)
PicoClaw on the $10 board, proxy on a more capable device:
1. Install proxy on the capable device
2. Change `api_base` in PicoClaw's config to point to the proxy host IP
3. Ensure port 8083 is accessible on the local network

### Docker
```bash
# PicoClaw in Docker, proxy on host
picoclaw start --env MORPHEUS_API_BASE=http://host.docker.internal:8083/v1
```

## Staking (unlimited P2P inference)

```bash
cd ~/.everclaw
node scripts/everclaw-wallet.mjs setup
node scripts/everclaw-wallet.mjs swap eth 0.05
node scripts/everclaw-wallet.mjs approve
node scripts/everclaw-wallet.mjs stake
```

## Contributing

PRs welcome for:
- Lightweight proxy alternatives (e.g., Rust/Go proxy for constrained devices)
- Termux-specific setup instructions
- RISC-V testing and benchmarks
- ARM32 compatibility patches

## Included with EverClaw v2026.2.21

When you install the EverClaw proxy via `setup.sh`, you get these features automatically:

- **Three-Shift Task Planning** — Morning/Afternoon/Night shift system proposes prioritized task plans with approval workflow. Nothing executes without your say-so.
- **Gateway Guardian v5** — Self-healing watchdog with direct curl inference probes, billing-aware escalation, DIEM credit monitoring, and 4-stage restart escalation. No more Signal spam from failed health checks.
- **Smart Session Archiver** — Automatically archives old sessions when size exceeds threshold, preventing browser slowdowns.
- **Model Router** — Open-source first: routes all tiers to Morpheus by default (GLM-5, GLM-4.7-flash). Claude only kicks in as a fallback.
- **Multi-Key Auth Rotation** — Configure multiple API keys; auto-rotates when credits drain.

See the main [EverClaw README](../README.md) for full documentation.

## License

MIT
