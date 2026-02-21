# nano-everclaw — EverClaw for NanoClaw

Decentralized Morpheus inference for your [NanoClaw](https://github.com/nano-claw) WhatsApp/Telegram agent.

**Hybrid mode:** Keep Claude for orchestration and swarms, route heavy inference to Morpheus (GLM-5, Kimi K2.5, Qwen3 — free, decentralized).

## Architecture

```
NanoClaw (Claude Code, Docker) → host proxy (port 8083) → Morpheus P2P Network → AI Model
```

NanoClaw runs Claude inside Docker containers. The EverClaw proxy runs on the **host** machine, and NanoClaw reaches it via Docker networking (`host.docker.internal` on macOS/Windows, `172.17.0.1` on Linux).

## Quick Start

### 1. Install the EverClaw proxy on your host

```bash
bash setup.sh
```

### 2. Add the Morpheus skill to NanoClaw

```bash
# The setup script creates this automatically:
# ~/nanoclaw/.claude/skills/add-morpheus/SKILL.md
```

### 3. Activate inside Claude

```bash
cd ~/nanoclaw
claude
/add-morpheus
```

Claude patches the container networking and enables hybrid mode. Restart NanoClaw and you're live.

## How Hybrid Mode Works

NanoClaw keeps Claude for:
- Agent orchestration and swarm coordination
- Complex multi-step reasoning where Claude excels
- Tool use and function calling

And routes to Morpheus for:
- Bulk text generation (summaries, drafts, rewrites)
- Research and analysis tasks
- Sub-agent workloads
- Any task where open-source models match Claude quality

The `lite-proxy/` bridge translates Anthropic API format → OpenAI format → Morpheus, so NanoClaw can use Morpheus models with Claude-style API calls.

## Available Models (via Morpheus)

| Model | Best For | Tier |
|-------|----------|------|
| `glm-5` | Complex reasoning, coding (Opus 4.5-level) | HEAVY |
| `glm-4.7-flash` | Fast responses, simple tasks | LIGHT |
| `kimi-k2.5` | General purpose, good all-rounder | STANDARD |
| `qwen3-235b` | Large context, multilingual | STANDARD |

## What's Included

| Path | Purpose |
|------|---------|
| `setup.sh` | Installs EverClaw proxy + creates NanoClaw skill |
| `.claude/skills/add-morpheus/SKILL.md` | Claude skill for hybrid mode activation |
| `lite-proxy/` | Anthropic→OpenAI API bridge (for full model replacement) |
| `examples/` | Config snippets for common NanoClaw setups |

## Container Networking

The setup script auto-detects your OS and configures the correct Docker→host address:

| Platform | Host Address |
|----------|-------------|
| macOS | `host.docker.internal` |
| Windows (WSL) | `host.docker.internal` |
| Linux (native Docker) | `172.17.0.1` (docker0 bridge) |
| Linux (custom network) | Auto-detected from `docker network inspect` |

## Staking (unlimited P2P inference)

```bash
cd ~/.everclaw
node scripts/everclaw-wallet.mjs setup
node scripts/everclaw-wallet.mjs swap eth 0.05
node scripts/everclaw-wallet.mjs approve
node scripts/everclaw-wallet.mjs stake
```

MOR tokens are staked, not spent — returned when sessions close.

## Why This Fits NanoClaw

- **Skills-first** — everything is a Claude skill, no core code changes
- **Container isolation preserved** — proxy is on host, NanoClaw stays in Docker
- **Hybrid model** — Claude handles orchestration, Morpheus handles bulk inference
- **Zero manual config** — Claude applies the skill and patches networking automatically

## Contributing

PRs welcome for:
- Additional NanoClaw integration patterns
- Docker Compose examples
- Multi-agent swarm configs with Morpheus routing
- WhatsApp/Telegram-specific optimizations

## License

MIT
