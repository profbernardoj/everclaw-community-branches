# nanobot-everclaw — EverClaw for Nanobot

Decentralized Morpheus inference for your [Nanobot](https://github.com/nanobot-ai) MCP agents.

**Drop-in replacement:** Nanobot's Go OpenAI client respects `OPENAI_BASE_URL` and `OPENAI_API_KEY`. Point them at the EverClaw proxy and your MCP agents instantly run on decentralized inference.

## Architecture

```
Nanobot (Go + Svelte) → EverClaw Proxy (Node.js, port 8083) → Morpheus P2P → AI Model
```

The EverClaw proxy is a standalone Node.js sidecar — completely independent of Nanobot's Go binary. Nanobot talks to it via standard OpenAI-compatible HTTP API. All MCP servers, multi-agent configs, and the Svelte UI stay untouched.

## Quick Start

### 1. Install

```bash
bash setup.sh
```

### 2. Run with Morpheus

```bash
# Using the example config
OPENAI_API_KEY=morpheus-local \
OPENAI_BASE_URL=http://127.0.0.1:8083/v1 \
nanobot run ~/nanobot-morpheus.yaml
```

Or use the alias the setup script creates:

```bash
nanobot-morpheus
```

### 3. Open the UI

Navigate to `http://localhost:8080` — chat with your GLM-5-powered MCP agent.

## Available Models

| Model | Best For | Tier |
|-------|----------|------|
| `glm-5` | Complex reasoning, coding (Opus 4.5-level) | HEAVY |
| `glm-4.7-flash` | Fast responses, simple tasks | LIGHT |
| `kimi-k2.5` | General purpose | STANDARD |
| `qwen3-235b` | Large context, multilingual | STANDARD |

## What's Included

| Path | Purpose |
|------|---------|
| `setup.sh` | Installs EverClaw proxy, creates config, adds shell alias |
| `nanobot-morpheus.yaml` | Single-file Nanobot config with GLM-5 default |
| `examples/` | Multi-agent configs, directory-style layouts |
| `mcp-server/` | Optional MCP server for Morpheus status/control |

## Staking (unlimited P2P inference)

```bash
cd ~/.everclaw
node scripts/everclaw-wallet.mjs setup
node scripts/everclaw-wallet.mjs swap eth 0.05
node scripts/everclaw-wallet.mjs approve
node scripts/everclaw-wallet.mjs stake
```

MOR tokens are staked, not spent — returned when sessions close.

## Why This Fits Nanobot

- **Zero code changes** — uses standard `OPENAI_BASE_URL` env var (Go OpenAI client)
- **MCP stays intact** — all MCP servers, tools, and multi-agent configs work as-is
- **Ultra-lightweight** — proxy is a separate process, Nanobot's Go binary + Svelte UI untouched
- **Model passthrough** — model names in YAML frontmatter route directly through the proxy
- **Docker compatible** — works in Docker with `host.docker.internal`

## Contributing

PRs welcome for:
- MCP server implementation (Morpheus status, wallet, staking)
- Additional Nanobot agent configs
- Docker Compose examples
- Multi-agent team configurations with model routing

## License

MIT
