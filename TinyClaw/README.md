# tiny-everclaw — EverClaw for TinyClaw

Decentralized Morpheus inference for your [TinyClaw](https://github.com/tiny-claw) multi-agent teams.

**Drop-in integration:** TinyClaw uses Node.js CLI wrappers that respect `OPENAI_BASE_URL`. Set the env var and your entire multi-agent team runs on decentralized inference.

## Architecture

```
TinyClaw (Node.js + tmux) → EverClaw Proxy (port 8083) → Morpheus P2P → AI Model
```

TinyClaw's <100 MB footprint, file-based queue, tmux 24/7 daemon, Discord/WhatsApp/Telegram channels, and live TUI visualizer stay 100% untouched.

## Quick Start

### 1. Install

```bash
bash setup.sh
```

### 2. Restart TinyClaw

```bash
tinyclaw start    # or tinyclaw restart
```

That's it. The setup script patches your settings and exports the env vars.

## Available Models

| Model | Best For | Suggested Role |
|-------|----------|----------------|
| `glm-5` | Complex reasoning, coding | `coder`, `reviewer` |
| `glm-4.7-flash` | Fast responses | `assistant`, `triage` |
| `kimi-k2.5` | General writing | `writer`, `researcher` |
| `qwen3-235b` | Large context | `analyst` |

## Multi-Team Model Routing

Different agents can use different models. Example `settings.json` snippet:

```json
{
  "agents": {
    "coder": { "provider": "openai", "model": "glm-5" },
    "writer": { "provider": "openai", "model": "kimi-k2.5" },
    "reviewer": { "provider": "openai", "model": "glm-4.7-flash" }
  },
  "default_provider": "openai",
  "default_model": "glm-5"
}
```

## What's Included

| Path | Purpose |
|------|---------|
| `setup.sh` | Installs proxy, patches settings.json, exports env vars |
| `settings.patch.json` | Exact JSON snippet merged into TinyClaw config |
| `workspace/skills/enable-morpheus/` | TinyClaw skill for runtime control |
| `examples/` | Team configs with model routing |

## Staking (unlimited P2P inference)

```bash
cd ~/.everclaw
node scripts/everclaw-wallet.mjs setup
node scripts/everclaw-wallet.mjs swap eth 0.05
node scripts/everclaw-wallet.mjs approve
node scripts/everclaw-wallet.mjs stake
```

## Why This Fits TinyClaw

- **Env var integration** — `OPENAI_BASE_URL` is all it takes
- **Per-agent models** — route different team members to different Morpheus models
- **tmux compatible** — proxy runs as a separate service, tmux daemon untouched
- **File queue intact** — no changes to TinyClaw's file-based IPC
- **All channels work** — Discord, WhatsApp, Telegram, live TUI — all untouched

## Contributing

PRs welcome for:
- Additional team configurations
- TinyClaw skill improvements
- Channel-specific optimizations
- Performance benchmarks vs API providers

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
