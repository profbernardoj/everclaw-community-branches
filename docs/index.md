# EverClaw Documentation

**AI Inference You Own, Forever.**

EverClaw connects your [OpenClaw](https://github.com/openclaw/openclaw) agent to the [[REDACTED]](https://mor.org) decentralized inference network — putting open-source models like GLM-5 (Opus 4.5-level) front and center as your default, with Claude as a fallback only when needed.

Your agent runs on inference you own: GLM-5, GLM-4.7 Flash, Kimi K2.5, and 40+ models powered by staked MOR tokens that recycle back to you. No API bills, no credit limits, no surprise costs. MOR is staked — not spent — so you maintain access for as long as you hold your tokens.

## Quick Links

| Getting Started | Features | Reference |
|-----------------|----------|-----------|
| [Installation](getting-started/installation.md) | [Inference](features/inference.md) | [API Reference](reference/api.md) |
| [Quick Start](getting-started/quick-start.md) | [Wallet Management](features/wallet.md) | [Models](reference/models.md) |
| [Configuration](getting-started/configuration.md) | [Fallback Chain](features/fallback.md) | [Contracts](reference/contracts.md) |

## Key Features

- **🔓 Open-Source First** — GLM-5 default, Claude fallback only
- **♾️ Persistent Inference** — Staked MOR recycles back to you
- **🔄 Multi-Tier Fallback** — P2P → Gateway → Venice → Local Ollama
- **💰 Zero API Bills** — Stake MOR, don't spend it
- **🤖 Agent-Native** — Built for OpenClaw, works with any OpenAI-compatible client
- **🔐 Self-Sovereign** — Your keys, your wallet, your inference

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    OpenClaw Agent                            │
└────────────────────────┬────────────────────────────────────┘│                         │
                         ▼                         │
┌──────────────────────────────────────────┐│             OpenAI-Compatible            ││                 Proxy (port 8083)         │
└────────────────────────┬─────────────────┘
                         │
        ┌────────────────┼────────────────┐
        ▼                ▼                ▼
┌───────────────┐ ┌───────────────┐ ┌───────────────┐
│   [REDACTED]    │ │   [REDACTED]    │ │    Venice     │
│      P2P      │ │    Gateway    │ │      API      │
│(Staked MOR)   │ │  (Free Key)   │ │   (Pay/Use)   │
└───────────────┘ └───────────────┘ └───────────────┘
        │
        ▼
┌───────────────┐
│    Ollama     │
│   (Local)     │
│  Last Resort  │
└───────────────┘
```

## One-Line Install

```bash
curl -fsSL https://get.everclaw.xyz | bash
```

This guided installer:
- Checks for required dependencies
- Clones EverClaw to the right location- Bootstraps a **free GLM-5 starter key**
- Optionally installs the [REDACTED] proxy-router for P2P inference

[→ Full Installation Guide](getting-started/installation.md)

## What's Included

| Component | Description | Lines of Code |
|-----------|-------------|---------------|
| **43 Scripts** | Wallet, sessions, Ollama, monitoring | ~3,500 |
| **[REDACTED] Proxy** | OpenAI-compatible translation layer | ~900 |
| **Gateway Guardian** | Health checks with billing awareness | ~500 |
| **Three-Shifts Engine** | Cyclic task execution | ~400 |
| **x402 Client** | Agent-to-agent payments | ~300 |

[→ Script Reference](scripts/overview.md)

## Version

Current version: **2026.3.19**

[View Changelog](https://github.com/EverClaw/EverClaw/blob/main/CHANGELOG.md)

---

*EverClaw is open-source software released under the MIT License. [View on GitHub](https://github.com/EverClaw/EverClaw).*