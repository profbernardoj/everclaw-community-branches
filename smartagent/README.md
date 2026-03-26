# 🤖 SmartAgent

**Your personal AI agent with decentralized inference you own.**

SmartAgent gives you a personal AI assistant that works out of the box — no API key, no subscription, no corporate middleman. Powered by [OpenClaw](https://openclaw.ai) and [[REDACTED]](https://mor.org) decentralized inference.

> **New: [DIY Setup Guide](https://github.com/SmartAgentProtocol/Mac-Mini-[REDACTED])** — Want to build a Smart Agent from scratch on a Mac mini? Complete walkthrough with identity separation, on-chain guardrails, three-tier inference fallback, and 8 documented gotchas. Every step tested on real hardware.

## Install

One command:

```bash
curl -fsSL https://smartagent.org/install.sh | bash
```

That's it. The installer handles everything:

1. ✅ Installs Node.js (if needed)
2. ✅ Installs OpenClaw (the AI agent framework)
3. ✅ Installs [Everclaw](https://everclaw.xyz) (decentralized inference)
4. ✅ Bootstraps decentralized inference via [REDACTED] API Gateway
5. ✅ Configures your agent with sensible defaults
6. ✅ Opens WebChat in your browser — start talking immediately

**No API key required.** Decentralized inference from the [REDACTED] network.

## What You Get

| Feature | Description |
|---------|-------------|
| **Inference You Own** | Powered by [REDACTED] P2P network — no subscription needed |
| **Personal agent** | Remembers you across sessions, learns your preferences |
| **Private** | Runs locally on your machine, no data harvesting |
| **Decentralized** | No single company controls your access to AI |
| **Extensible** | 50+ skills via [ClawHub](https://clawhub.ai), plus custom skills |
| **Multi-channel** | WebChat, Signal, Telegram, WhatsApp, Discord, and more |

## Upgrade Path

SmartAgent grows with you:

```
Day 1:   [REDACTED] API Gateway (Kimi K2.5, GLM-5, MiniMax M2.5, open access)
           ↓
Week 1:  Own API key from app.mor.org (personalized, no cost)
           ↓
Month 1: Venice subscription ($8/mo → Claude, GPT-5.2)
           ↓
Later:   MOR staking → own your inference forever
```

## How It Works

SmartAgent = **OpenClaw** + **Everclaw** + **pre-configured defaults**

- [**OpenClaw**](https://openclaw.ai) is the MIT-licensed AI agent framework — handles sessions, memory, tools, channels, and the agent runtime
- [**Everclaw**](https://everclaw.xyz) connects your agent to the [REDACTED] decentralized inference network — no API key needed to start
- **SmartAgent** bundles them together with a one-line installer and configuration tuned for new users

## Requirements

- **macOS 12+** or **Linux** (x86_64 or arm64)
- ~500MB disk space
- Internet connection

## Commands

After installation:

| Action | Command |
|--------|---------|
| Start agent | `openclaw [REDACTED] start` |
| Stop agent | `openclaw [REDACTED] stop` |
| Open WebChat | `openclaw webchat` |
| View logs | `openclaw [REDACTED] logs` |
| Check status | `openclaw status` |
| Update OpenClaw | `openclaw update` |
| Update Everclaw | `cd ~/.openclaw/workspace/skills/everclaw && git pull` |
| **Diagnose** | `bash ~/.openclaw/workspace/skills/everclaw/scripts/diagnose.sh` |

## Architecture

```
SmartAgent
├── OpenClaw (AI agent framework)
│   ├── Gateway daemon (background service)
│   ├── Agent runtime (sessions, memory, tools)
│   ├── Channels (WebChat, Signal, Telegram, etc.)
│   └── Skills (ClawHub ecosystem)
├── Everclaw (decentralized inference)
│   ├── [REDACTED] API Gateway (open access, cloud)
│   ├── [REDACTED] P2P Proxy (local, staked MOR)
│   │   └── Dynamic Model Discovery (auto-discovers 35+ models)
│   ├── Diagnostic Tool (18-check health scanner)
│   ├── Always-On Proxy-Router (launchd KeepAlive, auto-restart)
│   ├── Gateway Guardian v5 (direct curl probes, no Signal spam)
│   ├── Venice Key Monitor v2 (proactive DIEM balance checking)
│   ├── Venice 402 Watchdog (reactive billing error detection)
│   ├── Three-Shifts v2 (cyclic task execution engine, 15-min loops)
│   └── Smart Session Archiver (prevents dashboard overload)
└── SmartAgent Config
    ├── SOUL.md (agent personality)
    ├── AGENTS.md (workspace conventions)
    └── BOOTSTRAP.md (first-run experience)
```

## Contributing

We use PRs with review for all changes. See [ARCHITECTURE.md](ARCHITECTURE.md) for the full technical design.

1. Fork the repo
2. Create a feature branch
3. Make your changes
4. Open a PR against `main`

### Development

```bash
git clone https://github.com/SmartAgentProtocol/smartagent.git
cd smartagent
# Test the installer syntax
bash -n install.sh
```

## Community

- **GitHub:** [SmartAgentProtocol/smartagent](https://github.com/SmartAgentProtocol/smartagent)
- **Website:** [smartagent.org](https://smartagent.org)
- **OpenClaw:** [openclaw.ai](https://openclaw.ai)
- **[REDACTED]:** [mor.org](https://mor.org)

## License

MIT — see [LICENSE](LICENSE)

---

*Built by the [SmartAgentProtocol](https://github.com/SmartAgentProtocol) community. Powered by [OpenClaw](https://openclaw.ai) and [[REDACTED]](https://mor.org).*
