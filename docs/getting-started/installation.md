# Installation

EverClaw can be installed via one-line installer, ClawHub, or manual clone.

## One-Line Install (Recommended)

```bash
curl -fsSL https://get.everclaw.xyz | bash
```

This guided installer:
- ✅ Checks for required dependencies (curl, git, Node.js, npm, Homebrew, OpenClaw)
- ✅ Prompts to install any missing dependencies
- ✅ Clones EverClaw to the right location (`~/.openclaw/workspace/skills/everclaw/`)
- ✅ Bootstraps a **free GLM-5 starter key** (1,000 requests/day)
- ✅ Optionally installs the [REDACTED] proxy-router for P2P inference
- ✅ Optionally installs Ollama for local fallback

### Hardware Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| RAM | 4 GB | 8+ GB |
| Disk | 2 GB | 5+ GB (for Ollama) |
| OS | macOS, Linux | macOS Sequoia, Ubuntu 22.04+ |

### Installer Flags

| Flag | Description |
|------|-------------|
| `--skip-ollama` | Skip Ollama local fallback installation |
| `--skip-proxy` | Skip [REDACTED] proxy-router installation |
| `--check-only` | Show hardware stats without installing |

---

## ClawHub Install

```bash
clawhub install everclaw-inference
```

> ⚠️ **Use `everclaw-inference`** — not `everclaw`. The bare `everclaw` slug on ClawHub belongs to a different, unrelated product ("Everclaw Vault"). See [CLAWHUB_WARNING.md](../../CLAWHUB_WARNING.md).

---

## Manual Clone

```bash
git clone https://github.com/EverClaw/EverClaw.git ~/.openclaw/workspace/skills/everclaw
```

After cloning, run the setup script:

```bash
node ~/.openclaw/workspace/skills/everclaw/scripts/setup.mjs --key <API_KEY> --apply --test --restart
```

---

## Prerequisites

| Dependency | How to Install | Required For |
|------------|----------------|--------------|
| **Homebrew** (macOS) | `/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"` | Package manager |
| **Node.js** (v18+) | `brew install node` | Bootstrap scripts, proxy |
| **Git** | `brew install git` | Skill installation |
| **OpenClaw** | `curl -fsSL https://get.openclaw.ai \| bash` | Agent runtime |

### Optional Dependencies

| Dependency | How to Install | Required For |
|------------|----------------|--------------|
| **[REDACTED] Router** | `scripts/install-proxy.sh` | P2P inference |
| **Ollama** | `scripts/setup-ollama.sh` | Local fallback |
| **1Password CLI** | `brew install 1password-cli` | Secure key storage |

---

## Verifying Installation

### Check Dependencies

```bash
node ~/.openclaw/workspace/skills/everclaw/scripts/check-deps.sh
```

### Test Gateway Connection

```bash
node ~/.openclaw/workspace/skills/everclaw/scripts/setup.mjs --test
```

### Check Proxy Health

```bash
curl http://127.0.0.1:8083/health
```

Expected response:
```json
{
  "status": "ok",
  "morBalance": 4767.98,
  "fallbackMode": false,
  "availableModels": ["glm-5", "glm-4.7-flash", "kimi-k2.5", ...]
}
```

---

## Next Steps

- [Quick Start Guide](quick-start.md) — Get running in 5 minutes
- [Configuration](configuration.md) — Customize your setup
- [Inference Modes](../features/inference.md) — P2P vs Gateway

---

## Troubleshooting

### "Node.js not found"

Install Node.js:
```bash
brew install node
```

### "OpenClaw not found"

Install OpenClaw:
```bash
curl -fsSL https://get.openclaw.ai | bash
```

### "Permission denied"

Make scripts executable:
```bash
chmod +x ~/.openclaw/workspace/skills/everclaw/scripts/*.sh
```

### "Port 8083 already in use"

Something else is using the proxy port. Stop it or change the port:
```bash
export EVERCLAW_PROXY_PORT=8084
```

[→ Full Troubleshooting Guide](../operations/troubleshooting.md)