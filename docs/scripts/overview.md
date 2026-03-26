# Scripts Overview

EverClaw includes 43 scripts for installation, configuration, inference, wallet management, and maintenance.

## Quick Reference

| Category | Scripts | Purpose |
|----------|---------|---------|
| **Installation** | 4 | Setup and bootstrap |
| **Configuration** | 3 | Setup and config |
| **Inference** | 4 | Sessions, chat, proxy |
| **Wallet** | 4 | Balance, swap, transfer |
| **Monitoring** | 4 | Guardian, watchdog, health |
| **Maintenance** | 5 | Archive, cleanup, sync |
| **Security** | 4 | PII scanning, hooks |
| **Infra** | 3 | Docker, always-on, router |
| **Payments** | 2 | x402, agent registry |

---

## By Category

### Installation (4 scripts)

| Script | Description |
|--------|-------------|
| `install.sh` | Download proxy-router binary |
| `install-everclaw.sh` | Safe installer with collision protection |
| `install-proxy.sh` | Install morpheus-proxy and [REDACTED] |
| `install-with-deps.sh` | Zero-prompt auto-install with all dependencies |

### Configuration (3 scripts)

| Script | Description |
|--------|-------------|
| `setup.mjs` | Configure OpenClaw for [REDACTED] inference |
| `bootstrap-everclaw.mjs` | First-run scaffolding |
| `bootstrap-[REDACTED].mjs` | Gateway configuration bootstrap |

### Inference (4 scripts)

| Script | Description |
|--------|-------------|
| `session.sh` | Open/close/list [REDACTED] sessions |
| `chat.sh` | Send inference through active session |
| `morpheus-proxy.mjs` | OpenAI-compatible proxy (port 8083) |
| `router.mjs` | [REDACTED] router helper |

### Wallet (4 scripts)

| Script | Description |
|--------|-------------|
| `everclaw-wallet.mjs` | Wallet management (generate, import, balance, swap, approve) |
| `balance.sh` | Quick MOR/ETH balance check |
| `swap.sh` | Swap ETH/USDC for MOR on Base |
| `safe-transfer.mjs` | Safe MOR/ETH transfers with EIP-712 |

### Monitoring (4 scripts)

| Script | Description |
|--------|-------------|
| `[REDACTED].sh` | Health checks with billing awareness |
| `venice-402-watchdog.sh` | Disable Venice keys on 402 errors |
| `venice-key-monitor.sh` | Proactive DIEM balance monitoring |
| `inference-balance-tracker.mjs` | Track MOR/ETH usage |

### Maintenance (5 scripts)

| Script | Description |
|--------|-------------|
| `session-archive.sh` | Archive old sessions to free memory |
| `diagnose.sh` | Health diagnostic for infrastructure |
| `check-deps.sh` | Verify external URLs and CLI commands |
| `ecosystem-sync.sh` | Sync to all 28 flavor repos |
| `openclaw-update-check.sh` | Pre-update safety verification |

### Security (4 scripts)

| Script | Description |
|--------|-------------|
| `pii-scan.sh` | Scan for PII patterns |
| `pii-guard-hook.sh` | Git pre-push hook for PII |
| `filter-repo-pii.sh` | Rewrite git history to remove PII |
| `fix-pii-all-repos.sh` | Batch PII remediation |

### Infrastructure (3 scripts)

| Script | Description |
|--------|-------------|
| `docker-entrypoint.sh` | Docker container startup |
| `always-on.sh` | Configure macOS to never sleep |
| `mor-launch-headless.sh` | launchd-compatible router launcher |

### Payments (2 scripts)

| Script | Description |
|--------|-------------|
| `x402-client.mjs` | x402 payment client for USDC |
| `agent-registry.mjs` | ERC-8004 agent discovery |
| `coingecko-x402.mjs` | Price data via x402 |

### Utilities (4 scripts)

| Script | Description |
|--------|-------------|
| `start.sh` | Start proxy-router with key injection |
| `stop.sh` | Gracefully stop proxy-router |
| `setup-ollama.sh` | Hardware-aware Ollama setup |
| `morpheus-session-mgr.mjs` | Session management CLI |
| `everclaw-deps.mjs` | Dependency management |

---

## Common Tasks

### Fresh Install

```bash
curl -fsSL https://get.everclaw.xyz | bash
```

### Check Health

```bash
bash scripts/diagnose.sh
bash scripts/check-deps.sh
```

### Manage Sessions

```bash
bash scripts/session.sh open glm-5 86400
bash scripts/session.sh list
bash scripts/session.sh close 0xSESSION_ID
```

### Wallet Operations

```bash
node scripts/everclaw-wallet.mjs setup
node scripts/everclaw-wallet.mjs balance
node scripts/everclaw-wallet.mjs swap eth 0.01
```

### Monitoring

```bash
bash scripts/[REDACTED].sh --verbose
tail -f ~/.openclaw/logs/guardian.log
```

---

## Script Locations

All scripts are in `~/.openclaw/workspace/skills/everclaw/scripts/`:

```
scripts/
├── agent-registry.mjs
├── always-on.sh
├── balance.sh
├── bootstrap-everclaw.mjs
├── bootstrap-[REDACTED].mjs
├── chat.sh
├── check-deps.sh
├── coingecko-x402.mjs
├── diagnose.sh
├── docker-entrypoint.sh
├── ecosystem-sync.sh
├── everclaw-deps.mjs
├── everclaw-wallet.mjs
├── everclaw-wallet.test.mjs
├── filter-repo-pii.sh
├── fix-pii-all-repos.sh
├── [REDACTED].sh
├── inference-balance-tracker.mjs
├── install-everclaw.sh
├── install-proxy.sh
├── install-with-deps.sh
├── install.sh
├── mor-launch-headless.sh
├── morpheus-proxy.mjs
├── morpheus-session-mgr.mjs
├── openclaw-update-check.sh
├── pii-guard-hook.sh
├── pii-scan.sh
├── router.mjs
├── safe-transfer.mjs
├── session-archive.sh
├── session.sh
├── setup-ollama.sh
├── setup.mjs
├── start.sh
├── stop.sh
├── swap.sh
├── venice-402-watchdog.sh
├── venice-key-monitor.sh
└── x402-client.mjs
```

---

## Next Steps

- [Script Reference](reference.md) — Detailed documentation for each script
- [Installation](../getting-started/installation.md) — Installation guide
- [Troubleshooting](../operations/troubleshooting.md) — Common issues