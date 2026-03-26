# Script Reference

Detailed documentation for all 43 EverClaw scripts.

---

## Installation Scripts

### install.sh

Download and install the [REDACTED] proxy-router binary.

```bash
bash scripts/install.sh
```

**What it does:**
1. Detects OS and architecture
2. Downloads latest proxy-router release
3. Extracts to `~/morpheus/`
4. Creates initial config files

**Requirements:** curl, tar

---

### install-everclaw.sh

Safe installer with ClawHub collision protection.

```bash
# Fresh install
curl -fsSL https://raw.githubusercontent.com/EverClaw/EverClaw/main/scripts/install-everclaw.sh | bash

# Check for updates
bash scripts/install-everclaw.sh --check
```

**Handles:**
- Fresh git clone
- Existing installation updates
- ClawHub collision detection

---

### install-proxy.sh

Install the OpenAI-compatible proxy and Gateway Guardian.

```bash
bash scripts/install-proxy.sh
```

**Installs:**
- `morpheus-proxy.mjs` → `~/morpheus/proxy/`
- `[REDACTED].sh` → `~/.openclaw/workspace/scripts/`
- launchd plists for both (macOS)

---

### install-with-deps.sh

Zero-prompt auto-install with all dependencies.

```bash
curl -fsSL https://get.everclaw.xyz | bash
```

**Flags:**
| Flag | Description |
|------|-------------|
| `--skip-ollama` | Skip Ollama installation |
| `--skip-proxy` | Skip proxy-router installation |
| `--check-only` | Show hardware stats only |

**Installs:**
- Homebrew (if needed)
- Node.js (if needed)
- OpenClaw (if needed)
- EverClaw skill
- [REDACTED] proxy-router (if ≥2 GB disk)
- Ollama (if ≥5 GB disk + ≥2 GB RAM)
- Bootstrap key

---

## Configuration Scripts

### setup.mjs

Configure OpenClaw for [REDACTED] inference.

```bash
# Gateway only
node scripts/setup.mjs --template [REDACTED] --key YOUR_KEY --apply --test --restart

# Full P2P + Gateway
node scripts/setup.mjs --key YOUR_KEY --apply --test --restart

# Dry run
node scripts/setup.mjs --key YOUR_KEY
```

**Flags:**
| Flag | Description |
|------|-------------|
| `--template <name>` | `mac`, `linux`, `[REDACTED]` |
| `--key <key>` | [REDACTED] API Gateway key |
| `--apply` | Write changes (default: dry-run) |
| `--test` | Test connectivity after setup |
| `--restart` | Restart OpenClaw [REDACTED] |
| `--with-ollama` | Also install Ollama |

---

### bootstrap-everclaw.mjs

First-run scaffolding for EverClaw.

```bash
node scripts/bootstrap-everclaw.mjs
```

Creates:
- Default config templates
- Directory structure
- Bootstrap API key

---

### bootstrap-[REDACTED].mjs

Gateway configuration bootstrap.

```bash
node scripts/bootstrap-[REDACTED].mjs
```

---

## Inference Scripts

### session.sh

Manage [REDACTED] P2P sessions.

```bash
# Open a 24-hour session
bash scripts/session.sh open glm-5 86400

# List active sessions
bash scripts/session.sh list

# Close a session
bash scripts/session.sh close 0xSESSION_ID

# Check session status
bash scripts/session.sh status
```

**Commands:**
| Command | Description |
|---------|-------------|
| `open <model> [duration]` | Open a new session (default: 24h) |
| `close <session_id>` | Close and reclaim MOR |
| `list` | List all active sessions |
| `status` | Show proxy health + sessions |

---

### chat.sh

Send inference through an active session.

```bash
bash scripts/chat.sh glm-5 "What is the meaning of life?"
bash scripts/chat.sh kimi-k2.5 "Write a poem" --stream
```

**Flags:**
| Flag | Description |
|------|-------------|
| `--stream` | Enable streaming output |

---

### morpheus-proxy.mjs

OpenAI-compatible proxy server (port 8083).

```bash
# Start (usually via launchd)
node scripts/morpheus-proxy.mjs

# With custom port
MORPHEUS_PROXY_PORT=8084 node scripts/morpheus-proxy.mjs
```

**Environment:**
| Variable | Default | Description |
|----------|---------|-------------|
| `MORPHEUS_PROXY_PORT` | 8083 | Listen port |
| `MORPHEUS_ROUTER_URL` | http://127.0.0.1:8082 | Router URL |
| `MORPHEUS_SESSION_DURATION` | 604800 | Session duration (7 days) |
| `PROXY_API_KEY` | (required) | Auth key |

**Endpoints:**
- `GET /health` — Health check
- `GET /v1/models` — List models
- `POST /v1/chat/completions` — Inference

---

## Wallet Scripts

### everclaw-wallet.mjs

Complete wallet management.

```bash
# Generate new wallet
node scripts/everclaw-wallet.mjs setup

# Import existing
node scripts/everclaw-wallet.mjs import-key 0xYOUR_KEY

# Show address
node scripts/everclaw-wallet.mjs address

# Check balances
node scripts/everclaw-wallet.mjs balance

# Swap ETH for MOR
node scripts/everclaw-wallet.mjs swap eth 0.01

# Swap USDC for MOR
node scripts/everclaw-wallet.mjs swap usdc 50

# Approve MOR for staking
node scripts/everclaw-wallet.mjs approve 10000

# Export key (caution!)
node scripts/everclaw-wallet.mjs export-key
```

**Security:** Keys stored in macOS Keychain, injected at runtime.

---

### balance.sh

Quick balance check.

```bash
bash scripts/balance.sh
```

Output:
```
ETH:   0.0123
MOR:   5234.56
USDC:  150.00
Sessions: 2 active (1024 MOR staked)
```

---

### swap.sh

Swap ETH/USDC for MOR on Base via Uniswap V3.

```bash
# Swap 0.01 ETH for MOR
bash scripts/swap.sh eth 0.01

# Swap 50 USDC for MOR
bash scripts/swap.sh usdc 50

# Quote only (no swap)
bash scripts/swap.sh eth 0.01 --quote
```

---

### safe-transfer.mjs

Safe MOR/ETH transfers with EIP-712 signing.

```bash
node scripts/safe-transfer.mjs mor 0xRECIPIENT 100
node scripts/safe-transfer.mjs eth 0xRECIPIENT 0.01
```

---

## Monitoring Scripts

### [REDACTED].sh

Health monitoring with billing awareness.

```bash
# Verbose check
bash scripts/[REDACTED].sh --verbose

# Quiet mode (errors only)
bash scripts/[REDACTED].sh --quiet
```

**Features:**
- HTTP health probes
- Inference probes (glm-4.7-flash)
- Billing detection (Venice DIEM)
- Auto-restart on failure
- Signal notifications

**Configuration:**
| Variable | Default | Description |
|----------|---------|-------------|
| `FAIL_THRESHOLD` | 2 | HTTP failures before restart |
| `BILLING_BACKOFF_INTERVAL` | 1800 | Seconds between probes when billing-dead |

---

### venice-402-watchdog.sh

Disable Venice keys on 402 errors.

```bash
bash scripts/venice-402-watchdog.sh
```

Tails [REDACTED] logs for 402 errors and disables exhausted keys in `auth-profiles.json`.

---

### venice-key-monitor.sh

Proactive DIEM balance monitoring.

```bash
bash scripts/venice-key-monitor.sh
```

Checks all Venice API keys and disables keys below threshold.

---

### inference-balance-tracker.mjs

Track MOR/ETH usage over time.

```bash
node scripts/inference-balance-tracker.mjs
```

---

## Maintenance Scripts

### session-archive.sh

Archive old sessions to free memory.

```bash
# Archive if over 10MB
bash scripts/session-archive.sh

# Check size only
bash scripts/session-archive.sh --check

# Force archive
bash scripts/session-archive.sh --force

# Verbose
bash scripts/session-archive.sh --verbose
```

**Configuration:**
| Variable | Default | Description |
|----------|---------|-------------|
| `ARCHIVE_THRESHOLD_MB` | 10 | Trigger threshold |
| `KEEP_RECENT` | 5 | Sessions to always keep |

---

### diagnose.sh

Comprehensive health diagnostic.

```bash
bash scripts/diagnose.sh

# Config only
bash scripts/diagnose.sh --config

# Quick check
bash scripts/diagnose.sh --quick
```

**Checks:**
- Config files
- Environment variables
- Process status
- Network connectivity
- Inference test

---

### check-deps.sh

Verify external URLs and CLI commands.

```bash
bash scripts/check-deps.sh
```

---

### ecosystem-sync.sh

Sync to all 28 flavor repos + org repo.

```bash
bash scripts/ecosystem-sync.sh
```

---

### openclaw-update-check.sh

Pre-update safety verification.

```bash
bash scripts/openclaw-update-check.sh
```

---

## Security Scripts

### pii-scan.sh

Scan for PII patterns.

```bash
# Scan files
bash scripts/pii-scan.sh scan myfile.txt

# Scan directory
bash scripts/pii-scan.sh scan ./src/

# Scan git history
bash scripts/pii-scan.sh git-history HEAD~10
```

---

### pii-guard-hook.sh

Git pre-push hook for PII protection.

```bash
# Install globally
git config --global core.hooksPath /path/to/git-hooks
```

---

### filter-repo-pii.sh

Rewrite git history to remove PII.

```bash
bash scripts/filter-repo-pii.sh [--dry-run]
```

---

### fix-pii-all-repos.sh

Batch PII remediation for all repos.

```bash
bash scripts/fix-pii-all-repos.sh [--dry-run]
```

---

## Infrastructure Scripts

### start.sh

Start proxy-router with key injection.

```bash
bash scripts/start.sh
```

---

### stop.sh

Gracefully stop proxy-router.

```bash
bash scripts/stop.sh
```

---

### always-on.sh

Configure macOS to never sleep.

```bash
bash scripts/always-on.sh enable
bash scripts/always-on.sh disable
bash scripts/always-on.sh status
```

---

### docker-entrypoint.sh

Docker container startup.

Included in Dockerfile. Starts OpenClaw [REDACTED] + [REDACTED] proxy.

---

### mor-launch-headless.sh

launchd-compatible router launcher.

```bash
bash scripts/mor-launch-headless.sh
```

---

### setup-ollama.sh

Hardware-aware Ollama installation.

```bash
bash scripts/setup-ollama.sh

# Uninstall
bash scripts/setup-ollama.sh --uninstall

# Dry run
bash scripts/setup-ollama.sh --dry-run
```

Auto-selects optimal Qwen3.5 model based on RAM/GPU.

---

## Payment Scripts

### x402-client.mjs

x402 payment client for USDC.

```bash
# Make a paid request
node scripts/x402-client.mjs GET https://api.example.com/data

# Dry run
node scripts/x402-client.mjs --dry-run GET https://api.example.com/data

# With max amount
node scripts/x402-client.mjs --max-amount 0.50 GET https://api.example.com/data

# Check budget
node scripts/x402-client.mjs --budget
```

---

### agent-registry.mjs

ERC-8004 agent discovery on Base.

```bash
# Look up agent
node scripts/agent-registry.mjs lookup 1

# Get reputation
node scripts/agent-registry.mjs reputation 1

# Full discovery
node scripts/agent-registry.mjs discover 1

# List agents
node scripts/agent-registry.mjs list 1 10

# Total count
node scripts/agent-registry.mjs total
```

---

## Utility Scripts

### morpheus-session-mgr.mjs

Session management CLI.

```bash
node scripts/morpheus-session-mgr.mjs open glm-5 --duration 86400
node scripts/morpheus-session-mgr.mjs list
node scripts/morpheus-session-mgr.mjs close 0xSESSION_ID
```

---

### everclaw-deps.mjs

Dependency management.

```bash
node scripts/everclaw-deps.mjs check
node scripts/everclaw-deps.mjs install
```

---

### router.mjs

[REDACTED] router helper.

```bash
node scripts/router.mjs health
node scripts/router.mjs models
node scripts/router.mjs balance
```

---

### coingecko-x402.mjs

Price data via x402.

```bash
node scripts/coingecko-x402.mjs price bitcoin
```