---
name: agent-chat
description: "XMTP real-time agent-to-agent and user-to-agent E2E-encrypted messaging daemon for EverClaw. Use when setting up XMTP identity, managing the always-on messaging daemon, trusting peers, sending messages, or configuring multi-identity buddy bots across macOS and Linux."
user-invocable: true
triggers:
  - "agent chat"
  - "xmtp messaging"
  - "send message"
  - "trust peer"
  - "buddy bot"
  - "daemon status"
---

# agent-chat

XMTP real-time agent-to-agent and user-to-agent messaging for EverClaw.

## Overview

Always-on daemon providing E2E-encrypted messaging via XMTP's MLS protocol. Runs as a separate process managed by launchd (macOS) or systemd (Linux), communicating with OpenClaw through a filesystem bridge.

## Version

0.2.0

## Dependencies

- `@xmtp/agent-sdk` ^2.3.0
- `xmtp-comms-guard` ^6.0.0 (peer)
- Node.js >= 20.0.0

## Quick Start

```bash
# 1. Generate XMTP identity (one-time)
node skills/agent-chat/setup-identity.mjs

# 2. Install daemon as system service
bash scripts/setup-agent-chat.sh

# 3. Check status
bash scripts/setup-agent-chat.sh --status
```

## Daemon Management

The `setup-agent-chat.sh` script installs the XMTP daemon as a persistent system service.

### Commands

```bash
# Install and start daemon (auto-detects OS)
bash scripts/setup-agent-chat.sh

# Check daemon status
bash scripts/setup-agent-chat.sh --status

# View recent logs
bash scripts/setup-agent-chat.sh --logs

# Restart daemon
bash scripts/setup-agent-chat.sh --restart

# Uninstall daemon
bash scripts/setup-agent-chat.sh --uninstall

# Install without starting
bash scripts/setup-agent-chat.sh --skip-start
```

### Platform Support

| Platform | Service Manager | Location | Logs |
|----------|----------------|----------|------|
| macOS | launchd | `~/Library/LaunchAgents/com.everclaw.agent-chat.plist` | `~/.everclaw/logs/agent-chat.*` |
| Linux | systemd (user) | `~/.config/systemd/user/everclaw-agent-chat.service` | `journalctl --user -u everclaw-agent-chat` |

**Note:** Linux uses user-level systemd (no sudo required). All services run as your user account.

### Manual Commands

**macOS (launchd):**
```bash
# Check if loaded
launchctl list | grep everclaw

# View logs
tail -f ~/.everclaw/logs/agent-chat.log

# Stop/start
launchctl bootout gui/$(id -u)/com.everclaw.agent-chat
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.everclaw.agent-chat.plist
```

**Linux (systemd):**
```bash
# Check status
systemctl --user status everclaw-agent-chat

# View logs
journalctl --user -u everclaw-agent-chat -f

# Stop/start
systemctl --user stop everclaw-agent-chat
systemctl --user start everclaw-agent-chat
```

## Architecture

- **Process model**: Separate always-on daemon (not in-process with OpenClaw)
- **IPC**: Filesystem bridge (`~/.everclaw/xmtp/outbox/` → `inbox/`)
- **Message format**: V6 JSON inside XMTP text content type
- **Consent**: Configurable per-agent (`open`/`handshake`/`strict`)
- **Middleware chain**: Consent → CommsGuard V6 → Router

## Identity Model

Two-tier:
- **28 flavor canonical wallets** — project-controlled, `open` consent
- **Per-user wallets** — generated at install, `handshake` consent

XMTP wallet is messaging-only — no funds. Separate from MOR staking wallet.

## CLI Reference

```bash
# Identity status
node skills/agent-chat/cli.mjs status

# Daemon health
node skills/agent-chat/cli.mjs health

# List peer groups
node skills/agent-chat/cli.mjs groups

# Trust a peer (allow messages)
node skills/agent-chat/cli.mjs trust-peer 0x... --as colleague --name "Agent Name"

# List trusted peers
node skills/agent-chat/cli.mjs peers list

# Send a message (via outbox)
node skills/agent-chat/cli.mjs send 0x... "Hello, agent!"
```

## Files

| File | Purpose |
|------|---------|
| `daemon.mjs` | Entry point for launchd/systemd |
| `cli.mjs` | CLI commands |
| `setup-identity.mjs` | One-time key generation |
| `src/agent.mjs` | Agent creation + middleware wiring |
| `src/identity.mjs` | Secret/identity loading (multi-identity: agentId param) |
| `src/paths.mjs` | Path resolution + agent ID validation (multi-identity) |
| `src/consent.mjs` | 3-policy consent gate |
| `src/router.mjs` | Message routing (COMMAND/DATA dispatch) |
| `src/bridge.mjs` | Filesystem outbox watcher (multi-identity: agentId param) |
| `src/health.mjs` | Health file writer (multi-identity: agentId param) |
| `src/groups.mjs` | Group conversation mapping |
| `src/payer.mjs` | Fee stub (network currently free) |
| `src/index.mjs` | Public API re-exports |

## Multi-Identity (Buddy Bots)

Each buddy bot agent gets its own XMTP identity, daemon process, and data directory. This is called "multi-identity" mode — one daemon per agent, running as independent services.

### Directory Layout

| Agent | Data Directory | Service (macOS) | Service (Linux) |
|-------|---------------|-----------------|-----------------|
| Host (default) | `~/.everclaw/xmtp/` | `com.everclaw.agent-chat` | `everclaw-agent-chat` |
| Alice | `~/.everclaw/xmtp-alice/` | `com.everclaw.agent-chat.alice` | `everclaw-agent-chat-alice` |
| Bob | `~/.everclaw/xmtp-bob/` | `com.everclaw.agent-chat.bob` | `everclaw-agent-chat-bob` |

Each agent's directory contains its own `.secrets.json`, `identity.json`, `inbox/`, `outbox/`, and `peers.json` — fully isolated from other agents.

### Agent ID Rules

Agent IDs must be:
- 1-63 characters
- Lowercase alphanumeric + hyphens only
- Must start with a letter or digit (no leading hyphens)
- No path traversal characters (`..`, `/`, etc.)

This prevents directory traversal attacks and service name conflicts.

### Setup

```bash
# Generate identity for a buddy bot
node skills/agent-chat/setup-identity.mjs --agent-id alice

# Install daemon for that buddy bot
bash scripts/setup-agent-chat.sh --agent-id alice

# List all installed daemons
bash scripts/setup-agent-chat.sh --list

# Check status of a specific agent
bash scripts/setup-agent-chat.sh --status --agent-id alice

# Restart a specific agent
bash scripts/setup-agent-chat.sh --restart --agent-id alice

# Uninstall a specific agent
bash scripts/setup-agent-chat.sh --uninstall --agent-id alice
```

### Environment Variables

| Variable | Purpose |
|----------|---------|
| `AGENT_CHAT_AGENT_ID` | Agent ID (alternative to `--agent-id` flag) |
| `AGENT_CHAT_XMTP_DIR` | Override XMTP data directory (default agent only) |
| `EVERCLAW_HOME` | Base directory (default: `~/.everclaw`) |

`AGENT_CHAT_XMTP_DIR` only affects the default (host) agent. Per-agent paths always resolve from `EVERCLAW_HOME` to maintain isolation.

### How It Works

Each per-agent service file (launchd plist or systemd unit) contains the `AGENT_CHAT_AGENT_ID` environment variable. When the daemon starts, it reads this env var and resolves all paths accordingly:

1. `AGENT_CHAT_AGENT_ID=alice` → data dir is `~/.everclaw/xmtp-alice/`
2. No env var → data dir is `~/.everclaw/xmtp/` (default host)

The `--agent-id` CLI flag takes priority over the env var, allowing manual overrides.

### Security

- Each agent's data directory is `chmod 700`
- Each agent's `.secrets.json` is `chmod 600`
- Agent IDs are validated against a strict regex to prevent path traversal and service injection
- Agents cannot access each other's wallets, messages, or peer lists

## Security

- Keys stored in `~/.everclaw/xmtp/.secrets.json` (chmod 600)
- Directory secured: `~/.everclaw/xmtp/` (chmod 700)
- Path traversal protection on inbox writes
- Agent ID validation: regex `/^[a-z0-9][a-z0-9-]{0,62}$/` prevents directory traversal and service injection
- CommsGuard V6 validates all structured messages
- Plain text messages bypass comms-guard (acceptable for agent-to-agent v1)

## Troubleshooting

### Daemon won't start

1. Check Node.js version: `node --version` (need >= 20.0.0)
2. Verify identity exists: `ls ~/.everclaw/xmtp/.secrets.json`
3. Check logs: `bash scripts/setup-agent-chat.sh --logs`
4. Reinstall: `bash scripts/setup-agent-chat.sh --uninstall && bash scripts/setup-agent-chat.sh`

### Messages not sending

1. Check peer is trusted: `node skills/agent-chat/cli.mjs peers list`
2. Check daemon health: `node skills/agent-chat/cli.mjs health`
3. Check outbox queue: `ls ~/.everclaw/xmtp/outbox/`
4. Check daemon is running: `bash scripts/setup-agent-chat.sh --status`

### XMTP installation limit

XMTP limits the number of installations per identity. If you see warnings about installation limits:

1. Check installations: `node skills/agent-chat/cli.mjs status`
2. Revoke old installations via XMTP console (if available)
3. Generate new identity: `node skills/agent-chat/setup-identity.mjs` (creates new address)