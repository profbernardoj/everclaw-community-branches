# null-everclaw — EverClaw for NullClaw

Decentralized Morpheus inference for your [NullClaw](https://github.com/null-claw) agent.

**Zero overhead integration:** NullClaw's 678 KB Zig binary, ~1 MB RAM, and <2 ms startup stay untouched. The EverClaw proxy runs as a separate Node.js sidecar and registers as a standard OpenAI-compatible provider in NullClaw's pluggable vtable system.

## Architecture

```
NullClaw (Zig, 678 KB) → EverClaw Proxy (Node.js, port 8083) → Morpheus P2P → AI Model
```

NullClaw supports 22+ providers via its vtable architecture. The EverClaw proxy registers as a `custom` provider — NullClaw's binary stays pure Zig with zero additional dependencies.

## Quick Start

### 1. Install the proxy

```bash
bash setup.sh
```

### 2. Restart NullClaw

```bash
nullclaw daemon    # or nullclaw service restart
```

### 3. Verify

```bash
nullclaw doctor
nullclaw agent -m "Hello from Morpheus"
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
| `config.patch.json` | Provider + model config for NullClaw's JSON format |
| `workspace/skills/enable-morpheus/` | NullClaw skill for runtime control |
| `tools-src/morpheus-status/` | Optional native Zig status tool |
| `examples/` | Nix flake overlay, systemd service, multi-provider configs |

## NullClaw Config Format

NullClaw uses a provider-based config with vtable routing:

```json
{
  "default_provider": "morpheus",
  "models": {
    "providers": {
      "morpheus": {
        "api_base": "http://127.0.0.1:8083/v1",
        "api_key": "morpheus-local"
      }
    }
  },
  "agents": {
    "defaults": {
      "model": { "primary": "glm-5" }
    }
  }
}
```

All 22+ existing providers remain available — just switch `default_provider` or set per-agent.

## Deployment Options

### Native (any arch)
```bash
nullclaw onboard && bash setup.sh && nullclaw daemon
```

### Nix Flake
See `examples/flake-overlay.nix` for adding the proxy as a Nix service.

### Docker
```bash
# NullClaw in Docker, proxy on host
docker run --add-host=host.docker.internal:host-gateway nullclaw \
  --env MORPHEUS_API_BASE=http://host.docker.internal:8083/v1
```

### Systemd
Setup script auto-creates a systemd user service for the proxy on Linux.

## Staking (unlimited P2P inference)

```bash
cd ~/.everclaw
node scripts/everclaw-wallet.mjs setup
node scripts/everclaw-wallet.mjs swap eth 0.05
node scripts/everclaw-wallet.mjs approve
node scripts/everclaw-wallet.mjs stake
```

## Why This Fits NullClaw

- **Vtable compatible** — registers as a standard `custom` provider (no binary changes)
- **Zero overhead** — proxy is a separate process, NullClaw binary untouched
- **All 22+ providers stay** — just adds one more, switchable at runtime
- **Nix-friendly** — flake overlay for reproducible builds
- **Works everywhere** — bare metal, Docker, systemd, OpenRC, $5 boards

## Contributing

PRs welcome for:
- Native Zig status tool implementation
- Nix flake testing and improvements
- Landlock/firejail sandbox configs for the proxy
- Performance benchmarks on edge hardware

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
