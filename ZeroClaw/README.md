# zero-everclaw — EverClaw for ZeroClaw

Decentralized Morpheus inference for your [ZeroClaw](https://github.com/zero-claw) agent.

**Trait-compatible integration:** ZeroClaw's trait-driven provider system accepts any OpenAI-compatible endpoint via `custom:` URLs. The EverClaw proxy slots in with zero Rust code changes — just a TOML config patch.

## Architecture

```
ZeroClaw (Rust, 8.8 MB) → EverClaw Proxy (Node.js, port 8083) → Morpheus P2P → AI Model
```

ZeroClaw's <10 ms cold start, <5 MB RAM, sandboxing, and 70+ channels stay untouched.

## Quick Start

### 1. Install

```bash
bash setup.sh
```

### 2. Restart ZeroClaw

```bash
zeroclaw service restart    # or zeroclaw daemon
```

### 3. Verify

```bash
zeroclaw status
zeroclaw agent -m "Hello from Morpheus"
```

## Available Models

| Model | Best For | Tier |
|-------|----------|------|
| `glm-5` | Complex reasoning, coding (default) | HEAVY |
| `glm-4.7-flash` | Fast responses, simple tasks | LIGHT |
| `kimi-k2.5` | General purpose | STANDARD |
| `qwen3-235b` | Large context, multilingual | STANDARD |

## TOML Configuration

ZeroClaw uses TOML config with `custom:` provider URLs:

```toml
default_provider = "custom:http://127.0.0.1:8083/v1"
default_model = "glm-5"
api_key = "morpheus-local"

[models.glm5]
provider = "custom:http://127.0.0.1:8083/v1"
model = "glm-5"

[models.flash]
provider = "custom:http://127.0.0.1:8083/v1"
model = "glm-4.7-flash"

[models.kimi]
provider = "custom:http://127.0.0.1:8083/v1"
model = "kimi-k2.5"
```

## What's Included

| Path | Purpose |
|------|---------|
| `setup.sh` | Installs proxy, patches TOML config, starts services |
| `config.patch.toml` | TOML snippet to merge into ZeroClaw config |
| `workspace/skills/enable-morpheus/` | ZeroClaw skill for runtime control |
| `tools-src/morpheus-status/` | Native Rust status tool (optional) |
| `examples/` | Multi-model configs, systemd/OpenRC service files |

## Deployment

### Native
```bash
zeroclaw onboard && bash setup.sh && zeroclaw daemon
```

### Docker
```bash
docker run --add-host=host.docker.internal:host-gateway zeroclaw \
  --env DEFAULT_PROVIDER="custom:http://host.docker.internal:8083/v1"
```

### Systemd / OpenRC
Setup script auto-creates the appropriate service file.

## Staking (unlimited P2P inference)

```bash
cd ~/.everclaw
node scripts/everclaw-wallet.mjs setup
node scripts/everclaw-wallet.mjs swap eth 0.05
node scripts/everclaw-wallet.mjs approve
node scripts/everclaw-wallet.mjs stake
```

## Contributing

PRs welcome for:
- Native Rust status tool with `reqwest` or `ureq`
- ZeroClaw trait implementation for direct Morpheus integration
- OpenRC service file
- Sandbox (allowlist) config for proxy access

## License

MIT
