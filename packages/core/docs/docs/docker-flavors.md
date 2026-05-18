# Docker Flavors — Per-Flavor Container Images

EverClaw ships **per-flavor Docker images** so you can pull exactly the
agent you want — pre-configured with the right persona, model tiers,
and branding.

## Quick Start

```bash
# Generic EverClaw (default)
docker pull ghcr.io/everclaw/everclaw:latest

# Morpheus Agent (decentralized AI inference)
docker pull ghcr.io/everclaw/morpheus-agent:latest

# Any flavor
docker pull ghcr.io/everclaw/<flavor>:latest
```

Run it:

```bash
docker run -d \
  -p 18789:18789 \
  -p 8083:8083 \
  -v ~/.openclaw:/home/node/.openclaw \
  -v ~/.morpheus:/home/node/.morpheus \
  -v ~/.everclaw:/home/node/.everclaw \
  --name my-agent \
  ghcr.io/everclaw/morpheus-agent:latest
```

Then open: `http://localhost:18789`

## Available Flavors

All images are built from the same EverClaw engine. Each flavor
customizes the agent persona (SOUL.md, IDENTITY.md), user template
(USER.md), documentation (README.md), and default model configuration.

| Image | Description |
|-------|-------------|
| `everclaw/everclaw` | Generic EverClaw (default) |
| `everclaw/morpheus-agent` | Decentralized AI via MorpheusAI (Base L2) |
| `everclaw/baseclaw` | Base L2 focused agent |
| `everclaw/bitcoinclaw` | Bitcoin ecosystem agent |
| `everclaw/ethereumclaw` | Ethereum ecosystem agent |
| `everclaw/solanaclaw` | Solana ecosystem agent |
| ... | 24 more flavors |

Full list: check `templates/flavors/` in the repo, or pull the
[GitHub Actions build](https://github.com/profbernardoj/morpheus-skill/actions)
to see all images.

## How It Works

### Build-Time Flavor Overlay

Each flavor has a directory in `templates/flavors/<name>/` containing
override files:

```
templates/flavors/morpheus-agent/
├── SOUL.md                        # Agent persona
├── IDENTITY.md                    # Agent identity
├── USER.md                        # User template
├── README.md                      # Documentation
├── CHANGELOG.md                   # Flavor-specific changelog
└── openclaw-config-morpheus.json  # Model & inference config
```

When Docker builds with `--build-arg FLAVOR=morpheus-agent`:

1. **Flavor `.md` files** are copied directly to the workspace
   (`/home/node/.openclaw/workspace/`). These are final content —
   no template placeholders.

2. **Flavor config** (if present) replaces the generic default config
   at `/opt/everclaw/defaults/openclaw-default.json`. This is a full
   replacement, not a merge — flavor configs must be complete.

3. **File ownership** is fixed to `node:node` (the runtime user).

4. The entrypoint's scaffold step checks `if [ ! -f "$target" ]`
   before copying templates — so pre-populated flavor files are
   never overwritten.

### CI Pipeline

The GitHub Actions workflow uses a two-job pipeline:

```
┌──────────────────┐     ┌──────────────────────────────────┐
│ discover-flavors │────▶│ build-and-push (matrix: 30 jobs) │
│  (ls + jq)       │     │  - generic (no flavor)           │
│  ~3 seconds      │     │  - morpheus-agent                │
└──────────────────┘     │  - baseclaw                      │
                         │  - ... 27 more                   │
                         │  Multi-arch: amd64 + arm64       │
                         └──────────────────────────────────┘
```

- **Discovery:** Scans `templates/flavors/` and builds the matrix
  dynamically. Adding a new flavor is zero-config — just create the
  directory and push.
- **Matrix:** Each flavor builds in parallel with `fail-fast: false`.
  All images share 99%+ of layers — only the final overlay differs.
- **Tags:** Each image gets `:latest` and `:CalVer` (e.g. `:2026.4.7.0355`).

## Building Locally

```bash
# Generic (no flavor)
docker build -t my-everclaw .

# Specific flavor
docker build --build-arg FLAVOR=morpheus-agent -t my-morpheus .

# With specific EverClaw version
docker build \
  --build-arg FLAVOR=morpheus-agent \
  --build-arg EVERCLAW_VERSION=2026.4.7.0355 \
  -t my-morpheus .
```

## Creating a New Flavor

1. Create a directory: `templates/flavors/my-flavor/`
2. Add override files (at minimum, `SOUL.md`):
   - `SOUL.md` — Agent persona and personality
   - `IDENTITY.md` — Agent identity card
   - `USER.md` — User template with relevant fields
   - `README.md` — Flavor-specific documentation
   - `openclaw-config-<name>.json` — Model tiers and inference config
3. Push to main — CI auto-discovers and builds the new image
4. Pull: `docker pull ghcr.io/everclaw/my-flavor:latest`

**Naming convention:** The directory name becomes the Docker image
name. `templates/flavors/morpheus-agent/` → `ghcr.io/everclaw/morpheus-agent`.

## Config Strategy

Flavor configs use a **replace** strategy — the flavor config
completely replaces the generic default. This means:

- Flavor configs must be **complete and self-contained**
- All model providers, tiers, fallback chains, and settings must
  be defined in the flavor config
- If a flavor has no config file, the generic default is used

## Architecture

```
┌─────────────────────────────────────────────┐
│              Docker Image                    │
│                                              │
│  /app/                                       │
│  └── OpenClaw Gateway                        │
│                                              │
│  /home/node/.openclaw/workspace/             │
│  ├── SOUL.md          ◀── flavor override    │
│  ├── IDENTITY.md      ◀── flavor override    │
│  ├── USER.md          ◀── flavor override    │
│  ├── README.md        ◀── flavor override    │
│  └── skills/everclaw/ ◀── full engine        │
│                                              │
│  /opt/everclaw/defaults/                     │
│  └── openclaw-default.json  ◀── flavor config│
│                                              │
└─────────────────────────────────────────────┘
```

## FAQ

**Q: Are flavor images larger than the generic image?**
A: Negligibly — the overlay adds ~10-20 KB of markdown + JSON files
on top of the ~1 GB base image.

**Q: Can I switch flavors on an existing container?**
A: Yes — replace the workspace `.md` files and config, then restart.
Or pull the new flavor image and mount your existing volumes.

**Q: What happens if a flavor build fails in CI?**
A: `fail-fast: false` means other flavors continue building. Only the
failed flavor needs a re-run.

**Q: How do I add a centralized API fallback to a flavor?**
A: Edit the flavor config's `agents.defaults.model.fallbacks` array
and add your provider to `models.providers`. Or configure it at
runtime via environment variables.
