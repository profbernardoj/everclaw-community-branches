# EverClaw Full Stack — OpenClaw + Morpheus Inference
#
# ─────────────────────────────────────────────────────────────────────────────
# Version pinning policy:
#   - EverClaw versions (package.json, image tags, SKILL.md) never use a 'v' prefix
#   - OpenClaw git tags and the OPENCLAW_VERSION arg always do
#   - The EVERCLAW_VERSION build arg (without 'v') is supplied by docker-compose.yml
#     for image labeling
# ─────────────────────────────────────────────────────────────────────────────
#
# Multi-stage build:
#   Stage 1: Build OpenClaw from source (gateway + web UI)
#   Stage 2: Production image with OpenClaw + EverClaw skill
#
# Ports:
#   18789 — OpenClaw Gateway (web UI + API)
#   8083  — Morpheus inference proxy (OpenAI-compatible)
#
# Build (uses pinned OpenClaw version):
#   docker build -t ghcr.io/everclaw/everclaw:latest .
#
# Build with specific OpenClaw version:
#   docker build --build-arg OPENCLAW_VERSION=v2026.7.1-2 -t ghcr.io/everclaw/everclaw:latest .
#
# Run:
#   docker run -d \
#     -p 18789:18789 \
#     -p 8083:8083 \
#     -v ~/.openclaw:/home/node/.openclaw \
#     -v ~/.morpheus:/home/node/.morpheus \
#     -v ~/.everclaw:/home/node/.everclaw \
#     --name everclaw \
#     ghcr.io/everclaw/everclaw:latest
#
# Then open: http://localhost:18789
#
# Environment variables:
#   OPENCLAW_GATEWAY_TOKEN    — Auth token for the web UI (auto-generated if not set)
#   MORPHEUS_GATEWAY_API_KEY  — Morpheus API Gateway key (get free at https://app.mor.org)
#   MORPHEUS_PROXY_API_KEY    — Bearer token for local Morpheus proxy-router
#   EVERCLAW_AGENT_NAME       — Agent display name (default: EverClaw)
#   EVERCLAW_USER_NAME        — Your name (default: User)
#   EVERCLAW_USER_DISPLAY_NAME — How the agent addresses you (default: same as USER_NAME)
#   TZ                        — Timezone for the agent (default: UTC, e.g. America/New_York)
#   EVERCLAW_DEFAULT_MODEL    — Default AI model (default: glm-5)
#   EVERCLAW_AUTH_TOKEN       — Legacy alias for proxy auth (default: morpheus-local)
#   EVERCLAW_SECURITY_TIER    — Security tier: low|recommended|maximum (default: low)
#   !!! WARNING: "low" disables exec approval prompts for ALL allowlisted binaries !!!
#   !!! Money operations remain gated at app layer (everclaw-wallet.mjs) regardless !!!
#   WALLET_PRIVATE_KEY        — For local P2P staking (optional, use secrets in production)
#   OPENCLAW_ENABLE_DEVICE_AUTH=true — Re-enable device auth (default: disabled for containers)

# ─── Stage 1: Build OpenClaw ─────────────────────────────────────────────────

# Production pin — v2026.7.1-2.
# Prior pin: v2026.5.27 (v2026.6.8 broke SSO Session Bridge / auth-proxy trusted-proxy mode).
# SSO /auth/handoff verified end-to-end on the staging image (2026-08-12, staging tag) before
# this promotion; update.checkOnStart=false suppresses the update banner in openclaw-default.json.
ARG OPENCLAW_VERSION=v2026.7.1-2

FROM node:22-bookworm AS openclaw-builder

ARG OPENCLAW_VERSION

# Install Bun (required for OpenClaw build scripts)
RUN curl -fsSL https://bun.sh/install | bash
ENV PATH="/root/.bun/bin:${PATH}"

RUN corepack enable

WORKDIR /openclaw

# Clone pinned OpenClaw release (not latest — intentional)
RUN git clone --depth 1 --branch ${OPENCLAW_VERSION} https://github.com/openclaw/openclaw.git . && \
    rm -rf .git

# Copy EverClaw skill into build context (monorepo: scripts/, SKILL.md, etc. at root)
# Copy skill files needed for the OpenClaw integration (only files tracked in git)
COPY --chown=node:node scripts /everclaw-skill/scripts
COPY --chown=node:node SKILL.md /everclaw-skill/SKILL.md
COPY --chown=node:node AGENTS.md /everclaw-skill/AGENTS.md
COPY --chown=node:node BRAIN.md /everclaw-skill/BRAIN.md
COPY --chown=node:node TOOLS.md /everclaw-skill/TOOLS.md
COPY --chown=node:node VOICE.md /everclaw-skill/VOICE.md
COPY --chown=node:node skills /everclaw-skill/skills
COPY --chown=node:node templates /everclaw-skill/templates
COPY --chown=node:node package.json /everclaw-skill/package.json
COPY --chown=node:node config /everclaw-skill/config

# Install dependencies
RUN pnpm install --frozen-lockfile

# Build gateway + UI
RUN pnpm build
ENV OPENCLAW_PREFER_PNPM=1
RUN pnpm ui:build

# Install runtime deps for all bundled OpenClaw channel plugins.
# postinstall-bundled-plugins.mjs skips source checkouts (detects src/ + extensions/),
# so we remove these build-only artifacts first (also shrinks final image ~100 MB).
# Preserve runtime templates before removing build-only source artifacts.
# src/agents/templates/ contains HEARTBEAT.md and other workspace boot templates
# that OpenClaw reads at runtime (not compiled into dist/).
RUN cp -r ./src/agents/templates /tmp/openclaw-templates 2>/dev/null || true && \
    rm -rf ./src ./extensions && \
    mkdir -p ./src/agents && cp -r /tmp/openclaw-templates ./src/agents/templates 2>/dev/null || true && \
    rm -rf /tmp/openclaw-templates && \
    NODE_ENV=production node ./scripts/postinstall-bundled-plugins.mjs && \
    npm cache clean --force

# ─── Stage 1.5: Build Auth Proxy ────────────────────────────────────────────

# Auth proxy for Privy JWT authentication
# Built at image time — bundles Privy SDK + React (no runtime CDN dependency)
FROM node:22-bookworm-slim AS auth-proxy-builder

WORKDIR /auth-proxy

# Copy auth proxy files from the build context (monorepo: packages/core/auth-proxy/)
COPY packages/core/auth-proxy/package.json packages/core/auth-proxy/package-lock.json* ./
COPY packages/core/auth-proxy/server.mjs ./
COPY packages/core/auth-proxy/login.html ./
COPY packages/core/auth-proxy/login-app.jsx ./
COPY packages/core/auth-proxy/build-login.mjs ./
COPY packages/core/auth-proxy/assets/ ./assets/

# Install ALL dependencies (including devDependencies for build step)
# --ignore-scripts skips native addon compilation (utf-8-validate, bufferutil)
# which would fail in slim images without python3/gcc. These are optional
# WebSocket performance addons — pure JS fallbacks work fine.
RUN if [ -f package-lock.json ]; then npm ci --ignore-scripts; else npm install --ignore-scripts; fi

# Bundle Privy SDK + React into a single JS file (eliminates CDN dependency)
RUN npm run build

# Remove devDependencies after build (keep only production deps in final image)
RUN rm -rf node_modules && \
    if [ -f package-lock.json ]; then npm ci --omit=dev; else npm install --omit=dev; fi

# ─── Stage 2: Production Image ───────────────────────────────────────────────

FROM node:22-bookworm-slim AS production

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    ca-certificates \
    jq \
    age \
    zstd \
    python3 \
    python3-pip \
    zip \
    unzip \
    ffmpeg \
    gnupg \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ─── Install Java 21 (Temurin JRE) for signal-cli ────────────────────────────
RUN curl -fsSL https://packages.adoptium.net/artifactory/api/gpg/key/public | gpg --dearmor -o /usr/share/keyrings/adoptium.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/adoptium.gpg] https://packages.adoptium.net/artifactory/deb bookworm main" | tee /etc/apt/sources.list.d/adoptium.list > /dev/null \
    && apt-get update \
    && apt-get install -y --no-install-recommends temurin-21-jre \
    && rm -rf /var/lib/apt/lists/*

# ─── Install signal-cli (with SHA256 checksum verification) ────────────────
ARG SIGNAL_CLI_VERSION=0.14.5
RUN curl -sL -o /tmp/signal-cli.tar.gz \
    "https://github.com/AsamK/signal-cli/releases/download/v${SIGNAL_CLI_VERSION}/signal-cli-${SIGNAL_CLI_VERSION}.tar.gz" \
    && echo "62d38ebfef3988d78f437e7328183b75ee549d111382e66c1af70d3ebd3cd7a7  /tmp/signal-cli.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/signal-cli.tar.gz -C /opt \
    && ln -sf /opt/signal-cli-${SIGNAL_CLI_VERSION}/bin/signal-cli /usr/local/bin/signal-cli \
    && rm /tmp/signal-cli.tar.gz

# ─── Install GitHub CLI ───────────────────────────────────────────────────────
RUN curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | tee /etc/apt/sources.list.d/github-cli.list > /dev/null \
    && apt-get update \
    && apt-get install -y --no-install-recommends gh \
    && rm -rf /var/lib/apt/lists/*

# ─── Install Brave Browser (headless browser automation) ─────────────────────
# NOTE: Brave is a full Chromium-based browser (~400MB). It is installed for
# OpenClaw's browser tool (headless automation). The attack surface includes
# the Chromium engine + sandbox. This is acceptable for InstallOpenClaw.xyz
# containers where the user owns and controls the agent.
RUN curl -fsSLo /usr/share/keyrings/brave-browser-archive-keyring.gpg \
    https://brave-browser-apt-release.s3.brave.com/brave-browser-archive-keyring.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/brave-browser-archive-keyring.gpg] https://brave-browser-apt-release.s3.brave.com/ stable main" | tee /etc/apt/sources.list.d/brave-browser-release.list > /dev/null \
    && apt-get update \
    && apt-get install -y --no-install-recommends brave-browser \
    && rm -rf /var/lib/apt/lists/*

# Brave/Chromium requires --no-sandbox in Docker containers (no CAP_SYS_ADMIN).
# These env vars are picked up by OpenClaw's browser tool when launching Brave.
ENV BRAVE_PATH="/usr/bin/brave-browser" \
    BRAVE_FLAGS="--headless=new --no-sandbox --disable-dev-shm-usage --disable-gpu"

# ─── Install Whisper (speech-to-text, CPU-only torch, model downloads on demand)
# Pin torch to a known-good CPU wheel. The PyTorch CPU index moved to
# torch 2.14.0+cpu whose metadata has no prebuilt cp311 wheel (source build
# fails: flit_core<4 unavailable on the isolated index) — broke CI 2026-09-02.
# torch 2.3.1 has stable manylinux cp311 wheels on the CPU index.
# Preinstall typing-extensions from PyPI: pip 23.0.1 (bookworm) discards the
# PyTorch-index copy due to PEP 503 name normalization (typing_extensions vs
# typing-extensions), then falls back to an sdist build that needs flit_core
# which the pytorch-only index cannot provide.
RUN pip3 install --no-cache-dir --break-system-packages typing-extensions \
    && pip3 install --no-cache-dir --break-system-packages \
    torch==2.3.1 --index-url https://download.pytorch.org/whl/cpu \
    && pip3 install --no-cache-dir --break-system-packages \
    --extra-index-url https://download.pytorch.org/whl/cpu \
    openai-whisper

# Create all persistent directories (for Barney + local Docker)
RUN mkdir -p /home/node/.openclaw/workspace/skills/everclaw \
    && mkdir -p /home/node/.openclaw/workspace/scripts \
    && mkdir -p /home/node/.openclaw/workspace/memory \
    && mkdir -p /home/node/.openclaw/workspace/shifts \
    && mkdir -p /home/node/.morpheus \
    && mkdir -p /home/node/.everclaw \
    && chmod 700 /home/node/.everclaw \
    && touch /home/node/.morpheus/.cookie \
    && touch /home/node/.morpheus/sessions.json \
    && chown -R node:node /home/node

# ─── Copy Auth Proxy ───────────────────────────────────────────────────────
# Auth proxy for Privy JWT authentication (runs on :18789, proxies to :18790)
COPY --from=auth-proxy-builder --chown=node:node /auth-proxy /opt/everclaw/auth-proxy

WORKDIR /app

# Copy built OpenClaw from stage 1
COPY --from=openclaw-builder --chown=node:node /openclaw /app

# Install node-llama-cpp for local embeddings (optional peer dep of OpenClaw).
# Without this, memory_search silently fails on all fresh installs.
# Uses --no-save to avoid modifying package.json; || true so build doesn't
# fail if native compilation fails on some architectures.
RUN cd /app && npm install node-llama-cpp@3.18.1 --no-save 2>&1 || true

# Copy EverClaw skill into the workspace
COPY --from=openclaw-builder --chown=node:node /everclaw-skill /home/node/.openclaw/workspace/skills/everclaw

# Copy flavor overlays into the skill directory (if flavors/ exists)
# Monorepo note: flavors/ directory may not exist in all versions
# The flavor overlay system allows per-flavor customization
COPY --chown=node:node flavors* /home/node/.openclaw/workspace/skills/everclaw/

# Install EverClaw runtime dependencies in the OpenClaw workspace.
# These are also declared in root package.json for CI testing, but Docker
# installs them here because the skill runs inside OpenClaw's workspace.
WORKDIR /home/node/.openclaw/workspace
RUN npm init -y 2>/dev/null; \
    npm install --omit=dev @x402/fetch @x402/evm viem argon2 2>/dev/null || true

WORKDIR /app

# ─── Default OpenClaw Configuration Template ───────────────────────────────
# Template deliberately placed OUTSIDE any VOLUME (/opt/everclaw/defaults/)
# so it survives Barney's empty persistent mount overlay on first run.
# Copied to ~/.openclaw/openclaw.json by docker-entrypoint.sh ONLY if
# the config file does not already exist.
RUN mkdir -p /opt/everclaw/defaults

COPY config/openclaw-default.json /opt/everclaw/defaults/openclaw-default.json
RUN chown node:node /opt/everclaw/defaults/openclaw-default.json

# ─── Boot File Templates ─────────────────────────────────────────────────────
# Boot templates live OUTSIDE the persistent volume (/opt/everclaw/templates/)
# so they survive Barney's empty host bind mount over the workspace home dir on
# first run (Docker bind mounts shadow image content instead of copying it,
# unlike named volumes). The entrypoint scaffolds workspace AGENTS.md/SOUL.md
# from these on first boot. Same pattern as config/openclaw-default.json.
# Local Docker runs (named volume or no volume) keep working via the
# skills/everclaw/templates/boot/ fallback path in docker-entrypoint.sh.

RUN mkdir -p /opt/everclaw/templates/boot
COPY templates/boot/*.template.md /opt/everclaw/templates/boot/

# Full EverClaw skill also lives OUTSIDE the volume (/opt/everclaw/skill) so
# Barney's empty bind mount does not hide scripts/, three-shifts/, templates/.
# docker-entrypoint.sh restores it into the workspace on first boot when the
# workspace copy is missing (bind mount shadows the image's baked-in copy).
COPY --from=openclaw-builder --chown=node:node /everclaw-skill /opt/everclaw/skill
RUN chown -R node:node /opt/everclaw/templates /opt/everclaw/skill

COPY --chown=node:node scripts/docker-entrypoint.sh /app/docker-entrypoint.sh
RUN chmod +x /app/docker-entrypoint.sh

# ─── Flavor Overlay ───────────────────────────────────────────────────────────
# Build with --build-arg FLAVOR=morpheusclaw.com (or any flavor dir in flavors/)
# to bake flavor-specific files into the image at build time.
# Flavor .md files are FINAL content (no __PLACEHOLDER__ vars) — copied directly
# to the workspace, bypassing the template system. The entrypoint's scaffold step
# checks `if [ ! -f "$target" ]` so pre-populated files are never overwritten.
# Flavor config replaces the generic default config entirely ("replace" strategy).
# If no flavor config exists, the generic default is preserved.

ARG FLAVOR=
RUN FDIR="/home/node/.openclaw/workspace/skills/everclaw/flavors/${FLAVOR}"; \
    if [ -n "${FLAVOR}" ] && [ -d "${FDIR}" ]; then \
      # Copy flavor .md files directly to workspace (final content, not templates) \
      for f in "${FDIR}"/*.md; do \
        [ -f "$f" ] && cp "$f" /home/node/.openclaw/workspace/ ; \
      done; \
      # Replace default config if flavor has one \
      FLAVOR_CFG=$(find "${FDIR}" -name 'openclaw-config-*.json' -type f | head -1); \
      if [ -n "${FLAVOR_CFG}" ]; then \
        cp "${FLAVOR_CFG}" /opt/everclaw/defaults/openclaw-default.json; \
        echo "   Config: $(basename ${FLAVOR_CFG})"; \
      else \
        echo "   Config: generic default (no flavor config found)"; \
      fi; \
      # Fix ownership — RUN executes as root, runtime user is node \
      chown -R node:node /home/node/.openclaw/workspace/; \
      echo "🎨 Flavor applied: ${FLAVOR}"; \
    else \
      echo "🔧 Generic EverClaw (no flavor)"; \
    fi

# ─── Environment ──────────────────────────────────────────────────────────────

# Note: Prior release left this at 2026.5.20.1645 (desynchronized from package.json 2026.5.24.0400).
# Re-aligned with release version as of v2026.5.28.1854.
ARG EVERCLAW_VERSION=2026.8.20.0917
ENV EVERCLAW_VERSION=${EVERCLAW_VERSION}
ENV NODE_ENV=production
ENV EVERCLAW_PROXY_PORT=8083
ENV EVERCLAW_PROXY_HOST=0.0.0.0
ENV EVERCLAW_AUTH_TOKEN=morpheus-local

# Expose ports
EXPOSE 18789 8083

# Health checks for both services
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -sf http://127.0.0.1:18789/health 2>/dev/null || \
        curl -sf http://127.0.0.1:${EVERCLAW_PROXY_PORT}/health 2>/dev/null || \
        exit 1

# ─── Persistent Volumes for Barney & Docker ───────────────────────────────────
# Barney auto-detects these VOLUME declarations and attaches the 20 GB
# persistent storage SKU automatically.
# Memories (MEMORY.md + daily *.md files), configs, skills state,
# wallet keys (.everclaw/wallet.enc), proxy sessions & cookies
# now survive container restarts and image updates.
VOLUME ["/home/node/.openclaw", "/home/node/.morpheus", "/home/node/.everclaw"]

# Run as non-root
USER node

# Entrypoint starts both OpenClaw gateway and Morpheus proxy
CMD ["/app/docker-entrypoint.sh"]
