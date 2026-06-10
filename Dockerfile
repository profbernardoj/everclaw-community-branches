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
#   docker build --build-arg OPENCLAW_VERSION=v2026.5.27 -t ghcr.io/everclaw/everclaw:latest .
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
#   EVERCLAW_SECURITY_TIER    — Security tier: low|recommended|maximum (default: recommended)
#   WALLET_PRIVATE_KEY        — For local P2P staking (optional, use secrets in production)
#   OPENCLAW_ENABLE_DEVICE_AUTH=true — Re-enable device auth (default: disabled for containers)

# ─── Stage 1: Build OpenClaw ─────────────────────────────────────────────────

ARG OPENCLAW_VERSION=v2026.5.27

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
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

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
# Copy boot templates to workspace if they don't already exist (first run)

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
ARG EVERCLAW_VERSION=2026.6.10.0257
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
