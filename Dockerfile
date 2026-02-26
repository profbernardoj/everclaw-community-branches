# EverClaw Full Stack — OpenClaw + Morpheus Inference
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
#   docker build --build-arg OPENCLAW_VERSION=v2026.2.22 -t ghcr.io/everclaw/everclaw:latest .
#
# Run:
#   docker run -d \
#     -p 18789:18789 \
#     -p 8083:8083 \
#     -v ~/.openclaw:/home/node/.openclaw \
#     --name everclaw \
#     ghcr.io/everclaw/everclaw:latest
#
# Then open: http://localhost:18789
#
# Environment variables:
#   OPENCLAW_GATEWAY_TOKEN  — Auth token for the web UI (auto-generated if not set)
#   EVERCLAW_AUTH_TOKEN     — Bearer token for Morpheus proxy (default: morpheus-local)
#   MOR_GATEWAY_API_KEY     — Morpheus API Gateway key (for cloud inference)
#   WALLET_PRIVATE_KEY      — For local P2P staking (optional, use secrets in production)

# ─── Stage 1: Build OpenClaw ─────────────────────────────────────────────────
# Pin OpenClaw version for reproducible builds.
# Update this when upgrading to a new release.

ARG OPENCLAW_VERSION=v2026.2.22

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

# Copy EverClaw skill into build context
COPY --chown=node:node . /everclaw-skill

# Install dependencies
RUN pnpm install --frozen-lockfile

# Build gateway + UI
RUN pnpm build
ENV OPENCLAW_PREFER_PNPM=1
RUN pnpm ui:build

# ─── Stage 2: Production Image ───────────────────────────────────────────────

FROM node:22-bookworm-slim AS production

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    ca-certificates \
    jq \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create workspace directories
RUN mkdir -p /home/node/.openclaw/workspace/skills/everclaw \
    && mkdir -p /home/node/.openclaw/workspace/scripts \
    && mkdir -p /home/node/.openclaw/workspace/memory \
    && mkdir -p /home/node/.openclaw/workspace/shifts \
    && chown -R node:node /home/node

WORKDIR /app

# Copy built OpenClaw from stage 1
COPY --from=openclaw-builder --chown=node:node /openclaw /app

# Copy EverClaw skill into the workspace
COPY --from=openclaw-builder --chown=node:node /everclaw-skill /home/node/.openclaw/workspace/skills/everclaw

# Install EverClaw dependencies (x402, viem for finance tracker)
WORKDIR /home/node/.openclaw/workspace
RUN npm init -y 2>/dev/null; \
    npm install --omit=dev @x402/fetch @x402/evm viem 2>/dev/null || true

WORKDIR /app

# ─── Default OpenClaw Configuration ──────────────────────────────────────────
# This config bootstraps OpenClaw with Morpheus as the primary provider.
# Users can override by mounting their own ~/.openclaw/openclaw.json

RUN cat > /home/node/.openclaw/openclaw-default.json << 'DEFAULTCONFIG'
{
  "models": {
    "mode": "merge",
    "providers": {
      "morpheus-local": {
        "baseUrl": "http://127.0.0.1:8083/v1",
        "api": "openai-completions",
        "models": [
          { "id": "glm-5", "name": "GLM-5 (Morpheus Local)", "reasoning": false },
          { "id": "glm-4.7-flash", "name": "GLM 4.7 Flash (Morpheus Local)", "reasoning": false },
          { "id": "kimi-k2.5", "name": "Kimi K2.5 (Morpheus Local)", "reasoning": false },
          { "id": "kimi-k2-thinking", "name": "Kimi K2 Thinking (Morpheus Local)", "reasoning": true }
        ]
      },
      "mor-gateway": {
        "baseUrl": "https://api.mor.org/api/v1",
        "api": "openai-completions",
        "models": [
          { "id": "glm-5", "name": "GLM-5 (Morpheus Gateway)", "reasoning": false },
          { "id": "glm-4.7-flash", "name": "GLM 4.7 Flash (Morpheus Gateway)", "reasoning": false },
          { "id": "kimi-k2.5", "name": "Kimi K2.5 (Morpheus Gateway)", "reasoning": false }
        ]
      }
    }
  },
  "agents": {
    "defaults": {
      "model": {
        "primary": "morpheus-local/glm-5",
        "fallbacks": [
          "mor-gateway/glm-5",
          "mor-gateway/kimi-k2.5"
        ]
      }
    }
  }
}
DEFAULTCONFIG

RUN chown node:node /home/node/.openclaw/openclaw-default.json

# ─── Boot File Templates ─────────────────────────────────────────────────────
# Copy boot templates to workspace if they don't already exist (first run)

COPY --chown=node:node scripts/docker-entrypoint.sh /app/docker-entrypoint.sh
RUN chmod +x /app/docker-entrypoint.sh

# ─── Environment ──────────────────────────────────────────────────────────────

ARG EVERCLAW_VERSION=2026.2.23
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

# Run as non-root
USER node

# Entrypoint starts both OpenClaw gateway and Morpheus proxy
CMD ["/app/docker-entrypoint.sh"]
