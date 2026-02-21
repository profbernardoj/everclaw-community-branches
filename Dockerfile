# EverClaw Docker Container
# Decentralized Morpheus inference proxy for OpenClaw agents
#
# Build:  docker build -t ghcr.io/everclaw/everclaw:latest .
# Run:    docker run -d -p 8083:8083 --name everclaw ghcr.io/everclaw/everclaw:latest
# Health: curl http://localhost:8083/health

FROM node:20-slim AS base

# Install minimal runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -s /bin/bash everclaw

WORKDIR /app

# ─── Dependencies ─────────────────────────────────────────────────────────────
# Copy package files first for better layer caching
COPY --chown=everclaw:everclaw package*.json ./
RUN npm ci --omit=dev 2>/dev/null || npm install --omit=dev

# ─── Application ──────────────────────────────────────────────────────────────
COPY --chown=everclaw:everclaw . .

# Build arguments
ARG EVERCLAW_VERSION=2026.2.21
ENV EVERCLAW_VERSION=${EVERCLAW_VERSION}
ENV NODE_ENV=production

# Proxy configuration (can be overridden at runtime)
ENV EVERCLAW_PROXY_PORT=8083
ENV EVERCLAW_PROXY_HOST=0.0.0.0
ENV EVERCLAW_AUTH_TOKEN=morpheus-local

# Expose the proxy port
EXPOSE 8083

# Switch to non-root user
USER everclaw

# Health check — actually probe the proxy
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -sf http://127.0.0.1:${EVERCLAW_PROXY_PORT}/health || exit 1

# Start the Morpheus proxy
CMD ["node", "scripts/morpheus-proxy.mjs"]
