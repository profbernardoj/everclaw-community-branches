# EverClaw Docker Container
# Build: docker build -t ghcr.io/everclaw/everclaw:latest .
# Run: docker run -it ghcr.io/everclaw/everclaw:latest

FROM node:20-slim

# Install dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy source code
COPY . .

# Build argument for version
ARG EVERCLAW_VERSION=0.9.8.3

# Set environment variables
ENV EVERCLAW_VERSION=${EVERCLAW_VERSION}
ENV NODE_ENV=production

# Create non-root user
RUN useradd -m -s /bin/bash everclaw && \
    chown -R everclaw:everclaw /app
USER everclaw

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD node -e "console.log('healthy')" || exit 1

# Default command
CMD ["node", "index.js"]