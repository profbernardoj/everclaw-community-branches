#!/bin/bash
# EverClaw Docker Build and Push Script
# Usage: ./build-and-push.sh [version]

set -euo pipefail

# Get version from package.json or use argument
if [ -n "${1:-}" ]; then
    VERSION="$1"
else
    VERSION=$(node -p "require('./package.json').version")
fi

REGISTRY="ghcr.io"
IMAGE="${REGISTRY}/everclaw/everclaw"

echo "═══════════════════════════════════════════════"
echo "EverClaw Docker Build — v${VERSION}"
echo "═══════════════════════════════════════════════"

# Build Docker image with multiple tags (multi-platform)
echo ""
echo "Building Docker image..."
docker buildx build \
    --build-arg EVERCLAW_VERSION="$VERSION" \
    --platform linux/amd64,linux/arm64 \
    -t "${IMAGE}:latest" \
    -t "${IMAGE}:${VERSION}" \
    --push \
    .

echo ""
echo "═══════════════════════════════════════════════"
echo "✅ Pushed v${VERSION}"
echo "  - ${IMAGE}:latest"
echo "  - ${IMAGE}:${VERSION}"
echo "═══════════════════════════════════════════════"
