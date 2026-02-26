#!/bin/bash
# EverClaw Docker Build and Push Script
# Usage: ./build-and-push.sh [version]

set -e

# Get version from package.json or use argument
if [ -n "$1" ]; then
    VERSION="$1"
else
    VERSION=$(node -p "require('./package.json').version")
fi

echo "============================================"
echo "EverClaw Docker Build"
echo "Version: $VERSION"
echo "============================================"

# Build Docker image with multiple tags
echo ""
echo "Building Docker image..."
docker build \
    --build-arg EVERCLAW_VERSION="$VERSION" \
    -t ghcr.io/everclaw/everclaw:latest \
    -t ghcr.io/everclaw/everclaw:"$VERSION" \
    .

# Push to GitHub Container Registry
echo ""
echo "Pushing to GitHub Container Registry..."
docker push ghcr.io/everclaw/everclaw:latest
docker push ghcr.io/everclaw/everclaw:"$VERSION"

echo ""
echo "============================================"
echo "Done! Pushed version $VERSION"
echo "  - ghcr.io/everclaw/everclaw:latest"
echo "  - ghcr.io/everclaw/everclaw:$VERSION"
echo "============================================"