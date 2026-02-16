#!/bin/bash
set -euo pipefail

# Everclaw — Install Script
# Downloads the latest proxy-router release and sets up ~/morpheus/

INSTALL_DIR="$HOME/morpheus"
REPO="MorpheusAIs/Morpheus-Lumerin-Node"

echo "♾️  Everclaw — Installer"
echo "======================================"

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$OS" in
  darwin) PLATFORM="darwin" ;;
  linux)  PLATFORM="linux" ;;
  *)      echo "❌ Unsupported OS: $OS"; exit 1 ;;
esac

case "$ARCH" in
  x86_64)  GOARCH="amd64" ;;
  aarch64) GOARCH="arm64" ;;
  arm64)   GOARCH="arm64" ;;
  *)       echo "❌ Unsupported architecture: $ARCH"; exit 1 ;;
esac

echo "📋 Platform: ${PLATFORM}-${GOARCH}"

# Get latest release tag
echo "🔍 Finding latest release..."
LATEST_TAG=$(curl -sL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | head -1 | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')

if [[ -z "$LATEST_TAG" ]]; then
  echo "❌ Could not determine latest release. Check network connectivity."
  exit 1
fi

echo "📦 Latest release: ${LATEST_TAG}"

# Construct download URL
# Release assets follow pattern: mor-launch-<os>-<arch>.zip
ASSET_NAME="mor-launch-${PLATFORM}-${GOARCH}.zip"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST_TAG}/${ASSET_NAME}"

echo "⬇️  Downloading ${ASSET_NAME}..."

TMPDIR_DL=$(mktemp -d)
ZIPFILE="${TMPDIR_DL}/${ASSET_NAME}"

if ! curl -sL -o "$ZIPFILE" "$DOWNLOAD_URL"; then
  echo "❌ Download failed. URL: $DOWNLOAD_URL"
  rm -rf "$TMPDIR_DL"
  exit 1
fi

# Check the file is actually a zip
if ! file "$ZIPFILE" | grep -q -i "zip"; then
  echo "❌ Downloaded file is not a valid zip archive."
  echo "   URL might be wrong. Check releases at: https://github.com/${REPO}/releases"
  rm -rf "$TMPDIR_DL"
  exit 1
fi

# Create install directory
mkdir -p "$INSTALL_DIR"

echo "📂 Extracting to ${INSTALL_DIR}..."
unzip -o -q "$ZIPFILE" -d "$INSTALL_DIR"

# Clean up temp
rm -rf "$TMPDIR_DL"

# Remove macOS quarantine flags
if [[ "$PLATFORM" == "darwin" ]]; then
  echo "🍎 Removing macOS quarantine flags..."
  xattr -cr "$INSTALL_DIR" 2>/dev/null || true
fi

# Make binaries executable
chmod +x "$INSTALL_DIR/proxy-router" 2>/dev/null || true
chmod +x "$INSTALL_DIR/mor-cli" 2>/dev/null || true

# Create data/logs directory
mkdir -p "$INSTALL_DIR/data/logs"

# Create .env if it doesn't exist
if [[ ! -f "$INSTALL_DIR/.env" ]]; then
  echo "📝 Creating .env..."
  cat > "$INSTALL_DIR/.env" << 'ENVEOF'
# Morpheus Proxy-Router Configuration (Consumer Mode)
# Base Mainnet

# RPC endpoint — MUST be set or router silently fails
ETH_NODE_ADDRESS=https://base-mainnet.public.blastapi.io

# Chain
ETH_NODE_CHAIN_ID=8453
ETH_NODE_LEGACY_TX=false
ETH_NODE_USE_SUBSCRIPTIONS=false
ETH_NODE_POLLING_INTERVAL=10
ETH_NODE_MAX_RECONNECTS=30

# Contracts (Base mainnet)
DIAMOND_CONTRACT_ADDRESS=0x6aBE1d282f72B474E54527D93b979A4f64d3030a
MOR_TOKEN_ADDRESS=0x7431aDa8a591C955a994a21710752EF9b882b8e3

# WALLET_PRIVATE_KEY intentionally left blank — inject at runtime via 1Password
WALLET_PRIVATE_KEY=

# Proxy settings
PROXY_ADDRESS=0.0.0.0:3333
PROXY_STORAGE_PATH=./data/badger/
PROXY_STORE_CHAT_CONTEXT=true
PROXY_FORWARD_CHAT_CONTEXT=true
MODELS_CONFIG_PATH=./models-config.json

# Web API
WEB_ADDRESS=0.0.0.0:8082
WEB_PUBLIC_URL=http://localhost:8082

# Auth
AUTH_CONFIG_FILE_PATH=./proxy.conf
COOKIE_FILE_PATH=./.cookie

# Logging
LOG_COLOR=true
LOG_LEVEL_APP=info
LOG_LEVEL_TCP=warn
LOG_LEVEL_ETH_RPC=warn
LOG_LEVEL_STORAGE=warn
LOG_FOLDER_PATH=./data/logs

# Environment
ENVIRONMENT=production
ENVEOF
fi

# Create models-config.json if it doesn't exist
if [[ ! -f "$INSTALL_DIR/models-config.json" ]]; then
  echo "📝 Creating models-config.json..."
  cat > "$INSTALL_DIR/models-config.json" << 'MODEOF'
{
  "$schema": "./internal/config/models-config-schema.json",
  "models": [
    { "modelId": "0xb487ee62516981f533d9164a0a3dcca836b06144506ad47a5c024a7a2a33fc58", "modelName": "kimi-k2.5:web", "apiType": "openai", "apiUrl": "" },
    { "modelId": "0xbb9e920d94ad3fa2861e1e209d0a969dbe9e1af1cf1ad95c49f76d7b63d32d93", "modelName": "kimi-k2.5", "apiType": "openai", "apiUrl": "" },
    { "modelId": "0xc40b6871d0c0c24ddc3abde6565e8e60ab26a093d77f6b91c0b10f05fa823d7a", "modelName": "kimi-k2-thinking", "apiType": "openai", "apiUrl": "" },
    { "modelId": "0xfdc54de0b7f3e3525b4173f49e3819aebf1ed31e06d96be4eefaca04f2fcaeff", "modelName": "glm-4.7-flash", "apiType": "openai", "apiUrl": "" },
    { "modelId": "0xed0a2161f215f576b6d0424540b0ba5253fc9f2c58dff02c79e28d0a5fdd04f1", "modelName": "glm-4.7", "apiType": "openai", "apiUrl": "" },
    { "modelId": "0x2a7100f530e6f0f388e77e48f5a1bef5f31a5be3d1c460f73e0b6cc13d0e7f5f", "modelName": "qwen3-235b", "apiType": "openai", "apiUrl": "" },
    { "modelId": "0x470c71e89d3d9e05da58ec9a637e1ac96f73db0bf7e6ec26f5d5f46c7e5a37b3", "modelName": "qwen3-coder-480b-a35b-instruct", "apiType": "openai", "apiUrl": "" },
    { "modelId": "0x7e146f012beda5cbf6d6a01abf1bfbe4f8fb18f1e22b5bc3e2c1d0e9f8a7b6c5", "modelName": "hermes-3-llama-3.1-405b", "apiType": "openai", "apiUrl": "" },
    { "modelId": "0xc753061a5d2640decffa6f20a84f52a59ef4a6096d5ccf4eb5e1cbbaed39fe14", "modelName": "llama-3.3-70b", "apiType": "openai", "apiUrl": "" },
    { "modelId": "0x2e7228fe07523d84308d5a39f6dbf03d94c2be3fc4f73bf0b68c8e920f9a1c5a", "modelName": "gpt-oss-120b", "apiType": "openai", "apiUrl": "" }
  ]
}
MODEOF
fi

# Install Node.js dependencies (viem for wallet/contract interaction)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EVERCLAW_ROOT="$(dirname "$SCRIPT_DIR")"

if command -v npm &>/dev/null; then
  echo "📦 Installing Node.js dependencies..."
  (cd "$EVERCLAW_ROOT" && npm install --production 2>/dev/null) || {
    echo "⚠️  npm install failed. Run manually: cd $EVERCLAW_ROOT && npm install"
  }
else
  echo "⚠️  npm not found. Install Node.js, then run: cd $EVERCLAW_ROOT && npm install"
fi

echo ""
echo "✅ Everclaw (Morpheus Lumerin Node) installed to ${INSTALL_DIR}"
echo ""
echo "📋 Next steps:"
echo "  1. Edit ~/morpheus/.env if you need a custom RPC endpoint"
echo "  2. Update models-config.json with correct model IDs from the blockchain"
echo "  3. Run: bash skills/everclaw/scripts/start.sh"
echo ""
echo "⚠️  Before first use:"
echo "  - Ensure you have MOR tokens on Base mainnet"
echo "  - Ensure you have ETH on Base for gas"
echo "  - Set up 1Password with your wallet private key"
