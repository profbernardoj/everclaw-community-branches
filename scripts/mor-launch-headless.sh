#!/bin/bash
# mor-launch-headless.sh — launchd-compatible Morpheus proxy-router launcher
#
# Retrieves wallet private key from 1Password at runtime via macOS Keychain.
# Designed to run under launchd KeepAlive — runs in foreground via exec.
#
# If 1Password is not configured, falls back to macOS Keychain (everclaw-wallet).
#
# Usage: Called by com.morpheus.router launchd plist (not manually)

MORPHEUS_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$MORPHEUS_DIR"

# Source .env for ETH_NODE_ADDRESS and other config
if [[ -f .env ]]; then
  set -a
  source .env
  set +a
fi

# --- Key retrieval: try 1Password first, then macOS Keychain ---
WALLET_KEY=""

# Method 1: 1Password service account
OP_TOKEN=$(security find-generic-password -a "AGENT_USER" -s "op-service-account-token" -w 2>/dev/null || true)
if [[ -n "$OP_TOKEN" ]]; then
  export OP_SERVICE_ACCOUNT_TOKEN="$OP_TOKEN"
  WALLET_KEY=$(op item get "Base Session Key" --vault "AGENT_VAULT" --fields "Private Key" --reveal 2>/dev/null || true)
fi

# Method 2: macOS Keychain (everclaw-wallet.mjs stores keys here)
if [[ -z "$WALLET_KEY" ]]; then
  WALLET_KEY=$(security find-generic-password -s "everclaw-wallet" -w 2>/dev/null || true)
fi

if [[ -z "$WALLET_KEY" ]]; then
  echo "$(date -u +%Y-%m-%dT%H:%M:%S) FATAL: Cannot retrieve wallet key from 1Password or Keychain" >&2
  exit 1
fi

export WALLET_PRIVATE_KEY="$WALLET_KEY"
export ETH_NODE_ADDRESS="${ETH_NODE_ADDRESS:-https://base-mainnet.public.blastapi.io}"

# Ensure log directory exists
mkdir -p "$MORPHEUS_DIR/data/logs"

echo "$(date -u +%Y-%m-%dT%H:%M:%S) Starting proxy-router (headless, launchd-managed)"

# Run in foreground so launchd can track the process
exec ./proxy-router
