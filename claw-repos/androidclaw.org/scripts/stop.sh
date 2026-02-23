#!/bin/bash
set -euo pipefail

# Everclaw — Stop Script
# Gracefully stops the proxy-router process.

echo "🦋 Stopping Morpheus proxy-router..."

# Find proxy-router processes
PIDS=$(pgrep -f "proxy-router" 2>/dev/null || true)

if [[ -z "$PIDS" ]]; then
  echo "ℹ️  proxy-router is not running."
  exit 0
fi

# Send SIGTERM for graceful shutdown
echo "📤 Sending SIGTERM to proxy-router (PIDs: $PIDS)..."
echo "$PIDS" | xargs kill -TERM 2>/dev/null || true

# Wait for graceful shutdown
MAX_WAIT=15
WAITED=0
while [[ $WAITED -lt $MAX_WAIT ]]; do
  sleep 1
  WAITED=$((WAITED + 1))
  if ! pgrep -f "proxy-router" > /dev/null 2>&1; then
    echo "✅ proxy-router stopped gracefully."
    exit 0
  fi
done

# Force kill if still running
echo "⚠️  proxy-router did not stop gracefully. Sending SIGKILL..."
pgrep -f "proxy-router" | xargs kill -9 2>/dev/null || true
sleep 1

if pgrep -f "proxy-router" > /dev/null 2>&1; then
  echo "❌ Failed to stop proxy-router. Manual intervention required."
  exit 1
fi

echo "✅ proxy-router stopped (forced)."
