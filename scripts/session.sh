#!/bin/bash
set -euo pipefail

# Morpheus Session Manager
# Usage:
#   ./session.sh open <model_name> [duration_seconds]
#   ./session.sh close <session_id>
#   ./session.sh list

MORPHEUS_DIR="$HOME/morpheus"
API_BASE="http://localhost:8082"

# Model name → model ID mapping
# Update these IDs from the blockchain as models change
declare -A MODEL_IDS=(
  ["kimi-k2.5:web"]="0xb487ee62516981f533d9164a0a3dcca836b06144506ad47a5c024a7a2a33fc58"
  ["kimi-k2.5"]="0xbb9eaf3df30bbada0a6e3bdf3c836c792e3be34a64e68832874bbf0de7351e43"
  ["kimi-k2-thinking"]="0xc40b937ae4b89e8680520070e48e6b507b869e6010429c7da0fe1e3c0c0f5436"
  ["glm-4.7-flash"]="0xfdc5a596cf66236acb19c2825b7e4c3e48c2c463a183e3df4a8b46dc7e5b1a0e"
  ["glm-4.7"]="0xed0a70b5e93cb9389c498e16837a96012e41baabde942dfc11ada58877c27b2a"
  ["qwen3-235b"]="0x2a716a21c89a018e6e8e7e5f8a38505adff2e47bdd1be09f3e98e1a45c5ff76c"
  ["qwen3-coder-480b"]="0x4709f1237a3e0faacbe09e8988e2902a2bca88e6470e7e7a8e4708e2c1b7ee74"
  ["hermes-3-llama-3.1-405b"]="0x7e14da4e80529ca44e5e052ba855e7e6b5071635c0014e510e5be8493fabf54d"
  ["llama-3.3-70b"]="0xc75321f1a21f09d9b8a0e2bab6c4fa942e6e5e85fc5e2c2e3f5d5f46c7e5a37b"
  ["gpt-oss-120b"]="0x2e72a1b82478928e3481bab7f92e90f6a750f34c71da5e4b2ee54e7a98b2c231"
  ["venice-uncensored"]="0xa003c4fba6bdb87b5a05c8b2c1657db8270827db0e87fcc2eaef17029aa01e6b"
  ["whisper-v3-large-turbo"]="0x3e4f8c1a2b5d6e7f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7"
  ["tts-kokoro"]="0x4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5"
  ["text-embedding-bge-m3"]="0x5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6"
)

# Read auth cookie
get_auth() {
  if [[ ! -f "$MORPHEUS_DIR/.cookie" ]]; then
    echo "❌ .cookie file not found. Is the proxy-router running?" >&2
    exit 1
  fi
  COOKIE_PASS=$(cat "$MORPHEUS_DIR/.cookie" | cut -d: -f2)
}

# Resolve model name to model ID
resolve_model() {
  local model_name="$1"

  # If it already looks like a hex ID, use it directly
  if [[ "$model_name" == 0x* ]]; then
    echo "$model_name"
    return
  fi

  local model_id="${MODEL_IDS[$model_name]:-}"
  if [[ -z "$model_id" ]]; then
    echo "❌ Unknown model: $model_name" >&2
    echo "   Available models:" >&2
    for key in "${!MODEL_IDS[@]}"; do
      echo "     $key" >&2
    done
    exit 1
  fi
  echo "$model_id"
}

# Open a session
cmd_open() {
  local model_name="${1:?Usage: session.sh open <model_name> [duration_seconds]}"
  local duration="${2:-604800}"  # default: 7 days

  get_auth
  local model_id
  model_id=$(resolve_model "$model_name")

  echo "🦋 Opening session for $model_name (${duration}s)..."
  echo "   Model ID: $model_id"

  RESPONSE=$(curl -s -u "admin:$COOKIE_PASS" -X POST \
    "${API_BASE}/blockchain/models/${model_id}/session" \
    -H "Content-Type: application/json" \
    -d "{\"sessionDuration\": $duration}")

  echo "$RESPONSE" | jq . 2>/dev/null || echo "$RESPONSE"

  # Extract session ID if present
  SESSION_ID=$(echo "$RESPONSE" | jq -r '.sessionId // .SessionID // empty' 2>/dev/null || true)
  if [[ -n "$SESSION_ID" ]]; then
    echo ""
    echo "✅ Session opened: $SESSION_ID"
    echo "   Duration: ${duration}s"
    echo "   Model: $model_name"
  fi
}

# Close a session
cmd_close() {
  local session_id="${1:?Usage: session.sh close <session_id>}"

  get_auth

  echo "🦋 Closing session $session_id..."

  RESPONSE=$(curl -s -u "admin:$COOKIE_PASS" -X POST \
    "${API_BASE}/blockchain/sessions/${session_id}/close")

  echo "$RESPONSE" | jq . 2>/dev/null || echo "$RESPONSE"
  echo ""
  echo "✅ Session close initiated. MOR will be returned to your wallet."
}

# List active sessions
cmd_list() {
  get_auth

  echo "🦋 Active sessions:"
  echo ""

  RESPONSE=$(curl -s -u "admin:$COOKIE_PASS" "${API_BASE}/blockchain/sessions")

  echo "$RESPONSE" | jq . 2>/dev/null || echo "$RESPONSE"
}

# Main
ACTION="${1:-help}"

case "$ACTION" in
  open)
    shift
    cmd_open "$@"
    ;;
  close)
    shift
    cmd_close "$@"
    ;;
  list)
    cmd_list
    ;;
  *)
    echo "🦋 Morpheus Session Manager"
    echo ""
    echo "Usage:"
    echo "  session.sh open <model_name> [duration_seconds]   Open a new session"
    echo "  session.sh close <session_id>                     Close a session"
    echo "  session.sh list                                   List active sessions"
    echo ""
    echo "Available models:"
    for key in $(echo "${!MODEL_IDS[@]}" | tr ' ' '\n' | sort); do
      echo "  $key"
    done
    echo ""
    echo "Examples:"
    echo "  session.sh open kimi-k2.5 604800       # 7 day session (default)"
    echo "  session.sh open kimi-k2.5:web 3600    # 1 hour session"
    echo "  session.sh open kimi-k2.5 86400       # 1 day session"
    echo "  session.sh close 0xABC123...          # Close by session ID"
    ;;
esac
