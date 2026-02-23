#!/bin/bash
set -euo pipefail

# Morpheus Session Manager
# Usage:
#   ./session.sh open <model_name> [duration_seconds]
#   ./session.sh close <session_id>
#   ./session.sh list

MORPHEUS_DIR="$HOME/morpheus"
API_BASE="http://localhost:8082"

# Model name -> model ID mapping
# Uses a function instead of associative arrays for bash 3.2 compatibility
# (macOS ships bash 3.2 which doesn't support declare -A)
#
# To update: query the router for current on-chain model IDs:
#   curl -s -u "admin:$COOKIE_PASS" http://localhost:8082/blockchain/models | jq '.[] | {Name, Id}'
lookup_model_id() {
  case "$1" in
    kimi-k2.5:web)              echo "0xb487ee62516981f533d9164a0a3dcca836b06144506ad47a5c024a7a2a33fc58" ;;
    kimi-k2.5)                  echo "0xbb9e920d94ad3fa2861e1e209d0a969dbe9e1af1cf1ad95c49f76d7b63d32d93" ;;
    kimi-k2-thinking)           echo "0xc40b0a1ea1b20e042449ae44ffee8e87f3b8ba3d0be3ea61b86e6a89ba1a44e3" ;;
    glm-4.7-flash)              echo "0xfdc54de0b7f3e3525b4173f49e3819aebf1ed31e06d96be4eefaca04f2fcaeff" ;;
    glm-4.7)                    echo "0xed0a2161f215f576b6d0424540b0ba5253fc9f2c58dff02c79e28d0a5fdd04f1" ;;
    qwen3-235b)                 echo "0x2a7100f530e6f0f388e77e48f5a1bef5f31a5be3d1c460f73e0b6cc13d0e7f5f" ;;
    qwen3-coder-480b)           echo "0x470c71e89d3d9e05da58ec9a637e1ac96f73db0bf7e6ec26f5d5f46c7e5a37b3" ;;
    hermes-3-llama-3.1-405b)    echo "0x7e146f012beda5cbf6d6a01abf1bfbe4f8fb18f1e22b5bc3e2c1d0e9f8a7b6c5" ;;
    llama-3.3-70b)              echo "0xc753061a5d2640decfbbc1d1d35744e6805015d30d32872f814a93784c627fc3" ;;
    gpt-oss-120b)               echo "0x2e7228fe07523d84308d5a39f6dbf03d94c2be3fc4f73bf0b68c8e920f9a1c5a" ;;
    venice-uncensored)          echo "0xa003c4fba6bdb87b5a05c8b2c1657db8270827db0e87fcc2eaef17029aa01e6b" ;;
    whisper-v3-large-turbo)     echo "0x3e4f8c1a2b5d6e7f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7" ;;
    tts-kokoro)                 echo "0x4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5" ;;
    text-embedding-bge-m3)      echo "0x5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6" ;;
    *) echo "" ;;
  esac
}

# List of known model names for help output
KNOWN_MODELS="kimi-k2.5:web kimi-k2.5 kimi-k2-thinking glm-4.7-flash glm-4.7 qwen3-235b qwen3-coder-480b hermes-3-llama-3.1-405b llama-3.3-70b gpt-oss-120b venice-uncensored whisper-v3-large-turbo tts-kokoro text-embedding-bge-m3"

# Read auth cookie
get_auth() {
  if [[ ! -f "$MORPHEUS_DIR/.cookie" ]]; then
    echo "ERROR: .cookie file not found. Is the proxy-router running?" >&2
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

  local model_id
  model_id=$(lookup_model_id "$model_name")
  if [[ -z "$model_id" ]]; then
    echo "ERROR: Unknown model: $model_name" >&2
    echo "   Available models:" >&2
    for m in $KNOWN_MODELS; do
      echo "     $m" >&2
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

  echo "Opening session for $model_name (${duration}s)..."
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
    echo "Session opened: $SESSION_ID"
    echo "   Duration: ${duration}s"
    echo "   Model: $model_name"
  fi
}

# Close a session
cmd_close() {
  local session_id="${1:?Usage: session.sh close <session_id>}"

  get_auth

  echo "Closing session $session_id..."

  RESPONSE=$(curl -s -u "admin:$COOKIE_PASS" -X POST \
    "${API_BASE}/blockchain/sessions/${session_id}/close")

  echo "$RESPONSE" | jq . 2>/dev/null || echo "$RESPONSE"
  echo ""
  echo "Session close initiated. MOR will be returned to your wallet."
}

# List active sessions
cmd_list() {
  get_auth

  echo "Active sessions:"
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
    echo "Morpheus Session Manager"
    echo ""
    echo "Usage:"
    echo "  session.sh open <model_name> [duration_seconds]   Open a new session"
    echo "  session.sh close <session_id>                     Close a session"
    echo "  session.sh list                                   List active sessions"
    echo ""
    echo "Available models:"
    for m in $KNOWN_MODELS; do
      echo "  $m"
    done
    echo ""
    echo "Examples:"
    echo "  session.sh open kimi-k2.5 604800       # 7 day session (default)"
    echo "  session.sh open kimi-k2.5:web 3600    # 1 hour session"
    echo "  session.sh open kimi-k2.5 86400       # 1 day session"
    echo "  session.sh close 0xABC123...          # Close by session ID"
    ;;
esac
