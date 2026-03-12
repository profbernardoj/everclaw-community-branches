#!/bin/bash
set -euo pipefail

# Everclaw Chat — Send inference through an active session
# Usage: ./chat.sh <model_name> "prompt text" [--stream]
#
# ⚠️ session_id and model_id are HTTP HEADERS, not JSON body fields.
# This script handles that correctly.

MORPHEUS_DIR="$HOME/morpheus"
API_BASE="http://localhost:8082"

# Model name → model ID mapping
# Uses a function instead of declare -A to avoid bash arithmetic parsing
# issues with hyphenated keys (e.g. kimi-k2.5 is parsed as kimi minus k2.5)
resolve_model_id() {
  case "$1" in
    kimi-k2.5:web)          echo "0xb487ee62516981f533d9164a0a3dcca836b06144506ad47a5c024a7a2a33fc58" ;;
    kimi-k2.5)              echo "0xbb9e920d94ad3fa2861e1e209d0a969dbe9e1af1cf1ad95c49f76d7b63d32d93" ;;
    kimi-k2-thinking)       echo "0xc40b0a1ea1b20e042449ae44ffee8e87f3b8ba3d0be3ea61b86e6a89ba1a44e3" ;;
    glm-4.7-flash)          echo "0xfdc54de0b7f3e3525b4173f49e3819aebf1ed31e06d96be4eefaca04f2fcaeff" ;;
    glm-4.7)                echo "0xed0a2bc2a6e28cc87a9b55bc24b61f089f3c86b15d94e5776bc0312e0b4df34b" ;;
    qwen3-235b)             echo "0x2a71d1dfad6a7ead6e0c7f3d87d9a3c64e8bfa53f9a62fb71b83e7f49e3a6c0b" ;;
    llama-3.3-70b)          echo "0xc753061a5d2640decfbbc1d1d35744e6805015d30d32872f814a93784c627fc3" ;;
    gpt-oss-120b)           echo "0x2e7228fe07523d84307838aa617141a5e47af0e00b4eaeab1522bc71985ffd11" ;;
    *)                      echo "" ;;
  esac
}

# List available models for help text
list_models() {
  echo "    kimi-k2.5          kimi-k2.5:web"
  echo "    kimi-k2-thinking   glm-4.7-flash"
  echo "    glm-4.7            qwen3-235b"
  echo "    llama-3.3-70b      gpt-oss-120b"
}

# Parse arguments
MODEL_NAME="${1:?Usage: chat.sh <model_name> \"prompt text\" [--stream]}"
PROMPT="${2:?Usage: chat.sh <model_name> \"prompt text\" [--stream]}"
STREAM="false"

if [[ "${3:-}" == "--stream" ]]; then
  STREAM="true"
fi

# Read auth cookie
if [[ ! -f "$MORPHEUS_DIR/.cookie" ]]; then
  echo "❌ .cookie file not found. Is the proxy-router running?" >&2
  exit 1
fi
COOKIE_PASS=$(cat "$MORPHEUS_DIR/.cookie" | cut -d: -f2)

# Resolve model name to model ID
if [[ "$MODEL_NAME" == 0x* ]]; then
  MODEL_ID="$MODEL_NAME"
else
  MODEL_ID="$(resolve_model_id "$MODEL_NAME")"
  if [[ -z "$MODEL_ID" ]]; then
    echo "❌ Unknown model: $MODEL_NAME" >&2
    echo "   Available models:" >&2
    list_models >&2
    exit 1
  fi
fi

# Find active session for this model
# Query sessions and find one matching our model ID
SESSIONS_RESPONSE=$(curl -s -u "admin:$COOKIE_PASS" "${API_BASE}/blockchain/sessions" 2>/dev/null || echo "[]")

SESSION_ID=$(echo "$SESSIONS_RESPONSE" | jq -r --arg mid "$MODEL_ID" '
  if type == "array" then
    [.[] | select(.ModelAgentId == $mid or .modelAgentId == $mid or .ModelID == $mid or .modelId == $mid)] |
    first | (.Id // .id // .sessionId // .SessionId // empty)
  elif type == "object" and has("sessions") then
    [.sessions[] | select(.ModelAgentId == $mid or .modelAgentId == $mid or .ModelID == $mid or .modelId == $mid)] |
    first | (.Id // .id // .sessionId // .SessionId // empty)
  else empty end
' 2>/dev/null || true)

if [[ -z "$SESSION_ID" || "$SESSION_ID" == "null" ]]; then
  echo "❌ No active session found for model: $MODEL_NAME" >&2
  echo "   Open one first: bash skills/everclaw/scripts/session.sh open $MODEL_NAME 3600" >&2
  exit 1
fi

# Send inference request
# ⚠️ CRITICAL: session_id and model_id are HTTP HEADERS, not JSON body fields
if [[ "$STREAM" == "true" ]]; then
  curl -s -u "admin:$COOKIE_PASS" "${API_BASE}/v1/chat/completions" \
    -H "Content-Type: application/json" \
    -H "session_id: $SESSION_ID" \
    -H "model_id: $MODEL_ID" \
    -d "{
      \"model\": \"$MODEL_NAME\",
      \"messages\": [{\"role\": \"user\", \"content\": $(echo "$PROMPT" | jq -Rs .)}],
      \"stream\": true
    }"
else
  RESPONSE=$(curl -s -u "admin:$COOKIE_PASS" "${API_BASE}/v1/chat/completions" \
    -H "Content-Type: application/json" \
    -H "session_id: $SESSION_ID" \
    -H "model_id: $MODEL_ID" \
    -d "{
      \"model\": \"$MODEL_NAME\",
      \"messages\": [{\"role\": \"user\", \"content\": $(echo "$PROMPT" | jq -Rs .)}],
      \"stream\": false
    }")

  # Extract just the content from the response
  CONTENT=$(echo "$RESPONSE" | jq -r '.choices[0].message.content // empty' 2>/dev/null || true)

  if [[ -n "$CONTENT" ]]; then
    echo "$CONTENT"
  else
    # If content extraction failed, show full response for debugging
    echo "⚠️  Could not extract content. Full response:" >&2
    echo "$RESPONSE" | jq . 2>/dev/null || echo "$RESPONSE"
  fi
fi
