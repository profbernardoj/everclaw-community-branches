#!/bin/bash
set -euo pipefail

# Everclaw Chat — Send inference through an active session
# Usage: ./chat.sh <model_name> "prompt text" [--stream]
#
# ⚠️ session_id and model_id are HTTP HEADERS, not JSON body fields.
# This script handles that correctly.

MORPHEUS_DIR="$HOME/morpheus"
API_BASE="http://localhost:8082"

# Model name → model ID mapping (must match session.sh)
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
  MODEL_ID="${MODEL_IDS[$MODEL_NAME]:-}"
  if [[ -z "$MODEL_ID" ]]; then
    echo "❌ Unknown model: $MODEL_NAME" >&2
    echo "   Available models:" >&2
    for key in "${!MODEL_IDS[@]}"; do
      echo "     $key" >&2
    done
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
