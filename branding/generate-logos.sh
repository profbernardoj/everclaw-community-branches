#!/usr/bin/env bash
set -uo pipefail

# Generate 28 flavor logos via Venice AI image API
# Uses flux-dev model, 512x512, saves as PNG
# Compatible with bash 3.2+ (macOS)

VENICE_KEY="VENICE-INFERENCE-KEY-[REDACTED]"
API_URL="https://api.venice.ai/api/v1/images/generations"
OUTPUT_DIR="/Users/[REDACTED]/.openclaw/workspace/branding/flavor-logos"
MODEL="flux-dev"

STYLE="Minimal flat vector logo icon on pure white background, modern tech aesthetic, clean lines, no text, no words, single centered icon, professional brand mark, 2-3 colors maximum"

SUCCESS=0
FAIL=0

generate() {
  local flavor="$1"
  local desc="$2"
  local PROMPT="${STYLE}, ${desc}"
  local OUTPUT_FILE="${OUTPUT_DIR}/${flavor}-logo.png"

  if [ -f "$OUTPUT_FILE" ]; then
    echo "SKIP: $flavor (exists)"
    SUCCESS=$((SUCCESS + 1))
    return
  fi

  echo -n "Generating $flavor... "

  RESPONSE=$(curl -s -X POST "$API_URL" \
    -H "Authorization: Bearer $VENICE_KEY" \
    -H "Content-Type: application/json" \
    -d "{
      \"prompt\": $(echo "$PROMPT" | node -e "let d='';process.stdin.on('data',c=>d+=c);process.stdin.on('end',()=>process.stdout.write(JSON.stringify(d)))"),
      \"model\": \"$MODEL\",
      \"n\": 1,
      \"size\": \"512x512\",
      \"response_format\": \"b64_json\"
    }" 2>&1)

  if echo "$RESPONSE" | grep -q '"error"'; then
    echo "FAILED"
    FAIL=$((FAIL + 1))
    sleep 2
    return
  fi

  B64=$(echo "$RESPONSE" | node -e "
    let d='';
    process.stdin.on('data',c=>d+=c);
    process.stdin.on('end',()=>{
      try {
        const j=JSON.parse(d);
        if(j.data&&j.data[0]&&j.data[0].b64_json){
          process.stdout.write(j.data[0].b64_json);
        } else { process.exit(1); }
      } catch(e){ process.exit(1); }
    });
  " 2>/dev/null)

  if [ -n "$B64" ]; then
    echo "$B64" | base64 -d > "$OUTPUT_FILE"
    SIZE=$(wc -c < "$OUTPUT_FILE" | tr -d ' ')
    echo "OK (${SIZE} bytes)"
    SUCCESS=$((SUCCESS + 1))
  else
    echo "FAILED (decode)"
    FAIL=$((FAIL + 1))
  fi

  sleep 3
}

# Crypto/Blockchain
generate "bitcoinclaw" "orange Bitcoin-inspired claw mark with subtle circuit pattern, crypto gold accent"
generate "ethereumclaw" "purple and blue diamond-shaped claw with Ethereum-inspired geometric facets"
generate "solanaclaw" "gradient purple to teal claw with speed lines suggesting fast transactions"
generate "arbclaw" "blue claw with layered stacking effect suggesting L2 scaling"
generate "baseclaw" "blue claw with clean base platform underneath, Coinbase blue tones"

# Model flavors
generate "glmclaw" "deep blue claw with Chinese-inspired geometric pattern, AI brain motif"
generate "grokclaw" "black and white claw with X-shaped negative space, bold contrast"
generate "kimiclaw" "moonlight silver and blue claw with crescent moon accent, sleek"
generate "llamaclaw" "warm earth-toned claw with llama silhouette integrated, Meta purple accent"
generate "minimaxclaw" "red and black claw with minimalist max-min arrows, compact design"
generate "deepseekclaw" "ocean blue claw with deep water wave pattern, submarine depth feel"
generate "morpheusclaw" "green Matrix-style claw with digital rain accent, cyberpunk feel"

# Use case flavors
generate "familyclaw" "warm coral and soft blue claw cradling a small heart, family warmth"
generate "familyofficeclaw" "gold and navy claw with shield motif, wealth management prestige"
generate "investclaw" "green claw with upward trending arrow integrated, financial growth"
generate "vcclaw" "dark blue claw with diamond gem shape, venture capital prestige"
generate "friendclaw" "bright teal claw with two interlocking curves suggesting connection"
generate "emailclaw" "blue claw with envelope negative space, communication theme"
generate "officeclaw" "slate gray claw with briefcase silhouette, professional productivity"
generate "homeclaw" "warm green claw with house roofline integrated, smart home feel"
generate "bookingclaw" "coral and white claw with calendar grid accent, travel booking"
generate "briefingclaw" "navy claw with document clipboard shape, executive briefing"
generate "travelclaw" "sky blue claw with compass rose or airplane trail accent"

# Platform flavors
generate "appleclaw" "silver and space gray claw with Apple-inspired smooth curves, premium feel"
generate "androidclaw" "green claw with robotic geometric elements, Android green"
generate "linuxclaw" "black and yellow claw with penguin-inspired shape, Linux tux accent"
generate "windowsclaw" "blue claw with four-pane window grid integrated subtly"

# Meta
generate "installopenclaw" "vibrant gradient claw from blue to purple, gateway portal feel, welcoming"

echo ""
echo "Done: $SUCCESS succeeded, $FAIL failed"
echo "Output: $OUTPUT_DIR"
