# EverClaw Image Generation Setup

**Created:** February 20, 2026
**Purpose:** Generate 28 flavor logos using Venice API

---

## Venice API Configuration

**API Key:** Stored in 1Password (Venice API Key)
**Endpoint:** `https://api.venice.ai/api/v1/image/generate`
**Model:** Z-Image Turbo

---

## Image Generation Parameters

Based on Venice API docs:

```bash
curl -X POST "https://api.venice.ai/api/v1/image/generate" \
  -H "Authorization: Bearer VENICE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "z-image-turbo",
    "prompt": "DESCRIPTION",
    "width": 1024,
    "height": 1024,
    "steps": 30,
    "style_preset": "photographic" | "digital-art" | "3d-model"
  }'
```

---

## EverClaw Master Brand

**Concept:** Elephant-inspired logo
- Elephants represent wisdom, memory, longevity
- Trunk raised = good fortune
- Perfect for AI agent brand ("never forgets")

**Prompt Template:**
```
Majestic elephant logo for EverClaw AI brand, minimalist design, 
wisdom and memory symbolism, elegant curves, modern tech aesthetic, 
deep blue and purple gradient colors, clean professional look, 
white background, digital art style, iconic and memorable
```

---

## 28 Flavor Logos - Queue

### Platform Flavors (4)
1. BitcoinClaw - Elephant + Bitcoin orange/gold
2. EthereumClaw - Elephant + Ethereum purple/blue
3. BaseClaw - Elephant + Base blue
4. SolanaClaw - Elephant + Solana gradient

### Protocol Flavors (1)
5. MorpheusClaw - Elephant + Morpheus purple/green

### AI Model Flavors (6)
6. GLMClaw - Elephant + Chinese aesthetic
7. KamiClaw - Elephant + Japanese minimalist
8. GrokClaw - Elephant + X/Twitter aesthetic
9. LlamaClaw - Elephant + Open source green
10. MiniMaxClaw - Elephant + Modern tech blue
11. DeepSeekClaw - Elephant + Cost-effective green

### Use Case Flavors (10)
12. FamilyClaw - Elephant + Family warm colors
13. FamilyOfficeClaw - Elephant + Wealth gold/navy
14. InvestClaw - Elephant + Finance green/blue
15. VCIClaw - Elephant + Venture capital blue
16. FriendClaw - Elephant + Social pink/purple
17. EmailClaw - Elephant + Productivity blue
18. OfficeClaw - Elephant + Professional gray/blue
19. HomeClaw - Elephant + Smart home teal
20. BookingClaw - Elephant + Travel blue/teal
21. BriefingClaw - Elephant + News/media red

### Platform Flavors (4)
22. AppleClaw - Elephant + Apple white/silver
23. AndroidClaw - Elephant + Android green
24. LinuxClaw - Elephant + Linux penguin-inspired
25. WindowsClaw - Elephant + Windows blue

### Entry Point (1)
26. InstallOpenClaw - Elephant + Gateway/open aesthetic

### Additional (from earlier list)
27. HomeClaw - Already in use case flavors
28. BookingClaw - Already in use case flavors

---

## Scheduled Generation

**Time:** 12:00 PM CST today (February 20, 2026)
**After:** InstallOpenClaw.xyz launch
**Order:** Master EverClaw logo first, then flavor logos

---

## Output Format

- Size: 1024x1024
- Style: Digital art, minimalist
- Format: PNG
- Storage: `~/.openclaw/workspace/branding/logos/`