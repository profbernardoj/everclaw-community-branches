# TOOLS.md — MiniMaxClaw

## Inference Endpoints

### Morpheus API Gateway
- **Endpoint:** `https://api.mor.org/api/v1`
- **Models:** `MiniMax-M2.5`, `MiniMax-M2.5:web`
- **Cost:** API key (beta)
- **Note:** Web variant has internet search capability

### Venice.ai
- **Models:** `minimax-m21` (MiniMax M2.1)
- **Cost:** DIEM tokens

### MiniMax API (direct)
- **Endpoint:** `https://api.minimaxi.chat/v1`
- **Models:** Full MiniMax suite including multimodal
- **Sign up:** platform.minimaxi.com
- **Note:** Direct API has lowest latency and full multimodal support

## Required Skills

### web_search
- **What:** Research model updates, benchmarks, MiniMax news
- **Install:** Built into OpenClaw

### web_fetch
- **What:** Fetch detailed content for analysis tasks
- **Install:** Built into OpenClaw

### summarize
- **What:** Summarize content when MiniMax is used for analysis
- **Install:** Built into OpenClaw

## Configuration

### Model Routing
```
routing:
  standard:
    model: "MiniMax-M2.5"
    provider: "mor-gateway"
    use_for: ["creative writing", "analysis", "long-form generation"]
  web_search:
    model: "MiniMax-M2.5:web"
    provider: "mor-gateway"
    use_for: ["research with web access", "current events", "fact-checking"]
  fast:
    model: "minimax-m21"
    provider: "venice"
    use_for: ["quick tasks when latency matters"]
  fallback:
    model: "venice/claude-opus-4-6"
    use_when: "MiniMax unavailable or task needs different strengths"
```

### Provider Priority
```
providers:
  order:
    - "mor-gateway"           # Morpheus Gateway (decentralized)
    - "venice"                # Venice (M2.1)
    - "minimax-direct"        # Direct API (if configured)
```

### Quality Monitoring
```
quality:
  log_responses: false
  track_latency: true          # important for MiniMax — latency can vary
  latency_baseline_ms: 5000    # expected response time
  latency_alert_multiplier: 2  # alert if >2x baseline
  compare_to_alternatives: true
  log_path: "memory/model-quality/"
```

### Multimodal Config (if using direct API)
```
multimodal:
  audio_synthesis: false       # MiniMax TTS capabilities
  image_analysis: false        # Vision capabilities
  video_understanding: false   # Video analysis
  # These require direct API access — not available through Morpheus Gateway
```
