# TOOLS.md — KimiClaw

## Inference Endpoints

### Venice.ai
- **Models:** `kimi-k2-5`, `kimi-k2-thinking`
- **Context:** 131K (K2.5), 262K (K2 Thinking)
- **Cost:** DIEM tokens

### Morpheus Local Proxy
- **Endpoint:** `http://127.0.0.1:8083/v1`
- **Models:** `kimi-k2.5`, `kimi-k2-thinking`
- **Cost:** Staked MOR

### Morpheus API Gateway
- **Endpoint:** `https://api.mor.org/api/v1`
- **Models:** `kimi-k2.5`
- **Cost:** API key (beta)

## Required Skills

### summarize
- **What:** Pre-process long documents before feeding to Kimi
- **Install:** Built into OpenClaw
- **Use:** When content exceeds even Kimi's context window, chunk and summarize first

### web_fetch
- **What:** Fetch full documents, articles, and reports
- **Install:** Built into OpenClaw
- **Use:** Ingest long-form content for Kimi to analyze

### nano-pdf
- Built into OpenClaw
- **Use:** Extract text from PDFs before feeding to Kimi for analysis

## Configuration

### Model Routing
```
routing:
  quick_tasks:
    model: "kimi-k2-5"
    provider: "venice"
    use_for: ["general questions", "short analysis", "summaries"]
  deep_thinking:
    model: "kimi-k2-thinking"
    provider: "venice"
    use_for: ["complex reasoning", "math", "multi-step logic", "code review"]
  long_context:
    model: "kimi-k2-thinking"
    provider: "venice"
    use_for: ["full document analysis", "codebase review", "transcript processing"]
  fallback:
    model: "venice/claude-opus-4-6"
```

### Provider Priority
```
providers:
  kimi-k2-5:
    order: ["venice", "morpheus", "mor-gateway"]
  kimi-k2-thinking:
    order: ["venice", "morpheus"]
```

### Context Management
```
context:
  # Strategy for handling very long inputs
  max_single_pass_tokens: 128000
  chunking_strategy: "overlap"   # overlap | sequential | hierarchical
  chunk_overlap_tokens: 500
  summarize_before_analysis: true  # for inputs exceeding context window
```

### Quality Monitoring
```
quality:
  log_responses: false
  track_thinking_time: true      # log how long thinking model takes
  compare_to_standard: true      # compare K2 Thinking vs K2.5 on same tasks
  log_path: "memory/model-quality/"
```
