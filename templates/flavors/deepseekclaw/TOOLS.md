# TOOLS.md — DeepSeekClaw

## Local Deployment Options

### Ollama
```bash
# Install
curl -fsSL https://ollama.ai/install.sh | sh

# Pull DeepSeek models
ollama pull deepseek-v3        # flagship reasoning
ollama pull deepseek-coder-v2  # code-focused
ollama pull deepseek-r1        # reasoning-optimized

# Run
ollama serve                   # start server
ollama run deepseek-v3         # interactive
# API: http://localhost:11434/v1 (OpenAI-compatible)
```

### vLLM (for GPU servers)
```bash
pip install vllm
vllm serve deepseek-ai/DeepSeek-V3 --port 8000
# Better throughput for high-volume inference
```

## API Providers

### Venice.ai
- DeepSeek V3.2 available via Venice API
- Pay with DIEM tokens
- OpenAI-compatible endpoint

### Morpheus Network
- DeepSeek available through decentralized providers
- Pay with staked MOR
- Route through local proxy: `http://127.0.0.1:8083/v1`

### DeepSeek API (direct)
- `https://api.deepseek.com`
- Very low pricing: ~$0.14/M input, $0.28/M output tokens
- Sign up at platform.deepseek.com

## Required Skills

### exec (Shell Access)
- **What:** Manage local model deployment
- **Install:** Built into OpenClaw
- **Use:** Start/stop Ollama, check model status, GPU monitoring

### web_search
- **What:** Research model updates, benchmarks, techniques
- **Install:** Built into OpenClaw

## Configuration

### Model Routing
```
routing:
  # Route tasks to the best model for the job
  code:
    primary: "deepseek-coder-v2"
    fallback: "deepseek-v3"
  reasoning:
    primary: "deepseek-r1"
    fallback: "deepseek-v3"
  general:
    primary: "deepseek-v3"
    fallback: "venice/claude-opus-4-6"
  creative:
    primary: "venice/claude-opus-4-6"  # DeepSeek less strong here
    fallback: "deepseek-v3"
```

### Deployment Config
```
deployment:
  method: "ollama"           # ollama | vllm | api-only
  local_endpoint: "http://localhost:11434/v1"
  gpu_memory_gb: 0           # 0 = CPU only
  models_downloaded:
    - "deepseek-v3"
    - "deepseek-coder-v2"
```

### Cost Tracking
```
costs:
  track_inference: true
  log_path: "memory/inference-costs/"
  monthly_budget_usd: 10
  alert_at_percent: 80
```

### Quality Monitoring
```
quality:
  log_responses: false       # log model responses for quality review
  compare_models: true       # periodically compare output quality
  benchmark_frequency: "monthly"
```
