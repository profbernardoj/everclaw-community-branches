# TOOLS.md — GLMClaw

## Inference Endpoints

### Morpheus Local Proxy (preferred)
- **Endpoint:** `http://127.0.0.1:8083/v1`
- **Models:** `glm-5`, `glm-4.7-flash`
- **Cost:** Staked MOR (owned inference)
- **Health check:** `curl http://127.0.0.1:8083/v1/models`

### Morpheus API Gateway
- **Endpoint:** `https://api.mor.org/api/v1`
- **Models:** `glm-5`, `glm-5:web`, `glm-4.7-flash`
- **Cost:** API key (beta)

### Zhipu API (direct)
- **Endpoint:** `https://open.bigmodel.cn/api`
- **Models:** GLM-4 series, GLM-5
- **Sign up:** open.bigmodel.cn

### Local Deployment (Ollama)
```bash
ollama pull glm4               # GLM-4 (available on Ollama)
ollama serve
# API: http://localhost:11434/v1
```

## Required Skills

### exec (Shell Access)
- **What:** Manage local model deployment, Morpheus node
- **Install:** Built into OpenClaw

### web_search
- **What:** Research model updates, Zhipu news, benchmarks
- **Install:** Built into OpenClaw

## Configuration

### Model Routing
```
routing:
  # GLM 4.7 Flash for speed, GLM-5 for quality
  light_tasks:
    model: "glm-4.7-flash"
    provider: "morpheus"      # morpheus | mor-gateway | zhipu
    use_for: ["quick questions", "simple code", "translations", "summaries"]
  heavy_tasks:
    model: "glm-5"
    provider: "morpheus"
    use_for: ["complex reasoning", "long analysis", "code architecture", "research"]
  fallback:
    model: "venice/claude-opus-4-6"
    use_when: "GLM can't complete the task or quality is insufficient"
```

### Provider Priority
```
providers:
  order:
    - "morpheus"              # local P2P (owned inference)
    - "mor-gateway"           # Morpheus API Gateway
    - "zhipu"                 # direct API (if configured)
    - "venice"                # fallback
```

### Quality Monitoring
```
quality:
  log_responses: false
  compare_to_baseline: true   # periodically compare GLM vs Claude on same prompts
  track_failures: true        # log tasks where GLM failed and fallback was needed
  log_path: "memory/model-quality/"
```

### Bilingual Config
```
bilingual:
  primary_language: "en"
  secondary_language: "zh"
  auto_translate: false       # auto-translate responses if asked in other language
  chinese_sources:
    - "36kr.com"              # Chinese tech news
    - "zhihu.com"             # Chinese Q&A
```
