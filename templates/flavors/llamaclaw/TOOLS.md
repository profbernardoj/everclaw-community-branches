# TOOLS.md — LlamaClaw

## Local Deployment

### Ollama (recommended for most users)
```bash
# Install
curl -fsSL https://ollama.ai/install.sh | sh

# Pull Llama models
ollama pull llama3.3:70b       # flagship (needs ~40GB VRAM or lots of RAM)
ollama pull llama3.3:8b        # smaller, fast
ollama pull codellama:34b      # code-focused

# Run
ollama serve                   # start server (API at :11434)
ollama run llama3.3:8b         # interactive
```

### llama.cpp (maximum control)
```bash
# Build from source
git clone https://github.com/ggerganov/llama.cpp
cd llama.cpp && make -j

# Run with GGUF model
./llama-server -m model.gguf -c 4096 --port 8080
# Supports: Apple Silicon Metal, CUDA, Vulkan, CPU
```

### vLLM (high-throughput server)
```bash
pip install vllm
vllm serve meta-llama/Llama-3.3-70B-Instruct --port 8000
# Best for: multi-user serving, batched inference
```

## Required Skills

### exec (Shell Access)
- **What:** Manage local model deployment, GPU monitoring
- **Install:** Built into OpenClaw
- **Use:** Start/stop servers, check hardware, run benchmarks

### web_search
- **What:** Track community releases, fine-tunes, benchmarks
- **Install:** Built into OpenClaw

## Key Resources

### Model Sources
- `https://huggingface.co/meta-llama` — official Meta models
- `https://huggingface.co/models?sort=trending&search=llama` — community fine-tunes
- `https://ollama.ai/library` — Ollama model library

### Benchmarking
- `https://huggingface.co/spaces/open-llm-leaderboard/open_llm_leaderboard` — Open LLM Leaderboard
- `https://lmarena.ai` — Chatbot Arena (human preference ratings)

## Configuration

### Deployed Models
```
models:
  - name: "llama3.3:8b"
    runtime: "ollama"
    quantization: "Q4_K_M"
    status: "active"
    use_for: ["quick tasks", "chat", "simple code"]
  - name: "llama3.3:70b"
    runtime: "ollama"
    quantization: "Q4_K_M"
    status: "active"
    use_for: ["complex reasoning", "long analysis", "code review"]
```

### Hardware
```
hardware:
  gpu: ""                     # e.g., "RTX 4090 24GB", "Apple M4 Max 128GB"
  vram_gb: 0
  system_ram_gb: 0
  storage_models_gb: 0        # disk space for model files
```

### Model Routing
```
routing:
  light:
    model: "llama3.3:8b"
    max_context: 8192
  heavy:
    model: "llama3.3:70b"
    max_context: 4096         # shorter context for larger model on limited VRAM
  code:
    model: "codellama:34b"
    max_context: 16384
  fallback:
    model: "venice/claude-opus-4-6"
    use_when: "local models can't complete the task"
```

### Quantization Guide
```
# Quick reference for GGUF quantization levels
quantization:
  Q8_0: "Best quality, largest size (~1x model size)"
  Q5_K_M: "Great quality, moderate size (~0.65x)"
  Q4_K_M: "Good quality, recommended default (~0.5x)"
  Q3_K_M: "Acceptable quality, small size (~0.4x)"
  Q2_K: "Noticeable quality loss, minimum size (~0.3x)"
  # Rule of thumb: use the highest quantization your hardware can handle
```
