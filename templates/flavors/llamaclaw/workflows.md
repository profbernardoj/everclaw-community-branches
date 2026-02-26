# Workflows — LlamaClaw

## Example Use Cases

### 1. Local Setup
> "Set up Llama on my machine"

Agent evaluates hardware (GPU, RAM, disk), recommends the best model and quantization, walks through Ollama installation, and verifies everything works.

### 2. Model Selection
> "Which Llama model should I use for [task]?"

Agent evaluates the task against available models: 8B for speed, 70B for quality, CodeLlama for code. Considers hardware constraints.

### 3. Quantization Guide
> "I have 16GB VRAM — what can I run?"

Agent calculates which models and quantization levels fit the hardware, presents options ranked by quality, and recommends the best choice.

### 4. Fine-tune Evaluation
> "Is this community fine-tune safe to use?"

Agent checks: who published it, training data description, community reviews, benchmark scores, and any red flags. Recommends with caveats.

### 5. Performance Optimization
> "My inference is slow"

Agent profiles: model size vs VRAM, quantization level, context length, batch size, and hardware utilization. Suggests specific optimizations.

### 6. Benchmark Comparison
> "How does Llama 3.3 70B compare to GPT-4?"

Agent presents benchmark scores across categories (reasoning, code, math, language), noting where Llama excels and where it falls short.

### 7. Model Update
> "Should I update to the latest Llama release?"

Agent compares current deployed model against the new release: benchmark improvements, new capabilities, breaking changes, and migration steps.

### 8. Multi-Model Setup
> "I want different models for different tasks"

Agent configures model routing: lightweight model for chat, larger model for reasoning, code model for development. Sets up OpenClaw to route automatically.

### 9. Private Inference
> "I need to analyze sensitive documents"

Agent confirms local model is running (no data leaves the machine), processes the documents entirely on-device, and presents results.

### 10. Hardware Planning
> "I want to buy a GPU for local AI — what should I get?"

Agent evaluates: budget, desired models, VRAM requirements, and future-proofing. Recommends specific GPUs with price-performance analysis.
