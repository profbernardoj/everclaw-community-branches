# Workflows — GLMClaw

## Example Use Cases

### 1. Model Status
> "Are my GLM models running?"

Agent checks all configured endpoints (local Morpheus, gateway, direct API), reports which models are available, and tests response quality with a quick prompt.

### 2. Smart Routing
> "I need to analyze this document — which model should I use?"

Agent evaluates task complexity and recommends GLM-5 for deep analysis or Flash for quick summaries. Routes accordingly.

### 3. Chinese-English Translation
> "Translate this article from Chinese tech media"

Agent uses GLM's bilingual strength to translate with proper technical terminology and cultural context preserved.

### 4. Code Generation
> "Write a REST API in Python"

Agent routes to GLM-5 for code generation, producing well-structured code with documentation and error handling.

### 5. Model Comparison
> "Compare GLM-5 to Claude on this reasoning task"

Agent runs the same prompt through both models, presents both outputs side by side, and notes quality differences objectively.

### 6. Cost Analysis
> "How much am I saving with Morpheus GLM vs OpenAI?"

Agent calculates: inference volume, equivalent OpenAI/Anthropic pricing, Morpheus cost (MOR staking), and net savings.

### 7. Local Deployment
> "Set up GLM locally on my machine"

Agent guides through Ollama setup, model download, configuration, and integration with OpenClaw as a model provider.

### 8. Chinese Tech Research
> "What's happening in China's AI industry this week?"

Agent leverages GLM's Chinese language capabilities to search and summarize Chinese tech media, presenting key developments with context.
