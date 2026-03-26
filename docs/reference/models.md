# Models Reference

Models available on the [REDACTED] decentralized inference network. Availability changes as providers join and leave — check `/blockchain/models` for current status.

## Quick Check

```bash
# Via proxy (shows refreshed models)
curl http://localhost:8083/v1/models | jq '.data[].id'

# Via router (raw blockchain data)
curl -s -u "admin:$(cat ~/morpheus/.cookie | cut -d: -f2)" \
  http://localhost:8082/blockchain/models | jq '.models[].Name' | sort
```

---

## GLM Family

Zhipu AI's GLM models — strong general reasoning, Chinese/English bilingual.

| Model | P2P | Gateway | Description |
|-------|-----|---------|-------------|
| `glm-5` | ✅ | ✅ | **Best quality** GLM, Opus 4.5-level reasoning |
| `glm-5:web` | ✅ | ✅ | GLM-5 with web search |
| `glm-4.7` | ✅ | ✅ | Previous generation, balanced |
| `glm-4.7:web` | ✅ | ✅ | GLM-4.7 with web search |
| `glm-4.7-flash` | ✅ | ✅ | **Fast**, lightweight, cheap |
| `glm-4.7-flash:web` | ✅ | ✅ | Flash with web search |
| `glm-4.7-thinking` | ✅ | ❌ | Extended thinking/chain-of-thought |
| `glm-4.7-thinking:web` | ✅ | ❌ | Thinking with web search |
| `glm-4.6` | ✅ | ✅ | Older generation |
| `glm-4.6:web` | ✅ | ✅ | GLM-4.6 with web search |

**Recommended:**
- `glm-5` for best quality
- `glm-4.7-flash` for speed/cost

---

## Kimi Family

Moonshot AI's Kimi models — strong reasoning with web search variants.

| Model | P2P | Gateway | Description |
|-------|-----|---------|-------------|
| `kimi-k2.5` | ✅ | ✅ | High-quality general reasoning |
| `kimi-k2.5:web` | ✅ | ✅ | Kimi K2.5 with web search |
| `kimi-k2-thinking` | ✅ | ❌ | Extended thinking, best for complex tasks |

**Recommended:**
- `kimi-k2.5` for general use
- `kimi-k2-thinking` for complex reasoning

---

## Qwen Family

Alibaba's Qwen models — massive scale, strong multilingual.

| Model | P2P | Gateway | Description |
|-------|-----|---------|-------------|
| `qwen3-235b` | ✅ | ❌ | 235B parameter model, multilingual |
| `qwen3-next-80b` | ✅ | ❌ | 80B next-generation |
| `qwen3-coder-480b-a35b-instruct` | ✅ | ❌ | 480B code specialist (MoE) |

**Recommended:**
- `qwen3-coder-480b-a35b-instruct` for code

---

## Llama Family

Meta's Llama models — open-weights, good balance.

| Model | P2P | Gateway | Description |
|-------|-----|---------|-------------|
| `llama-3.3-70b` | ✅ | ❌ | Llama 3.3 70B, good balance |
| `llama-3.2-3b` | ✅ | ❌ | Small, fast |

---

## Other Models

| Model | P2P | Gateway | Description |
|-------|-----|---------|-------------|
| `gpt-oss-120b` | ✅ | ❌ | Open-source GPT-style 120B |
| `mistral-31-24b` | ✅ | ❌ | Mistral 31B, fast |
| `MiniMax-M2.5` | ✅ | ✅ | MiniMax general model |
| `hermes-3-llama-3.1-405b` | ✅ | ❌ | Hermes 3 405B, uncensored |
| `hermes-4-14b` | ✅ | ❌ | Hermes 4 14B |
| `venice-uncensored` | ✅ | ❌ | Dolphin-Mistral, no content filtering |

---

## Audio Models

| Model | P2P | Gateway | Description |
|-------|-----|---------|-------------|
| `whisper-v3-large-turbo` | ✅ | ❌ | Speech-to-text transcription |
| `tts-kokoro` | ✅ | ❌ | Text-to-speech synthesis |

---

## Embedding Models

| Model | P2P | Gateway | Description |
|-------|-----|---------|-------------|
| `text-embedding-bge-m3` | ✅ | ❌ | Multilingual embeddings for RAG |

---

## Model IDs

Blockchain-assigned model IDs (may change if providers re-register):

| Model | Model ID |
|-------|----------|
| glm-5 | `0x2034b95f87b6d68299aba1fdc381b89e43b9ec48609e308296c9ba067730ec54` |
| kimi-k2.5 | `0xbb9eaf3df30bbada0a6e3bdf3c836c792e3be34a64e68832874bbf0de7351e43` |
| kimi-k2.5:web | `0xb487ee62516981f533d9164a0a3dcca836b06144506ad47a5c024a7a2a33fc58` |
| glm-4.7-flash | `0xfdc5a596cf66236acb19c2825b7e4c3e48c2c463a183e3df4a8b46dc7e5b1a0e` |

To get all model IDs:
```bash
curl -s -u "admin:$(cat ~/morpheus/.cookie | cut -d: -f2)" \
  http://localhost:8082/blockchain/models | jq '.models[] | {Name, Id}'
```

---

## Model Selection Guide

| Use Case | Recommended Model |
|----------|-------------------|
| General chat | `glm-5`, `kimi-k2.5` |
| Fast/cheap | `glm-4.7-flash` |
| Complex reasoning | `kimi-k2-thinking`, `glm-4.7-thinking` |
| Web search | `glm-5:web`, `kimi-k2.5:web` |
| Code generation | `qwen3-coder-480b-a35b-instruct` |
| Multilingual | `qwen3-235b`, `glm-5` |
| Uncensored | `venice-uncensored`, `hermes-3-llama-3.1-405b` |
| Speech-to-text | `whisper-v3-large-turbo` |
| Text-to-speech | `tts-kokoro` |
| Embeddings/RAG | `text-embedding-bge-m3` |

---

## Notes

- Model IDs are blockchain-assigned and may change
- Not all models have providers at all times
- `:web` variants add real-time web search
- P2P models require staked MOR
- Gateway models require API key

---

## Next Steps

- [Inference](../features/inference.md) — How to use models
- [API Reference](api.md) — Endpoint documentation