# Everclaw — Available Models

Models available on the Morpheus decentralized inference network (Base mainnet). Model IDs are blockchain-assigned hashes that identify the model on-chain.

## Text Generation Models

| Model | Model ID | Description |
|-------|----------|-------------|
| kimi-k2.5:web | `0xb487ee62516981f533d9164a0a3dcca836b06144506ad47a5c024a7a2a33fc58` | Moonshot's Kimi K2.5 with web search capability. Strong reasoning + real-time web access. |
| kimi-k2.5 | `0xbb9eaf3df30bbada0a6e3bdf3c836c792e3be34a64e68832874bbf0de7351e43` | Moonshot's Kimi K2.5 base model. High-quality general reasoning. |
| kimi-k2-thinking | `0xc40b937ae4b89e8680520070e48e6b507b869e6010429c7da0fe1e3c0c0f5436` | Kimi K2 with extended thinking/chain-of-thought. Best for complex reasoning tasks. |
| glm-4.7-flash | `0xfdc5a596cf66236acb19c2825b7e4c3e48c2c463a183e3df4a8b46dc7e5b1a0e` | Zhipu's GLM-4.7 Flash — fast, efficient model for quick tasks. Low cost per inference. |
| glm-4.7 | `0xed0a70b5e93cb9389c498e16837a96012e41baabde942dfc11ada58877c27b2a` | Zhipu's GLM-4.7 full model. Better quality than Flash, slower. |
| qwen3-235b | `0x2a716a21c89a018e6e8e7e5f8a38505adff2e47bdd1be09f3e98e1a45c5ff76c` | Alibaba's Qwen3 235B parameter model. Massive model, strong multilingual support. |
| qwen3-coder-480b | `0x4709f1237a3e0faacbe09e8988e2902a2bca88e6470e7e7a8e4708e2c1b7ee74` | Qwen3 Coder 480B — specialized for code generation and analysis. Very large model. |
| hermes-3-llama-3.1-405b | `0x7e14da4e80529ca44e5e052ba855e7e6b5071635c0014e510e5be8493fabf54d` | NousResearch's Hermes 3 based on Llama 3.1 405B. Strong instruction following, uncensored. |
| llama-3.3-70b | `0xc75321f1a21f09d9b8a0e2bab6c4fa942e6e5e85fc5e2c2e3f5d5f46c7e5a37b` | Meta's Llama 3.3 70B. Good balance of speed and quality. |
| gpt-oss-120b | `0x2e72a1b82478928e3481bab7f92e90f6a750f34c71da5e4b2ee54e7a98b2c231` | Open-source GPT-style 120B model. General purpose. |
| venice-uncensored | `0xa003c4fba6bdb87b5a05c8b2c1657db8270827db0e87fcc2eaef17029aa01e6b` | Venice AI uncensored model. No content filtering or refusal behavior. |

## Speech & Audio Models

| Model | Model ID | Description |
|-------|----------|-------------|
| whisper-v3-large-turbo | `0x3e4f8c1a2b5d6e7f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7` | OpenAI Whisper V3 Large Turbo — speech-to-text transcription. Fast and accurate. |
| tts-kokoro | `0x4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5` | Kokoro TTS — text-to-speech synthesis. Natural-sounding voice output. |

## Embedding Models

| Model | Model ID | Description |
|-------|----------|-------------|
| text-embedding-bge-m3 | `0x5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6` | BGE-M3 text embedding model. Multilingual, multi-granularity embeddings for RAG and search. |

## Notes

- Model IDs are determined by the blockchain and may change if providers re-register models
- Not all models have providers available at all times — check `/blockchain/models` for current availability
- The `models-config.json` file must include an entry for every model you want to use
- Use `/v1/models` endpoint to see models that the router currently knows about
- Model availability and pricing depends on active providers
- To discover new models: `curl -s -u "admin:$COOKIE_PASS" http://localhost:8082/blockchain/models | jq .`

## Recommended Models for Different Tasks

| Task | Recommended Model |
|------|-------------------|
| General chat | kimi-k2.5, glm-4.7 |
| Web-connected queries | kimi-k2.5:web |
| Complex reasoning | kimi-k2-thinking, qwen3-235b |
| Code generation | qwen3-coder-480b |
| Fast/cheap queries | glm-4.7-flash, llama-3.3-70b |
| Uncensored content | venice-uncensored, hermes-3-llama-3.1-405b |
| Speech-to-text | whisper-v3-large-turbo |
| Text-to-speech | tts-kokoro |
| Embeddings/RAG | text-embedding-bge-m3 |
