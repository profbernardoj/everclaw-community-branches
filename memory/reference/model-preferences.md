---
tags: [models, preferences, inference, david]
created: 2026-02-15
updated: 2026-02-21
status: active
---
# David's Model Preferences

- **DO NOT use:** llama-3.3-70b, deepseek-v3.2 as backup models
- **Open-source first:** Morpheus models handle everything possible, Claude only as fallback
- GLM-5: default for most work (free via Morpheus, Opus 4.5 level quality)
- GLM 4.7 Flash: trivial tasks (free, fast)
- Claude 4.6: fallback only when GLM-5 can't complete the task (expensive)
- Cron jobs should use `morpheus/glm-5` (migrated from kimi-k2.5)
- MiniMax-M2.5: available but unreliable — latency issues, broken streaming. Revisit later.
- **Don't highlight Llama 3.3** — David considers it outdated. Focus on Kimi K2.5 and GLM models.
