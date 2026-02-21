# Enable Morpheus — Decentralized Inference for TinyClaw

## What This Does

Switches TinyClaw agents to use the EverClaw proxy for Morpheus decentralized inference.

## When To Use

Use `/enable-morpheus` to:
- Verify the proxy is running and healthy
- Check which models are available
- Switch agent model assignments

## Proxy Details

- **Endpoint:** `http://127.0.0.1:8083/v1`
- **Auth:** `morpheus-local` (Bearer token)
- **Health:** `curl -sf http://127.0.0.1:8083/health`

## Available Models

| Model | Tier | Best For |
|-------|------|----------|
| `glm-5` | HEAVY | Coding, analysis, complex reasoning |
| `glm-4.7-flash` | LIGHT | Quick responses, triage |
| `kimi-k2.5` | STANDARD | Writing, general purpose |
| `qwen3-235b` | STANDARD | Large context, multilingual |

## Team Configuration

Assign models by agent role in `~/.tinyclaw/settings.json`:

```json
{
  "agents": {
    "coder": { "provider": "openai", "model": "glm-5" },
    "writer": { "provider": "openai", "model": "kimi-k2.5" },
    "reviewer": { "provider": "openai", "model": "glm-4.7-flash" },
    "researcher": { "provider": "openai", "model": "qwen3-235b" }
  }
}
```

## Troubleshooting

- **Proxy down:** `cd ~/.everclaw && bash scripts/start.sh`
- **Wrong model:** Edit `~/.tinyclaw/settings.json` agent entries
- **Env vars missing:** `export OPENAI_BASE_URL=http://127.0.0.1:8083/v1`
