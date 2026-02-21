# Enable Morpheus — Decentralized Inference for NullClaw

## Proxy

- **Endpoint:** `http://127.0.0.1:8083/v1`
- **Auth:** `morpheus-local`
- **Provider name:** `morpheus` (in NullClaw config)

## Models

| Model | Tier | Best For |
|-------|------|----------|
| `glm-5` | HEAVY | Coding, analysis, reasoning (default) |
| `glm-4.7-flash` | LIGHT | Quick tasks, triage |
| `kimi-k2.5` | STANDARD | Writing, general purpose |
| `qwen3-235b` | STANDARD | Large context, multilingual |

## Switch Provider

To switch back to another provider:
```bash
# Edit ~/.nullclaw/config.json
"default_provider": "anthropic"  # or any of NullClaw's 22+ providers
```

Per-agent override:
```json
{
  "agents": {
    "my-agent": {
      "model": { "primary": "glm-5", "provider": "morpheus" }
    }
  }
}
```

## Troubleshooting

- **Proxy down:** `cd ~/.everclaw && bash scripts/start.sh`
- **nullclaw doctor:** Shows provider health including morpheus
- **Firewall:** Ensure localhost:8083 is accessible
