# Enable Morpheus — Decentralized Inference for ZeroClaw

## Proxy

- **Endpoint:** `http://127.0.0.1:8083/v1`
- **Auth:** `morpheus-local`
- **Provider URL:** `custom:http://127.0.0.1:8083/v1`

## Models

| Config Key | Model | Tier |
|------------|-------|------|
| `glm5` | GLM-5 (default) | HEAVY |
| `flash` | GLM-4.7-flash | LIGHT |
| `kimi` | Kimi K2.5 | STANDARD |
| `qwen` | Qwen3-235b | STANDARD |

## Switch Model

Edit `~/.zeroclaw/config.toml`:
```toml
default_model = "glm-4.7-flash"    # fast mode
```

## Switch Back to Another Provider

```toml
default_provider = "anthropic"    # or any of ZeroClaw's 70+ channels
```

## Per-Agent Override

```toml
[agents.my-agent]
provider = "custom:http://127.0.0.1:8083/v1"
model = "glm-5"
```

## Troubleshooting

- **Proxy down:** `cd ~/.everclaw && bash scripts/start.sh`
- **TOML conflict:** If duplicate `default_provider`, remove the old one (last wins)
- **Docker:** Use `custom:http://host.docker.internal:8083/v1` as provider URL
