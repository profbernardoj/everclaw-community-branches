# Enable Morpheus — Decentralized Inference for PicoClaw

## Proxy Details

- **Endpoint:** `http://127.0.0.1:8083/v1`
- **Auth:** `morpheus-local`
- **Health:** `curl -sf http://127.0.0.1:8083/health`

## Models

| Name in Config | Model | Use Case |
|----------------|-------|----------|
| `morpheus-glm5` | GLM-5 | Heavy reasoning, coding (default) |
| `morpheus-flash` | GLM-4.7-flash | Fast, lightweight |
| `morpheus-kimi` | Kimi K2.5 | General purpose |

## Switch Default Model

Edit `~/.picoclaw/config.json`:
```json
{ "agents": { "defaults": { "model": "morpheus-flash" } } }
```

## Split Deployment

If the proxy runs on a different device, update `api_base` in all model entries:
```json
{ "api_base": "http://192.168.1.100:8083/v1" }
```

## Troubleshooting

- **Proxy down:** `cd ~/.everclaw && bash scripts/start.sh`
- **Timeout on tiny boards:** Proxy may need 10-15s to start on low-RAM devices
- **Network unreachable:** Check firewall allows port 8083
