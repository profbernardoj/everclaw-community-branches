# lite-proxy — Anthropic→OpenAI API Bridge

A lightweight bridge that translates Anthropic API format (Claude) to OpenAI API format (Morpheus).

## Why

NanoClaw's internal code may call models using Anthropic's API format (`/v1/messages` with `claude-*` model names). This bridge lets you drop in Morpheus models as replacements without changing NanoClaw's code.

## How It Works

```
NanoClaw → lite-proxy (port 8084) → EverClaw proxy (port 8083) → Morpheus
         Anthropic format           OpenAI format                 P2P inference
```

The bridge:
1. Accepts Anthropic `/v1/messages` requests
2. Translates to OpenAI `/v1/chat/completions` format
3. Maps model names: `claude-3.5-sonnet` → `glm-5`, `claude-3-haiku` → `glm-4.7-flash`
4. Forwards to the EverClaw proxy
5. Translates the response back to Anthropic format

## Usage

```bash
node bridge.mjs
```

Configure via `config.json`:

```json
{
  "listen": "127.0.0.1:8084",
  "upstream": "http://127.0.0.1:8083/v1",
  "modelMap": {
    "claude-3.5-sonnet": "glm-5",
    "claude-3-haiku": "glm-4.7-flash",
    "claude-3-opus": "glm-5",
    "claude-sonnet-4": "glm-5",
    "claude-haiku-4": "glm-4.7-flash"
  }
}
```

## Status

**Placeholder** — the bridge implementation (`bridge.mjs`) is a community TODO. The config and architecture are defined; contributions welcome.

## Contributing

The bridge needs:
- `/v1/messages` → `/v1/chat/completions` request translation
- Response format translation (Anthropic response → OpenAI response)
- Streaming support (`text/event-stream` format differences)
- Error mapping

PRs welcome!

## License

MIT
