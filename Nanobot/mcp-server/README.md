# Morpheus Status MCP Server

An MCP (Model Context Protocol) server that exposes EverClaw proxy status and control as tools for Nanobot agents.

## Planned Tools

| Tool | Description |
|------|-------------|
| `morpheus_health` | Check proxy health and available models |
| `morpheus_models` | List available Morpheus models with tiers |
| `morpheus_balance` | Check MOR token balance and staking status |
| `morpheus_switch_model` | Switch the default inference model |

## Usage (once implemented)

Add to your `nanobot.yaml`:

```yaml
agents:
  main:
    mcpServers:
      - name: morpheus-status
        command: node
        args: ["~/.everclaw/nanobot/mcp-server/index.mjs"]
```

## Status

**Community TODO** — the MCP server interface is defined above. The implementation (`index.mjs`) needs to be built using the `@modelcontextprotocol/sdk` package.

The proxy health endpoint is at `http://127.0.0.1:8083/health` — the MCP server would wrap this (and wallet/staking commands) into MCP tool calls.

## Contributing

PRs welcome! The implementation needs:
- MCP SDK setup (`@modelcontextprotocol/sdk`)
- HTTP calls to the EverClaw proxy health endpoint
- Optional: wallet balance queries via `everclaw-wallet.mjs`

## License

MIT
