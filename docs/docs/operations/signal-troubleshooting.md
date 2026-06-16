# Signal Troubleshooting

Guide for setting up and troubleshooting Signal messaging with EverClaw/OpenClaw.

> **Note:** This guide assumes you are using OpenClaw with signal-cli's HTTP API mode (either native daemon or [bbernhard/signal-cli-rest-api](https://github.com/bbernhard/signal-cli-rest-api) container). Direct `signal-cli` CLI usage without the HTTP wrapper has different behavior.

## Requirements

| Component | Minimum Version | Notes |
|-----------|-----------------|-------|
| **signal-cli** | ≥0.14.3 | Required for SSE fix |
| **Node.js** | 20.x or 22.x | Node.js 25.x has SSE bugs on macOS |
| **Java** | 21+ | signal-cli dependency |

> **⚠️ Critical:** signal-cli versions before 0.14.3 have incompatible SSE event formats that prevent OpenClaw from receiving inbound messages.

## Installation

### macOS (Homebrew)

```bash
brew install signal-cli
signal-cli --version  # Should be ≥0.14.3
```

### Linux (Manual)

```bash
# Download latest release
VERSION=0.14.5
curl -L -o signal-cli.tar.gz \
  "https://github.com/AsamK/signal-cli/releases/download/v${VERSION}/signal-cli-${VERSION}.tar.gz"
tar xzf signal-cli.tar.gz
sudo mv signal-cli-${VERSION} /opt/signal-cli
sudo ln -sf /opt/signal-cli/bin/signal-cli /usr/local/bin/signal-cli
```

### Docker (bbernhard container)

If running in Docker or having persistent SSE issues, use the container mode:

```json
{
  "channels": {
    "signal": {
      "apiMode": "container",
      "containerUrl": "http://signal-api:8080"
    }
  }
}
```

See [bbernhard/signal-cli-rest-api](https://github.com/bbernhard/signal-cli-rest-api) for container setup.

---

## Common Issues

### Outbound works, inbound doesn't

**Symptoms:**
- Sending messages via JSON-RPC succeeds
- Replies from contacts never arrive in OpenClaw
- Logs show `TypeError: fetch failed` or SSE errors

**Cause:** signal-cli version <0.14.3 or Node.js v25 SSE bug

**Fix:**
```bash
# Upgrade signal-cli
brew upgrade signal-cli  # macOS
# or reinstall manually on Linux

# Verify version
signal-cli --version  # Must be ≥0.14.3

# Restart gateway
openclaw gateway restart
```

### NullPointerException in receive

**Log shows:**
```
java.lang.NullPointerException: Cannot invoke "...ReceiveCommand$ReceiveParams.timeout()" because "request" is null
```

**Cause:** Old signal-cli daemon still running after upgrade

**Fix:**
```bash
# Kill old daemon gracefully, then force if needed
pkill -TERM -f 'signal-cli.*daemon' 2>/dev/null || true
pkill -TERM -f 'java.*signal-cli' 2>/dev/null || true
sleep 3
pkill -KILL -f 'signal-cli' 2>/dev/null || true

# Restart gateway
openclaw gateway restart
```

> **Linux users:** If `openclaw gateway restart` isn't available, use your service manager (e.g., `systemctl restart openclaw-gateway`).

### SSE connection drops repeatedly

**Log shows:**
```
[signal] connection lost, reconnecting in 2.191s...
[signal] [default] auto-restart attempt 1/10 in 5s
```

**Possible causes:**
1. Node.js v25 on macOS (downgrade to v22 or use container mode)
2. signal-cli <0.14.3 (upgrade)
3. Network instability

**Fix:** Try container mode with WebSocket instead of SSE:
```json
{
  "channels": {
    "signal": {
      "apiMode": "container",
      "containerUrl": "http://localhost:8080"
    }
  }
}
```

### "Config file is in use by another instance"

**Cause:** Multiple signal-cli processes accessing the same account

**Fix:**
```bash
# Find and kill all signal-cli processes gracefully
pkill -TERM -f 'signal-cli' 2>/dev/null || true
pkill -TERM -f 'java.*signal-cli' 2>/dev/null || true
sleep 3
pkill -KILL -f 'signal-cli' 2>/dev/null || true

# Restart gateway (it will spawn a fresh daemon)
openclaw gateway restart
```

---

## Verification

### Check signal-cli version

```bash
# CLI version
signal-cli --version

# Running daemon version (if using HTTP API)
curl -s http://127.0.0.1:8080/api/v1/rpc \
  -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"version","id":1}'
```

### Test sending

```bash
curl -s http://127.0.0.1:8080/api/v1/rpc \
  -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"send","params":{"recipient":["+1XXXXXXXXXX"],"message":"Test"},"id":1}'
```

### Check SSE endpoint

```bash
# Should return 200 with Content-type: text/event-stream
curl -I http://127.0.0.1:8080/api/v1/events
```

### View gateway logs

```bash
tail -f ~/Library/Logs/openclaw/gateway.log | grep -i signal
```

---

## Node.js v25 SSE Bug

There's a known issue ([nodejs/node#53040](https://github.com/nodejs/node/issues/53040)) where Node.js v25 on macOS fails to properly handle SSE streams. This causes OpenClaw to connect to the signal-cli SSE endpoint but never receive events.

**Workarounds:**
1. Use Node.js 20.x or 22.x (recommended)
2. Use container mode with WebSocket
3. Wait for Node.js fix (tracked in #53040)

EverClaw's Docker images use Node.js 20, so this only affects native macOS installations with Node.js v25.

---

## Related

- [OpenClaw Signal Docs](https://docs.openclaw.ai/channels/signal)
- [signal-cli GitHub](https://github.com/AsamK/signal-cli)
- [bbernhard/signal-cli-rest-api](https://github.com/bbernhard/signal-cli-rest-api)
