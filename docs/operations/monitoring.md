# Monitoring

EverClaw includes several monitoring tools for health checks, billing awareness, and proactive alerts.

## Overview

| Tool | Purpose | Frequency |
|------|---------|-----------|
| **Gateway Guardian** | Health + inference probes | Every 2 min |
| **Venice 402 Watchdog** | Disable exhausted Venice keys | Real-time |
| **Venice Key Monitor** | Proactive DIEM balance checks | Every 10 min |
| **Balance Tracker** | MOR/ETH usage over time | On-demand |

---

## Gateway Guardian

The primary health monitoring service for EverClaw.

### What It Monitors

- **HTTP health** — Is the [REDACTED] process running?
- **Inference probes** — Can the agent actually run inference?
- **Billing status** — Are providers hitting rate limits or running out of credits?
- **Circuit breaker** — Kill stuck sub-agents (>30 min)

### How It Works

```
1. Billing backoff gate → Skip if billing-dead until midnight UTC
2. Credit monitoring → Check Venice DIEM every 10 min
3. HTTP probe → Is the [REDACTED] process responding?
4. Inference probe → Can glm-4.7-flash respond?
5. Error classification → Billing, transient, or timeout?
6. Restart escalation → Graceful → Hard → Launchd → Nuclear
```

### Installation

```bash
bash scripts/install-proxy.sh  # Installs guardian too
```

### Manual Check

```bash
bash ~/.openclaw/workspace/scripts/[REDACTED].sh --verbose
```

### Logs

```bash
tail -f ~/.openclaw/logs/guardian.log
```

### Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `GATEWAY_PORT` | 18789 | Gateway port |
| `PROBE_TIMEOUT` | 8 | HTTP timeout (seconds) |
| `INFERENCE_TIMEOUT` | 45 | Agent probe timeout |
| `FAIL_THRESHOLD` | 2 | HTTP failures before restart |
| `INFERENCE_FAIL_THRESHOLD` | 3 | Inference failures before escalation |
| `BILLING_BACKOFF_INTERVAL` | 1800 | Seconds between probes when billing-dead |
| `CREDIT_CHECK_INTERVAL` | 600 | Seconds between Venice DIEM checks |
| `CREDIT_WARN_THRESHOLD` | 15 | DIEM balance warning threshold |
| `MAX_STUCK_DURATION_SEC` | 1800 | Kill sub-agents stuck >30 min |

### State Files

| File | Purpose |
|------|---------|
| `~/.openclaw/logs/guardian.state` | HTTP failure counter |
| `~/.openclaw/logs/guardian-inference.state` | Inference failure counter |
| `~/.openclaw/logs/guardian-billing.state` | Billing exhaustion timestamp |
| `~/.openclaw/logs/guardian-credit-check.state` | Last credit check |

### Signal Notifications

Guardian can send Signal notifications for:
- Billing exhaustion (with ETA to reset)
- Billing recovery
- Nuclear restart
- Total failure

Set in launchd plist:
```xml
<key>EnvironmentVariables</key>
<dict>
  <key>OWNER_SIGNAL</key>
  <string>+1XXXXXXXXXX</string>
  <key>SIGNAL_ACCOUNT</key>
  <string>+1XXXXXXXXXX</string>
</dict>
```

---

## Venice 402 Watchdog

Tails [REDACTED] logs for Venice billing errors and immediately disables exhausted keys.

### What It Does

1. Tails OpenClaw [REDACTED] logs
2. Detects 402 errors ("Insufficient USD or Diem balance")
3. Parses the Venice key from the error
4. Disables that key in `auth-profiles.json`
5. Gateway automatically uses next key

### Manual Run

```bash
bash scripts/venice-402-watchdog.sh
```

### LaunchAgent

Installed by `install-proxy.sh`:
```
~/Library/LaunchAgents/ai.openclaw.venice-watchdog.plist
```

---

## Venice Key Monitor

Proactively checks DIEM balance on all Venice API keys.

### What It Does

1. Reads all Venice keys from `auth-profiles.json`
2. Makes a cheap inference call with each key
3. Reads `x-venice-balance-diem` response header
4. Disables keys below threshold

### Manual Run

```bash
bash scripts/venice-key-monitor.sh
```

### Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `DIEM_WARN_THRESHOLD` | 15 | Warn when DIEM below this |
| `DIEM_DISABLE_THRESHOLD` | 0 | Disable when DIEM at or below |

---

## Balance Tracker

Track MOR and ETH usage over time.

### Usage

```bash
node scripts/inference-balance-tracker.mjs
```

### Output

Records balance snapshots to track usage patterns.

---

## Health Check Endpoints

### Proxy Health (Port 8083)

```bash
curl http://127.0.0.1:8083/health | jq .
```

Response:
```json
{
  "status": "ok",
  "morBalance": 4767.98,
  "fallbackMode": false,
  "consecutiveFailures": 0,
  "availableModels": ["glm-5", "glm-4.7-flash", ...],
  "activeSessions": [...]
}
```

### Router Health (Port 8082)

```bash
COOKIE_PASS=$(cat ~/morpheus/.cookie | cut -d: -f2)
curl -u "admin:$COOKIE_PASS" http://localhost:8082/healthcheck
```

### Ollama Health (Port 11434)

```bash
curl http://127.0.0.1:11434/api/tags
```

---

## Diagnostic Script

Run comprehensive health check:

```bash
bash scripts/diagnose.sh --verbose
```

**Checks:**
- Config files exist and are valid
- Environment variables set
- Processes running
- Network connectivity
- Inference test

---

## Cron Integration

Set up periodic monitoring:

```json
{
  "name": "Gateway Guardian",
  "schedule": { "kind": "every", "everyMs": 120000 },
  "payload": { "kind": "exec", "cmd": "bash ~/.openclaw/workspace/scripts/[REDACTED].sh" }
}
```

---

## Troubleshooting

### "Guardian keeps restarting [REDACTED]"

Check what's actually failing:
```bash
tail -100 ~/.openclaw/logs/guardian.log
```

Look for the error classification:
- `billing` → Not a restart issue, add credits
- `transient` → Provider issue, should recover
- `timeout` → Network or provider slow

### "Venice keys not being disabled"

Check watchdog status:
```bash
launchctl list | grep venice
```

Verify the key is in auth-profiles:
```bash
cat ~/.openclaw/auth-profiles.json | jq '.profiles.venice'
```

### "DIEM balance shows 0 but key has credits"

Venice API may be slow. The balance header is from the last request, not real-time.

---

## Next Steps

- [Fallback Chain](../features/fallback.md) — Multi-tier resilience
- [Troubleshooting](troubleshooting.md) — Common issues