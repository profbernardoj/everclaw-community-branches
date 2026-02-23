---
tags: [lessons, debugging, infrastructure, gotchas]
created: 2026-02-11
updated: 2026-02-21
status: active
---
# Lessons Learned

## Morpheus & Provider Issues

### Morpheus models need reasoning: false in OpenClaw config (2026-02-11)
All Morpheus provider models (kimi-k2.5, kimi-k2-thinking, glm-4.7-flash) must have `"reasoning": false` in openclaw.json. The upstream litellm rejects the `reasoning_effort` parameter — if set to true, cron jobs using Morpheus models fail with HTTP 400. Fixed via config.patch.

### Morpheus Proxy Error Classification (2026-02-11)
Morpheus infrastructure failures (502s) must return `type: "server_error"` not `"billing"` — otherwise OpenClaw triggers extended cooldown and cascades across all providers.

### Venice billing backoff config — 1h not 5h (2026-02-14)
Applied `auth.cooldowns.billingBackoffHoursByProvider.venice: 1` (down from default 5h). Also `billingMaxHours: 6`, `failureWindowHours: 12`. DIEM resets daily at midnight UTC — 1h backoff means keys get retried promptly instead of being locked out for most of the day.

### Venice DIEM credits (2026-02-12)
Venice uses "DIEM" as credit unit (1:1 USD). When exhausted, returns billing errors. Credits reset daily. Claude Opus 4.6 burns through them fast ($6/M input, $30/M output in DIEM).

### Claude Opus 4.6 costs 30-50+ DIEM per request (2026-02-14)
At $6/M input + $30/M output, a single main session request with full workspace context can cost 30-50+ DIEM. 50 DIEM on a key is essentially 1-2 Claude requests. Venice refuses preemptively when balance is insufficient for estimated cost.

## Gateway & Guardian Issues

### Gateway Guardian: HTTP healthy ≠ inference healthy (2026-02-12)
Guardian v1 only probed HTTP (gateway dashboard). Real failure: gateway alive but ALL providers in cooldown = brain-dead. Fix: probe providers directly. Restarting gateway clears in-memory cooldown state.

### Guardian v3 restart chain silently fails (2026-02-14)
`set -euo pipefail` + `openclaw gateway restart` returning non-zero = silent exit. Also `pkill -9 -f "openclaw.*gateway"` matches the Guardian's own process path. Fix: `set -uo pipefail`, ERR trap, exclude own PID. Guardian v4 needed with billing-aware escalation (don't restart for billing — useless).

### openclaw agent CLI needs --to or --session-id (2026-02-12)
Can't use `openclaw agent --message` headless without specifying a target. Direct provider HTTP probes are better for health checks.

## Coding & Development

### Sub-agent Task Complexity (2026-02-11)
Kimi K2.5 via sub-agent choked on complex multi-file coding task (2s exit, no output). Heavy coding work should stay on Claude. This validates the HEAVY tier in the router.

### ERC-8004 Contract Quirks (2026-02-11)
- `totalSupply()` not available on Identity Registry — use binary search via `ownerOf()`
- Registration files often stored as base64 `data:application/json;base64,...` URIs on-chain
- Same contract addresses deployed across all EVM chains

### ClawRouter Evaluation (2026-02-11)
Rejected BlockRunAI/ClawRouter: routes through BlockRun API (middleman), plaintext wallet keys, no Venice/Morpheus models. Extracted scoring concept (MIT) but built custom system.

## ClawHub Issues

### ClawHub name collision — "everclaw" slug squatted (2026-02-12)
Someone published "Everclaw Vault" under the `everclaw` slug on ClawHub (owner `kn732f1vmcycvykq1gp4meydas80dshj`, v0.3.3). User Barry's agent ran `clawhub update everclaw` and it overwrote his entire skill directory. Fix: `install-everclaw.sh` with collision detection, CLAWHUB_WARNING.md. Our ClawHub slug will be `everclaw-inference`.
