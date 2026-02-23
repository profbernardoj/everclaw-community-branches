# Shift Context — Living Document

Last updated: 2026-02-22

## Stack & Environment
- macOS arm64 (Darwin 25.3.0), Mac mini
- OpenClaw 2026.2.21-2, Node v25.5.0
- Workspace: ~/.openclaw/workspace
- Git repos: ~/.openclaw/workspace (everclaw), ~/morpheus (proxy-router)
- 1Password for secrets via service account (never store raw keys in files)
- Signal for user comms (+14432859111 = David)
- Brave Search: Free tier, 1 req/sec, 2000/month — space by 2+ seconds

## Active Providers
- Venice AI: 6 API keys rotating (currently key3 primary)
- Morpheus local proxy: localhost:8083 (via proxy-router + morpheus-proxy.mjs)
- Morpheus Gateway: api.mor.org (beta expires March 1, 2026)
- Fallback chain: glm-5 → kimi-k2.5 → morpheus/glm-5 → claude-opus-4-6 → claude-opus-45

## Constraints
- Never force push or delete git branches
- trash > rm (recoverable beats gone forever)
- Never store secrets in files — use 1Password runtime retrieval
- Ask before any external-facing action (emails, tweets, posts)
- MiniMax-M2.5: DO NOT USE (broken streaming, severe latency)
- Llama 3.3 70B: DO NOT USE
- Never say "free inference" → say "own your inference"

## Known Pitfalls (learned from experience)
- Morpheus: session_id and model_id MUST be HTTP headers, not JSON body fields
- signal-cli drops connections periodically — not actionable, just retry
- Venice billing cooldown: 1 hour per key on 402 error
- Always check git status before committing — avoid partial commits
- OpenClaw creator Peter hired by OpenAI — verify trust on every update
- GLM-5 times out on some cron jobs — switched main session to Claude 4.6
- context.md gets read every cycle — keep it lean, remove stale entries monthly

## Test Results
Git status: On branch main with 37 modified files (SOUL.md, gateway-guardian.sh scripts, subrepos) and many untracked files (shifts/, skills/, memory/ drafts).
No changes staged for commit — working directory has pending modifications across multiple repos.
Step 1.2 verified: cyclesRun = 0 (will increment to 1 when cycle completes)

## Night Shift Rules
- No external communications (Signal, email, social)
- No financial transactions
- No destructive operations (rm, force push, branch delete)
- No security changes (key rotation, permissions)
- No new tasks without prior approval
- OK: research, memory maintenance, documentation, git housekeeping, file cleanup
