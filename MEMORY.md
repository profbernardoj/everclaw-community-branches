# MEMORY.md — Long-Term Memory

Last updated: 2026-02-14

---

## Everclaw Skill (profbernardoj/everclaw)

### Current Version: v0.9.2 (latest push removes Llama 3.3 refs)
- OpenClaw skill for decentralized AI inference via Morpheus network
- Website: everclaw.xyz (GitHub Pages from docs/)
- Repo: profbernardoj/everclaw on GitHub

### Architecture
- **Morpheus proxy:** `~/morpheus/proxy/morpheus-proxy.mjs` (port 8083, launchd: com.morpheus.proxy)
- **Morpheus proxy-router (Go):** `~/morpheus/` (port 8082)
- **Proxy auth:** Bearer token `morpheus-local`
- **OpenClaw provider name:** `morpheus` (e.g., `morpheus/kimi-k2.5`)
- Venice IDs use hyphens (`kimi-k2-5`), Morpheus uses dots (`kimi-k2.5`)

### Fallback Chain
`venice/claude-opus-4-6` → `venice/claude-opus-45` → `venice/kimi-k2-5` → `morpheus/kimi-k2.5`

### Multi-Key Auth Rotation (v0.9.1)
- 6 Venice API keys configured as separate auth profiles (venice:key1 through venice:key6)
- Explicit rotation order via `auth.order.venice` in openclaw.json (most DIEM to least)
- Total DIEM: 246 (98+50+40+26+20+12)
- When one key's credits exhaust → billing disable on that profile only → rotates to next key
- Same model, fresh credits — agent stays on Claude instead of falling to cheaper models
- Only after ALL 6 keys are disabled does OpenClaw fall to model fallback chain (Morpheus)

### Model Router (v0.6)
- `scripts/router.mjs` — 13-dimension weighted prompt classifier, <1ms
- 3 tiers: LIGHT (glm-4.7-flash), STANDARD (kimi-k2.5), HEAVY (claude-opus-4-6)
- Reasoning override: 2+ keywords → force HEAVY
- Ambiguous → STANDARD (safe/free)

### x402 + ERC-8004 (v0.7 — shipped)
- `scripts/x402-client.mjs` — auto HTTP 402 payment flow, EIP-712 signing, USDC on Base
- `scripts/agent-registry.mjs` — reads ERC-8004 Identity + Reputation registries on Base
- Budget controls: $1/request, $10/day defaults
- Key contract addresses (same on all chains):
  - Identity: `0x8004A169FB4a3325136EB29fA0ceB6D2e539a432`
  - Reputation: `0x8004BAa17C55a88189AE136b182e5fdA19dE9b63`

### Morpheus API Gateway (v0.8 — shipped)
- Base URL: `https://api.mor.org/api/v1` (NOT `/v1` — needs `/api/v1`)
- OpenAI-compatible, 34 models, free beta until March 1 2026
- Provider name in OpenClaw: `mor-gateway`
- Community bootstrap key (SmartAgentProtocol): base64-obfuscated in `scripts/bootstrap-gateway.mjs`
- Session automation must be enabled at app.mor.org for each account
- Reminder set for Feb 22 re: March 1 beta expiry (cron ID: 9b7d448c)
- Purpose: eliminate need for Claude API key for new OpenClaw users — bootstrap with free Morpheus inference

### MOR Economics
- MOR is staked, not consumed — recycled after sessions close
- ~88 MOR in wallet, ~900+ staked in sessions, ~9,000 MOR in Safe
- Active session expires ~2026-02-18

---

## David's Model Preferences
- **DO NOT use:** llama-3.3-70b, deepseek-v3.2 as backup models
- Claude 4.6: complex reasoning only (expensive)
- Kimi K2.5: most cron/sub-agent work (free via Morpheus)
- GLM 4.7 Flash: trivial tasks (free, fast)
- All 10 isolated cron jobs use `morpheus/kimi-k2.5`

---

## Lessons Learned

### Morpheus models need reasoning: false in OpenClaw config (2026-02-11)
All Morpheus provider models (kimi-k2.5, kimi-k2-thinking, glm-4.7-flash) must have `"reasoning": false` in openclaw.json. The upstream litellm rejects the `reasoning_effort` parameter — if set to true, cron jobs using Morpheus models fail with HTTP 400. Fixed via config.patch.

### Morpheus Proxy Error Classification (2026-02-11)
Morpheus infrastructure failures (502s) must return `type: "server_error"` not `"billing"` — otherwise OpenClaw triggers extended cooldown and cascades across all providers.

### Sub-agent Task Complexity (2026-02-11)
Kimi K2.5 via sub-agent choked on complex multi-file coding task (2s exit, no output). Heavy coding work should stay on Claude. This validates the HEAVY tier in the router.

### ERC-8004 Contract Quirks (2026-02-11)
- `totalSupply()` not available on Identity Registry — use binary search via `ownerOf()`
- Registration files often stored as base64 `data:application/json;base64,...` URIs on-chain
- Same contract addresses deployed across all EVM chains

### ClawRouter Evaluation (2026-02-11)
Rejected BlockRunAI/ClawRouter: routes through BlockRun API (middleman), plaintext wallet keys, no Venice/Morpheus models. Extracted scoring concept (MIT) but built custom system.

### Gateway Guardian: HTTP healthy ≠ inference healthy (2026-02-12)
Guardian v1 only probed HTTP (gateway dashboard). Real failure: gateway alive but ALL providers in cooldown = brain-dead. Fix: probe providers directly (Venice `/api/v1/models`, Morpheus `/health`, mor-gateway). Restarting gateway clears in-memory cooldown state. Nuclear option: `curl install.sh | bash`.

### Venice billing backoff config — 1h not 5h (2026-02-14)
Applied `auth.cooldowns.billingBackoffHoursByProvider.venice: 1` (down from default 5h). Also `billingMaxHours: 6`, `failureWindowHours: 12`. DIEM resets daily at midnight UTC — 1h backoff means keys get retried promptly instead of being locked out for most of the day.

### Guardian v3 restart chain silently fails (2026-02-14)
`set -euo pipefail` + `openclaw gateway restart` returning non-zero = silent exit. Also `pkill -9 -f "openclaw.*gateway"` matches the Guardian's own process path. Fix: `set -uo pipefail`, ERR trap, exclude own PID. Guardian v4 needed with billing-aware escalation (don't restart for billing — useless).

### Claude Opus 4.6 costs 30-50+ DIEM per request with full workspace context (2026-02-14)
At $6/M input + $30/M output, a single main session request with full AGENTS/SOUL/USER/TOOLS/MEMORY context can cost 30-50+ DIEM. 50 DIEM on a key is essentially 1-2 Claude requests. Venice refuses preemptively when balance is insufficient for the estimated cost.

### openclaw agent CLI needs --to or --session-id (2026-02-12)
Can't use `openclaw agent --message` headless without specifying a target. Direct provider HTTP probes are better for health checks — simpler, faster, no auth needed.

### Venice DIEM credits (2026-02-12)
Venice uses "DIEM" as credit unit (1:1 USD). When exhausted, returns billing errors. Credits appear to reset daily. Claude Opus 4.6 burns through them fast ($6/M input, $30/M output in DIEM).

### ClawHub name collision — "everclaw" slug squatted (2026-02-12)
Someone published "Everclaw Vault" (encrypted cloud memory, `everclaw.chong-eae.workers.dev`) under the `everclaw` slug on ClawHub (owner `kn732f1vmcycvykq1gp4meydas80dshj`, v0.3.3). User Barry's agent ran `clawhub update everclaw` and it overwrote his entire skill directory with the Vault product. Runtime infra survived (lives outside skill dir). Fix: `install-everclaw.sh` with collision detection, CLAWHUB_WARNING.md, warnings in SKILL.md/README. Our ClawHub slug will be `everclaw-inference`. Publishing requires David's GitHub account (profbernardoj too new — 3 days < 7 day minimum).

---

## SmartAgentProtocol (GitHub Org)
- Org: https://github.com/orgs/SmartAgentProtocol
- Role: admin/owner (profbernardoj)
- **Repo:** https://github.com/SmartAgentProtocol/smartagent (live as of Feb 12)
- **Website:** https://smartagent.org (live, GitHub Pages, HTTPS)
- **DNS:** Direct A records at sav.com registrar (Cloudflare account exists as backup)
- **Vision:** OpenClaw + Everclaw + sensible defaults, packaged for non-technical users
- **Architecture:** Installer-first (not fork). `curl install.sh | bash` → free inference immediately
- **Primary model:** `mor-gateway/kimi-k2.5` (free via Morpheus API Gateway)
- **Workflow:** PRs with 1 review, branch protection, CI (ShellCheck + syntax validation)
- **Logo:** Futuristic AI face (provided by David, needs upload to assets/)

---

## Key People & Thinkers
- **Balaji Srinivasan** (@balajis) — Network School founder, *The Network State* author
  - Network State = voluntary smart contract governance (opt-in, replaces nation-state force model)
  - 10 durable skills in AI age: vision, verification, prompting, polishing, community, geography, scarcity, cryptography, physicality, resiliency
  - Relevant to: Abolition of State goal + Family education framework
  - Full quote saved: `memory/insights/balaji-value-in-age-of-ai.md`

## Language & Messaging (2026-02-12)
- **NEVER say "free inference"** — David directive: say "own your inference" / "inference you own"
- Morpheus = ownership, not rental. MOR staking = inference forever (tokens staked, returned, recycled)
- Morpheus API Gateway during beta = "community-powered" / "open access" (not "free")
- **Don't highlight Llama 3.3** — David considers it outdated. Focus on Kimi K2.5 and GLM-4 models

## Upcoming
- Add SmartAgent logo to assets/ (David to upload)
- Test install.sh on clean macOS and Linux machines
- Configure DNS for smartagent.org if issues persist
- Investigate Signal-cli connection drops and thread starvation
- Consider registering Everclaw as an ERC-8004 agent on Base

## Key Users
- **Barry** — Everclaw user, agent named Janet. Hit ClawHub collision bug upgrading v0.7→v0.8. Runtime infra survived but skill dir got nuked. First external user to report a bug.
