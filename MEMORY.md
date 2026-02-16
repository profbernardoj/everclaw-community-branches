# MEMORY.md — Long-Term Memory

Last updated: 2026-02-14

---

## Everclaw Skill (profbernardoj/everclaw)

### Current Version: v0.9.8.3 (community contributions)
- Merged 7 PRs from Scott Berenzweig (betterbrand): dynamic model discovery, install.sh v5.11.0 fix, bash 3.2 compat, agent integration docs, DIY guide link, viem dependency, staking economics fix
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

### Model Router (v0.6 → v0.7 open-source first)
- `scripts/router.mjs` — 13-dimension weighted prompt classifier, <1ms
- **Open-source first design** — Morpheus handles everything, Claude is escape hatch only
- 3 tiers: LIGHT (glm-4.7-flash), STANDARD (glm-5), HEAVY (glm-5 → claude fallback)
- GLM-5 replaces Kimi K2.5 as default (Feb 15 2026)
- GLM-5 tested on: reasoning, complex coding, structured output, agentic tasks — all Opus 4.5 level
- Reasoning override: 2+ keywords → force HEAVY
- Ambiguous → STANDARD (safe/free via Morpheus)

### x402 + ERC-8004 (v0.7 — shipped)
- `scripts/x402-client.mjs` — auto HTTP 402 payment flow, EIP-712 signing, USDC on Base
- `scripts/agent-registry.mjs` — reads ERC-8004 Identity + Reputation registries on Base
- Budget controls: $1/request, $10/day defaults
- Key contract addresses (same on all chains):
  - Identity: `0x8004A169FB4a3325136EB29fA0ceB6D2e539a432`
  - Reputation: `0x8004BAa17C55a88189AE136b182e5fdA19dE9b63`

### Smart Session Archiver (v0.9.4 — shipped)
- `scripts/session-archive.sh` — size-triggered session archiver
- Default threshold: 10MB (browsers choke at ~15-20MB of session DOM)
- Protects active sessions, guardian probe, keeps 5 most recent
- Cron job runs every 6 hours, no-op when under threshold
- Replaced the fixed "every 2 days" approach with intelligent size monitoring
- Root cause: 134 sessions (17MB) = "Page Unresponsive" in all browsers

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
- **Open-source first:** Morpheus models handle everything possible, Claude only as fallback
- GLM-5: default for most work (free via Morpheus, Opus 4.5 level quality)
- GLM 4.7 Flash: trivial tasks (free, fast)
- Claude 4.6: fallback only when GLM-5 can't complete the task (expensive)
- Cron jobs should migrate from `morpheus/kimi-k2.5` to `morpheus/glm-5`
- MiniMax-M2.5: available on mor-gateway and Venice but has latency issues (streaming broken on Venice, mor-gateway unreliable). Better at coding benchmarks but GLM-5 is better all-rounder

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

## OpenClaw Update Security Checks (2026-02-15)

**Context:** OpenClaw creator Peter was hired by OpenAI (Feb 2026). OpenAI has a track record of pivoting from open-source mission to closed, for-profit model. Foundation promises notwithstanding, we must verify on EVERY update:

**Fork:** https://github.com/profbernardoj/openclaw — preserved pre-OpenAI version as backup

### Mandatory Pre-Update Checks
1. **License verification:** `git log --follow -p -- LICENSE | head -50` — confirm MIT license unchanged
2. **No OpenAI defaults:** `grep -ri "openai" packages/ --include="*.js" --include="*.json" | grep -v node_modules` — check for OpenAI API endpoints, model defaults, or auth integration
3. **Package dependencies:** Check for new dependencies on `openai` npm package or OpenAI-specific SDKs
4. **Default model config:** Verify default provider/model hasn't changed to OpenAI

### Post-Update Verification
After any `openclaw update.run` or git pull:
- Run `openclaw status` and verify providers
- Check `~/.openclaw/openclaw.json` for any new OpenAI-related fields
- Review changelog for concerning changes

**If any check fails:** Do NOT update. Investigate further. Consider forking from last known-good commit.

---

## Upcoming
- ~~Add SmartAgent logo to assets/~~ ✅ Merged
- **Follow Scott's DIY Guide for new Mac Mini setup** — Reminder set for tomorrow 9 AM
- Test install.sh on clean macOS and Linux machines
- ~~Configure DNS for smartagent.org~~ ✅ Working (browser cache issue)
- ~~Redesign SmartAgent.org website~~ ✅ Done (Lovable, light theme, deployed)
- Investigate Signal-cli connection drops and thread starvation
- Consider registering Everclaw as an ERC-8004 agent on Base

## Key Users
- **Barry** — Everclaw user, agent named Janet. Hit ClawHub collision bug upgrading v0.7→v0.8. Runtime infra survived but skill dir got nuked. First external user to report a bug.
