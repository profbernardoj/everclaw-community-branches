# MEMORY.md — Long-Term Memory

Last updated: 2026-02-11

---

## Everclaw Skill (profbernardoj/everclaw)

### Current Version: v0.7.0
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

---

## Upcoming
- Publish Everclaw to ClawHub on Feb 16 (cron job `6ff30a74` scheduled)
- ~~Version x402 + agent registry as v0.7~~ DONE
- Investigate Signal-cli connection drops and thread starvation
- Consider registering Everclaw as an ERC-8004 agent on Base
