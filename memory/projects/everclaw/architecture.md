---
tags: [everclaw, architecture, morpheus, infrastructure]
created: 2026-02-11
updated: 2026-02-21
status: active
---
# Everclaw Architecture

## Current Version: v2026.2.21 (date-based versioning)
- Three-shift task planning (morning/afternoon/night with approval workflow)
- Gateway Guardian v5 (direct curl probes, eliminates Signal spam)
- Version scheme: semver → date-based (YYYY.M.DD)
- Pushed to all 30 repos (everclaw + 28 flavors + baseclaw.ai)
- PR #9 opened to EverClaw/everclaw org repo

## Previous: v0.9.8.3 (community contributions)
- Merged 7 PRs from Scott Berenzweig (betterbrand): dynamic model discovery, install.sh v5.11.0 fix, bash 3.2 compat, agent integration docs, DIY guide link, viem dependency, staking economics fix
- OpenClaw skill for decentralized AI inference via Morpheus network
- Website: everclaw.xyz (GitHub Pages from docs/)
- Repo: profbernardoj/everclaw on GitHub

## Infrastructure
- **Morpheus proxy:** `~/morpheus/proxy/morpheus-proxy.mjs` (port 8083, launchd: com.morpheus.proxy)
- **Morpheus proxy-router (Go):** `~/morpheus/` (port 8082)
- **Proxy auth:** Bearer token `morpheus-local`
- **OpenClaw provider name:** `morpheus` (e.g., `morpheus/kimi-k2.5`)
- Venice IDs use hyphens (`kimi-k2-5`), Morpheus uses dots (`kimi-k2.5`)

## Fallback Chain
`venice/claude-opus-4-6` → `venice/claude-opus-45` → `venice/kimi-k2-5` → `morpheus/kimi-k2.5`

## Multi-Key Auth Rotation (v0.9.1)
- 6 Venice API keys configured as separate auth profiles (venice:key1 through venice:key6)
- Explicit rotation order via `auth.order.venice` in openclaw.json (most DIEM to least)
- Total DIEM: 246 (98+50+40+26+20+12)
- When one key's credits exhaust → billing disable on that profile only → rotates to next key
- Same model, fresh credits — agent stays on Claude instead of falling to cheaper models
- Only after ALL 6 keys are disabled does OpenClaw fall to model fallback chain (Morpheus)

## Model Router (v0.6 → v0.7 open-source first)
- `scripts/router.mjs` — 13-dimension weighted prompt classifier, <1ms
- **Open-source first design** — Morpheus handles everything, Claude is escape hatch only
- 3 tiers: LIGHT (glm-4.7-flash), STANDARD (glm-5), HEAVY (glm-5 → claude fallback)
- GLM-5 replaces Kimi K2.5 as default (Feb 15 2026)
- Reasoning override: 2+ keywords → force HEAVY
- Ambiguous → STANDARD (safe/free via Morpheus)

## x402 + ERC-8004 (v0.7)
- `scripts/x402-client.mjs` — auto HTTP 402 payment flow, EIP-712 signing, USDC on Base
- `scripts/agent-registry.mjs` — reads ERC-8004 Identity + Reputation registries on Base
- Budget controls: $1/request, $10/day defaults
- Key contract addresses (same on all chains):
  - Identity: `0x8004A169FB4a3325136EB29fA0ceB6D2e539a432`
  - Reputation: `0x8004BAa17C55a88189AE136b182e5fdA19dE9b63`

## Smart Session Archiver (v0.9.4)
- `scripts/session-archive.sh` — size-triggered session archiver
- Default threshold: 10MB (browsers choke at ~15-20MB of session DOM)
- Protects active sessions, guardian probe, keeps 5 most recent
- Cron job runs every 6 hours, no-op when under threshold

## Morpheus API Gateway (v0.8)
- Base URL: `https://api.mor.org/api/v1` (NOT `/v1` — needs `/api/v1`)
- OpenAI-compatible, 34 models, free beta until March 1 2026
- Provider name in OpenClaw: `mor-gateway`
- Community bootstrap key (SmartAgentProtocol): base64-obfuscated in `scripts/bootstrap-gateway.mjs`
- Session automation must be enabled at app.mor.org for each account
- **⚠️ Beta expiry: March 1 2026** — need transition plan

## MOR Economics
- MOR is staked, not consumed — recycled after sessions close
- ~88 MOR in wallet, ~900+ staked in sessions, ~9,000 MOR in Safe
