---
tags: [morpheus, gateway, transition, planning]
created: 2026-02-22
status: draft
---
# Morpheus API Gateway Transition Plan

## Situation

The Morpheus API Gateway (api.mor.org) free beta was originally scheduled to end 1/31/26, but has been extended. Billing infrastructure is "coming soon." Our internal deadline was March 1 based on prior communications.

**Current role in our stack:**
- Primary inference provider: `mor-gateway/glm-5`
- Bootstrap path for new EverClaw/SmartAgent users (free inference, no API keys)
- 34+ models via OpenAI-compatible API
- Provider name: `mor-gateway`

**What we know (as of Feb 22):**
- apidocs.mor.org still says "FREE — no cost"
- Billing infrastructure "coming soon" (not yet live)
- Beta has already outlived original 1/31 deadline
- No public announcement of shutdown date found
- Beta page version: 20251030-1451 (hasn't been updated in months)

## Risk Assessment

| Risk | Likelihood | Impact |
|------|-----------|--------|
| Gateway goes paid (MOR or USD) | HIGH | MEDIUM — we have MOR to pay |
| Gateway shuts down abruptly | LOW | HIGH — breaks new user onboarding |
| Gateway rate-limits free tier | MEDIUM | LOW — we have local proxy fallback |
| Gateway stays free longer | MEDIUM | NONE — best case |

## Fallback Options (Already Available)

### Option 1: Direct Morpheus P2P (LOCAL PROXY) ✅ READY
- Provider: `morpheus` (port 8083)
- Uses staked MOR tokens (~88 wallet + ~900 in sessions + ~9,000 in Safe)
- Models: glm-5, glm-4.7-flash, kimi-k2.5, kimi-k2-thinking
- Pros: Fully decentralized, already working, MOR recycled not consumed
- Cons: Requires local proxy-router + MOR tokens, not viable for new users without MOR

### Option 2: Venice API ✅ READY
- Provider: `venice` (6 rotating keys, 246 DIEM total)
- Models: Claude Opus 4.6, 4.5, Kimi K2.5, etc.
- Pros: Reliable, high-quality models
- Cons: Costs DIEM, not free for new users

### Option 3: BasedAI Gateway (Thomas Borrel)
- Stage 3 of the 28 Flavors funnel
- Thomas is building commercial inference layer
- Could replace mor-gateway as bootstrap provider
- Status: In development — needs follow-up with Thomas

## Required Changes If Gateway Dies

### 1. OpenClaw Config (our system)
```
Current primary: mor-gateway/glm-5
New primary:     morpheus/glm-5 (local proxy)
New fallbacks:   morpheus/kimi-k2.5 → venice/claude-opus-4-6 → venice/claude-opus-45
```
Just a config.patch — 5 minutes.

### 2. EverClaw install.sh
- Remove `bootstrap-gateway.mjs` auto-config (sets up mor-gateway provider)
- Replace with direct Morpheus proxy setup OR BasedAI gateway
- Update fallback chain in default config template

### 3. SmartAgent.org Installer
- Currently bootstraps with `mor-gateway/kimi-k2.5` as primary
- Needs alternative free inference path for new users
- Options: BasedAI gateway, community MOR pool, or Venice free tier

### 4. 28 Flavors Impact
- Stage 3 (Inference Access) led by Thomas Borrel
- If mor-gateway dies, Thomas's BasedAI gateway becomes MORE critical
- Accelerate conversation with Thomas about timeline

## Action Plan

### Immediate (This Week)
- [ ] Ask Kyle in maintainers meeting about post-beta plans
- [ ] Message Thomas Borrel about BasedAI gateway timeline
- [ ] Verify local proxy fallback is healthy (test session open/inference)
- [ ] Prepare config.patch ready to deploy if gateway goes down

### If Gateway Goes Paid
- Evaluate MOR-based pricing vs USD pricing
- We have 9,000+ MOR — likely sufficient for years of usage
- Update install.sh to explain MOR staking requirement

### If Gateway Shuts Down
- Deploy config.patch switching to morpheus/glm-5 (local proxy)
- Push EverClaw update removing mor-gateway bootstrap
- Coordinate with Thomas on BasedAI gateway as replacement
- Update SmartAgent installer

## Decision Needed from David

1. **Should we preemptively switch primary from mor-gateway to local morpheus proxy?**
   - Pro: Removes dependency on beta service
   - Con: Local proxy requires MOR + proxy-router running, not portable to new users

2. **Should we accelerate Thomas Borrel conversation about BasedAI gateway?**
   - This is the long-term answer for Stage 3 of the funnel

3. **Should we prepare a "MOR staking required" path in install.sh?**
   - For power users who want fully decentralized inference
