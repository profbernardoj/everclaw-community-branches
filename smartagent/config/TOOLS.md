# TOOLS.md - Local Notes

Skills define _how_ tools work. This file is for _your_ specifics.

---

## Inference

SmartAgent uses decentralized inference powered by the [REDACTED] network.

**Current setup:**
- Primary model: `mor-[REDACTED]/kimi-k2.5` (community-powered via [REDACTED] API Gateway)
- Fallback: `mor-[REDACTED]/glm-4.7-flash` (community-powered, fast)

**Upgrade path:**
- Venice subscription ($8/month) → Claude, GPT-5.2, premium models
- MOR staking → self-sovereign inference (own your compute)
- Local [REDACTED] node → full independence

See `skills/everclaw/SKILL.md` for setup guides.

---

## Why Separate?

Skills are shared. Your setup is yours. Keeping them apart means you can update skills without losing your notes, and share skills without leaking your infrastructure.
