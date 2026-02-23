# MEMORY.md — Index

Last updated: 2026-02-22

Use `memory_search` for deep recall. This file is the map, not the territory.

---

## ⚡ Active Context (what we're working on RIGHT NOW)

- **Memory system overhaul** — COMPLETE. Local embeddings, hybrid search, session transcripts, tagging all working.
- **Morpheus API Gateway beta expires March 1** — need transition plan (7 days remaining)
- **EverClaw v2026.2.22** — memory-upgrade skill shipped, pushed to all 30 repos, PR #12 merged

## 📋 Release Process — CRITICAL

When pushing a new named version to `profbernardoj/everclaw`:
1. Push to `profbernardoj/everclaw` (main)
2. Push to all 28+ flavor repos (batch script)
3. Open PR from `profbernardoj` → `EverClaw/everclaw` org repo
4. David merges the org PR

## 🗂️ Memory Map

| Area | Location | What's there |
|------|----------|-------------|
| **Daily notes** | `memory/daily/YYYY-MM-DD*.md` | Raw session logs |
| **Everclaw project** | `memory/projects/everclaw/` | Architecture, strategy, flavors, ClawHub |
| **SmartAgent project** | `memory/projects/smartagent/` | Org, website, installer |
| **ClawBox project** | `memory/projects/clawbox/` | IronHill deal, BOM, support bot |
| **Morpheus infra** | `memory/projects/morpheus/` | Proxy router, sessions, MOR economics |
| **Marketing (58 files)** | `memory/marketing/` | All flavor stage 1 & 2 plans |
| **Campaigns** | `memory/campaigns/` | Viral narratives, launch campaigns |
| **Goals** | `memory/goals/` | Space, abolition, great commission, etc. |
| **Relationships** | `memory/relationships/` | CRM by category |
| **Reference** | `memory/reference/` | Lessons learned, model prefs, security protocol |
| **Insights** | `memory/insights/` | Balaji, other thinkers |

## 🏗️ Active Projects

### Everclaw (profbernardoj/everclaw)
- Version: v2026.2.21 (date-based versioning)
- Skill for decentralized AI inference via Morpheus network
- Website: everclaw.xyz | Repo: profbernardoj/everclaw
- **Details →** `memory/projects/everclaw/architecture.md`
- **Flavors strategy →** `memory/projects/everclaw/everclaw-flavors-strategy.md`

### 28 Flavors Sales Funnel
- Mission: Own your Smart Agent — hardware, data, and inference
- 5 stages: Sales → VM → Inference → Hardware → DIY
- All 28 repos created, READMEs white-labeled, marketing plans done
- **Details →** `memory/projects/everclaw/everclaw-flavors-strategy.md`

### SmartAgentProtocol
- Website: smartagent.org | Repo: SmartAgentProtocol/smartagent
- Installer-first architecture for non-technical users
- **Details →** `memory/projects/smartagent/overview.md`

### ClawBox (IronHill partnership)
- $999/unit, 10% affiliate ($100), ships end of month
- **Details →** `memory/projects/clawbox/ironhill-negotiation.md`

## 🔧 Key Infrastructure

- **Fallback chain:** claude-opus-4-6 → claude-opus-45 → kimi-k2-5 → morpheus/kimi-k2.5
- **6 Venice API keys** rotating (246 total DIEM)
- **Model router:** 3 tiers (LIGHT/STANDARD/HEAVY), open-source first
- **GLM-5** is default (replaces Kimi K2.5 as of Feb 15)
- **Details →** `memory/projects/everclaw/architecture.md`

## 🗣️ Language Rules
- NEVER say "free inference" → say "own your inference"
- Morpheus = ownership, not rental
- Don't highlight Llama 3.3
- **Details →** `memory/reference/language-messaging.md`

## 🔐 Security
- OpenClaw creator Peter hired by OpenAI — verify every update
- Fork preserved: profbernardoj/openclaw
- **Protocol →** `memory/reference/security-update-protocol.md`

## 📚 Reference Pointers
- **Model preferences →** `memory/reference/model-preferences.md`
- **Lessons learned →** `memory/reference/lessons-learned.md`
- **Key people →** `memory/reference/key-people.md`
- **School calendar →** `memory/reference/school-calendar-rrisd-2025-2026.md`
- **Family reminders →** `memory/reference/family-reminders.md`

## ✅ Recently Completed
- Memory system overhaul — local embeddings, hybrid search, 968 chunks indexed (Feb 22)
- memory-upgrade skill built and released (Feb 22)
- v2026.2.22 pushed to all 30 repos, PR #12 merged (Feb 22)
- 28 Stage 1 + 26 Stage 2 marketing plans (Feb 19)
- Viral narratives — 10 meta + 28 per-flavor hooks (Feb 19)
- InstallOpenClaw.xyz launch campaign (Feb 19)
- EverClaw Docker container PR (Feb 19)
- Three-shift skill replacing night-shift (Feb 21)
- SmartAgent.org redesign + DNS (Feb 12)

## 🔲 Open Items
- Morpheus API Gateway beta expires March 1 — transition plan needed
- Websites for each flavor
- Referral tracking infrastructure
- ERC-8004 agent registration on Base
- Signal-cli connection drops investigation
- Test install.sh on clean macOS and Linux
