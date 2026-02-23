# Handoff — Night Shift 2026-02-23

## Queued Tasks

### P2: Research AppFactory for EverClaw Mobile App
**Goal:** Evaluate 0xAxiom/AppFactory as the tool to build EverClaw's App Store / Play Store app.

**Context:**
- AppFactory is an OpenClaw skill (Expo/React Native) that generates buildable mobile apps from descriptions
- Repo: https://github.com/0xAxiom/AppFactory
- KellyClaudeAI (@KellyClaudeAI on X) is the agent behind it — claims sub-hour app builds
- David has Apple Developer + Google Play Console accounts from a previous project (needs fresh ones for EverClaw)
- Brand: **EverClaw** (not SmartAgent)
- If it works for EverClaw, replicate for all 28 flavors this week

**Steps:**
1. Read the full AppFactory README + QUICKSTART.md + app-factory/ docs via GitHub API
2. Assess: What does it actually generate? How close to App Store-ready?
3. Draft an EverClaw app spec (what screens, what functionality, what the app connects to)
4. Document findings in memory/projects/everclaw/mobile-app-research.md
5. Do NOT install or run AppFactory yet — research only (night shift rules: no external actions)
6. Run SkillGuard scan on AppFactory before any future install

**App requirements (from David):**
- Onboarding flow (pick a flavor or go generic EverClaw)
- Connect to user's OpenClaw gateway
- Native chat interface
- Settings for Morpheus API Gateway key, Venice key, MOR staking
- Push notifications for shift plans, alerts
- Cross-platform: iOS + Android via Expo

---

### P3: David's 21 Strategic Questions (one per cycle, answer in memory/daily/2026-02-23-night-answers.md)

**Instructions:** For each question, read MEMORY.md, USER.md, SOUL.md, IDENTITY.md, TOOLS.md, and recent memory/daily/ files. Give honest, specific, actionable answers — not generic AI advice. Reference real projects, real patterns, real decisions. Write ALL answers to `memory/daily/2026-02-23-night-answers.md`.

**Q1:** From everything you know about David and his workflows, what tools or automations is he missing that would measurably improve how he operates?

**Q2:** What assumptions do you currently hold about David, his priorities, or his preferences that could be wrong and should be vetted and corrected?

**Q3:** Based on all decision patterns and asks you've experienced, what is David likely to need next week or in the future that you can get ahead of and systemize?

**Q4:** What skills or capabilities should you be developing and adding to the repertoire right now based on where David's projects are heading?

**Q5:** What context about David's vision, voice, or priorities are you losing between sessions from compactions that needs clear fixes so you stop getting dumber over time?

**Q6:** What connections between David's projects, ideas, or goals do you see that he likely hasn't made yet, and what should we build or adjust based on those connections?

**Q7:** What recurring friction points have you observed in how David works that you could eliminate by building a new workflow, template, or automation without him having to ask?

**Q8:** From every correction, redirect, and piece of feedback David has given you, what rules should you be writing into your own identity and skill files right now so you never repeat those mistakes?

**Q9:** If you audited every action you've taken in the last week, which ones actually moved David's goals forward and which were wasted motion we should cut permanently?

**Q10:** Where are you defaulting to generic output when you have enough context on David to be building something specific, tailored, and actually useful?

**Q11:** What's one system you could build for yourself right now that would compound in value and make every future task you do for David faster or sharper?

**Q12:** What errors or missed opportunities have you repeated more than once, and what self-check or guardrail can we build together so they never happen again?

**Q13:** Based on everything you know about where David's ecosystem is going, what should you be researching, learning, or prototyping right now without him telling you to?

**Q14:** Where are you filling gaps in your knowledge about David or his projects with assumptions instead of flagging them so we can lock in the real answers?

**Q15:** What's the most valuable data, insight, or pattern buried in your memory and context files that you're sitting on and underutilizing for David's benefit?

**Q16:** Score yourself 1-10 on how accurately you model David's priorities, goals, and how he thinks. What's dragging it down, and what specific fixes bring it up?

**Q17:** What external data sources, feeds, or signals should you be pulling or can David provide so you can operate on a regular cadence that would make every decision sharper?

**Q18:** If a brand new agent replaced you tomorrow with only the documentation, what critical things would it get wrong that you've learned through working with David, and how do we capture that knowledge permanently?

**Q19:** What workflows is David still doing manually or inefficiently that you already have enough context to fully automate or streamline if given the green light?

**Q20:** Based on how David's thinking and priorities have evolved since you started working together, what parts of your current approach are outdated and need to be rebuilt?

**Q21:** What's the single highest leverage thing you could do in the next 24 hours that David hasn't asked for but would meaningfully accelerate where he's trying to go?

---

## Notes for Night Shift Planner
- P2 (AppFactory) should be decomposed into 4-5 steps, mostly web_fetch + write
- P3 questions: batch 3-4 per cycle, each answer should be 3-5 sentences of real substance
- All P3 answers go in ONE file: memory/daily/2026-02-23-night-answers.md
- Night shift rules apply: NO external comms, NO financial txns, NO destructive ops
- Prioritize P2 first, then work through as many P3 questions as cycles allow

## Today's Session Summary (for context)
- Shipped Three-Shifts v2 (cyclic executor) + Multi-Key Auth Rotation v2
- v2026.2.23 pushed to all 30 repos, GitHub Release published
- Docker pipeline fixed, ghcr.io/everclaw/everclaw:latest now public
- EverClaw/everclaw migrated from fork to standalone repo
- profbernardoj has PR-only access to EverClaw/everclaw (no write — security policy)
- Venice keys: key1 (82 DIEM), key2 (50 DIEM), key3 (0.91 USD) active; key4-6 depleted
