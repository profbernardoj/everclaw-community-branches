# Night Shift — 2026-02-22 (10 PM – 6 AM CST)
Auto-approved: All tasks pre-approved from today's session. Research + documentation only.
Exec model: GLM-5 | Plan model: Claude Opus 4.6 | ~32 cycles available

---

## Task 1: Research AppFactory for EverClaw Mobile App [P2] ✅

### Summary
Total steps: 5 | Done: 5 | Blocked: 0 | Remaining: 0
Recommendation: Capacitor for MVP (2-3 weeks), React Native later if needed
Output: `memory/projects/everclaw/mobile-app-research.md`

### Step 1.1: Fetch AppFactory README and docs [x]
- `web_fetch` https://raw.githubusercontent.com/0xAxiom/AppFactory/main/README.md (full)
- `web_fetch` https://raw.githubusercontent.com/0xAxiom/AppFactory/main/QUICKSTART.md
- `web_fetch` https://api.github.com/repos/0xAxiom/AppFactory/contents/app-factory (list directory)
- Write raw content to `/tmp/appfactory-docs.md` for reference in next steps
- **Expected output:** Combined markdown of all docs in /tmp/appfactory-docs.md — DONE (cycle 1): Fetched README, QUICKSTART, directory listing; wrote 5.7KB summary to /tmp/appfactory-docs.md

### Step 1.2: Fetch AppFactory skill files and deeper docs [x]
- From the directory listing in step 1.1, identify key files (SKILL.md, package.json, config files)
- `web_fetch` each key file (max 4 fetches)
- Append content to `/tmp/appfactory-docs.md`
- **Expected output:** Complete documentation dump — DONE (cycle 2): Fetched app-factory/CLAUDE.md (29KB skill constitution), appended key excerpts to docs

### Step 1.3: Analyze AppFactory capabilities and assess App Store readiness [x]
- Read `/tmp/appfactory-docs.md`
- Assess: What does it generate? (Expo project? bare React Native? just UI?)
- Assess: How close to App Store/Play Store ready? What manual steps remain?
- Assess: Does it support push notifications, native modules, custom APIs?
- Assess: Security considerations (SkillGuard scan needed before install)
- Write analysis to `memory/projects/everclaw/mobile-app-research.md` under "## AppFactory Analysis"
- **Expected output:** Detailed analysis section written — DONE (cycle 3): Wrote comprehensive analysis (5.4KB) covering output type, store readiness, push support, native modules, API gaps, security, QA system, templates, and limitations for EverClaw

### Step 1.4: Draft EverClaw mobile app spec [x]
- Read `memory/projects/everclaw/architecture.md` for current EverClaw architecture
- Read MEMORY.md for context on flavors strategy and mobile app requirements
- Draft spec with: screens (onboarding, flavor picker, chat, settings), API connections (OpenClaw gateway, Morpheus, Venice), push notifications, cross-platform requirements
- Requirements from David: onboarding flow, flavor picker, gateway connection, chat interface, settings (Morpheus key, Venice key, MOR staking), push notifications, iOS + Android via Expo
- Append spec to `memory/projects/everclaw/mobile-app-research.md` under "## EverClaw Mobile App Spec"
- **Expected output:** Complete app spec section written — DONE (cycle 4): Wrote comprehensive app spec (8KB) covering 4 screens, API integrations, push notifications, security, monetization options, and open questions

### Step 1.5: Write recommendations and next steps [x]
- Read `memory/projects/everclaw/mobile-app-research.md` (what you wrote so far)
- Compare AppFactory approach vs Capacitor approach (from Feb 22 research — see memory/daily/2026-02-22.md)
- Write pros/cons comparison and recommendation
- Add "## Next Steps" section: what David needs to decide, what SkillGuard checks are needed before install
- **Expected output:** Completed research doc with recommendation — DONE (cycle 5): Wrote comparison table, pros/cons, recommended Capacitor for MVP with React Native later, outlined next steps and timeline

---

## Task 2: David's 21 Strategic Questions [P3]

All answers go to `memory/daily/2026-02-23-night-answers.md`. Create the file on first step.
For each question: read MEMORY.md, USER.md, SOUL.md, IDENTITY.md, TOOLS.md, and recent daily files. Give honest, specific, actionable answers referencing real projects, patterns, and decisions. 3-5 sentences each minimum.

### Step 2.1: Answer Questions 1-3 [x]
- Read: SOUL.md, USER.md, IDENTITY.md (if exists), TOOLS.md, MEMORY.md
- Create `memory/daily/2026-02-23-night-answers.md` with header
- **Q1:** Tools/automations David is missing that would measurably improve operations
- **Q2:** Assumptions about David that could be wrong and should be vetted
- **Q3:** What David likely needs next week based on decision patterns
- Write answers to the file
- **Expected output:** File created with Q1-Q3 answers — DONE (cycle 6): Created file with 5 specific missing tools (ERC-8004, git sync, Morpheus monitor, ClawBox dashboard, school calendar), 5 assumptions to vet (evening window, delegation boundaries, article relevance, family size, caution level), and 5 next-week priorities (XMTP, Gateway transition, CTA unblocking, $1B tracking, smart contract prep)

### Step 2.2: Answer Questions 4-6 [x]
- Read relevant context files if needed
- **Q4:** Skills/capabilities to develop based on where projects are heading
- **Q5:** Context being lost between sessions that needs fixes
- **Q6:** Connections between projects/ideas David hasn't made yet
- Append answers to `memory/daily/2026-02-23-night-answers.md`
- **Expected output:** Q4-Q6 appended — DONE (cycle 6): Appended 5 skills to develop (XMTP, mobile, smart contracts, x402, ERC-8004), 5 context-loss fixes (project status, cron alerts, meeting notes, config changelog, process lessons), and 5 project connections (TabHR flavors, ERC-8004 reputation for $1B goal, active staking demand, cron-as-a-service, agent stack positioning)

### Step 2.3: Answer Questions 7-9 [x]
- **Q7:** Recurring friction points that could be eliminated with new workflows
- **Q8:** Rules to write into identity/skill files based on corrections received
- **Q9:** Audit of last week's actions — what moved goals forward vs wasted motion
- Append answers to `memory/daily/2026-02-23-night-answers.md`
- **Expected output:** Q7-Q9 appended — DONE (cycle 7): Wrote 5 friction points (session startup lag, CTA blockers, cron health visibility, multi-repo sync, git drift), 5 rules to codify (ship-first, reference-before-asking, active protocol use, verify-cached-values, test-on-clean-systems), and week audit (70% forward: memory fix, releases, Docker, x402, three-shifts, mobile research; 30% overhead: Docker iteration, repo recreation, watchdog false positives, shift rewrite, marketing reorg)

### Step 2.4: Answer Questions 10-12
- **Q10:** Where defaulting to generic output when specific/tailored is possible
- **Q11:** One compounding system to build that makes every future task faster
- **Q12:** Repeated errors and guardrails to prevent them
- Append answers to `memory/daily/2026-02-23-night-answers.md`
- **Expected output:** Q10-Q12 appended

### Step 2.5: Answer Questions 13-15
- **Q13:** What to research/prototype based on ecosystem direction
- **Q14:** Where filling gaps with assumptions instead of flagging them
- **Q15:** Most valuable underutilized data/pattern in memory files
- Append answers to `memory/daily/2026-02-23-night-answers.md`
- **Expected output:** Q13-Q15 appended

### Step 2.6: Answer Questions 16-18
- **Q16:** Score 1-10 on modeling David's priorities + specific fixes
- **Q17:** External data sources/feeds that would sharpen decisions
- **Q18:** What a replacement agent would get wrong — capture knowledge permanently
- Append answers to `memory/daily/2026-02-23-night-answers.md`
- **Expected output:** Q16-Q18 appended

### Step 2.7: Answer Questions 19-21
- **Q19:** Workflows David still does manually that could be automated
- **Q20:** Parts of current approach that are outdated and need rebuilding
- **Q21:** Single highest leverage thing in next 24 hours David hasn't asked for
- Append answers to `memory/daily/2026-02-23-night-answers.md`
- **Expected output:** Q19-Q21 appended, file complete

---

## Task 3: Night Maintenance [P3-Autonomous]

### Step 3.1: Memory maintenance — review and update MEMORY.md [~]
- Read memory/daily/2026-02-23.md and memory/daily/2026-02-22.md
- Identify items to add/update in MEMORY.md (new projects, completed items, stale entries)
- Update MEMORY.md: add AppFactory research pointer, add x402 milestone, update active context, move completed items
- **Expected output:** MEMORY.md updated with current state

---

## Summary
Total steps: 13 | Tasks: 3 (1 P2, 1 P3, 1 P3-auto)
Estimated cycles: ~10-13 (some steps may complete in same cycle)
All steps are research, writing, or memory maintenance — fully night-safe.
