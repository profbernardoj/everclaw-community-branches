# Night Shift — 2026-02-26 (10 PM – 6 AM CST)
Exec model: GLM-5 | Plan model: Claude Opus 4.6 | ~32 cycles available

---

## STATUS: AWAITING APPROVAL

**Context:** Tasks carried over from Feb 24-25. Major PII remediation completed Feb 25 but workspace never committed. Multiple cron jobs in error state.

---

## CARRYOVER TASKS (from Feb 24-25)

## Task 1: Fix Cron Job Timeouts [P2] [CARRYOVER]
**Why:** Venice 402 Watchdog (status=running, no timeout, every 5 min) and Disk Usage Monitor (status=error, no timeout) both need explicit timeoutSeconds.

### Step 1.1: Add timeoutSeconds to both cron jobs [ ]
- Read `~/.openclaw/cron/jobs.json`
- Find job `63364746-e6bc-45a7-95f0-44bc1f29ba54` (Venice 402 Watchdog) — add `"timeoutSeconds": 180`
- Find job `88a4609b-87b0-42c0-9c4f-69cb927b7fa3` (Disk Usage Monitor) — add `"timeoutSeconds": 120`
- Write updated JSON back
- **Expected output:** Both jobs have explicit timeoutSeconds

### Step 1.2: Restart gateway and verify [ ]
- Run: `openclaw gateway restart`
- Wait 15s, run: `openclaw gateway status` — confirm active
- Run: `openclaw cron list 2>/dev/null | grep -E "Watchdog|Disk"` — verify jobs present
- **Expected output:** Gateway restarted, jobs active

---

## Task 2: Commit Workspace (PII Remediation Complete) [P2] [CARRYOVER]
**Why:** 20+ dirty files including PII remediation fixes from Feb 25. Uncommitted work = risk.
**Night-safe approach:** Stage and commit locally only, push requires morning approval.

### Step 2.1: Stage workspace changes [ ]
- Run: `cd ~/.openclaw/workspace && git status --short`
- Stage all: `git add -A`
- **Expected output:** All changes staged

### Step 2.2: Create local commit (no push) [ ]
- Commit: `git commit -m "chore: post-PII-remediation workspace sync

- Updated handoff, tasks, state files
- mission-control index.html update
- skillguard CLI updates
- smartagent gateway scripts
- submodule commits from flavor repos"`
- Verify: `git log -1 --oneline`
- **Expected output:** Commit created locally, NOT pushed

### Step 2.3: Document need for morning push [ ]
- Append to `memory/daily/2026-02-26.md`: "Git push required — workspace commit ready, needs David approval for push to public repos"
- **Expected output:** Reminder documented for morning

---

## Task 3: Research MOR Staking vs Credits [P2] [CARRYOVER]
**Why:** Morpheus beta expires March 1 (3 days). David needs recommendation.

### Step 3.1: Research current pricing and staking info [ ]
- Run: `web_search "Morpheus MOR token staking API credits 2026"` (wait 3s)
- Run: `web_fetch https://mor.org` for pricing details
- Check proxy-router logs for session cost data from Feb (if accessible)
- Document findings in `memory/projects/morpheus/gateway-transition-plan.md`
- **Expected output:** Pricing data collected

### Step 3.2: Write recommendation section [ ]
- Append "## Cost Recommendation" to transition plan
- Include: cost comparison, staking info, urgency (3 days), recommended approach
- **Expected output:** Clear recommendation ready for morning review

---

## Task 4: Agent Architecture Prep Checklist [P3] [CARRYOVER]
**Why:** Architecture work planned for this week. David needs ready checklist.

### Step 4.1: Create setup checklist [ ]
- Create `memory/projects/agent-architecture-setup.md` if not exists
- Document: Business Mac Mini #1 (5 agents), Personal Mac Mini #2 (7 agents)
- List: 12 soulbound NFTs, ERC-8004 registration, ERC-6551 TBAs
- Note: Code already written (hash-identity.mjs, registration-builder.mjs, chain-client.mjs)
- Include: Current blockers (Morpheus Gateway key not working, Venice DIEM timing)
- **Expected output:** Complete checklist ready for David

---

## Task 5: Daily Log & Memory Maintenance [P3]

### Step 5.1: Create today's daily log [ ]
- Create `memory/daily/2026-02-26.md`
- Document: Night shift activity, cron timeout fixes, MOR research, agent prep
- **Expected output:** Daily log started

### Step 5.2: Archive old shift file [ ]
- Archive `shifts/tasks.md` to `shifts/history/2026-02-25-night.md`
- **Expected output:** Old shift archived

### Step 5.3: Update MEMORY.md active context [ ]
- Remove stale items (Morpheus beta now 3 days, not 6)
- Update completed items (PII remediation done, 41 repos cleaned)
- Update open items (add cron job errors)
- **Expected output:** MEMORY.md current

---

## Task 6: Proactive Issue Scan [P3] [STANDING]
**Why:** Standing night task — leave the workspace slightly better than we found it.

### Step 6.1: Diagnose error-state cron jobs [ ]
- List all error jobs: Daily GitHub PR Check, Morning X Briefing, Finance Tracker, Disk Usage Monitor, Capabilities Report, Weekly Goals
- Check one: `openclaw cron logs be4215d6-0c51-4d9f-8ab2-cba2ed2cfcfa` (Morning X Briefing)
- Identify pattern: Are all using Morpheus Gateway which is failing?
- Document findings in `memory/daily/2026-02-26.md`
- **Expected output:** Root cause identified or flagged for morning

---

## Summary
| Priority | Task | Steps | Est. Cycles | Source |
|----------|------|-------|-------------|--------|
| P2 | Fix cron job timeouts | 2 | 2-3 | Carryover |
| P2 | Commit workspace (local only) | 3 | 3-4 | Carryover |
| P2 | Research MOR staking vs credits | 2 | 2-3 | Carryover |
| P3 | Agent architecture prep | 1 | 1-2 | Carryover |
| P3 | Daily log & memory maintenance | 3 | 3-4 | Maintenance |
| P3 | Proactive issue scan (cron errors) | 1 | 1-2 | Standing |

Total steps: 12 | Estimated: 12-16 cycles | Buffer: 16-20 cycles

---

## Night Rules Enforced
- ✅ NO external communications (Signal, email, social)
- ✅ NO financial transactions
- ✅ NO destructive operations (rm -rf, force push)
- ✅ NO security changes (key rotation, permissions)
- ✅ Git push held for morning approval
- ✅ Research and documentation only