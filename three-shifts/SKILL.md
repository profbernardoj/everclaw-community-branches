---
name: three-shifts
description: >
  Cyclic shift execution engine. Plans tasks 3x daily (6 AM, 2 PM, 10 PM),
  decomposes them into granular steps, then executes via 15-minute cron cycles.
  Each cycle reads state files, picks the next step, executes it, writes results back.
  Errors are logged and skipped — never fatal. Planning uses Claude 4.6; execution uses GLM-5.
version: 2.0.0
---

# Three Shifts v2 — Cyclic Execution Engine

**Architecture:** Plan once → decompose → execute in 15-minute cycles → each cycle does ONE step → state persists in files between runs.

**Why v2:** V1 ran everything in one long session. One timeout killed the whole shift. V2 is a state machine — errors get logged, skipped, and retried. 32 cycles per shift, each learning from the last.

---

## File Structure

All state lives in `workspace/shifts/`:

```
shifts/
├── tasks.md        # Current shift's step-by-step plan (the state machine)
├── context.md      # Stack, constraints, known pitfalls, learned lessons
├── handoff.md      # What the previous shift left behind
├── state.json      # Machine-readable shift metadata
└── history/        # Archived completed shifts
    └── YYYY-MM-DD-{shift}.md
```

### tasks.md Format

```markdown
# Afternoon Shift — 2026-02-22
Approved by: user | Approved at: 2:15 PM CST
Shift window: 2:00 PM – 10:00 PM CST
Cycles remaining: ~30

## Task 1: API migration plan [P1]
- [x] Step 1.1: Read current proxy-router config and session economics — DONE (cycle 1)
- [ ] Step 1.2: Research mor-[REDACTED] paid tier pricing and limits
- [!] Step 1.3: Compare cost of paid tier vs local-only — BLOCKED: need pricing from step 1.2
- [ ] Step 1.4: Draft transition recommendation in memory/projects/example/

## Task 2: Commit workspace changes [P1]
- [ ] Step 2.1: Run git status, identify logical commit groups
- [ ] Step 2.2: Stage and commit new skills (three-shifts, relationships)
- [ ] Step 2.3: Stage and commit memory reorganization files
- [ ] Step 2.4: Stage and commit scripts and config changes
- [ ] Step 2.5: Push to remote

## Summary
Total steps: 9 | Done: 1 | Blocked: 1 | Remaining: 7
Last cycle: 2026-02-22 14:15 CST — completed step 1.1
Next target: Step 1.2
```

**Step markers:**
- `[ ]` — Not started (available for next cycle)
- `[x]` — Completed (with cycle number and brief result)
- `[!]` — Blocked (with reason — will be retried after dependencies clear)
- `[~]` — In progress (claimed by current cycle, prevents double-execution)
- `[-]` — Skipped (manually removed or deprioritized)

### context.md Format

```markdown
# Shift Context — Living Document

## Stack & Environment
- macOS arm64, OpenClaw 2026.2.21-2
- Git repos: ~/.openclaw/workspace
- 1Password for secrets (never store raw keys)
- Primary messaging channel for user comms

## Constraints
- Never force push or delete branches
- trash > rm (recoverable beats gone)
- Space Brave searches by 2+ seconds (rate limit)
- MiniMax-M2.5: DO NOT USE (broken streaming)
- Llama 3.3 70B: DO NOT USE

## Known Pitfalls (learned from experience)
- API-specific gotchas go here
- Check messaging connectivity if deliveries fail
- Check provider billing cooldown policies
- Always check git status before committing — avoid partial commits

## Rules for This Shift
- Night shift: no external comms, no financial txns, no destructive ops
- If blocked on user input, skip and note in handoff
- Max 1 web search per cycle (Brave rate limit)
```

### state.json Format

```json
{
  "shift": "afternoon",
  "date": "2026-02-22",
  "status": "executing",
  "startedAt": "2026-02-22T20:00:00Z",
  "approvedAt": "2026-02-22T20:15:00Z",
  "approvedBy": "user",
  "planModel": "your-heavy-model (e.g. Claude, GPT-4)",
  "execModel": "your-light-model (e.g. GLM-5, GPT-4o-mini)",
  "totalSteps": 9,
  "completed": 1,
  "blocked": 1,
  "skipped": 0,
  "cyclesRun": 1,
  "lastCycleAt": "2026-02-22T20:15:00Z",
  "nightAutoApproved": false,
  "carryoverFromShift": null
}
```

---

## Shifts

| Shift | Plan Cron | Cycle Crons | Window | Character |
|-------|-----------|-------------|--------|-----------|
| Morning | 6:00 AM | 6:15 AM – 1:45 PM (every 15 min) | 6 AM – 2 PM | Comms, decisions, user-facing |
| Afternoon | 2:00 PM | 2:15 PM – 9:45 PM (every 15 min) | 2 PM – 10 PM | Deep work, building, coding |
| Night | 10:00 PM | 10:15 PM – 5:45 AM (every 15 min) | 10 PM – 6 AM | Autonomous, research, maintenance |

---

## Phase 1: Planning (runs once per shift)

**Model:** `your-heavy-model (e.g. Claude, GPT-4)` (heavy model for quality planning)

When the planning cron fires:

### 1. Gather Context

Read these sources:
- `shifts/handoff.md` — what last shift left behind
- `shifts/context.md` — rules, constraints, pitfalls
- `shifts/state.json` — previous shift stats
- `memory/daily/YYYY-MM-DD.md` — today's activity
- `MEMORY.md` — active projects, priorities, deadlines
- Calendar (if available) — meetings in shift window
- Email (if available) — urgent unreads
- Git status of active repos

### 2. Check for Carryover

If `shifts/tasks.md` has incomplete `[ ]` or `[!]` steps from a previous shift:
- Carry them forward into the new plan automatically
- Mark them as `[carryover]` in the new plan
- Night shift: if ALL remaining items were approved in morning/afternoon, auto-approve (no user ping needed)

### 3. Generate Shift Plan

Present to user in this format:

```
☀️/🌤️/🌙 [SHIFT] SHIFT PLAN
Date: [DATE] | Window: [START]–[END] [TZ]
Exec model: GLM-5 | Cycles: ~32

P1 (Must do):
1. [Task] — [Est. time] — [Why now]
2. ...

P2 (Should do):
3. ...

P3 (Could do):
5. ...

Blocked/Waiting:
- [Item] — [Blocker]

Carryover from last shift:
- [Item] — [Status]

Reply: "Approve" / "Approve all" / "Approve 1,3" / "Add: [task]" / "Skip"
```

### 4. On Approval — Auto-Decompose

This is the critical v2 step. After approval, **before any execution begins:**

1. Take each approved task and break it into **atomic steps** that GLM-5 can execute in a single cycle (~10-12 minutes of work max per step)
2. Each step must be:
   - **Self-contained:** Can be done without remembering previous cycles
   - **Verifiable:** Has a clear "done" condition
   - **Small:** One file edit, one command, one search, one commit — not five things
   - **Context-light:** The step description + context.md should be enough; no conversation history needed
3. Write the decomposed plan to `shifts/tasks.md`
4. Initialize `shifts/state.json`
5. Start the cycle cron (or let the existing every-15-min cron pick it up)

**Decomposition guidelines for GLM-5:**
- Prefer explicit commands over abstract instructions ("Run `git status` in your project dir" not "check the repo")
- Include file paths, command snippets, expected outputs where possible
- If a step requires a decision, split it: "Research X" → "Write recommendation to file" → separate step for user to review
- Max 3 tool calls per step (keeps GLM-5 focused)
- If a task has >8 steps, split it into two tasks

### 5. Night Shift Auto-Approve

If it's 10 PM and:
- `shifts/tasks.md` has incomplete steps from today's morning or afternoon shifts
- Those steps were already approved by the user earlier today
- No new tasks need approval

Then:
- Auto-approve the carryover items
- Skip the user ping
- Write `"nightAutoApproved": true` to state.json
- Begin cycling immediately
- Do NOT add new P1/P2 tasks without user approval (P3 autonomous tasks like cleanup/memory are OK)

### User Approval Flow

When the user responds to a shift plan:

**"Approve" / "Approve all":**
1. Read `shifts/state.json` — confirm status is `awaiting_approval`
2. Set `status` to `"executing"`, `approvedAt` to current ISO timestamp, `approvedBy` to the user's name`
3. Write updated state.json
4. The next cycle executor cron (every 15 min) will pick it up automatically

**"Add: [task]":**
1. Decompose the new task into atomic steps (same rules as planning phase)
2. Append the new steps to `shifts/tasks.md`
3. Update `totalSteps` in state.json
4. Then approve (set status to `"executing"`)

**"Skip":**
1. Set `status` to `"cancelled"` in state.json
2. Write a note in `shifts/handoff.md` that the shift was skipped

**No response after 30 minutes (morning/afternoon):**
- The planning cron already delivered the plan. If no approval comes, cycles will no-op (status stays `awaiting_approval`)
- Next shift's planner will carry forward any planned tasks

---

## Phase 2: Cycle Execution (runs every 15 minutes)

**Model:** `your-light-model (e.g. GLM-5, GPT-4o-mini)` (light model, cost-efficient)

Each cycle is an **isolated session** — no memory of previous cycles except what's in the files.

### Cycle Algorithm

```
1. READ shifts/state.json
   → If status is "completed", "cancelled", "idle", or "awaiting_approval": reply HEARTBEAT_OK (no-op)
   → If status is "executing": continue

2. READ shifts/tasks.md
   → Find first step marked [ ] (not started)
   → If none found, check for [!] (blocked) steps — retry if dependency cleared
   → If all steps are [x], [-], or still [!]: shift is DONE → go to Handoff

3. READ shifts/context.md
   → Load rules, constraints, pitfalls

4. CHECK FOR STALE CLAIMS
   → If any step is marked [~] (claimed by a previous cycle that crashed/timed out):
     - Change it back to [ ] — the previous cycle didn't finish
     - This step becomes the next available step to claim

5. CLAIM the step
   → Mark it [~] (in progress) in tasks.md
   → Write current timestamp to state.json

6. EXECUTE the step
   → Do the work (one focused action)
   → Stay within the step's scope — do NOT drift to other tasks

7. WRITE RESULTS back to tasks.md
   → Success: [x] Step N.N: description — DONE (cycle X): brief result
   → Blocked: [!] Step N.N: description — BLOCKED (cycle X): reason why
   → If blocked, check if next [ ] step has no dependency on this one → continue to it

8. UPDATE state.json
   → Increment cyclesRun, update completed/blocked counts, lastCycleAt

9. UPDATE shifts/context.md (if learned something new)
   → New pitfall discovered? Add it.
   → Found a useful command? Note it.
   → This is how cycles teach future cycles.

10. IF time permits in this cycle, take the NEXT available [ ] step
   → But only if the current step took <5 minutes
   → Never take more than 2 steps per cycle
```

### Cycle Rules

- **One step at a time.** Don't try to be clever and batch.
- **Errors are data, not failures.** Log the error, mark blocked, move on.
- **Never ask the user mid-cycle.** If you need user input, mark blocked and note what's needed.
- **Stay in scope.** The step says "commit skill files" — don't also refactor the README.
- **Update context.md with lessons.** This is how you teach the next cycle.
- **Respect quiet hours.** Night cycles: no messages, no external comms.
- **Max 2 steps per cycle.** Leave time for the next cycle to start clean.

### Handling Blocks

When a step is blocked:
1. Mark it `[!]` with a clear reason
2. Check if the block is:
   - **Dependency block** (step 3 needs step 2's output): Skip, will retry when step 2 clears
   - **User block** (needs user input): Note in handoff, skip
   - **External block** (API down, service unavailable): Retry next cycle automatically
   - **Error block** (command failed): Log error in context.md, retry with different approach next cycle
3. Move to the next available `[ ]` step
4. Blocked steps get re-evaluated each cycle — if the blocker resolves, they become available again

### Handling Retries

If a `[!]` step has been blocked for 3+ cycles:
1. Write a note in context.md about the persistent failure
2. Check if there's an alternative approach
3. If the step has failed 5+ times, mark it `[-]` (skipped) and note in handoff for user review

---

## Phase 3: Handoff (automatic when shift ends)

When all steps are `[x]`, `[-]`, or `[!]`, OR when the shift window expires:

1. **Archive the shift:**
   - Copy `shifts/tasks.md` → `shifts/history/YYYY-MM-DD-{shift}.md`
   - Include final state.json data as YAML frontmatter

2. **Write handoff.md:**
```markdown
# Handoff: Afternoon → Night | 2026-02-22

## Completed
- Task 1: API migration plan — recommendation written to memory/projects/example/
- Task 2 steps 1-3: Workspace commits (skills, memory reorg)

## Still In Progress
- Task 2 steps 4-5: Script commits and push (2 steps remaining)

## Blocked (needs user)
- Task 1 step 3: Need pricing confirmation for mor-[REDACTED] paid tier

## Lessons Learned This Shift
- GLM-5 handles git operations well but struggles with multi-file diffs
- Brave search rate limit hit on cycle 4 — added 3-second delay to context.md

## Recommendations for Next Shift
- Finish Task 2 push (quick, 1 cycle)
- Review migration recommendation in memory/projects/example/transition.md
```

3. **Update state.json:** Set status to "completed"

4. **Update daily log:** Append shift summary to `memory/daily/YYYY-MM-DD.md`

5. **Notify user** (morning/afternoon only): Brief summary via messaging channel
   - Night shift: write summary but don't ping until morning planning cron

---

## Cron Setup

### Planning Crons (3 jobs — Claude 4.6)

```
Name: three-shifts-plan-morning
Schedule: cron 0 6 * * * (America/Chicago)
Model: your-heavy-model (e.g. Claude, GPT-4)
Session: isolated
Message: >
  Read the three-shifts skill at skills/three-shifts/SKILL.md.
  Execute Phase 1 (Planning) for the MORNING shift (6 AM – 2 PM CST).
  Read shifts/handoff.md, shifts/context.md, shifts/state.json, and recent memory files.
  Generate the shift plan and present for user approval.
  If carryover items exist from last night that were already approved, note them.
  After approval, decompose all tasks into atomic GLM-5-sized steps and write to shifts/tasks.md.

Name: three-shifts-plan-afternoon
Schedule: cron 0 14 * * * (America/Chicago)
Model: your-heavy-model (e.g. Claude, GPT-4)
Session: isolated
Message: >
  Read the three-shifts skill at skills/three-shifts/SKILL.md.
  Execute Phase 1 (Planning) for the AFTERNOON shift (2 PM – 10 PM CST).
  Read shifts/handoff.md, shifts/context.md, shifts/state.json, and recent memory files.
  Generate the shift plan and present for user approval.
  After approval, decompose all tasks into atomic GLM-5-sized steps and write to shifts/tasks.md.

Name: three-shifts-plan-night
Schedule: cron 0 22 * * * (America/Chicago)
Model: your-heavy-model (e.g. Claude, GPT-4)
Session: isolated
Message: >
  Read the three-shifts skill at skills/three-shifts/SKILL.md.
  Execute Phase 1 (Planning) for the NIGHT shift (10 PM – 6 AM CST).
  Read shifts/handoff.md, shifts/context.md, shifts/state.json, and recent memory files.
  IMPORTANT: If shifts/tasks.md has carryover items already approved today, auto-approve them
  and set state.json nightAutoApproved=true. Do NOT ping the user for already-approved carryover.
  Only present new tasks for approval.
  After approval (or auto-approve), decompose into atomic steps and write to shifts/tasks.md.
```

### Execution Crons (1 job — GLM-5, runs every 15 min)

```
Name: three-shifts-cycle
Schedule: cron */15 * * * * (America/Chicago)
Model: your-light-model (e.g. GLM-5, GPT-4o-mini)
Session: isolated
Message: >
  You are a cycle executor for the three-shifts system.
  Read skills/three-shifts/SKILL.md Phase 2 (Cycle Execution) for your algorithm.
  Then read shifts/state.json — if status is not "executing", reply HEARTBEAT_OK.
  If executing: read shifts/tasks.md and shifts/context.md.
  Find the first [ ] step, claim it [~], execute it, write result back.
  If blocked, mark [!] with reason, move to next [ ] step.
  Update state.json and context.md as needed.
  Stay focused. One step. Write results. Done.
```

---

## Configuration

See `references/config.md` for:
- Customizing shift times
- Weekend behavior
- Quiet hours
- Task categories and safety rules

---

## Safety Rules

### Always OK (any shift, any cycle)
- Reading files, git status, web search
- Writing to workspace files (tasks.md, context.md, memory/)
- Running non-destructive commands

### Requires Approval (via shift plan, not mid-cycle)
- Sending emails, messages, social posts
- Creating PRs, pushing code
- Financial transactions

### Never During Night Shift Cycles
- External communications (messaging, email, social)
- Financial transactions
- Destructive operations (rm, force push, branch delete)
- Security changes (key rotation, permissions)
- New tasks not already approved

### Cycle-Specific Safety
- Never take more than 2 steps per cycle
- Never exceed 12 minutes of execution per step
- If a step seems dangerous, mark it `[!] NEEDS_REVIEW` instead of executing
- Never modify context.md to remove safety rules
- Never modify this SKILL.md during a cycle
