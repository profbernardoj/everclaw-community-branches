# Three Shifts v2 — Configuration Reference

## Default Schedule

| Shift | Plan Cron | Cycle Start | Window | Approval Timeout |
|-------|-----------|-------------|--------|-----------------|
| Morning | 6:00 AM | 6:15 AM | 6 AM – 2 PM | 30 min (skip if no response by 6:30 AM) |
| Afternoon | 2:00 PM | 2:15 PM | 2 PM – 10 PM | 30 min |
| Night | 10:00 PM | 10:15 PM | 10 PM – 6 AM | Auto-approve carryover; 15 min for new tasks |

All times in user's local timezone (America/Chicago).

## Models

| Phase | Model | Why |
|-------|-------|-----|
| Planning | venice/claude-opus-4-6 | Quality decomposition, understands complex multi-project context |
| Execution | mor-gateway/glm-5 | Cost-efficient, fast, good at single-step tasks |
| Fallback (exec) | morpheus/glm-5 → venice/claude-opus-4-6 | If gateway times out |

## Cycle Frequency

- **Every 15 minutes** — 32 cycles per 8-hour shift
- Each cycle: ~10-12 min of execution time + 3-5 min buffer
- If a step completes in <5 min, the cycle may take a second step (max 2 per cycle)

## Customizing Shift Times

To change shift times, update the plan and cycle cron jobs. The three shifts should cover 24 hours with no gaps.

Example for an early riser:
```
Morning:   4 AM – 12 PM  (plan cron: 0 4, cycles: 4:15 AM – 11:45 AM)
Afternoon: 12 PM – 8 PM  (plan cron: 0 12, cycles: 12:15 PM – 7:45 PM)
Night:     8 PM – 4 AM   (plan cron: 0 20, cycles: 8:15 PM – 3:45 AM)
```

The cycle cron runs every 15 min globally — it checks state.json to know if it should execute or no-op.

## Task Categories

### Always OK (any shift)
- Reading files, organizing workspace
- Research and analysis
- Code review, documentation
- Memory updates, planning
- Git status, non-destructive commands

### Requires Approval (via shift plan)
- Sending emails, messages, social posts
- Creating PRs, pushing code
- Financial transactions
- Any external-facing action

### Never During Night Shift
- External communications
- Financial transactions
- Destructive operations (rm, force push, branch delete)
- Security changes (key rotation, permission changes)
- Adding new tasks not previously approved

## Night Shift Auto-Approve Rules

The night shift can auto-approve WITHOUT pinging the user when ALL of these are true:
1. All remaining tasks were already approved in today's morning or afternoon shift
2. No new P1 or P2 tasks are being added
3. The tasks are safe for autonomous execution (no external comms, no financial ops)

The night shift CAN autonomously add P3 tasks:
- Memory maintenance, file cleanup
- Documentation updates
- Git housekeeping
- Research and reading

## Approval Behaviors

| Scenario | Behavior |
|----------|----------|
| User approves | Decompose tasks → write tasks.md → cycles begin |
| User modifies | Re-decompose with modifications |
| User says "skip" | Log skip, set state.json to "cancelled" |
| No response (30 min) | Morning/Afternoon: one reminder, then P1 only. Night: auto-approve carryover only |
| User adds mid-shift | Planning model (Claude 4.6) decomposes the new task and appends to tasks.md |

## Weekend Behavior

By default, shifts run 7 days/week. To skip weekends:
- The planning cron should check the day: "If Saturday/Sunday, only propose maintenance tasks unless there are urgent items"
- Or modify cycle cron schedule: `*/15 * * * 1-5` (weekdays only)

## Quiet Hours

- Night shift cycles: no Signal messages, no notifications
- Night handoff: written to file, delivered at morning plan time
- Exception: security alerts or system-down events can notify immediately

## Step Sizing Guide (for decomposition)

A well-sized step for GLM-5:
- **1-3 tool calls** (read, edit, exec — not 10 calls)
- **~5-10 minutes** of actual work
- **One logical action** (commit these files, search for this info, edit this config)
- **Self-contained context** (description + context.md is enough, no conversation history)

Steps that are TOO BIG:
- "Refactor the entire module" → split into per-file steps
- "Research and write a recommendation" → split into "research" + "write"
- "Set up the project from scratch" → split into scaffold, config, deps, test

Steps that are TOO SMALL:
- "Create a directory" → combine with the file write that needs it
- "Read a file" → combine with the action that uses the data

## Error Budget

- After 3 consecutive blocked cycles on the same step: log warning in context.md
- After 5: skip the step, mark `[-]`, note in handoff for user review
- After 10 total cycle failures in a shift: pause execution, notify user

## State Tracking

Track in `shifts/state.json` (see SKILL.md for full schema).

For historical analysis, `shifts/history/` stores completed shift archives with frontmatter stats.
