---
name: three-shifts
description: Generate and propose 8-hour shift task plans for user approval, three times daily (default 6 AM, 2 PM, 10 PM local time). Use when the user asks about shift planning, daily task proposals, work scheduling, or when a shift cron job fires. Replaces night-shift with full-day coverage.
---

# Three Shifts

Propose a prioritized task list at the start of each 8-hour shift. The user approves, modifies, or rejects before execution begins. Nothing runs without approval.

## Shifts

| Shift | Default Time | Window | Character |
|-------|-------------|--------|-----------|
| Morning | 6:00 AM | 6 AM – 2 PM | Ramp-up: meetings, comms, decisions |
| Afternoon | 2:00 PM | 2 PM – 10 PM | Deep work: coding, writing, building |
| Night | 10:00 PM | 10 PM – 6 AM | Autonomous: research, prep, maintenance |

Times are in the user's local timezone (from USER.md or system config).

## Shift Planning Process

When a shift cron fires or the user requests a shift plan:

### 1. Gather Context

Read these sources to understand what's relevant:
- `memory/YYYY-MM-DD.md` (today + yesterday) — recent activity
- `MEMORY.md` — active projects, priorities, upcoming deadlines
- `HEARTBEAT.md` — any standing checks
- Calendar (if gog skill available) — meetings in the shift window
- Email (if gog skill available) — urgent unreads
- Git status of active repos — open PRs, pending reviews
- Any pending items from the previous shift's handoff

### 2. Generate the Shift Plan

Build a plan that fits the 8-hour window. Include:

**Header:**
```
☀️/🌤️/🌙 [SHIFT NAME] SHIFT PLAN
Date: [DATE]
Window: [START] – [END] [TZ]
```

**Active Projects** — Brief status of each in-flight project.

**Proposed Tasks** — Grouped by priority:
- **P1 (Must do)** — Time-sensitive, blocking, or committed deliverables
- **P2 (Should do)** — Advances active projects meaningfully
- **P3 (Could do)** — Research, cleanup, nice-to-haves

Each task: `[Task description] — [Est. time] — [Why now]`

Total estimated time should not exceed 7 hours (leave buffer for interruptions).

**Blocked/Waiting** — Items that can't progress and why.

**Handoff Notes** — What the next shift should pick up.

### 3. Present for Approval

Send the plan to the user. Include response options:
```
Reply with:
• "Approve" — Execute all P1+P2
• "Approve all" — Execute P1+P2+P3
• "Approve [numbers]" — Specific tasks only
• "Add: [task]" — Add a task
• "Skip" — No shift today
• Or just tell me what to change
```

### 4. Execute Approved Tasks

After approval:
- Work through tasks in priority order
- Log progress in `memory/YYYY-MM-DD.md`
- If a task takes longer than estimated, note it and continue
- If blocked, move to next task and flag for handoff

### 5. Shift Handoff

At shift end (or when tasks complete), write a brief handoff:
- What was completed
- What's in progress
- What's blocked
- Recommendations for next shift

Store in `memory/YYYY-MM-DD.md` under a `## [Shift Name] Shift` heading.

## Shift-Specific Guidelines

### Morning Shift (6 AM – 2 PM)
- Check email/calendar first — surface anything urgent
- Front-load tasks requiring user decisions (user is most available)
- Schedule meetings prep early
- External communications are OK with approval

### Afternoon Shift (2 PM – 10 PM)
- Deep focus work — coding, writing, building
- Minimize interruptions to the user unless blocked
- Good window for PR reviews, documentation, complex tasks
- Batch communications for end of shift

### Night Shift (10 PM – 6 AM)
- Autonomous work only — minimize user pings
- **Never:** send external comms, make financial transactions, delete data, change security settings
- **Good for:** research, content drafts, code refactoring, documentation, monitoring, file organization
- If user doesn't approve by 10:30 PM, the night shift is cancelled
- At 6 AM: update Mission Control dashboard if available

## Configuration

Default config lives in `references/config.md`. Read it when:
- Setting up cron jobs for the first time
- User wants to change shift times
- Customizing task categories or approval behavior

## Cron Setup

Create three cron jobs via OpenClaw:

```
Name: three-shifts-morning
Schedule: 0 6 * * *
Message: Generate morning shift plan. Read the three-shifts skill, gather context, and propose tasks for the 6 AM – 2 PM window.
Model: [default model]

Name: three-shifts-afternoon
Schedule: 0 14 * * *
Message: Generate afternoon shift plan. Read the three-shifts skill, gather context, and propose tasks for the 2 PM – 10 PM window.
Model: [default model]

Name: three-shifts-night
Schedule: 0 22 * * *
Message: Generate night shift plan. Read the three-shifts skill, gather context, and propose tasks for the 10 PM – 6 AM window.
Model: [default model]
```

## Integration with Night Shift

This skill supersedes the standalone `night-shift` skill. The night shift (10 PM – 6 AM) is now one of three shifts rather than a standalone concept. Migrate any night-shift-specific cron jobs to the three-shifts system.
