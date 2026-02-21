# Three Shifts — Configuration Reference

## Default Schedule

| Shift | Cron | Window | Approval Timeout |
|-------|------|--------|-----------------|
| Morning | `0 6 * * *` | 6:00 AM – 2:00 PM | 30 min (skip if no response by 6:30 AM) |
| Afternoon | `0 14 * * *` | 2:00 PM – 10:00 PM | 30 min |
| Night | `0 22 * * *` | 10:00 PM – 6:00 AM | 30 min (cancel shift if no response) |

All times in user's local timezone.

## Customizing Shift Times

To change shift times, update the cron jobs. The three shifts should always cover 24 hours with no gaps. Example for an early riser:

```
Morning:   4 AM – 12 PM  (cron: 0 4 * * *)
Afternoon: 12 PM – 8 PM  (cron: 0 12 * * *)
Night:     8 PM – 4 AM   (cron: 0 20 * * *)
```

## Task Categories

### Always OK (any shift)
- Reading files, organizing workspace
- Research and analysis
- Code review, documentation
- Memory updates, planning

### Requires Approval (morning/afternoon only)
- Sending emails, messages, social posts
- Creating PRs, pushing code
- Financial transactions
- Any external-facing action

### Never During Night Shift
- External communications
- Financial transactions
- Destructive operations (rm, force push, branch delete)
- Security changes (key rotation, permission changes)

## Approval Behaviors

| Scenario | Behavior |
|----------|----------|
| User approves | Execute approved tasks in priority order |
| User modifies | Re-plan with modifications, re-present if major changes |
| User says "skip" | Log skip, no execution, handoff notes still generated |
| No response (30 min) | Morning/Afternoon: send one reminder, then proceed with P1 only. Night: cancel entirely |
| User is sleeping | Night shift: never ping after initial plan. Wait for morning |

## Model Selection

Shift planning should use the default model (currently GLM-5 via Morpheus). The planning task is STANDARD tier — no need for Claude unless the user has complex multi-project prioritization.

## Weekend Behavior

By default, shifts run 7 days/week. To skip weekends:
- Wrap cron message with: "If today is Saturday or Sunday, reply HEARTBEAT_OK unless there are urgent items."
- Or use cron schedule: `0 6 * * 1-5` (weekdays only)

## Quiet Hours

The agent should not send notifications during these windows unless truly urgent:
- 11 PM – 7 AM (default quiet hours)
- Night shift plan is the exception (sent at 10 PM)
- If the user is in a different timezone while traveling, adjust accordingly

## State Tracking

Track shift state in `memory/shift-state.json`:

```json
{
  "lastShift": {
    "name": "afternoon",
    "date": "2026-02-21",
    "status": "completed",
    "tasksApproved": 5,
    "tasksCompleted": 4,
    "tasksBlocked": 1
  },
  "streaks": {
    "consecutiveShifts": 12,
    "lastSkip": "2026-02-18"
  }
}
```

This helps the agent understand momentum and avoid proposing stale tasks.
