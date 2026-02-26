# Night Shift Skill

**Purpose:** Generate actionable overnight tasks based on the day's projects and objectives.

---

## How It Works

### 1. Cron Job (Every Night at 9:30 PM CST)
- Triggers the night shift planning process
- Reviews the day's context (projects, objectives, conversations)
- Generates a prioritized list of actions for the 10 PM - 6 AM window

### 2. Action List Generation
The night shift action list should include:
- Tasks that can be completed autonomously
- Research tasks
- Content creation
- Code/documentation work
- Prep for the next day

### 3. Human Review (Before 10 PM)
- List is presented to David for approval
- David can approve, modify, or reject tasks
- Only approved tasks are executed during night shift

---

## Night Shift Execution

### Time Window: 10:00 PM - 6:00 AM CST

### Task Types Approved for Night Shift:
1. **Research** — Web searches, documentation review, competitive analysis
2. **Content Creation** — Writing drafts, marketing copy, documentation
3. **Code Tasks** — Non-breaking changes, refactoring, documentation
4. **Prep Work** — Scheduling cron jobs, preparing agendas, organizing files
5. **Monitoring** — Watching for PR reviews, checking discussion responses

### Task Types NOT Approved for Night Shift:
1. **Breaking Changes** — Any code that could break production
2. **External Communications** — Sending emails, tweets, DMs
3. **Financial Transactions** — Any money-moving actions
4. **Deletions** — Deleting files, branches, or data
5. **Security-Sensitive** — Key rotations, permission changes

---

## Cron Job Setup

```bash
# Night Shift Planning Cron
# Runs every night at 9:30 PM CST
# Generates action list for David to review before 10 PM
```

---

## Output Format

### Night Shift Action Plan (Generated at 9:30 PM)

```
🌙 NIGHT SHIFT ACTION PLAN
Date: [DATE]
Time Window: 10:00 PM - 6:00 AM CST

## Projects in Progress
- [Project 1]: [Status]
- [Project 2]: [Status]

## Proposed Actions
### Priority 1 (Can Complete Tonight)
1. [Task] — [Estimated time] — [Why it matters]
2. [Task] — [Estimated time] — [Why it matters]

### Priority 2 (Research/Prep)
1. [Task] — [Estimated time] — [Why it matters]
2. [Task] — [Estimated time] — [Why it matters]

### Priority 3 (Nice to Have)
1. [Task] — [Estimated time] — [Why it matters]

## Actions NOT Approved for Night Shift
- [Task] — [Reason: requires external communication]
- [Task] — [Reason: security-sensitive]

---
Please review and approve. Reply with:
- "Approve all" — Execute all priority 1+2
- "Approve [numbers]" — Execute specific tasks
- "Modify: [instructions]" — Adjust the plan
- "Reject" — No night shift tonight
```

---

## Setup Instructions

To enable Night Shift:

1. Create the cron job:
```bash
# Add to crontab
30 21 * * * /path/to/night-shift-planner.sh
```

2. Or use OpenClaw's cron system:
```bash
openclaw cron add --name "Night Shift Planning" --schedule "30 21 * * *" --message "Generate night shift action plan"
```

---

## Example Use Cases

### Example 1: Marketing Campaign Prep
**Day shift:** Discuss viral narratives for EverClaw flavors
**Night shift:** Write social media thread templates for each flavor

### Example 2: Code Documentation
**Day shift:** Review Docker PR for EverClaw
**Night shift:** Write comprehensive README updates

### Example 3: Research Tasks
**Day shift:** Discuss EverClaw accelerator concept
**Night shift:** Research existing accelerators, compile comparison table

---

## End of Night Shift: Mission Control Update

**At 6:00 AM CST**, before ending the night shift:

1. Run the Mission Control dashboard data generator:
   ```bash
   cd ~/.openclaw/workspace && node mission-control/generate-data.mjs
   ```

2. This updates `mission-control/dashboard-data.json` and embeds data into `index.html`

3. The dashboard includes:
   - Completed tasks from memory files
   - Updated goal progress
   - Activity feed with night shift actions

4. David can review the dashboard at `file://~/.openclaw/workspace/mission-control/index.html`

This gives David a rich UI view of overnight progress in addition to the Signal summary.

---

## Notes

- Night shift is optional — David must approve before execution
- Tasks that require external communication are never automated
- All night shift actions are logged and reported in the morning
- If David doesn't respond by 10 PM, night shift is cancelled by default
- Mission Control dashboard is updated at end of night shift (6 AM)