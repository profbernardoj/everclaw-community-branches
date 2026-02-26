# TOOLS.md — OfficeClaw

## Required Skills

### gog (Google Workspace CLI)
- **What:** Gmail, Calendar, Drive, Docs, Sheets, Contacts
- **Install:** Built into OpenClaw
- **Setup:** Run `gog auth` to authenticate
- **Key commands:**
  - `gog cal list` — List upcoming events
  - `gog cal add` — Create a calendar event
  - `gog gmail list --unread` — Check inbox
  - `gog drive list` — Browse Drive files
  - `gog docs read <id>` — Read a Google Doc

### summarize
- **What:** Summarize documents, URLs, and long threads
- **Install:** Built into OpenClaw
- **Use:** Pre-meeting briefs, document summaries, research digests

### github (optional)
- **What:** Issue tracking, PR management, code review
- **Install:** Built into OpenClaw
- **Use:** For teams that use GitHub for project management

## Optional Skills (install via ClawHub)

### trello
- Built into OpenClaw
- Kanban-style task management

### notion
- Built into OpenClaw
- For teams using Notion as their workspace

### slack
- Built into OpenClaw
- Slack channel monitoring and messaging

## Configuration

### Key Stakeholders
<!-- People whose messages/meetings get priority -->
```
stakeholders:
  - manager: "name@company.com"
  - direct_reports:
    - "alice@company.com"
    - "bob@company.com"
  - key_clients:
    - "client@partner.com"
```

### Meeting Defaults
```
meetings:
  default_duration: 30
  prep_lead_time: 15  # minutes before meeting to generate brief
  auto_notes: true
  follow_up_deadline: 24  # hours to send follow-up
```

### Work Hours
```
work_hours:
  start: "08:00"
  end: "18:00"
  timezone: "{{TIMEZONE}}"
  work_days: ["Mon", "Tue", "Wed", "Thu", "Fri"]
```
