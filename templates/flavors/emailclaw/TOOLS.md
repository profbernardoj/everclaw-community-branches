# TOOLS.md — EmailClaw

## Required Skills

### gog (Google Workspace CLI)
- **What:** Gmail, Calendar, Contacts access
- **Install:** Built into OpenClaw
- **Setup:** Run `gog auth` to authenticate with Google account
- **Key commands:**
  - `gog gmail list --unread` — List unread messages
  - `gog gmail read <id>` — Read a specific message
  - `gog gmail send` — Send a message (requires approval)
  - `gog gmail search <query>` — Search inbox

### summarize
- **What:** Summarize long email threads and attachments
- **Install:** Built into OpenClaw
- **Use:** When an email thread is >5 messages, summarize before presenting

## Optional Skills (install via ClawHub)

### email-daily-summary
- `clawhub install email-daily-summary`
- Generates formatted daily email digests

### himalaya
- `clawhub install himalaya`
- Alternative IMAP/SMTP client for non-Gmail accounts (Outlook, ProtonMail, etc.)

## Configuration

### VIP Senders
<!-- Add email addresses that should always trigger alerts -->
```
vip_senders:
  - boss@company.com
  - spouse@email.com
```

### Labels / Categories
<!-- Define how you want mail organized -->
```
categories:
  urgent: "Needs response today"
  followup: "Needs response this week"
  fyi: "Read when you have time"
  noise: "Newsletters, promotions, auto-generated"
```

### Quiet Hours
```
quiet_hours:
  start: "23:00"
  end: "07:00"
  timezone: "{{TIMEZONE}}"
  vip_override: true
```
