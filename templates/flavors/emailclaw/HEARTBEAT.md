# HEARTBEAT.md — EmailClaw

## Inbox Check
- Check for unread emails in primary inbox
- Flag any messages from VIP senders (see TOOLS.md for VIP list)
- Summarize anything urgent (deadline-related, time-sensitive, requires action today)
- If nothing urgent, reply HEARTBEAT_OK

## Follow-up Tracker
- Check `memory/email-followups.md` for threads awaiting response
- If any follow-up is overdue (>48h), alert the user

## Quiet Hours
- Between 23:00–07:00 local time, only alert for messages from VIP senders
- Everything else waits until the morning digest
