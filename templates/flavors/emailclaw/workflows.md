# Workflows — EmailClaw

## Example Use Cases

### 1. Morning Inbox Triage
> "Check my email"

The agent scans unread messages, categorizes them (urgent/followup/fyi/noise), and presents a prioritized summary. Urgent items get full context; noise gets a count.

### 2. Draft a Reply
> "Draft a reply to the email from Sarah about the project deadline"

The agent reads the thread, understands context, and drafts a reply matching your tone. You review and approve before it sends.

### 3. Track Follow-ups
> "Remind me to follow up with Mike if he doesn't reply by Thursday"

The agent adds the thread to `memory/email-followups.md` with a deadline. Heartbeat checks will surface it when it's overdue.

### 4. Summarize a Thread
> "Summarize the thread with legal about the contract"

The agent reads the full thread and produces a concise summary with key decisions, open questions, and action items.

### 5. Unsubscribe from Noise
> "Unsubscribe me from all marketing emails from last month"

The agent identifies newsletter/marketing emails, lists them for your approval, then processes unsubscribe links for the ones you confirm.

### 6. Extract Action Items
> "What do I owe people from this week's emails?"

The agent scans the week's messages for commitments you made or tasks assigned to you, and presents them as a checklist.

### 7. Meeting Prep
> "Pull up all emails related to tomorrow's meeting with the board"

The agent searches for threads involving board members or the meeting topic, summarizes key points, and presents a pre-meeting briefing.
