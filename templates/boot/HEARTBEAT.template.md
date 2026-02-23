# HEARTBEAT.md

<!-- ═══════════════════════════════════════════════════════════════
     WHAT IS THIS FILE?
     
     OpenClaw sends your agent a "heartbeat" message periodically
     (default: every ~30 minutes). The agent reads this file to decide
     what to do during each heartbeat.
     
     If this file is empty (or only has comments), the agent replies
     HEARTBEAT_OK and does nothing — saving tokens and API calls.
     
     HOW TO USE IT:
     
     Add short checklist items when you want the agent to periodically
     check on something. Remove them when they're no longer needed.
     
     GOOD HEARTBEAT ITEMS:
     - [ ] Check email for replies from [person] about [topic]
     - [ ] Monitor PR #42 for merge — notify me when it's done
     - [ ] Check if [website] is back online
     - [ ] Remind me about [task] if I haven't done it by 3 PM
     
     BAD HEARTBEAT ITEMS (use cron instead):
     - Things that need exact timing (use cron with schedule)
     - Heavy tasks that take many tool calls (use cron with isolated session)
     - Things that should run on a different model (use cron with model override)
     
     KEEP IT SMALL:
     The entire contents of this file are included in every heartbeat
     turn. More text = more tokens burned every 30 minutes. Aim for
     5 items or fewer. Move completed items to daily notes.
     ═══════════════════════════════════════════════════════════════ -->

<!-- Add tasks below when you want the agent to check something periodically. -->
