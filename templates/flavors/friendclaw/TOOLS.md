# TOOLS.md — FriendClaw

## Required Skills

### gog (Google Workspace CLI)
- **What:** Contacts, Calendar for events and birthdays
- **Install:** Built into OpenClaw
- **Use:** Contact lookup, birthday sync, event scheduling

### apple-reminders (macOS)
- **What:** Shared reminder lists for gift ideas, to-dos
- **Install:** Built into OpenClaw
- **Use:** Gift lists, errand reminders for friends

## Optional Skills (install via ClawHub)

### apple-notes (macOS)
- Built into OpenClaw
- Store detailed notes about friends (interests, preferences, conversation topics)

### weather
- Built into OpenClaw
- Check weather for event planning ("Is Saturday good for the BBQ?")

## Configuration

### Contact Tiers
<!-- Define how often to check in based on relationship closeness -->
```
tiers:
  inner_circle:
    description: "Closest friends and family"
    check_in_days: 14        # nudge if no contact in 14 days
    contacts: []              # add names/identifiers
  close_friends:
    description: "Good friends you see regularly"
    check_in_days: 30
    contacts: []
  extended:
    description: "Friends you value but see less often"
    check_in_days: 90
    contacts: []
  network:
    description: "Professional-social connections"
    check_in_days: 180
    contacts: []
```

### Birthday Reminders
```
birthdays:
  advance_notice_days: 7      # first reminder X days before
  day_before_reminder: true
  day_of_reminder: true
  auto_suggest_gift: true
  default_gift_budget: 50
```

### Event Preferences
```
events:
  preferred_venues: []
  dietary_notes: []           # track friends' dietary restrictions
  default_group_size: 6
  planning_lead_days: 14      # start planning X days before
```

### Gift Log
```
# Track gifts given to avoid repeats and remember preferences
gift_log:
  # - person: "Mike"
  #   date: "2025-12-25"
  #   gift: "Whiskey stones set"
  #   occasion: "Christmas"
  #   reaction: "Loved it"
```

### Conversation Starters
```
# Topics and interests by friend — helps generate natural check-in prompts
interests:
  # - person: "Mike"
  #   interests: ["golf", "bourbon", "Formula 1"]
  #   recent_events: ["just got promoted", "kid started kindergarten"]
```
