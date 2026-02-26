# TOOLS.md — FamilyClaw

## Required Skills

### gog (Google Workspace CLI)
- **What:** Shared family calendar, contacts
- **Install:** Built into OpenClaw
- **Setup:** `gog auth` — authenticate with the family Google account
- **Key commands:**
  - `gog cal list` — View upcoming family events
  - `gog cal add` — Add events to the family calendar

### apple-reminders
- **What:** Shared reminders and lists (groceries, to-dos, chores)
- **Install:** Built into OpenClaw (macOS only)
- **Use:** Shared Apple Reminders lists sync across family devices

### weather
- **What:** Weather forecasts
- **Install:** Built into OpenClaw
- **Use:** "Do the kids need jackets?" "Is soccer practice likely to be rained out?"

## Optional Skills (install via ClawHub)

### apple-notes
- Built into OpenClaw (macOS only)
- Shared family notes, packing lists, recipe collections

### family-todo-management
- `clawhub install family-todo-management`
- Dedicated family task management

## Configuration

### Family Members
<!-- List family members and their key info -->
```
family:
  - name: "Parent 1"
    role: "parent"
    calendar: "parent1@gmail.com"
  - name: "Parent 2"
    role: "parent"
    calendar: "parent2@gmail.com"
  - name: "Child 1"
    role: "child"
    age: 10
    school: "Elementary School"
    activities: ["soccer", "piano"]
  - name: "Child 2"
    role: "child"
    age: 7
    school: "Elementary School"
    activities: ["gymnastics"]
```

### School Calendar
```
school:
  district: "Your School District"
  calendar_url: ""  # ICS feed if available
  start_date: "2025-08-18"
  end_date: "2026-05-28"
  # Add key dates manually if no ICS feed
  breaks:
    - name: "Fall Break"
      start: "2025-10-13"
      end: "2025-10-17"
    - name: "Winter Break"
      start: "2025-12-22"
      end: "2026-01-02"
    - name: "Spring Break"
      start: "2026-03-16"
      end: "2026-03-20"
```

### Meal Planning
```
meals:
  plan_days: 7           # plan a week at a time
  dietary_restrictions: []
  grocery_store: ""        # preferred store
  grocery_day: "Sunday"
```

### Chore Rotation
```
chores:
  rotation: "weekly"  # daily | weekly
  assignments:
    - chore: "dishes"
      members: ["Child 1", "Child 2"]
    - chore: "trash"
      members: ["Child 1"]
    - chore: "laundry"
      members: ["Parent 1", "Parent 2"]
```
