# CRM Directory

*Relationship tracking. Add contacts, interactions, follow-ups.*

---

## Structure

```
crm/
├── README.md (this file)
├── contacts/     — Individual contact files
├── interactions/ — Meeting notes, call logs
└── followups/    — Pending follow-ups by person/date
```

## Contact Template

Create a file per person: `contacts/[firstname]-[lastname].md`

```markdown
# [Name]

## Basic Info
- **Role:** 
- **Organization:** 
- **Location:** 
- **Email:** 
- **Signal:** 
- **First contact:** 

## Context
How they connect to David

## Interactions
- YYYY-MM-DD: [summary]

## Follow-ups
- [ ] [next action] by [date]

## Notes
```

---

*Sync from PEOPLE.md when someone becomes an active relationship.*