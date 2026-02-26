---
name: relationships
description: "Relationship CRM for tracking people, connections, and context. Categories: family, close_friends, church_friends, colleagues, broader_community, strangers, bad_actors, unknown. Use to add, search, list, or update people in the user's network."
---

# Relationships CRM

## Overview
Track people in the user's life with rich context. Store relationship data, interaction history, and personal details in structured memory files.

## Categories
| Category | Description |
|----------|-------------|
| `family` | Immediate and extended family |
| `close_friends` | Trusted inner circle |
| `church_friends` | Friends from church community |
| `colleagues` | Professional contacts, collaborators, business partners |
| `broader_community` | Acquaintances, community members, loose connections |
| `strangers` | One-time contacts, unknown intent |
| `bad_actors` | People to avoid or be cautious around |
| `unknown` | Not yet categorized |

## Commands

### Add a person
```
/relationship add "Firstname Lastname" --category <category> [details]
```
Creates a new contact file or updates existing.

### List by category
```
/relationship list <category>
```
Shows all contacts in a category.

### Search
```
/relationship search <query>
```
Full-text search across all contacts.

### Update
```
/relationship update "Firstname Lastname" --field <field> --value <value>
```
Updates a specific field.

### Note interaction
```
/relationship interact "Firstname Lastname" --date YYYY-MM-DD --summary "what happened"
```
Logs an interaction to the contact's history.

## File Structure
```
memory/relationships/
├── family/
│   ├── family-member.md
│   └── ...
├── close_friends/
├── church_friends/
├── colleagues/
├── broader_community/
├── strangers/
├── bad_actors/
├── unknown/
└── index.json    # Quick lookup index
```

## Contact File Format
```markdown
# Firstname Lastname

## Basics
- **Category:** family
- **Relationship:** Wife
- **First met:** YYYY-MM-DD or "since childhood" etc.
- **Last contact:** YYYY-MM-DD

## Context
[Background, how we know them, what they mean to David]

## Key Details
- Birthday: YYYY-MM-DD
- Location: City, State
- Phone: +1...
- Email: ...
- Social: @handle

## Family
- Spouse: ...
- Children: ...

## Interactions
### YYYY-MM-DD - [Title]
[What happened, key points, follow-ups]

## Notes
[Running notes, things to remember]
```

## Workflow
1. When asked about someone, search first
2. When adding new people, ask clarifying questions
3. After interactions, prompt to log them
4. Periodically suggest categorization updates
5. Respect privacy — never share contact info externally without permission

## Integration with Memory
- Contacts live in `memory/relationships/` for context persistence
- Key people may also be referenced in `MEMORY.md` for high-level context
- Daily notes in `memory/YYYY-MM-DD.md` can reference contacts

## Privacy
- Contact files stay local
- Never sync to cloud or external services
- Malicious actors flagged in `bad_actors/` with caution notes