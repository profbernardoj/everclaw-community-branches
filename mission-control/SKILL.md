---
name: mission-control
description: >
  Visual dashboard for your OpenClaw agent. Shows life goals, activity feed,
  key facts from memory, and project status. Auto-refreshes via daily cron job.
  No external dependencies — pure HTML + JSON data file.
version: 1.0.0
---

# Mission Control Dashboard

A visual overview of your agent's world — goals, activity, projects, and key facts.

## Setup

### 1. Copy files to workspace

```bash
cp -r skills/everclaw/mission-control/ ~/.openclaw/workspace/mission-control/
```

### 2. Edit configuration

In `generate-data.mjs`, update the `CONFIG` object:

```javascript
const CONFIG = {
  ownerName: "Your Name",
  timezone: "America/Chicago",
  // Goals are auto-discovered from memory/goals/*.md
};
```

### 3. Generate initial data

```bash
cd ~/.openclaw/workspace && node mission-control/generate-data.mjs
```

### 4. View dashboard

Open `mission-control/index.html` in any browser. Data is embedded directly — no server needed.

### 5. Set up daily refresh cron

```
Name: Dashboard Refresh
Schedule: 0 3 * * * (your timezone)
Model: your-light-model
Session: isolated
Timeout: 120s
Message: >
  Run the Mission Control dashboard data generator to refresh the dashboard.
  Execute: cd ~/.openclaw/workspace && node mission-control/generate-data.mjs
  Report the output. If it fails, report the error.
```

## How It Works

- `generate-data.mjs` scans your workspace: goals, memory files, MEMORY.md
- Produces `dashboard-data.json` with structured data
- Embeds the data directly into `index.html` (works from `file://` protocol)
- Dashboard renders goals, activity timeline, key facts, and stats
- No external API calls, no server, no dependencies

## Customization

- Edit `index.html` CSS for colors/layout
- Goal files in `memory/goals/` are auto-discovered — just add new `.md` files
- Activity feed reads from `memory/daily/` and `memory/YYYY-MM-DD*.md`
