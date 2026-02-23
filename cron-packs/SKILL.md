---
name: cron-packs
description: >
  Pre-built cron job templates for common agent automation patterns.
  Pick a pack, customize the placeholders, and register via OpenClaw.
  Categories: Essential, Family, Investor, Developer, Briefings.
version: 1.0.0
---

# Cron Starter Packs

Ready-made cron job templates to automate your agent's daily work. Each pack is a set of JSON job definitions you can register via OpenClaw's cron system.

## How to Use

1. Pick a pack below
2. Edit the placeholders (`YOUR_PHONE`, `YOUR_TIMEZONE`, etc.)
3. Register via OpenClaw cron tool or paste into your agent's setup

## Packs

### 📋 Essential Pack
The basics every agent should have.

| Job | Schedule | What It Does |
|-----|----------|-------------|
| Dashboard Refresh | 3 AM daily | Regenerates Mission Control data |
| Disk Usage Monitor | 9 AM daily | Alerts if disk > 50% full |
| Session Archiver | Every 6 hours | Prevents session files from growing too large |

→ See `packs/essential.json`

### 👨‍👩‍👧‍👦 Family Pack
For agents helping manage family life.

| Job | Schedule | What It Does |
|-----|----------|-------------|
| Morning Briefing | 6:30 AM weekdays | Daily family reminders, weather, school notes |
| Afternoon Pickup | Configurable | School pickup schedule reminder |
| Birthday Tracker | 4 weeks before | Gift reminder for each family member |
| Weekend Fun Planner | 7 AM Saturday | Finds local family activities for the weekend |

→ See `packs/family.json`

### 💰 Investor Pack
For portfolio tracking and market awareness.

| Job | Schedule | What It Does |
|-----|----------|-------------|
| Daily Finance Tracker (x402) | 8 AM daily | Fetches prices via x402, updates Finance.md |
| Market Briefing | 7:45 AM weekdays | Morning market + crypto news summary |

→ See `packs/investor.json`

### 💻 Developer Pack
For agents helping with code and infrastructure.

| Job | Schedule | What It Does |
|-----|----------|-------------|
| PR Check | 7:30 AM weekdays | Scans GitHub repos for open PRs |
| Security Audit | 1st of month | Runs OpenClaw security checks |
| Dependency Monitor | Weekly | Checks for outdated packages |

→ See `packs/developer.json`

### 📰 Briefings Pack
Daily news and intelligence gathering.

| Job | Schedule | What It Does |
|-----|----------|-------------|
| Morning Briefing (Weekday) | 7:45 AM M-F | News across configurable topics |
| Morning Briefing (Weekend) | 8:45 AM Sat-Sun | Same, slightly later |
| Capabilities Report | 2 PM daily | New tools, skills, and AI developments |

→ See `packs/briefings.json`

### ⏰ Three-Shifts Pack
Full cyclic execution engine (requires three-shifts skill).

| Job | Schedule | What It Does |
|-----|----------|-------------|
| Morning Planner | 6 AM daily | Plans morning shift tasks |
| Afternoon Planner | 2 PM daily | Plans afternoon shift tasks |
| Night Planner | 10 PM daily | Plans night shift (auto-approves carryover) |
| Cycle Executor | Every 15 min | Executes one step from current shift |

→ See `packs/three-shifts.json`

## Customization

All packs use these placeholders — replace before registering:

| Placeholder | Example | Where Used |
|-------------|---------|-----------|
| `YOUR_TIMEZONE` | `America/Chicago` | All jobs |
| `YOUR_PHONE` | `+1XXXXXXXXXX` | Jobs that send notifications |
| `YOUR_CHANNEL` | `signal` | Messaging channel |
| `YOUR_HEAVY_MODEL` | `claude-opus-4-6` | Planning jobs |
| `YOUR_LIGHT_MODEL` | `glm-4.7-flash` | Quick execution jobs |
| `YOUR_STANDARD_MODEL` | `glm-5` | Standard execution jobs |
| `YOUR_GITHUB_REPOS` | `owner/repo1, owner/repo2` | Developer pack |
| `YOUR_CITY` | `Austin, TX` | Family/weather jobs |
| `YOUR_TOPICS` | `AI, crypto, space` | Briefing jobs |
