# PII Guard V2 — Personal Data Leak Prevention for EverClaw

## What's New in V2
- **Built-in API key detection** — Venice, OpenAI, GitHub, AWS, Stripe, Slack tokens caught automatically (no config needed)
- **Filesystem path detection** — `/Users/*`, `/home/*`, `C:\Users\*` patterns
- **Private IP detection** — RFC1918 addresses (192.168.x.x, 10.x.x.x, 172.16-31.x.x)
- **Blocked files/paths** — `verified-bundle.json`, `.env`, `secrets.json` + user-configurable paths
- **Git history scanning** — `--history` mode scans all past commits, not just current HEAD
- **Deep repo scan** — `--repo-scan` combines files + blocked paths + history in one pass
- **First-name matching** — `first_names` category for word-boundary matching of family member first names
- **Location signals** — `location_signals` category for school districts, neighborhoods, area-specific terms
- **False positive filtering** — automatically skips template placeholders, test tokens, and doc examples

## Components

### 1. Pattern File (User-Created, NEVER Committed)
```
~/.openclaw/workspace/.pii-patterns.json
```
Users populate this with their own protected data. V2 adds three new categories:
- `first_names` — first names only (catches "Jane" without needing "Jane Doe")
- `location_signals` — school districts, neighborhoods, area-specific terms
- `blocked_paths` — directories/files that should never appear in a repo

### 2. Git Pre-Push Hook (Global)
Automatically scans every `git push`. Now includes built-in API key and path detection alongside user patterns. False positives from templates/examples are filtered automatically.

### 3. Scanner Script
Standalone scanner with new modes:
- File/directory scan (V1)
- Text/stdin scan (V1)
- **Git history scan** (V2)
- **Deep repo scan** (V2)

### 4. Agent Behavior
The agent MUST scan content before any outbound action:
- **HARD BLOCK** — Do not proceed when PII is detected
- **REPORT** — Show the user what was found, where, and which category
- **WAIT** — Only proceed after the user reviews and explicitly confirms override

## Setup

### First-Time Install
```bash
bash ~/.openclaw/workspace/skills/everclaw/security/pii-guard/setup.sh
```

### Upgrade from V1
Run setup again — it preserves your existing patterns file and only updates the hook + scanner.

## Usage

### Scan a file or directory
```bash
pii-scan.sh <file_or_directory>
```

### Scan a string
```bash
pii-scan.sh --text "check this content before posting"
```

### Scan stdin
```bash
cat README.md | pii-scan.sh -
```

### Scan git history (V2)
```bash
pii-scan.sh --history              # Current repo
pii-scan.sh --history /path/to/repo
```

### Deep repo scan — files + blocked paths + history (V2)
```bash
pii-scan.sh --repo-scan              # Current repo
pii-scan.sh --repo-scan /path/to/repo
```

### Exit codes
- `0` — Clean, no PII found
- `1` — PII detected (blocked)
- `2` — Error (missing patterns file, missing jq, etc.)

## Pattern Categories

| Category | Examples | Why It Matters |
|----------|----------|---------------|
| `names` | Full names of you, family, associates | Identity exposure |
| `first_names` | First names only (word-boundary match) | Catches partial name mentions |
| `emails` | Personal/work email addresses | Contact info leak |
| `phones` | Phone numbers (all formats) | Contact info leak |
| `wallets` | Blockchain addresses (personal, not agent) | Financial exposure |
| `organizations` | Church, school, employer names | Location/affiliation exposure |
| `people` | Business contacts, missionaries, etc. | Third-party privacy |
| `websites` | Personal domains | Identity linkage |
| `location_signals` | School districts, neighborhoods | Geographic fingerprinting |
| `keywords` | Any other protected strings | Catch-all |
| `regex` | Custom regex patterns (SSN, credit card, etc.) | Structured data |
| `blocked_paths` | Directories/files to block from repos | Prevents memory/log leaks |

## Built-in Detection (No Config Needed)

These patterns are detected automatically without any user configuration:

| Category | Patterns | Example |
|----------|----------|---------|
| API keys | Venice, OpenAI, GitHub PAT, AWS, Stripe, Slack | `VENICE-INFERENCE-KEY-abc...`, `sk-abc...`, `ghp_...` |
| Filesystem paths | macOS/Linux/Windows home directories | `/Users/john/`, `/home/admin/` |
| Private IPs | RFC1918 addresses | `192.168.1.100`, `10.0.0.1` |
| SSN format | US Social Security Number pattern | `123-45-6789` |

### False Positive Filtering
Built-in patterns automatically skip:
- Template placeholders (`YOUR_KEY_HERE`, `XXXXXXXXXX`, `YOUR_LOCAL_IP`)
- Test tokens (`sk-abcdef...`, `sk_test_...`)
- Documentation examples (`123 Main St`, `user@example.com`)

## Blocked Files (Enforced in --repo-scan)

These files are **always** flagged if found in a repo, regardless of content:
- `verified-bundle.json` — system config dumps
- `.env`, `.env.local`, `.env.production` — environment secrets
- `secrets.json`, `credentials.json` — credential stores
- `.pii-patterns.json` — the patterns file itself

Plus any paths configured in the `blocked_paths` array.

## When the Agent Checks

**Mandatory before:**
- `git push` (automated via hook + agent double-check)
- Sending emails
- Posting to social media
- Publishing skills to ClawHub
- Creating/updating GitHub issues, PRs, discussions, comments
- Uploading files to any external service
- Any HTTP POST/PUT with user content

## Security Notes
- `.pii-patterns.json` contains the very data it protects — **NEVER commit it**
- The hook can be bypassed with `git push --no-verify` — use with extreme caution
- Built-in patterns catch common secrets even if the user hasn't configured anything
- Run `--repo-scan` periodically to check for drift
- After finding PII in history, use `git filter-repo` to scrub it permanently
