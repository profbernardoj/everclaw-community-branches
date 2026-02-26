# PII Guard — Personal Data Leak Prevention

## Purpose
Prevents personal identifiable information (PII) from being sent to external services. This skill MUST be checked before any outbound action that transmits data externally.

## When This Fires
**Mandatory check before:**
- `git push` (any repo)
- Sending emails
- Posting to social media (X/Twitter, Moltbook, etc.)
- Publishing to ClawHub
- Creating/updating GitHub issues, PRs, discussions, or comments
- Any `message` action to external channels with file attachments
- Any `web_fetch` POST or form submission
- Any `exec` command that sends data externally (curl POST, scp, rsync, etc.)

## How It Works

### 1. Pattern File
All protected patterns live in the workspace:
```
~/.openclaw/workspace/.pii-patterns.json
```
This file is **NEVER committed** — it contains the very data it protects.

### 2. Scanning
The scanner checks content against all patterns in these categories:
- `names` — Protected personal names
- `emails` — Protected email addresses
- `phones` — Protected phone numbers (all formats)
- `wallets` — Protected blockchain addresses
- `organizations` — Protected org/church/school names
- `people` — Protected associate/contact names
- `websites` — Protected personal domains
- `keywords` — Any other protected strings

### 3. Behavior: HARD BLOCK
When PII is detected:
1. **STOP** — Do not proceed with the external action
2. **REPORT** — Tell the user exactly what was found and where
3. **WAIT** — Only proceed if the user explicitly confirms after reviewing

Error format:
```
🚫 PII GUARD: Blocked — personal data detected

Found in: <filename or content description>
Match: "<the matched pattern>"
Category: <names|emails|phones|etc>

Action blocked: <what was about to happen>
To proceed: Remove the PII or explicitly confirm override.
```

### 4. Git Pre-Push Hook
A global git hook is installed at:
```
~/.openclaw/workspace/scripts/git-hooks/pre-push
```
Configured via: `git config --global core.hooksPath ~/.openclaw/workspace/scripts/git-hooks`

This runs automatically on every `git push` across ALL repos on this machine.
- Scans the diff being pushed (not just HEAD)
- Blocks push if PII detected
- Can be bypassed with `git push --no-verify` (use with extreme caution)

### 5. Agent Integration
The agent (Bernardo) should call `pii_scan` before external actions:

```bash
# Scan a file
~/.openclaw/workspace/scripts/pii-scan.sh <file_or_directory>

# Scan stdin
echo "some content" | ~/.openclaw/workspace/scripts/pii-scan.sh -

# Scan a string
~/.openclaw/workspace/scripts/pii-scan.sh --text "check this string"
```

Exit codes:
- `0` — Clean, no PII found
- `1` — PII detected (blocked)
- `2` — Error (patterns file missing, etc.)

## Adding New Patterns
Edit `~/.openclaw/workspace/.pii-patterns.json` and add entries to the appropriate category array. Changes take effect immediately — no restart needed.

## Security Notes
- `.pii-patterns.json` must NEVER be committed to any repo
- The patterns file itself contains PII — treat it as sensitive
- The hook and scan scripts are safe to publish (they contain no PII)
- When in doubt, scan first
