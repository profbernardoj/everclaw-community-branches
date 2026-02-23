# TOOLS.md - Local Notes

Skills define _how_ tools work. This file is for _your_ specifics — the stuff that's unique to your setup.

<!-- ═══════════════════════════════════════════════════════════════
     TOOLS.md vs SKILL.md:
     
     SKILL.md files are shared — they come with skills and tell the agent
     how to USE a tool (commands, API formats, workflows).
     
     TOOLS.md is personal — it holds YOUR specific configuration:
     account names, API keys references, device names, quirks of your setup.
     
     Keeping them separate means you can update skills without losing
     your notes, and share skills without leaking your infrastructure.
     ═══════════════════════════════════════════════════════════════ -->

---

## Security Protocols

<!-- Document security procedures your agent should follow.
     
     Examples:
     - After installing any new skill, run a security scan
     - Keep browser sessions closed when not in use
     - Before updating OpenClaw, verify the changelog
     - Never store raw API keys in files — use a secret manager -->

---

## Accounts & Keys

<!-- List accounts your agent uses. NEVER put raw secrets here —
     reference where they're stored (1Password, Keychain, env var).
     
     Format:
     ### Service Name
     - **Account:** your-username
     - **Auth:** stored in [1Password / Keychain / env var]
     - **Policy:** [READ ONLY / full access / etc.]
     - **Notes:** any quirks or limitations
     
     Example:
     ### GitHub
     - **Handle:** your-username
     - **Auth:** `gh` CLI authenticated via PAT
     - **PAT stored in:** 1Password item "GitHub PAT"
     - **PAT expires:** YYYY-MM-DD
     - **Scopes:** repo, workflow, read:org -->

---

## Permissions Needed

<!-- Track permissions that require manual setup (not automatable).
     
     Example:
     ### Screen Recording (macOS)
     - **Status:** PENDING — needs manual grant
     - **Path:** System Settings → Privacy & Security → Screen Recording
     
     ### SSH Access to Server
     - **Status:** CONFIGURED
     - **Host:** my-server.example.com
     - **Auth:** SSH key (added to agent) -->

---

## Infrastructure Notes

<!-- Document your specific setup: what's running where, ports, paths.
     
     Example:
     ### Local Services
     - Morpheus proxy-router: port 8082
     - OpenAI-compatible proxy: port 8083
     - Health check: curl http://localhost:8083/health
     
     ### Network
     - Tailscale IP: 100.x.x.x
     - Local subnet: 192.168.x.x -->

---

## Why Separate?

Skills are shared. Your setup is yours. Keeping them apart means you can update skills without losing your notes, and share skills without leaking your infrastructure.
