---
tags: [project, everclaw]
status: active
---
# Scott Upgrade Notes — 2026-02-19

Notes from David and Scott conversation about upgrading Bernardo and multi-agent architecture.

---

## Upgrading Bernardo

### Workflow
1. **Use Cloud Code** to describe what you want Bernardo to accomplish and create a plan
2. **Execute the plan** either via SSH or manually
3. **Use Cursor IDE** to review code changes top-to-bottom and see relationships between files

### Security Setup
- **Create a second Mac user as admin** — run the agent as a regular user with no Homebrew/sudo access
- This prevents the agent from being convinced to install malware
- Use **Tailscale** for remote SSH access to the admin account when needed
- SSH hardening guide should be completed for secure connections

### Update Process
- SSH into Bernardo's Mac Mini from your IDE to update files
- Alternative: Give Claude Code agent SSH access to perform updates automatically
- Only manual copy-paste needed when sudo access is required

---

## Multi-Agent Capabilities

### Key Distinction
- **Skills**: Tasks Bernardo performs himself (stored as MD files in skills/)
- **Agents**: Separate entities with their own LLM context that handle specialized tasks (also MD files in Everclaw)

### How to Create Agents
1. Tell Cloud Code: "I need an agent that does X for Bernardo"
2. Provide context about Bernardo, SSH access, and the Everclaw GitHub repo
3. The agent gets written as an MD file in Everclaw's agents directory

### Architecture Approach
- **No multi-agent framework needed** for small numbers (up to ~10 agents) — tool-calling models handle orchestration naturally
- Label agents clearly so Claude selects the right one
- Each sub-agent has isolated context; if one fails, others aren't affected

### Security Agent Example (Bagman)
- Created "Bagman" as a security-focused MD agent
- Bernardo's memory includes: "This agent exists for all security tasks"
- When touching core code, Bernardo prompts: "Do you want to run the security agent?"
- Security agents can sandbox code, run malicious content checks, and perform pen-testing

### Best Practices
- **Easier to have an external entity help Bernardo** than have Bernardo work on himself
- **Regularly red-team/attack Bernardo** to surface vulnerabilities
- **Edge cases found through usage** (e.g., cache archiver skill built after browser crashed at 10MB+ context)

---

## Action Items
- [ ] Create second Mac user as admin
- [ ] Run Bernardo as regular user without Homebrew/sudo access
- [ ] Set up Tailscale for remote admin SSH
- [ ] Complete SSH hardening guide
- [ ] Set up Cloud Code workflow for Bernardo improvements
- [ ] Consider creating additional specialized agents as needed

---

## References
- Cloud Code 2.1 multi-agent AI coding: https://medium.com/@kapildevkhatik2/cloud-code-2-1-0-multi-agent-ai-coding-in-the-terminal-407f610c06ab
- Claude Code sandboxing: https://www.anthropic.com/engineering/claude-code-sandboxing
- Secure agent deployment: https://platform.claude.com/docs/en/agent-sdk/secure-deployment
- Multi-agent orchestration: https://github.com/wshobson/agents