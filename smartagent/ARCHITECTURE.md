# SmartAgent — Architecture & Strategy

*An OpenClaw fork with Everclaw built-in, packaged for non-technical users.*
*SmartAgentProtocol org: https://github.com/SmartAgentProtocol*

---

## 1. Vision

SmartAgent is a **pre-configured, easy-to-install version of OpenClaw** that bundles Everclaw's decentralized inference capabilities. The target user has never opened a terminal, doesn't have a Claude API key, and wants a personal AI agent that "just works."

**Key differentiator:** Decentralized inference from day one via Morpheus API Gateway, with a natural upgrade path to self-sovereign MOR-staked inference where you own your compute forever.

---

## 2. OpenClaw Baseline Analysis

### What OpenClaw Is
- **MIT-licensed** personal AI assistant framework (TypeScript, Node.js 22+)
- 185k+ stars, 31k+ forks — very active open source project
- Author: Peter Steinberger
- Install: `npm install -g openclaw` → `openclaw onboard`
- Single Gateway daemon (WebSocket control plane) that manages:
  - Agent runtime (embedded pi-mono derivative)
  - Chat channels (WhatsApp, Telegram, Signal, Discord, Slack, iMessage, etc.)
  - Browser control (CDP)
  - Canvas/A2UI (visual workspace)
  - Voice wake + talk mode
  - Node pairing (macOS/iOS/Android)
  - Cron, heartbeats, sub-agents, sessions

### How Models Work
- Built-in provider catalog ("pi-ai catalog") for: OpenAI, Anthropic, Google, Z.AI, etc.
- Custom providers via `models.providers` in `openclaw.json` — this is how Venice, Morpheus, and mor-gateway are configured
- Model failover: auth profile rotation → model fallback chain
- Cooldown tracking per provider

### How Skills Work
- Loaded from 3 locations (workspace wins):
  1. Bundled (shipped with install): 50+ skills
  2. Managed/local: `~/.openclaw/skills`
  3. Workspace: `<workspace>/skills` ← **Everclaw lives here**
- Each skill has a `SKILL.md` with frontmatter (name, version, description)
- ClawHub registry for discovery/install

### How Install Works
- `curl -fsSL https://openclaw.ai/install.sh | bash` (handles Node detection)
- `openclaw onboard` wizard: picks provider, sets up auth, creates workspace
- Bootstrap files: AGENTS.md, SOUL.md, TOOLS.md, BOOTSTRAP.md, IDENTITY.md, USER.md
- Gateway daemon: `openclaw gateway start`

### Key Directories
```
~/.openclaw/
├── openclaw.json          # Main config
├── workspace/             # Agent workspace
│   ├── AGENTS.md, SOUL.md, etc.
│   ├── skills/            # Workspace skills (Everclaw)
│   └── memory/            # Agent memory
├── agents/main/
│   ├── sessions/          # JSONL transcripts
│   └── agent/
│       └── auth-profiles.json
└── skills/                # Managed skills (clawhub)
```

---

## 3. SmartAgent Strategy

### 3A. Fork vs Wrapper vs Installer

| Approach | Pros | Cons |
|----------|------|------|
| **Fork** | Full control, can modify core | Maintenance burden tracking upstream |
| **Wrapper** | Light, tracks upstream automatically | Limited customization |
| **Installer** | Easiest, just adds config + skills | No core changes possible |

**Recommendation: Installer-first, with a fork path for deeper integration.**

Start with an **installer/bootstrapper** that:
1. Installs OpenClaw (upstream, untouched)
2. Installs Everclaw skill
3. Runs `bootstrap-gateway.mjs` for decentralized inference
4. Pre-configures workspace (AGENTS.md, SOUL.md, etc.)
5. Sets up Morpheus API Gateway as primary provider

This avoids fork maintenance while delivering the "just works" experience. If we later need core changes (custom onboarding wizard, GUI), we fork then.

### 3B. The Cold Start Problem (Solved by v0.8)

Current OpenClaw onboarding requires:
1. Install Node.js
2. Install OpenClaw
3. **Get an API key** (Claude, OpenAI, etc.) ← **THIS IS THE FRICTION**
4. Run onboard wizard
5. Start using

SmartAgent onboarding:
1. Run SmartAgent installer
2. **Immediately have decentralized inference** (Morpheus API Gateway)
3. Agent guides user through getting their own key
4. Agent guides user toward MOR staking for sovereignty

### 3C. Target Repo Structure

```
SmartAgentProtocol/smartagent/
├── README.md
├── LICENSE (MIT)
├── install.sh              # One-command installer
├── install.ps1             # Windows installer
├── package.json            # If npm-based installer
├── config/
│   ├── openclaw.json       # Pre-configured with mor-gateway
│   ├── AGENTS.md           # SmartAgent personality
│   ├── SOUL.md             # SmartAgent defaults
│   ├── TOOLS.md            # Pre-configured tool notes
│   ├── USER.md             # Template
│   └── BOOTSTRAP.md        # SmartAgent first-run ritual
├── scripts/
│   ├── setup.sh            # Post-install setup
│   └── upgrade.sh          # Upgrade path
├── docs/
│   └── index.html          # Website (smartagent.xyz?)
└── .github/
    ├── PULL_REQUEST_TEMPLATE.md
    ├── ISSUE_TEMPLATE/
    └── workflows/
        ├── ci.yml          # Tests
        └── release.yml     # Build + publish
```

---

## 4. Install Flow (Detailed)

### Step 1: One-Line Install
```bash
curl -fsSL https://smartagent.xyz/install.sh | bash
```

The script:
1. Checks for Node.js 22+ (installs if missing via nvm/fnm)
2. Installs OpenClaw globally: `npm install -g openclaw`
3. Clones Everclaw skill into workspace
4. Runs `bootstrap-gateway.mjs` (Morpheus decentralized inference)
5. Copies pre-configured workspace files (AGENTS.md, SOUL.md, etc.)
6. Starts the gateway daemon
7. Opens WebChat in browser — user can talk immediately

### Step 2: Agent Guides User
The pre-configured BOOTSTRAP.md instructs the agent to:
1. Greet the user and introduce itself
2. Explain what SmartAgent is
3. Walk through getting their own Morpheus API key (app.mor.org)
4. Offer to set up messaging channels (Signal, Telegram, WhatsApp)
5. Introduce the upgrade path (MOR staking → full sovereignty)

### Step 3: Progressive Enhancement
```
Day 1: Morpheus API Gateway (open access, cloud)
  ↓
Week 1: Own API key from app.mor.org (no cost, personalized)
  ↓
Month 1: Venice subscription (premium models like Claude)
  ↓
Later: MOR staking + local Morpheus node (full sovereignty)
```

---

## 5. Pre-Configured Defaults

### openclaw.json (SmartAgent edition)
```json5
{
  "models": {
    "mode": "merge",
    "providers": {
      "mor-gateway": {
        "baseUrl": "https://api.mor.org/api/v1",
        "apiKey": "<decoded-from-bootstrap>",
        "api": "openai-completions",
        "models": [
          { "id": "kimi-k2.5", "reasoning": false, "contextWindow": 131072, "maxTokens": 8192 },
          { "id": "glm-4.7-flash", "reasoning": false, "contextWindow": 131072, "maxTokens": 8192 }
        ]
      }
    }
  },
  "agents": {
    "defaults": {
      "model": {
        "primary": "mor-gateway/kimi-k2.5",
        "fallbacks": ["mor-gateway/glm-4.7-flash"]
      }
    }
  }
}
```

### Key Decisions
- **Primary model: `mor-gateway/kimi-k2.5`** — community-powered, strong, good for bootstrapping
- **No Venice/Anthropic/OpenAI required at first** — zero-cost onboarding
- **reasoning: false on all gateway models** — litellm rejects reasoning_effort
- **WebChat as default surface** — no phone setup needed initially

---

## 6. Development Workflow (SmartAgentProtocol)

### Branch Protection
- `main` branch protected: require PR + 1 review
- All work on feature branches
- Squash merges to keep history clean

### CI/CD (GitHub Actions)
- **ci.yml:** Lint, test, build on every PR
- **release.yml:** Tag → build → publish to npm + GitHub Releases
- Test matrix: macOS + Linux + Windows (WSL2)

### PR Template
```markdown
## What
Brief description of the change.

## Why
Context and motivation.

## Testing
How was this tested?

## Checklist
- [ ] Tests pass
- [ ] Documentation updated
- [ ] Install script tested on clean machine
```

---

## 7. Future GUI Options

For users who can't use Terminal at all:

### Option A: Electron App
- Wraps OpenClaw gateway + WebChat in a native window
- Tray icon, auto-start on boot
- Built-in terminal for advanced users
- Pros: Full desktop experience
- Cons: Large binary, complex build

### Option B: .dmg / .pkg Installer (macOS)
- Native macOS installer
- Installs Node.js, OpenClaw, Everclaw, starts daemon
- Pros: Familiar Mac install experience
- Cons: macOS only

### Option C: Docker Desktop Plugin
- Runs everything in a container
- WebChat exposed on localhost
- Pros: Cross-platform, isolated
- Cons: Requires Docker

### Option D: Web-Only (Recommended First)
- `install.sh` + WebChat in browser
- No native app needed
- Gateway runs as background service
- Pros: Simplest, cross-platform, works now
- Cons: Requires Terminal for initial install

**Recommendation: Start with Option D (web-only), add Option B (macOS .pkg) later.**

---

## 8. Open Questions

1. **Repo name:** `smartagent`? `smart-agent`? Reuse existing `Smart-Agent-Chat`?
2. **Domain:** smartagent.xyz? smartagentprotocol.com? Subdomain of mor.org?
3. **npm package name:** `smartagent`? `@smartagent/cli`? Or just point people at OpenClaw install?
4. **OpenClaw version pinning:** Pin to specific OpenClaw version or track latest?
5. **Branding:** SmartAgent logo/icon? Reuse Morpheus wings?
6. **When to fork:** What features would require forking OpenClaw vs skill/installer approach?

---

## 9. Immediate Next Steps

1. **Create the repo** — `SmartAgentProtocol/smartagent` with branch protection + PR template
2. **Build install.sh** — one-line installer that does everything
3. **Pre-configure workspace** — AGENTS.md, SOUL.md, BOOTSTRAP.md tuned for SmartAgent
4. **Test on clean machine** — fresh macOS, no Node.js, no OpenClaw
5. **Set up CI** — GitHub Actions for linting + install script testing
6. **Website** — simple landing page explaining what SmartAgent is
