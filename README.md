# ♾️ Everclaw — AI Inference You Own, Forever Powering Your OpenClaw Agents

**Open-source first.** Everclaw connects your [OpenClaw](https://github.com/openclaw/openclaw) agent to the [Morpheus](https://mor.org) decentralized inference network — putting open-source models like GLM-5 (Opus 4.5-level) front and center as your default, with Claude as a fallback only when needed.

Your agent runs on inference you own: GLM-5, GLM-4.7 Flash, Kimi K2.5, and 30+ models powered by staked MOR tokens that recycle back to you. No API bills, no credit limits, no surprise costs. MOR is staked — not spent — so you maintain access for as long as you hold your tokens.

> **New: [DIY Setup Guide](https://github.com/betterbrand/Mac-Mini-Morpheus-Agent-DIY-Guide)** — Want to build an always-on Morpheus-powered agent from scratch on a Mac mini? Complete walkthrough with identity separation, on-chain guardrails, three-tier inference fallback, and 9 documented gotchas. Every step tested on real hardware.

---

## Install

**From ClawHub:**

```bash
clawhub install everclaw-inference
```

**Or one-command installer:**

```bash
curl -fsSL https://raw.githubusercontent.com/profbernardoj/everclaw/main/scripts/install-everclaw.sh | bash
```

**Or manual clone:**

```bash
git clone https://github.com/profbernardoj/everclaw.git ~/.openclaw/workspace/skills/everclaw
```

> ⚠️ **Use `everclaw-inference`** — not `everclaw`. The bare `everclaw` slug on ClawHub belongs to a different, unrelated product ("Everclaw Vault"). See [CLAWHUB_WARNING.md](CLAWHUB_WARNING.md).

Then configure your OpenClaw agent:

```bash
# Easiest: Gateway only (no local proxy needed)
node ~/.openclaw/workspace/skills/everclaw/scripts/setup.mjs --template gateway-only --key YOUR_KEY --apply --test --restart

# Full: Local P2P + Gateway (auto-detects OS)
node ~/.openclaw/workspace/skills/everclaw/scripts/setup.mjs --key YOUR_KEY --apply --test --restart
```

Get a free API key at [app.mor.org](https://app.mor.org). Run without `--apply` first to preview changes.

**Want local P2P inference too?** Set up the wallet, proxy, and guardian:

```bash
# Step 1: Install the Morpheus proxy-router
bash ~/.openclaw/workspace/skills/everclaw/scripts/install.sh

# Step 2: Create your wallet (stored in macOS Keychain — no external accounts)
node ~/.openclaw/workspace/skills/everclaw/scripts/everclaw-wallet.mjs setup

# Step 3: Send ETH to the wallet address shown above, then swap for MOR
node ~/.openclaw/workspace/skills/everclaw/scripts/everclaw-wallet.mjs swap eth 0.05

# Step 4: Approve MOR for staking
node ~/.openclaw/workspace/skills/everclaw/scripts/everclaw-wallet.mjs approve

# Step 5: Install the proxy and guardian (auto-starts on boot)
bash ~/.openclaw/workspace/skills/everclaw/scripts/install-proxy.sh
```

That's it. Your agent now has decentralized inference — either via the API Gateway (instant) or local P2P (stake MOR for persistent access you own).

---

## Who Is This For?

**You don't need to be an engineer to use Everclaw.** If you can copy and paste commands, you can set this up.

Everclaw is built for early adopters who:

- **Run an OpenClaw agent on a Mac mini, laptop, or VPS** — and want it to stay online 24/7 without babysitting
- **Use AI daily for real work** — writing, research, analysis, communication — and can't afford downtime when API credits run out at 2 AM
- **Own or want to own MOR tokens** — and want to put them to work earning inference instead of sitting idle in a wallet
- **Care about decentralization** — you believe AI infrastructure shouldn't depend on a single company's API, and want a censorship-resistant fallback
- **Want their agent to handle crypto** — DeFi interactions, token management, wallet operations — and need the security to match the stakes

If you've ever had your AI assistant go dark because an API key expired or credits ran out, Everclaw solves that problem permanently.

---

## How It Works

1. **Get MOR tokens** on Base (swap from ETH or USDC)
2. **Stake MOR** to open an inference session (7 days by default)
3. **Your agent sends requests** through a local proxy that handles everything
4. **When the session ends**, your MOR comes back — stake it again
5. **Repeat forever** — MOR is recycled, not consumed

```
Your Agent → Everclaw Proxy (port 8083) → Morpheus P2P Network → AI Model
```

The proxy handles all the blockchain complexity: opening sessions, renewing before expiry, authenticating with the network, and routing requests. Your agent just talks to a standard OpenAI-compatible API.

---

## What's Included

### ♾️ Core — Decentralized Inference
| Component | What It Does |
|-----------|-------------|
| **Morpheus Proxy Router** | Connects to the Morpheus P2P network and routes inference requests to providers |
| **OpenAI-Compatible Proxy** | Translates standard API calls into Morpheus format — any OpenAI client works |
| **Auto-Session Manager** | Opens 7-day blockchain sessions on demand, renews before expiry, recycles MOR |
| **Session Auto-Retry** | If a session expires mid-request, opens a fresh one and retries automatically (v0.5) |
| **Cooldown-Safe Errors** | Returns proper OpenAI error types so failover engines don't misclassify Morpheus errors as billing errors (v0.5) |
| **Model Router** | Open-source first 3-tier classifier — routes simple tasks to GLM Flash, standard + complex tasks to GLM-5, Claude fallback only (v0.9.8) |
| **x402 Payment Client** | Automatic HTTP 402 payment handling — signs USDC on Base via EIP-712, with budget controls and dry-run mode (v0.7) |
| **ERC-8004 Agent Registry** | Discover agents on-chain — reads Identity + Reputation registries on Base, resolves registration files, checks trust signals (v0.7) |
| **API Gateway Bootstrap** | One-command setup for community-powered Morpheus inference — no API key, no wallet, no node required. New users get instant AI access (v0.8) |
| **Multi-Key Auth Rotation** | Configure multiple Venice API keys — OpenClaw rotates through them automatically when credits drain, keeping you on premium models longer (v0.9.1) |
| **Gateway Guardian v5** | Direct curl inference probes — eliminates 71K prompt bloat and Signal spam. Billing-aware escalation, DIEM reset awareness, circuit breaker, 4-stage self-healing, proactive credit monitoring (v2026.2.21) |
| **Three-Shift Task Planning** | Morning/Afternoon/Night shift system — proposes prioritized task plans with approval workflow, shift-specific rules, handoff notes (v2026.2.21) |
| **MOR Swap Scripts** | Swap ETH or USDC for MOR tokens directly from the command line |

**Benefit:** Your agent runs on inference you own — GLM-5 (Opus 4.5-level), GLM-4.7 Flash, Kimi K2.5, and 30+ open-source models via staked MOR tokens. No API bills, no credit limits — stake once, use forever. MOR tokens are staked, not consumed — returned when sessions close and restaked indefinitely. The open-source first model router (v0.9.8) sends all tiers to Morpheus by default — Claude is only the escape hatch for tasks GLM-5 can't handle. Cron jobs, heartbeats, research, coding, and complex reasoning all run on inference you own. The x402 client and agent registry (v0.7) let your agent discover and pay other agents on-chain. And with the API Gateway bootstrap (v0.8), new users get instant inference from their very first launch — no API key needed.

### 💸 Agent Economy — x402 Payments + ERC-8004 Registry
| Component | What It Does |
|-----------|-------------|
| **x402 Payment Client** | Automatic HTTP 402 payment handling — detects payment-required responses, signs USDC on Base via EIP-712, retries with payment |
| **Budget Controls** | Per-request max ($1 default) and daily spending limit ($10 default) prevent runaway payments |
| **ERC-8004 Agent Registry** | Discovers agents on Base via on-chain Identity (ERC-721) and Reputation registries |
| **Agent Discovery** | Full pipeline: identity → fetch registration file → check endpoints → check reputation scores |
| **Combined Flow** | Discover an agent on-chain → check its x402 support → make a paid API request — all programmatic |

**Benefit:** Your agent can discover other agents on-chain, verify their reputation, and pay them for services — all without custodial intermediaries. USDC payments are signed with EIP-712 and settled via the Coinbase facilitator. Budget controls prevent surprise spending.

### 🛡️ Gateway Guardian v5 — Direct Probe Self-Healing
| Component | What It Does |
|-----------|-------------|
| **Direct Curl Probes** | Probes gateway's LiteLLM proxy directly with tiny prompt (~50 chars) — no more 71K workspace prompt bloat |
| **No Signal Spam** | Failures stay in logs only — no agent session means no accidental Signal message delivery |
| **Fast Lightweight Model** | Uses glm-4.7-flash for probes instead of glm-5 — faster, cheaper, purpose-built for health checks |
| **Billing-Aware Escalation** | Classifies errors as `billing` vs `transient` vs `timeout`. Billing → backs off + notifies (restart is useless). Transient → restarts as before |
| **DIEM Reset Awareness** | Calculates hours to midnight UTC (daily DIEM reset). Billing-dead → 30-min probe interval. Auto-clears on UTC day rollover |
| **Proactive Credit Monitoring** | Reads Venice DIEM balance from response headers. Warns when balance drops below threshold |
| **Circuit Breaker** | Detects sub-agents stuck >30 min with repeated timeouts and kills them |
| **Fixed Restart Chain** | No more `set -e` silent exits or pkill self-kill. ERR trap logs unexpected failures |
| **4-Stage Restart Escalation** | Graceful restart → hard kill (excludes own PID) → kickstart → **nuclear reinstall** |
| **Signal Notifications** | Notifies owner on: billing exhaustion (with ETA), billing recovery, nuclear restart, total failure |
| **launchd Integration** | Survives reboots, auto-starts on macOS |

**Benefit:** v4's `openclaw agent` probes injected the full 71K workspace system prompt into every health check, causing timeouts and delivering error messages to Signal as normal replies. v5 uses direct curl to the LiteLLM proxy with a tiny prompt — fast, silent, no side effects. Combined with billing-aware escalation from v4, your gateway self-heals reliably without spamming you.

### 📋 Three-Shift Task Planning — Structured Work Management
| Component | What It Does |
|-----------|-------------|
| **Morning Shift (6 AM)** | Ramp-up: meetings, comms, decisions — front-loads tasks requiring user input |
| **Afternoon Shift (2 PM)** | Deep work: coding, writing, building — minimizes interruptions |
| **Night Shift (10 PM)** | Autonomous: research, maintenance, prep — no external actions without approval |
| **Priority Tiers** | P1 (must-do), P2 (should-do), P3 (could-do) — respects the 8-hour window |
| **Approval Workflow** | Nothing executes until the user approves, modifies, or skips |
| **Shift Handoff** | Each shift writes completion summary for the next shift to pick up |
| **Configurable Schedule** | Adjust times, skip weekends, set quiet hours — see config reference |

**Benefit:** Your agent proposes what to work on instead of waiting to be told. Three shifts cover 24 hours with clear boundaries — the morning shift handles human-interactive work, afternoon goes deep on building, and the night shift runs autonomously. Approval gates ensure nothing happens without your say-so.

### ⚡ Always-On Power Config — 24/7 Agent Operation
| Component | What It Does |
|-----------|-------------|
| **Power Management Setup** | Configures macOS to never sleep — disables sleep, standby, hibernation |
| **Caffeinate LaunchAgent** | Background process prevents system sleep while running |
| **Power Nap + Wake on LAN** | Network activity works even with display off; remote wake enabled |
| **Auto-Restart** | System restarts automatically after power failure |
| **Restore Mode** | One command restores default power settings |

**Benefit:** Your agent needs your Mac to stay awake. Without this, cron jobs miss schedules, heartbeats don't fire, and long tasks fail mid-execution. With always-on configured, your agent is reachable 24/7, tasks complete uninterrupted, and cron jobs fire exactly when scheduled. Power cost is negligible (~$0.50-1/month for a Mac Mini M4 at idle).

### 🔍 SkillGuard — Skill Security Scanner
| Component | What It Does |
|-----------|-------------|
| **Pattern Scanner** | Detects credential theft, code injection, data exfiltration in skills |
| **Batch Audit** | Scan all installed skills at once |
| **ClawHub Scanner** | Check skills before installing from the public registry |

**Benefit:** Protects against the ClawHavoc-style supply chain attacks that target agents running on always-on machines. Scan before you install.

### 🔒 ClawdStrike — Security Auditor
| Component | What It Does |
|-----------|-------------|
| **Config Audit** | Checks your OpenClaw configuration for security gaps |
| **Exposure Check** | Identifies network exposure, open ports, weak auth |
| **Report Generator** | Produces OK/VULNERABLE report with evidence and fixes |

**Benefit:** Know if your agent's front door is locked. Catches misconfigurations that could expose your wallet, messages, or files.

### 🧱 PromptGuard — Injection Defense
| Component | What It Does |
|-----------|-------------|
| **Multi-Language Detection** | Catches injection attempts in English, Korean, Japanese, Chinese |
| **Severity Scoring** | Rates threats from low to critical |
| **HiveFence Network** | Shares threat intelligence with other agents for collective defense |

**Benefit:** When your agent processes messages from groups or untrusted sources, PromptGuard blocks attempts to manipulate it into revealing secrets or sending tokens.

### 💰 Bagman — Key Management
| Component | What It Does |
|-----------|-------------|
| **Secure Storage Patterns** | Never store keys on disk — 1Password runtime injection |
| **Session Keys** | Ephemeral keys with limited permissions for daily operations |
| **Delegation Framework** | EIP-7710 integration for scoped agent authority |
| **Leak Prevention** | Patterns to detect and block accidental secret exposure |

**Benefit:** Your agent handles MOR tokens and private keys safely. The same security patterns used by professional custody solutions, adapted for AI agents.

---

## Available Models

| Model | Type | Router Tier | Notes |
|-------|------|-------------|-------|
| **GLM-5** | General | ⭐ STANDARD + HEAVY | **Default** — Opus 4.5-level reasoning, coding, and analysis. Open-source first. |
| **GLM 4.7 Flash** | Fast | LIGHT | Quick responses for trivial tasks — cron, heartbeats, simple lookups |
| **Kimi K2.5** | General | — | Solid general model, previous default |
| **Kimi K2 Thinking** | Reasoning | — | Extended thinking for complex problems |
| **GLM-5:web** | General + Web | — | GLM-5 with web search capability |
| **GLM 4.7** | General | — | Full GLM model |
| **Qwen3 235B** | General | — | Large parameter count |
| **GPT-OSS 120B** | General | — | OpenAI's open-source model |

All models are accessed through the same proxy endpoint. Switch models by changing the model name in your request.

**Why GLM-5?** Zhipu's 744B MoE model (40B active) matches Claude Opus 4.5 on benchmarks: 92.7% AIME 2026, 86% GPQA-Diamond, 50.4 Humanity's Last Exam (with tools). Industry-leading hallucination resistance. Handles reasoning, coding, structured output, and agentic tasks at frontier quality — all through Morpheus inference you own.

---

## MOR Token Economics

MOR is **staked, not spent**. Here's how the economics work:

| Duration | MOR Staked | What Happens |
|----------|-----------|--------------|
| 1 hour | ~11 MOR | Returned after 1 hour |
| 1 day | ~274 MOR | Returned after 1 day |
| **7 days** | **~1,915 MOR** | **Returned after 7 days (default)** |

When a session ends, your MOR comes back. Open a new session with the same tokens. This is what makes the access yours forever — you're staking a refundable deposit for compute, not buying consumable API credits.

**Getting started:** 50–100 MOR is enough for daily use. Swap from ETH on Base using the included scripts.

---

## Quick Reference

| Action | Command |
|--------|---------|
| **Setup (recommended)** | `node scripts/setup.mjs --key YOUR_KEY --apply --test --restart` |
| Setup (dry-run) | `node scripts/setup.mjs` |
| Install (ClawHub) | `clawhub install everclaw-inference` |
| Install (script) | `curl -fsSL https://raw.githubusercontent.com/profbernardoj/everclaw/main/scripts/install-everclaw.sh \| bash` |
| Update (ClawHub) | `clawhub update everclaw-inference` |
| Update (git) | `cd skills/everclaw && git pull` |
| Check version | `bash skills/everclaw/scripts/install-everclaw.sh --check` |
| Install router | `bash skills/everclaw/scripts/install.sh` |
| Create wallet | `node scripts/everclaw-wallet.mjs setup` |
| Check balance | `node scripts/everclaw-wallet.mjs balance` |
| Swap ETH→MOR | `node scripts/everclaw-wallet.mjs swap eth 0.05` |
| Swap USDC→MOR | `node scripts/everclaw-wallet.mjs swap usdc 50` |
| Approve MOR | `node scripts/everclaw-wallet.mjs approve` |
| Install proxy + guardian | `bash skills/everclaw/scripts/install-proxy.sh` |
| Start router | `bash skills/everclaw/scripts/start.sh` |
| Proxy health | `curl http://127.0.0.1:8083/health` |
| Route a prompt | `node scripts/router.mjs "your prompt here"` |
| Route (JSON) | `node scripts/router.mjs --json "your prompt"` |
| x402 request | `node scripts/x402-client.mjs GET <url>` |
| x402 dry-run | `node scripts/x402-client.mjs --dry-run GET <url>` |
| Lookup agent | `node scripts/agent-registry.mjs lookup <id>` |
| Discover agent | `node scripts/agent-registry.mjs discover <id>` |
| Agent reputation | `node scripts/agent-registry.mjs reputation <id>` |
| Scan a skill | `node security/skillguard/src/cli.js scan <path>` |
| Security audit | `bash security/clawdstrike/scripts/collect_verified.sh` |
| Guardian logs | `tail -f ~/.openclaw/logs/guardian.log` |
| **Always-on setup** | `sudo bash skills/everclaw/scripts/always-on.sh` |
| Restore power defaults | `sudo bash skills/everclaw/scripts/always-on.sh --restore` |
| Check power settings | `pmset -g` |

---

## Requirements

- **OpenClaw** — installed and running
- **Node.js** — v20+ (bundled with OpenClaw)
- **ETH or USDC on Base** — to swap for MOR tokens
- **macOS** — for Keychain wallet storage (v0.4+)

That's it. No external accounts. No API keys. No subscriptions.

---

## Links

- **Morpheus AI:** [mor.org](https://mor.org)
- **OpenClaw:** [openclaw.ai](https://openclaw.ai)
- **MOR on Base:** [Uniswap](https://app.uniswap.org/explore/tokens/base/0x7431ada8a591c955a994a21710752ef9b882b8e3)
- **Morpheus GitHub:** [MorpheusAIs/Morpheus-Lumerin-Node](https://github.com/MorpheusAIs/Morpheus-Lumerin-Node)
- **x402 Protocol:** [x402.org](https://x402.org)
- **ERC-8004:** [eips.ethereum.org/EIPS/eip-8004](https://eips.ethereum.org/EIPS/eip-8004)
- **8004scan:** [8004scan.io](https://www.8004scan.io)

---

## License

MIT — see [LICENSE](LICENSE).
