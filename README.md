# ♾️ Everclaw — AI Inference You Own, Forever Powering Your OpenClaw Agents

**Own your inference.** Everclaw connects your [OpenClaw](https://github.com/openclaw/openclaw) agent to the [Morpheus](https://mor.org) decentralized inference network — giving you consistent, self-sovereign access to Kimi K2.5, Qwen3, GLM-4, Llama 3.3, and 10+ open-source models powered by staked MOR tokens that recycle back to you.

When your primary API credits run out, Everclaw kicks in automatically. Your agent stays online. No interruptions, no downtime, no surprise bills. And because MOR is staked — not spent — you maintain access for as long as you hold your tokens.

---

## Install

One command inside your OpenClaw workspace:

```bash
git clone https://github.com/profbernardoj/everclaw.git ~/.openclaw/workspace/skills/everclaw
```

Then set up your wallet, proxy, and guardian:

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

That's it. Your agent now has a fallback inference provider that runs on decentralized infrastructure. No API keys, no external accounts, no subscriptions.

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
| **Model Router** | 3-tier local prompt classifier — routes simple tasks to GLM Flash, standard tasks to Kimi K2.5, complex tasks to Claude (v0.6) |
| **MOR Swap Scripts** | Swap ETH or USDC for MOR tokens directly from the command line |

**Benefit:** Your agent gets persistent access to 10+ open-source models (Kimi K2.5, GLM-4, Qwen3, Llama 3.3, and more) that you own through staked MOR tokens. No API bills, no credit limits — stake once, use continuously. The model router (v0.6) ensures you only use expensive models when you need to — cron jobs, heartbeats, and simple tasks run on free Morpheus models automatically.

### 🛡️ Gateway Guardian — Self-Healing Agent
| Component | What It Does |
|-----------|-------------|
| **Health Monitor** | Probes your OpenClaw gateway every 2 minutes |
| **Auto-Restart** | Three-stage restart if the gateway becomes unresponsive |
| **launchd Integration** | Survives reboots, auto-starts on macOS |

**Benefit:** Your agent recovers from crashes automatically. No more waking up to find your assistant has been offline for 8 hours.

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

| Model | Type | Notes |
|-------|------|-------|
| **Kimi K2.5** | General | Recommended primary fallback — most reliable |
| **Kimi K2 Thinking** | Reasoning | Extended thinking for complex problems |
| **GLM 4.7 Flash** | Fast | Quick responses, lower latency |
| **GLM 4.7** | General | Full GLM model |
| **Qwen3 235B** | General | Large parameter count |
| **Llama 3.3 70B** | General | Meta's open model |
| **GPT-OSS 120B** | General | OpenAI's open-source model |

All models are accessed through the same proxy endpoint. Switch models by changing the model name in your request.

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
| Install Everclaw | `git clone https://github.com/profbernardoj/everclaw.git ~/.openclaw/workspace/skills/everclaw` |
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
| Scan a skill | `node security/skillguard/src/cli.js scan <path>` |
| Security audit | `bash security/clawdstrike/scripts/collect_verified.sh` |
| Guardian logs | `tail -f ~/.openclaw/logs/guardian.log` |

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

---

## License

MIT — see [LICENSE](LICENSE).
