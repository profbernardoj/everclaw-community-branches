# Standard Operating Procedures

**Created:** 2026-03-08
**Purpose:** Documented workflows for consistent, safe, and verified operations.

---

## SOP Index

| SOP # | Title | Created |
|-------|-------|---------|
| 001 | Development & Deployment | 2026-03-08 |
| 002 | [REDACTED] P2P Session Management | 2026-03-09 |
| 003 | XMTP Agent-to-Agent Communication | 2026-03-14 |
| 004 | Marketing & Sales Pipeline | 2026-03-17 |

---

## SOP-001: Development & Deployment

> **Canonical source:** `memory/reference/SOP-001.md` — this section is synced from there.


## Pipeline Stages

| Stage | Name | Description | Gate |
|-------|------|-------------|------|
| 0 | **Research** | Survey landscape, evaluate options, produce research brief | David reviews brief, picks direction |
| 1 | **Planning** | Requirements, architecture, design decisions | David approval |
| 2 | **Coding** | Implementation, commits to working branch | Compiles clean |
| 3 | **Dependency Check** | Detect new deps, update installer if needed | Installer covers all deps |
| 4 | **Audit** | Cross-model security review, line-by-line verification | All changes rated Excellent |
| 5 | **Testing** | Unit tests, integration tests, edge cases | All tests pass |
| 6 | **PII Scan** | Scan for leaked keys, addresses, personal data | 0 PII findings |
| 7 | **Documentation** | Update SKILL.md, CHANGELOG, README, architecture docs | Docs reviewed |
| 8 | **Primary Deploy** | Push to `EverClaw/EverClaw` (org) + `EverClaw/EverClaw` | Clean push |
| 9 | **Ecosystem Deploy** | Sync to all 28+ flavor repos via `ecosystem-sync.sh` | All repos synced |
| 10 | **Package Tag & Docker** | Version bump, git tag, Docker image build via GitHub Actions | Image verified |

---

## Stage Details

### Stage 0 — Research

- **Executed by the Researcher agent** (`researcher`, Claude Opus 4.6)
- Survey the landscape: existing solutions, SDKs, packages, protocols, prior art
- Search npm, GitHub, docs, and community resources for candidate tools
- Read documentation, changelogs, GitHub issues for each candidate
- Evaluate trade-offs: pros/cons/risks for each option
- Check compatibility with our stack (Node version, existing deps, patterns)
- Identify dependencies, licensing, maintenance status, breaking change history
- Produce a **Research Brief** saved to `memory/research/<topic>.md`
- **Research Brief structure:**
  - Problem statement and context
  - Options evaluated (with pros/cons table)
  - Compatibility notes (Node version, existing deps, patterns)
  - Recommended approach + rationale
  - Open questions / blockers
  - Links to docs and references
  - Date and researcher ID
- David reviews the brief and picks a direction
- Only then does Stage 1 (Planning) begin
- **Skip condition:** If the problem space is well-understood and no external deps are involved, David can approve skipping directly to Stage 1

### Stage 1 — Planning

- Define what's being built or fixed
- Write specs, architecture decisions, scope
- Identify affected files and dependencies
- David approves before coding begins

### Stage 2 — Coding

- Implement changes against live codebase
- Commit to working branch with descriptive messages
- Ensure code compiles/parses clean (no syntax errors)
- Follow existing code style and patterns

### Stage 3 — Dependency Check

- **Detect new dependencies** in all changed files:
  - Check `package.json` for new runtime dependencies
  - Check `package.json` for new peer dependencies
  - Check skill subdirectories (`skills/*/package.json`) for skill-specific deps
  - Check for new system-level deps (e.g., `ollama`, external binaries)
- **Update EverClaw installer** (`scripts/install.sh`) if new deps found:
  - Add `npm install` calls for skill-specific deps (auto-discovered via `find . -name package.json`)
  - Add system-level dependency checks/installers
  - Test installer on clean environment (Docker container or fresh VM)
- **Verify installer covers all deps** before proceeding to audit
- **Skip condition:** If no new dependencies added, mark as PASS and proceed

### Stage 4 — Audit

- **Executed by the Code Audit agent** (`code-audit`, Claude Opus 4.6)
- Bernardo (main agent) sends patches via `sessions_send` to the audit agent
- Audit agent reviews against live repo code and sends findings back
- **Loop until all changes rated Excellent** — automated back-and-forth
- **Check for:**
  - Correctness (does the fix actually resolve the issue?)
  - Variable name accuracy (match live code, not pseudocode)
  - Security implications and new attack surfaces
  - Edge cases and regressions
  - Logic errors, off-by-one, type mismatches
- **Rate each change:** Excellent / Good / Acceptable / Flawed / Broken
- **Iterate patches** until all changes rated **Excellent**
- Document audit findings in `memory/projects/everclaw/audit-*.md`
- David can also trigger audits directly via Signal (group TBD)

### Stage 5 — Testing

- Run all unit tests (`npm test` or equivalent)
- Run integration tests if applicable
- Test edge cases identified during audit
- Verify on target platforms (macOS, Linux, Docker)
- All tests must pass before proceeding

### Stage 6 — PII Scan

- Scan all changed files for:
  - Private keys, wallet addresses, API keys
  - Personal data (names, emails, phone numbers)
  - Hardcoded secrets or credentials
- Use automated PII Guard + manual review
- **0 findings required** to proceed

### Stage 7 — Documentation

- **Update SKILL.md** with:
  - New features, CLI commands, config options
  - API changes or breaking changes
  - Dependency requirements
- **Update CHANGELOG.md** with:
  - Version number and date
  - Summary of changes (Added/Fixed/Changed/Security)
  - Link to relevant issues/PRs
- **Update README.md** if:
  - Installation process changed
  - New commands or workflows added
  - Prerequisites changed
- **Update architecture docs** (`memory/projects/everclaw/*.md`) if:
  - New modules or components
  - Data flow or process changes
  - Integration changes
- **Review** all doc changes for accuracy
- **Skip condition:** If no user-facing changes, mark as PASS and proceed

### Stage 8 — Primary Deploy

- Push to `EverClaw/EverClaw` (origin)
- Push to `EverClaw/EverClaw` (org remote)
- Verify both repos match

### Stage 9 — Ecosystem Deploy

- Run `bash scripts/ecosystem-sync.sh`
- Syncs to all 28+ flavor repos
- Verify all repos updated (check sync output)

### Stage 10 — Package Tag & Docker

- Bump version in: `package.json`, `SKILL.md`, `Dockerfile`, `docker-compose.yml`
- Update `CHANGELOG.md` with release notes
- Create git tag: `git tag -a vYYYY.M.DD -m "release message"`
- Push tag: `git push origin main --tags`
- Docker image builds via GitHub Actions workflow
- Verify image: `ghcr.io/everclaw/everclaw:<version>` + `:latest`
- Optionally publish to ClawHub: `clawhub publish`

---

## Agent Assignments

| Stage | Agent ID | Agent Name | Model | Signal Group ID |
|-------|----------|------------|-------|-----------------|
| 0. Research | `researcher` | Researcher | claude-opus-4-6 | `3BhhUIY7YhoUaljmxbACxUtUkf+7+krTxLu5PtCR5ok=` |
| 1. Planning | `arch-design` | Architecture & Design | claude-opus-4-6 | `azKAGmzMO2idaoDC18t9WNd7sRyV9vsLW5Ws0P5tx3c=` |
| 2. Coding | `coder` | Coder | claude-opus-4-6 | `Pc0giAwEpUyRhKWZpHEl7uHaHpIDPfaUDOUdN3QtVGE=` |
| 3. Dependency Check | `coder` | Coder | claude-opus-4-6 | `Pc0giAwEpUyRhKWZpHEl7uHaHpIDPfaUDOUdN3QtVGE=` |
| 4. Audit | `code-audit` | Code Audit | claude-opus-4-6 | `nqQowO5pGMZCLGov73OxNf85tx5aQ14NesPcFUyhZGA=` |
| 5. Testing | `tester` | Tester | claude-opus-4-6 | `vZyh9z/JFn/ve+CF8YXuuynB5UA1CPKwFBV/NQ1MSPs=` |
| 6. PII Scan | `pii-checker` | PII Checker | claude-opus-4-6 | `69tGhtpP/fWP3QJJcAaaRBMogMvMI624dRMyJ7kYd/U=` |
| 7. Documentation | `coder` | Coder | claude-opus-4-6 | `Pc0giAwEpUyRhKWZpHEl7uHaHpIDPfaUDOUdN3QtVGE=` |
| 8-10. Deploy | `deployer` | Deployer | claude-opus-4-6 | `DDzMXAM/OG9g+GJ5rAg63YOQp24N34js2etji1GcdKo=` |

### Agent Workspaces

| Agent | Workspace | Agent Dir |
|-------|-----------|-----------|
| researcher | `~/.openclaw/workspace-researcher/` | `~/.openclaw/agents/researcher/agent/` |
| arch-design | `~/.openclaw/workspace-arch-design/` | `~/.openclaw/agents/arch-design/agent/` |
| coder | `~/.openclaw/workspace-coder/` | `~/.openclaw/agents/coder/agent/` |
| code-audit | `~/.openclaw/workspace-code-audit/` | `~/.openclaw/agents/code-audit/agent/` |
| tester | `~/.openclaw/workspace-tester/` | `~/.openclaw/agents/tester/agent/` |
| pii-checker | `~/.openclaw/workspace-pii-checker/` | `~/.openclaw/agents/pii-checker/agent/` |
| deployer | `~/.openclaw/workspace-deployer/` | `~/.openclaw/agents/deployer/agent/` |

### Inter-Agent Communication

- **Primary:** `sessions_send` (internal, low-latency)
- **Secondary:** Signal groups (external, human-visible)
- **Future:** XMTP transport layer (decentralized, Phase 2)

### Pipeline Flow

```
David / Bernardo (main)
        │
        ▼
  ┌─────────────┐
  │  researcher  │  Stage 0: Research
  │ (Researcher) │  → Produces research brief
  └──────┬──────┘
         │ brief approved
         ▼
  ┌─────────────┐
  │ arch-design  │  Stage 1: Planning
  │  (Architect) │  → Produces specs
  └──────┬──────┘
         │ spec
         ▼
  ┌─────────────┐
  │    coder     │  Stage 2: Coding
  │   (Coder)   │  → Implements spec
  └──────┬──────┘
         │ code
         ▼
  ┌─────────────┐
  │    coder     │  Stage 3: Dependency Check
  │   (Coder)   │  → Detect new deps, update installer
  └──────┬──────┘
         │ installer covers deps
         ▼
  ┌─────────────┐
  │ code-audit   │  Stage 4: Audit
  │  (Auditor)  │  → Reviews line-by-line
  └──────┬──────┘  → Loop with coder until Excellent
         │ approved
         ▼
  ┌─────────────┐
  │   tester     │  Stage 5: Testing
  │  (Tester)   │  → Unit/integration/edge tests
  └──────┬──────┘
         │ all pass
         ▼
  ┌─────────────┐
  │ pii-checker  │  Stage 6: PII Scan
  │ (PII Guard) │  → Zero tolerance scan
  └──────┬──────┘
         │ PASS
         ▼
  ┌─────────────┐
  │    coder     │  Stage 7: Documentation
  │   (Coder)   │  → Update SKILL.md, CHANGELOG, README
  └──────┬──────┘
         │ docs reviewed
         ▼
  ┌─────────────┐
  │  deployer    │  Stages 8-10: Deploy
  │ (Deployer)  │  → Primary → Ecosystem → Tag & Docker
  └─────────────┘
```

---

## Quick Reference

```
0. Research → 1. Plan → 2. Code → 3. Deps → 4. Audit → 5. Test → 6. PII → 7. Docs → 8. Deploy → 9. Ecosystem → 10. Tag & Docker
```

## History

- **Mar 9, 2026** — SOP-001 created (Stages 1–6)
- **Mar 14, 2026** — Stage 7 added (Package Tag & Docker)
- **Mar 15, 2026** — Stage 3 (Audit) added between Coding and Testing; stages renumbered
- **Mar 15, 2026** — 6 dedicated agents created and bound to Signal groups for full pipeline automation
- **Mar 16, 2026** — Stage 0 (Research) added before Planning; `researcher` agent created with Signal group binding. Total pipeline agents: 7
- **Mar 17, 2026** — Stage 3 (Dependency Check) added between Coding and Audit; stages renumbered 4-9. Known issue: agent-chat v0.1.0 deps were missed by installer (fixed in v0.2.0)
- **Mar 17, 2026** — Stage 7 (Documentation) added between PII Scan and Deploy; stages renumbered 8-10. Ensures docs stay in sync with code changes.

---

## SOP-002: [REDACTED] P2P Session Management

**Version:** 1.1
**Created:** 2026-03-09
**Updated:** 2026-03-09
**Purpose:** Manage [REDACTED] P2P staking sessions for decentralized inference — wallet operations, session lifecycle, balance monitoring, and fallback behavior.

### How [REDACTED] Inference Staking Works

**CRITICAL: MOR is STAKED, not spent.** There are two modes on the [REDACTED] network:

1. **Staking Mode (`directPayment:false`)** — MOR is temporarily locked in the Diamond smart contract for the session duration. After the session closes, **all staked MOR is returned** to the consumer's wallet (with a short delay). This is how our router is configured.

2. **Direct Payment Mode (`directPayment:true`)** — MOR is paid directly to the provider and NOT returned. This mode is not used in our setup.

**Our configuration uses Staking Mode.** The MOR does NOT "run out." It is locked temporarily per session, then returned. The only real costs are:
- **ETH gas** for opening/closing session transactions (~0.001 ETH per session)
- **Opportunity cost** — staked MOR cannot be used for other sessions simultaneously

**Key implications:**
- You need enough MOR to cover **one session's stake at a time**, not cumulative
- When a session expires and closes, the staked MOR returns to the wallet
- The `SESSION_CLOSER` component in the proxy-router auto-closes expired sessions
- There may be a delay between session close and MOR return (blockchain processing)
- Multiple concurrent sessions require enough MOR to cover all stakes simultaneously

**Verification:** Router logs confirm `directPayment:false` on all session attempts.

### Overview

[REDACTED] P2P inference requires staking MOR tokens to open sessions with providers. The staked MOR is returned after the session closes. This SOP documents the architecture, operational procedures, and upgrade roadmap for reliable session management.

---

### Architecture

```
OpenClaw → morpheus-proxy (port 8083) → proxy-router (port 8082) → [REDACTED] P2P Network
                  ↓ (fallback)
           [REDACTED] Gateway API (api.mor.org)
                  ↓ (fallback)
           Venice API (api.venice.ai)
```

**Key Components:**
| Component | Location | Purpose |
|-----------|----------|---------|
| morpheus-proxy.mjs | `~/morpheus/proxy/` + `skills/everclaw/scripts/` | OpenAI-compatible proxy with balance monitoring |
| proxy-router | `~/morpheus/proxy-router` | Lumerin binary — session creation, provider selection |
| safe-transfer.mjs | `skills/everclaw/scripts/` | Transfer MOR from Safe → Router wallet |
| everclaw-wallet.mjs | `skills/everclaw/scripts/` | Wallet ops: balance, swap, approve, stake |

**Wallet Addresses:**
| Address | Role |
|---------|------|
| *(set via `ROUTER_WALLET` env var)* | Router EOA (sessions, gas) |
| *(set via `SAFE_WALLET` env var)* | Safe Smart Account (MOR reserve) |

**Key Contracts (Base Mainnet):**
| Contract | Address |
|----------|---------|
| MOR Token | `0x7431aDa8a591C955a994a21710752EF9b882b8e3` |
| Diamond (Staking) | `0x6aBE1d282f72B474E54527D93b979A4f64d3030a` |
| Uniswap Router | `0x7b9684855E9d52c67C29c810E4240662c9d2e0d0` |
| Uniswap Quoter | `0xC5290058841028F1614F3A6F0F5816cAd0df5E27` |

---

### Procedure 1: Check Session Health

**When:** Before any session-dependent work, or when inference errors occur.

```bash
# 1. Check proxy health (balance, sessions, fallback mode)
curl -s http://127.0.0.1:8083/health | jq '.'

# 2. Check router logs for session errors
tail -50 ~/morpheus/data/logs/router-stdout.log | grep -i "session\|error\|stake"

# 3. Check MOR balance on-chain
node scripts/everclaw-wallet.mjs balance
```

**Healthy indicators:**
- `morBalance` > 500 MOR
- `fallbackMode` = false
- `consecutiveFailures` = 0
- At least 1 active session

---

### Procedure 2: Fund Router Wallet

**When:** `morBalance` is less than the provider's stake requirement for a single session (~633 MOR for 1-day sessions), or session open fails with "transfer amount exceeds balance"

**Remember:** MOR is staked, not spent. The staked MOR returns after each session closes. You only need enough to cover concurrent session stakes.

```bash
# 1. Check current balances
node scripts/safe-transfer.mjs <amount>        # Dry run

# 2. Execute transfer from Safe → Router
node scripts/safe-transfer.mjs <amount> --execute

# 3. Verify
curl -s http://127.0.0.1:8083/health | jq '.morBalance'
```

**Guidelines:**
- Need enough MOR to cover **one session's stake** (currently ~633 MOR per 1-day session)
- For concurrent sessions across multiple models, multiply by number of simultaneous sessions
- Staked MOR is returned after each session closes (with a short delay)
- Safe holds reserve MOR (currently 5,700 MOR) for additional funding if needed
- Only ETH gas is permanently consumed (~0.001 ETH per session open/close)

---

### Procedure 3: Adjust Session Duration

**When:** Balance is low but sufficient for shorter sessions.

```bash
# Edit launchd plist
# MORPHEUS_SESSION_DURATION: seconds (default 86400 = 1 day)
vim ~/Library/LaunchAgents/com.morpheus.proxy.plist

# Restart proxy
launchctl unload ~/Library/LaunchAgents/com.morpheus.proxy.plist
launchctl load ~/Library/LaunchAgents/com.morpheus.proxy.plist
```

**Duration vs Stake (approximate, MOR is returned after session close):**
| Duration | Stake Locked | Returned After Close |
|----------|-------------|---------------------|
| 1 day | ~633 MOR | ✅ ~633 MOR returned |
| 3 days | ~1,900 MOR | ✅ ~1,900 MOR returned |
| 7 days | ~4,434 MOR | ✅ ~4,434 MOR returned |

**Note:** Longer sessions lock more MOR but it's all returned. The trade-off is liquidity — locked MOR can't be used for other sessions until the current one closes.

---

### Procedure 4: Model Selection

**When:** Selecting models for P2P inference.

**Available on P2P (as of 2026-03-15):**
| Model | Type | Notes |
|-------|------|-------|
| **glm-5** | General | ✅ Best quality GLM, now on P2P |
| **glm-5:web** | Web search | GLM-5 with web access |
| glm-4.7 | General | Previous gen GLM |
| glm-4.7-flash | Fast | Lightweight tasks |
| glm-4.7-thinking | Reasoning | Thinking model |
| glm-4.6 | General | Older GLM |
| kimi-k2-thinking | Reasoning | Best for complex tasks |
| kimi-k2.5 | General | High quality |
| kimi-k2.5:web | Web search | With web access |
| qwen3-235b | Large | 235B parameters |
| qwen3-next-80b | General | 80B next-gen |
| qwen3-coder-480b-a35b-instruct | Code | 480B code specialist |
| llama-3.3-70b | General | Llama 3.3 |
| llama-3.2-3b | Small | Lightweight |
| gpt-oss-120b | Large | Open-source GPT |
| mistral-31-24b | Fast | Mistral |
| MiniMax-M2.5 | General | MiniMax |
| hermes-3-llama-3.1-405b | Large | Hermes |
| hermes-4-14b | General | Hermes 4 |
| venice-uncensored | Uncensored | Dolphin-Mistral |

**Also available:** `:web` variants for most models (web search enabled)

**Check live model list:**
```bash
curl -s -u "admin:$(cat ~/morpheus/.cookie)" http://127.0.0.1:8082/blockchain/models | jq '.models[].Name' | sort
```

---

### Procedure 5: Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `transfer amount exceeds balance` | Not enough MOR | Fund router (Procedure 2) |
| `Unknown model: X` | Model not on P2P | Use Gateway or different model |
| `502 [REDACTED] session unavailable` | Session creation failed | Check balance, restart proxy |
| High `consecutiveFailures` | Persistent P2P issues | Will auto-fallback after threshold |
| `fallbackMode: true` | Using Gateway instead of P2P | Wait for retry timer or restart proxy |

---

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| MORPHEUS_SESSION_DURATION | 86400 | Session duration in seconds |
| MORPHEUS_RENEW_BEFORE | 3600 | Renew this many seconds before expiry |
| MORPHEUS_WALLET_ADDRESS | (required) | Router EOA address for balance checks |
| MORPHEUS_MOR_THRESHOLD | 500 | Warn when MOR below this |
| MORPHEUS_FALLBACK_THRESHOLD | 3 | P2P failures before Gateway fallback |
| MORPHEUS_FALLBACK_RETRY_MS | 21600000 | How long to stay in fallback (6 hours) |
| MORPHEUS_GATEWAY_API_KEY | (optional) | Gateway API key for fallback |
| MORPHEUS_GATEWAY_URL | https://api.mor.org/v1 | Gateway base URL |

---

### Upgrade Roadmap

| Priority | Feature | Status | Description |
|----------|---------|--------|-------------|
| P0 | Balance monitoring | ✅ Done | Check MOR before sessions |
| P0 | Hybrid fallback | ✅ Done | P2P → Gateway after failures |
| P1 | Provider bid query | ⬜ Planned | Show stake needed before attempting |
| P1 | Auto-adjust duration | ⬜ Planned | Calculate max duration from balance |
| P1 | Session health endpoint | ✅ Done | /health shows balance + sessions |
| P2 | Provider preferences | ⬜ Planned | Filter by max bid or whitelist |
| P2 | Session analytics log | ⬜ Planned | Track stake, cost, provider performance |
| P2 | Safe executor support | ⬜ Planned | Execute sessions directly from Safe |
| P3 | Multi-agent session sharing | ⬜ Planned | Share sessions across agents |

---

### Lessons Learned (2026-03-09, Updated 2026-03-15)

1. **MOR is STAKED, not spent** — All staked MOR is returned after session close. `directPayment:false` confirmed in router logs. Only ETH gas is consumed.
2. **Session stake is pro-rated by duration** — 4,434 MOR/7 days = 633 MOR/day (all returned after close)
3. **Need enough for one session at a time** — MOR doesn't "run out"; you just need enough unlocked MOR to cover the next session's stake
4. **MOR must be in EOA, not Safe** — Router only uses EOA for signing; Safe funds need to be transferred to EOA first
5. **GLM-5 IS on P2P** — As of Mar 15, GLM-5 has providers on P2P. Model list must be refreshed from router (`/blockchain/models`).
6. **Check balance proactively** — Prevents cryptic "ERC20: transfer amount exceeds balance" revert errors
7. **Provider bids vary** — Can't control which provider the router selects; stake amount depends on provider bid
8. **Safe 1-of-2 threshold** — Single owner can execute transfers from Safe to EOA
9. **SESSION_CLOSER auto-closes** — The router has a built-in component that auto-closes expired sessions and triggers MOR return
10. **Model list refresh bug (Fixed 2026-03-15)** — Proxy was parsing router response incorrectly. Router returns `{ models: [...] }`, not a raw array. Fix: `const models = Array.isArray(data) ? data : (data.models || [])`
11. **Model list changes frequently** — Always check live models via `/blockchain/models` endpoint. Don't rely on stale notes from previous sessions.
12. **40+ models now on P2P** — Including glm-5, glm-5:web, hermes-4-14b, MiniMax-M2.5, qwen3-next-80b, qwen3-coder-480b, and many more.

---

## SOP-003: XMTP Agent-to-Agent Communication

**Version:** 3.0
**Created:** 2026-03-14
**Updated:** 2026-03-14 (V3 Trust Framework upgrade)
**Purpose:** Manage XMTP-based agent-to-agent messaging — keypair management, client initialization, V3 message protocol, EIP-191 handshakes, and operational procedures.

### Overview

XMTP enables decentralized, encrypted messaging between AI agents using Ethereum wallet signatures for identity. No on-chain funds are required for messaging — only an Ethereum keypair for signing.

**Architecture (V3):**
```
┌────────────────────────────────────────────────────────────────────┐
│ OPENCLAW ECOSYSTEM                                                 │
│                                                                    │
│  Agent A ◄──► xmtp-comms-guard (middleware) ◄──► Agent B          │
│               │ Schema → Auth → Rate → PII → Injection → Trust │  │
└───────────────┼────────────────────────────────────────────────────┘
                │ XMTP (MLS E2EE)
                ▼
         External Agents
```

All agents **MUST** use `createGuardedXmtpClient` from the `xmtp-comms-guard` skill. Raw `@xmtp/client` calls are prohibited.

---

### XMTP Keypair Management

**Key Principle:** XMTP keypairs are messaging-only identities. They do NOT need funds. Keep them separate from wallets that hold tokens.

**Storage Locations:**
| Location | Content | Security |
|----------|---------|----------|
| `projects/xmtp-poc/identities/<agent>.json` | Private keys + addresses | Gitignored, local only |
| macOS Keychain (`lumerin-wallet`) | Router EOA key | System-level encryption |
| Memory files | Public addresses ONLY | Never store private keys |
| Bagman (future) | All keys encrypted at rest | 1Password / OS Keychain + EIP-7710 |

**Current XMTP Identities:**
| Agent | Address | Network | Created |
|-------|---------|---------|---------|
| morpheusai | `0x528DC1C6A154A88730cE6314C4AcB6f7628F3Cf4` | production | 2026-03-14 |
| everclaw | `0x60F627f6d332bC7dD48E359899999e66fBc5729a` | production | 2026-03-14 |

**Generating New Keypairs:**
```bash
cd projects/xmtp-poc && node keygen.mjs
```
New agents can be added by editing the `agents` array in `keygen.mjs`.

**NEVER:**
- Store private keys in memory files, MEMORY.md, or any committed file
- Reuse token-holding wallets (Router EOA, Safe) for XMTP messaging
- Share keypair files across machines without encrypted transport

---

### XMTP SDK v6 — Key API Differences

The SDK underwent a major rewrite from v0.x to v6.x. Key changes:

| v0.x API | v6.x API | Notes |
|----------|----------|-------|
| `Client.create(signer, { env })` | Same, but signer shape changed | `identifierKind` is now numeric (0=Ethereum) |
| `conversations.newConversation(address)` | `conversations.createDmWithIdentifier({identifier, identifierKind})` | Takes Identifier object |
| `conversation.send(text)` | `conversation.sendText(text)` | `send()` requires EncodedContent |
| `canMessage([address])` | `canMessage([{identifier, identifierKind}])` | Takes Identifier array |
| `client.close()` | (removed in v6) | No explicit cleanup needed |
| `message.sentAtNs` | `message.sentAtNs` (bigint) | Unchanged |

**Platform Fix (macOS arm64):**
The `@xmtp/node-bindings` native binary is compiled against Nix's `libiconv`. On macOS without Nix:
```bash
brew install libiconv

install_name_tool -change \
  /nix/store/7h6icyvqv6lqd0bcx41c8h3615rjcqb2-libiconv-109.100.2/lib/libiconv.2.dylib \
  /opt/homebrew/opt/libiconv/lib/libiconv.2.dylib \
  node_modules/@xmtp/node-bindings/dist/bindings_node.darwin-arm64.node

codesign --force --sign - node_modules/@xmtp/node-bindings/dist/bindings_node.darwin-arm64.node
```

---

### V3 Agent Message Protocol

All messages use the V3 JSON schema at `projects/xmtp-poc/agent-message-schema.json`.

**Protocol version:** `3.0`

**Required fields (every message):**
| Field | Purpose |
|-------|---------|
| `messageType` | HANDSHAKE, RESPONSE, COMMAND, DATA, BYE, INTRODUCTION |
| `version` | Must be `"3.0"` |
| `payload` | Message content (type-specific) |
| `topics` | Topic tags for trust boundary enforcement |
| `sensitivity` | public, guarded, technical, personal, financial |
| `intent` | query, update, introduce, handshake, revoke, status |
| `correlationId` | UUID linking responses to requests |
| `timestamp` | ISO 8601 |
| `nonce` | Base64-encoded 32-byte random (replay protection) |

**V3 Handshake Flow (EIP-191 replay-protected):**
1. Agent A builds HANDSHAKE with signed challenge (`conversationId` + `timestamp` + `nonce` + `version`)
2. Agent A sends structured JSON over XMTP
3. Agent B validates V3 schema, verifies EIP-191 signature against claimed wallet address
4. Agent B sends RESPONSE with counter-signature on the same challenge
5. Agent A verifies counter-signature → mutual authentication complete
6. For trust ≥6: ERC-8004 on-chain lookup (Phase 4)

**Check Pipeline (enforced by `xmtp-comms-guard` middleware):**
1. Schema validation (Zod) — kills 90% of injections
2. Peer authorization (Bagman DB + XMTP consent)
3. Rate limiting (10 msg/min per peer, 256 KB max)
4. PII Guard (existing skill)
5. Prompt Injection Guard (existing skill)
6. Trust & Context Boundary (rule-based + hybrid classifier)

---

### Procedure 1: Test V3 Roundtrip

**When:** After keypair changes, SDK updates, code changes, or network issues.

```bash
cd projects/xmtp-poc
rm -rf data/*.db3*              # Clean local DB state
node test-roundtrip.mjs         # Full V3 bidirectional test with EIP-191
```

**Expected output:** All checks pass with `✅`. Tests cover:
- Agent initialization
- Mutual reachability
- V3 schema validation
- EIP-191 challenge signing
- Counter-signature verification
- Correlation ID linking

---

### Procedure 2: Send a V3 Message

```bash
cd projects/xmtp-poc
node send.mjs --from morpheusai --to 0x60F627f6d332bC7dD48E359899999e66fBc5729a \
  --message "Hello" --topic everclaw --sensitivity technical
```

All messages are V3-structured, schema-validated, and EIP-191 signed before sending.

---

### Procedure 3: Listen for V3 Messages

```bash
cd projects/xmtp-poc
node receive.mjs --agent everclaw --timeout 60
```

The receiver validates all inbound messages against V3 schema. Invalid messages are logged with errors but not processed.

---

### Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `Cannot find native binding` | Nix libiconv path mismatch | Run `install_name_tool` + `codesign` patch (see above) |
| `IdentifierKind` enum error | Passing string instead of number | Use `identifierKind: 0` (not `"Ethereum"`) |
| `Content type is required` | Using `send()` for text | Use `sendText()` for plain strings |
| `canMessage` returns false | Agent not yet registered on XMTP | Run `Client.create()` for that agent first (auto-registers) |
| DB lock errors | Stale db3 files | Delete `data/*.db3*` and retry |
| V3 validation fails | Missing fields in message | Check all 9 required fields (see protocol table above) |
| EIP-191 sig fails | Wrong canonical challenge format | Must be: `xmtp-comms-guard:handshake:v3.0\nconversation:...\ntimestamp:...\nnonce:...` |
| Challenge expired | >5 min between send and verify | Handshake TTL is 5 minutes; retry with fresh challenge |

---

### Security (V3 Trust Framework)

The `xmtp-comms-guard` skill at `skills/xmtp-comms-guard/` provides the full V3 security layer:

- **Default policy:** `reject-and-notify` — unknown peers are blocked
- **Storage:** Bagman-encrypted SQLCipher DB (peers, profiles, audit)
- **Consent sync:** XMTP native `setConsent()` / `publishConsent()`
- **Handshake:** Replay-protected EIP-191 with nonce + TTL + version binding
- **Trust tiers:** 10-point scale with profile-based topic/sensitivity enforcement
- **Threat model:** See `skills/xmtp-comms-guard/threat-model.md`
- **Full V3 design spec:** `memory/projects/everclaw/xmtp-trust-framework-v3.md`

---

### Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `@xmtp/node-sdk` | 6.0.0 | XMTP client |
| `viem` | 2.x | Ethereum wallet/signing + EIP-191 |

---

### Lessons Learned

1. **XMTP doesn't need funds** — Pure signing, no gas. Fresh keypairs work immediately.
2. **v6 is a full rewrite** — Most v0.x examples online are obsolete. Check types, not tutorials.
3. **Native bindings are Nix-compiled** — `install_name_tool` + `codesign` workaround required on macOS without Nix.
4. **Deterministic DB key required** — V3 derives encryption key from agent private key for persistent message history. Random keys lose history on restart.
5. **XMTP production network works** — No rate limits or fees encountered during PoC.
6. **`createDmWithIdentifier` vs `createDm`** — The former takes an Ethereum address (Identifier object), the latter takes an inbox ID string.
7. **V3 structured messages kill injections early** — Zod validation at pipeline entry rejects 90%+ of attack vectors before any LLM processing.
8. **EIP-191 canonical format matters** — Challenge must be deterministic string (newline-separated key:value pairs). Any deviation breaks signature verification.

## SOP-004: Marketing & Sales Pipeline

**Version:** 1.0
**Created:** 2026-03-17
**Purpose:** Define the agent-driven marketing and sales pipeline that moves users through the EverClaw ownership funnel — from discovery to full hardware sovereignty.

---

### Overview

The EverClaw sales funnel has 5 stages. Each stage is supported by dedicated AI agents running on GLM-5 ([REDACTED]). All agents operate in **draft-and-approve** mode — they produce drafts, David reviews and approves before anything goes external.

**Core Message:** "Own your AI agent. Hardware, data, inference — all yours."

**Language Rules:**
- NEVER say "free inference" → say "own your inference"
- [REDACTED] = ownership, not rental
- MOR is staked, not spent — all staked MOR returns after session close
- Don't highlight Llama 3.3

---

### Funnel Stages

| Stage | Name | Goal | External Lead |
|-------|------|------|---------------|
| 1 | **Discovery & Sales** | User finds a flavor site, gets hooked on the ownership message | David |
| 2 | **VM Setup** | User gets EverClaw running in a hosted VM — zero hardware needed | StarkClaw / TBD |
| 3 | **Inference Access** | User connects to decentralized inference via [REDACTED] | Thomas Borrel / BasedAI |
| 4 | **Hardware Purchase** | User buys a ClawBox — owns their compute | Eric Bravick / IronHill |
| 5 | **DIY Setup** | User sets up their own hardware from scratch | Scott B. |

**Entry points are non-linear.** Users can enter at any stage:
- Stage 1: New user discovering AI agents
- Stage 2: User wants to try before buying hardware
- Stage 5: User already has dedicated hardware

---

### Agent Assignments

| Agent ID | Agent Name | Model | Stages | Role | Signal Group ID |
|----------|------------|-------|--------|------|-----------------|
| `content-writer` | Content Writer | morpheus/glm-5 | 1 | Write blog posts, landing page copy, X threads, flavor-specific marketing materials for all 28 flavors. Takes persona and flavor context as input. | `L33pPTSPmX7vgOhTjWWJIqUhs+T2i2erb4gO+GPYRv0=` |
| `social-manager` | Social Manager | morpheus/glm-5 | 1 | Draft social posts for X/Farcaster/Discord/Telegram. Track engagement, draft responses to mentions, coordinate influencer outreach. | `HG7jhfrk5F9jnwzZMXYLhCgFJumSXTvIJQs8a06Y1t0=` |
| `lead-tracker` | Lead Tracker | morpheus/glm-5 | 1–2 | Track inbound interest (GitHub stars, website visits, install counts, DMs). Maintain CRM data. Score and qualify leads. | `ve3o3EJZlJCO6lXnFcwB9pVxmaBRYFAQbmSp8/05q9w=` |
| `onboarding-agent` | Onboarding Agent | morpheus/glm-5 | 2, 5 | Guide new users through VM setup or DIY hardware setup. Answer setup questions. Escalate blockers. Track conversion from signup → running agent. | `+4cUWjjPju+8b6klwQ/1o5BRqGED94go490mWXY18Yg=` |
| `inference-support` | Inference Support | morpheus/glm-5 | 3 | Help users connect to [REDACTED] inference. Troubleshoot MOR staking, proxy-router setup, model selection. Monitor inference health. | `KN5ycpjeU1Ge7OlTCEqA/tQkc6W3qqLubWBfj6GiztQ=` |
| `sales-closer` | Sales Closer | morpheus/glm-5 | 3–4 | Nurture users from VM → hardware purchase. Handle objections. Track pipeline from trial → ClawBox order. Coordinate with IronHill. | `8SfeDCsivG8n/RZZ8YqpUcWNBA2t1aoytOhiIvQsZD0=` |
| `community-manager` | Community Manager | morpheus/glm-5 | 1–5 | Manage Discord/Telegram communities per flavor. Welcome new members, answer FAQs, escalate issues, run engagement campaigns. | `OmV9k3tDGP9FqZRdqsmocUBlRBZUStcObwAt0SWO8Aw=` |
| `analytics-agent` | Analytics Agent | morpheus/glm-5 | 1–5 | Track funnel metrics across all stages: conversion rates, drop-off points, install counts, active users, MOR staking growth. Produce weekly reports. | `U9WymONIRKHKoEDEObVHBiQtdko1hJPYUZCJNhehMYI=` |

**Total new agents: 8**

---

### Agent Workspaces

Each agent follows the same workspace pattern as SOP-001:

| Agent | Workspace | Agent Dir |
|-------|-----------|-----------|
| content-writer | `/Users/bernardo/.openclaw/workspace-content-writer/` | `/Users/bernardo/.openclaw/agents/content-writer/agent/` |
| social-manager | `/Users/bernardo/.openclaw/workspace-social-manager/` | `/Users/bernardo/.openclaw/agents/social-manager/agent/` |
| lead-tracker | `/Users/bernardo/.openclaw/workspace-lead-tracker/` | `/Users/bernardo/.openclaw/agents/lead-tracker/agent/` |
| onboarding-agent | `/Users/bernardo/.openclaw/workspace-onboarding-agent/` | `/Users/bernardo/.openclaw/agents/onboarding-agent/agent/` |
| inference-support | `/Users/bernardo/.openclaw/workspace-inference-support/` | `/Users/bernardo/.openclaw/agents/inference-support/agent/` |
| sales-closer | `/Users/bernardo/.openclaw/workspace-sales-closer/` | `/Users/bernardo/.openclaw/agents/sales-closer/agent/` |
| community-manager | `/Users/bernardo/.openclaw/workspace-community-manager/` | `/Users/bernardo/.openclaw/agents/community-manager/agent/` |
| analytics-agent | `/Users/bernardo/.openclaw/workspace-analytics-agent/` | `/Users/bernardo/.openclaw/agents/analytics-agent/agent/` |

---

### Pipeline Flow

```
                    ┌──────────────┐
                    │content-writer│  Stage 1: Content creation
                    │social-manager│  → Drives discovery across 28 flavors
                    └──────┬───────┘
                           │ user discovers flavor site
                           ▼
                    ┌──────────────┐
                    │ lead-tracker │  Stage 1→2: Capture & qualify
                    └──────┬───────┘
                           │ qualified lead
                           ▼
                    ┌────────────────┐
                    │onboarding-agent│  Stage 2: VM setup
                    └──────┬─────────┘
                           │ user running on VM
                           ▼
                    ┌─────────────────┐
                    │inference-support│  Stage 3: Connect to [REDACTED]
                    └──────┬──────────┘
                           │ user staking MOR
                           ▼
                    ┌──────────────┐
                    │ sales-closer │  Stage 3→4: Convert to hardware
                    └──────┬───────┘
                           │ ClawBox order
                           ▼
                    ┌────────────────────┐
                    │ onboarding-agent   │  Stage 5: Hardware setup
                    │ (reused for DIY)   │
                    └────────────────────┘

    ─── Across all stages ──────────────────────────────
    ┌───────────────────┐  ┌─────────────────┐
    │ community-manager │  │ analytics-agent  │
    └───────────────────┘  └─────────────────┘
```

---

### Operating Model: Draft & Approve

All agents operate in draft-and-approve mode. Nothing goes external without David's explicit approval.

#### Workflow

1. **Bernardo (main agent)** receives task from David or triggers from pipeline events
2. **Dispatches to appropriate agent** via `sessions_send`
3. **Agent produces draft** (content, post, report, response)
4. **Draft sent to David** via Signal for review
5. **David approves, edits, or rejects**
6. **If approved:** Bernardo executes (publishes post, sends email, updates CRM, etc.)
7. **If rejected:** Agent revises based on feedback

#### Escalation Path

- Agent can't complete task → escalates to Bernardo
- Bernardo can't resolve → escalates to David
- Urgent issues (security, PR crisis) → immediate David notification

---

### The 28 Flavors (Content Writer Context)

The content-writer agent serves all 28 flavors from a single instance. At task time, it receives:

1. **Flavor name and domain** (e.g., BitcoinClaw / bitcoinclaw.ai)
2. **Target persona** (e.g., BTC holders, sovereignty-focused)
3. **Content type** (blog post, X thread, landing page, etc.)
4. **Messaging hooks** specific to that persona

Flavor categories for content strategy:

| Category | Flavors | Messaging Angle |
|----------|---------|-----------------|
| **Protocol/Chain** | BitcoinClaw, EthereumClaw, SolanaClaw, BaseClaw, ArbClaw, [REDACTED] | Self-custody meets AI — own your inference like you own your keys |
| **Model-Specific** | GLMClaw, GrokClaw, KimiClaw, LlamaClaw, MiniMaxClaw, DeepSeekClaw | Your favorite model, your hardware, no API landlord |
| **Platform** | AndroidClaw, AppleClaw, LinuxClaw, WindowsClaw | Native AI agent for your OS — no cloud dependency |
| **Use Case** | EmailClaw, BookingClaw, BriefingClaw, InvestClaw, FamilyClaw, HomeClaw, OfficeClaw, FriendClaw, FamilyOfficeClaw, VCClaw | AI that works for you, not a subscription service |
| **Entry Point** | InstallOpenClaw | Generic funnel — "get started with your own AI agent" |

---

### Inter-Agent Communication

Same pattern as SOP-001:

- **Primary:** `sessions_send` (internal, low-latency)
- **Secondary:** Signal groups (external, human-visible, one per agent)
- **Future:** XMTP transport layer (decentralized, SOP-003)

---

### Metrics & Reporting (Analytics Agent)

Weekly report to David covering:

| Metric | Source |
|--------|--------|
| GitHub stars / forks per flavor | GitHub API |
| Install counts (`curl \| bash` hits) | CloudFlare analytics on get.everclaw.xyz |
| Active users (inference sessions) | [REDACTED] proxy logs |
| MOR staking growth | On-chain data |
| Content published (posts, threads, blogs) | Internal tracking |
| Community growth (Discord/Telegram members) | Platform APIs |
| Funnel conversion rates (stage → stage) | Cross-agent data |
| Lead pipeline status | Lead tracker CRM |

---

### Build Order

Agents will be created one at a time, tested, and connected to Signal before moving to the next:

| Priority | Agent | Rationale |
|----------|-------|-----------|
| 1 | `content-writer` | Highest impact — drives top-of-funnel for all 28 flavors |
| 2 | `analytics-agent` | Measure before optimizing — need baseline metrics |
| 3 | `social-manager` | Amplify content-writer output across platforms |
| 4 | `community-manager` | Engage and retain users who discover via content |
| 5 | `lead-tracker` | Track and qualify inbound interest |
| 6 | `onboarding-agent` | Guide users through setup (VM + hardware) |
| 7 | `inference-support` | Technical support for [REDACTED] connection |
| 8 | `sales-closer` | Convert trial users to hardware buyers |

---

### Agent Creation Checklist (per agent)

For each new agent, follow these steps:

- [ ] Create agent config in `/Users/bernardo/.openclaw/agents/<agent-id>/agent/`
- [ ] Write `SOUL.md` with agent identity, role, and constraints
- [ ] Write `USER.md` pointing to David as the human
- [ ] Write `AGENTS.md` with workspace conventions
- [ ] Set model to `morpheus/glm-5` in agent config
- [ ] Create workspace at `/Users/bernardo/.openclaw/workspace-<agent-id>/`
- [ ] Create Signal group and bind to agent
- [ ] Test agent responds via Signal
- [ ] Update this SOP with Signal Group ID
- [ ] Log creation in `memory/daily/YYYY-MM-DD.md`

---

### Dependencies on Other SOPs

| Dependency | SOP | Notes |
|------------|-----|-------|
| Agent deployment infra | SOP-001 | Agent creation patterns, workspace layout |
| Inference access | SOP-002 | Agents use [REDACTED] P2P for inference |
| Agent-to-agent comms | SOP-003 | Future: XMTP for decentralized inter-agent messaging |

---

### Lessons Learned

*(To be populated as agents are deployed and the pipeline matures)*

---

### History

- **Mar 17, 2026** — SOP-004 created. 8 agents defined. Build order prioritized. Draft-and-approve workflow. All agents on GLM-5 ([REDACTED]).
- **Mar 17, 2026** — All 8 agents deployed and bound to Signal groups. Total system agents: 22. content-writer tested and confirmed responsive. SOP-004 fully operational.
