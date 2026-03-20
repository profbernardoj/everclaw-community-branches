# EverClaw Changelog

All notable changes to EverClaw are documented here.

## [2026.3.20.1950] - 2026-03-20

### Fixed
- **Docker default config routed to dead local proxy** — The Dockerfile's inline default config set `morpheus-local/glm-5` as primary model, which requires a running local proxy + `MORPHEUS_PROXY_API_KEY`. Most Docker users only have a Gateway API key → proxy fails on startup → every request hits dead endpoint → instant timeout. Fix:
  - Dockerfile default config now uses `mor-gateway/glm-5` as primary (works with just `MORPHEUS_GATEWAY_API_KEY`)
  - `morpheus-local` provider kept as optional (only useful when `MORPHEUS_PROXY_API_KEY` is set)
  - Default config includes `timeoutSeconds: 300` and streaming overrides
  - Entrypoint auto-detects: if primary is `morpheus-local/*` but `MORPHEUS_PROXY_API_KEY` isn't set, swaps to `mor-gateway/*` equivalent
  - Morpheus local proxy now only starts when `MORPHEUS_PROXY_API_KEY` is set (no more scary error on startup)

## [2026.3.20.1823] - 2026-03-20

### Fixed
- **Streaming enabled on all models** — Without streaming, OpenClaw waits for the complete response before any data arrives. With Morpheus P2P provider discovery taking 30-120s, connections hit timeout. Streaming keeps connections alive once the first token arrives. Fix:
  - Streaming set at `agents.defaults.models["provider/id"].streaming = true` (the correct schema location — OpenClaw's `models.providers.*.models.*` is strict `additionalProperties: false` and rejects unknown keys like `streaming`)
  - All 3 config templates updated with correct streaming overrides
  - `setup.mjs` auto-enables streaming for all discovered models during config merge + removes stale `streaming` from provider model definitions
  - Docker entrypoint auto-patches existing configs at container startup (streaming + timeout)
  - `diagnose.sh` new check A9: flags models missing streaming
  - Credit: Thomas (ClawBox) identified the streaming root cause
- **Docker tag-triggered builds were producing empty tags** — `type=semver` can't parse our 4-part `YYYY.M.DD.HHMM` version format. Replaced with `type=match,pattern=v(.*),group=1`. Tag pushes now also tag `:latest`.
- **Docker workflow `no-cache-filter` deprecation** — Renamed to `no-cache-filters` (plural) to match `docker/build-push-action@v6`

## [2026.3.20.1442] - 2026-03-20

### Fixed
- **"LLM request timed out" on container/gateway-only installs** — Morpheus Gateway models (GLM-5, gpt-oss-120b) can take 30-120s on first request due to P2P provider discovery. OpenClaw's default timeout was too low, causing immediate timeout errors for gateway-only users. Fix:
  - All 3 config templates now set `agents.defaults.timeoutSeconds: 300` (5 min)
  - `setup.mjs` auto-enforces minimum 180s timeout during config merge (upgrades low values, preserves user values ≥180s)
  - `diagnose.sh` new check A8: flags `timeoutSeconds < 180` as FAIL with fix instructions
  - Agent boot template (`AGENTS.template.md`) now instructs agents to send a brief acknowledgment ("On it!", "Working on that...") on first message so users aren't left staring at a blank screen

## [2026.3.31] - 2026-03-19

### Fixed
- **Installer false-positive dependency reporting on macOS** — Non-admin accounts (family, corporate, school Macs) saw misleading `✓ installed` messages when Homebrew failed silently due to missing sudo access. Fix includes:
  - Early admin pre-check with soft warning + automatic nvm fallback for Node.js (100% Mac compatibility)
  - Real verification after each install (`verify_installed()` helper) instead of unconditional `log_ok`
  - Immediate PATH reload for current script session (`reload_brew_path()` + `hash -r`)
  - Permanent PATH persistence to `~/.zprofile` / `~/.bash_profile` via `persist_brew_path()`
  - Robust Intel Mac support (`/usr/local/bin/brew`) alongside Apple Silicon (`/opt/homebrew/bin/brew`)
  - Localized admin group detection (`admin|administradores|administrator`)
  - nvm fallback with `--lts` for future-proof Node.js installs
  - Soft git warning on non-admin Macs (hints at `xcode-select --install` instead of hard fail)
  - Grok 4.2 final audit: 93/100 — 3 fixes applied (brew version display, soft git warning, header verification)

### Added
- **API key injection via environment variables** — Container entrypoint now accepts `MORPHEUS_GATEWAY_API_KEY` and `MORPHEUS_PROXY_API_KEY` env vars and injects them into the OpenClaw config at startup. `mor-gateway` is a custom provider not in OpenClaw's auto-detection list, so env vars weren't picked up. Users get a clear warning with signup URL if no AI provider keys are configured.
- **Template placeholder substitution** — Boot templates (IDENTITY.md, USER.md, SOUL.md, TOOLS.md) now have `__PLACEHOLDER__` tokens replaced with actual values during first-run scaffold. Supports env vars: `EVERCLAW_AGENT_NAME` (default: EverClaw), `EVERCLAW_USER_NAME` (default: User), `EVERCLAW_USER_DISPLAY_NAME`, `TZ` (default: UTC), `EVERCLAW_DEFAULT_MODEL` (default: glm-5). Previously, placeholders like `__AGENT_NAME__` were copied verbatim.

### Fixed
- **Docker image shipping stale OpenClaw v2026.3.11 instead of v2026.3.13** — GitHub Actions CI workflow had `OPENCLAW_VERSION=v2026.3.11` hardcoded in `build-args`, overriding the Dockerfile. Combined with GHA layer caching, the OpenClaw binary never updated. Fixed by: (1) reading `OPENCLAW_VERSION` from Dockerfile dynamically, (2) adding `no-cache-filter: openclaw-builder` to bust the build cache for the OpenClaw build stage.

## [2026.3.29] - 2026-03-19

### Fixed
- **Container crash on first run: "Refusing to bind gateway to lan without auth"** — Regression from v2026.3.28. The `gateway.auth.mode: "none"` we added to the default template caused the entrypoint to skip token injection (treated `"none"` as "user configured"). Gateway then refused to bind to LAN without auth. Fixed by: (1) removing `auth.mode: "none"` from default template, (2) treating `"none"` as equivalent to empty/unset in the entrypoint — always upgrades to `"token"` mode with auto-generated token.

## [2026.3.28] - 2026-03-19

### Fixed
- **"Disconnected from Gateway" / "Device Identity Required" on container LAN access** — Browsers block `crypto.subtle` on plain HTTP from non-localhost IPs, preventing Ed25519 device keypair generation. The gateway rejected the WebSocket connect with `DEVICE_IDENTITY_REQUIRED`. Fixed by adding `dangerouslyDisableDeviceAuth: true` and `allowInsecureAuth: true` across all config paths: Dockerfile default template, all 3 config templates (mac/linux/gateway-only), docker-entrypoint.sh jq merges, and setup.mjs safe-merge. Matches upstream OpenClaw issues #11590, #44485, #40812, #44967.
- **Race condition: gateway could start before config was fully patched** — Added a defensive config verification step in docker-entrypoint.sh that runs AFTER auth injection but BEFORE gateway start. Forces `dangerouslyDisableDeviceAuth` and `allowInsecureAuth` if missing (respects `OPENCLAW_ENABLE_DEVICE_AUTH=true` env var to opt out).
- **Default config missing `gateway.auth` block** — Added `gateway.auth.mode: "none"` to `openclaw-default.json` so the gateway has a defined auth state from first read. Entrypoint cleanly upgrades to `"token"` mode.

### Changed
- Bumped OpenClaw from v2026.3.11 to v2026.3.13 (22 security patches + auth fixes for device identity handling)
- All config templates now include both `dangerouslyDisableDeviceAuth` and `allowInsecureAuth` for consistent container/headless support
- `setup.mjs` mergeConfig now propagates `dangerouslyDisableDeviceAuth` and `allowInsecureAuth` from templates (only if user hasn't explicitly set them)

## [2026.3.27] - 2026-03-19

### Fixed
- **Gateway startup crash on non-loopback binds (`--bind lan`)** — Now auto-configures `controlUi.allowedOrigins` + `dangerouslyAllowHostHeaderOriginFallback` safely in Docker, config templates, and setup.mjs. Fixes container first-run crash reported by tester.
- **Misleading "✅ EverClaw is ready!" banner** — No longer prints success when gateway actually crashed. Shows clear "❌ EverClaw failed to start" with actionable fix steps and exits with code 1.
- **ENOENT spam on first run** — Pre-creates `.morpheus/.cookie` and `.morpheus/sessions.json` in both Dockerfile and entrypoint. Eliminates all "Failed to read cookie file" and "Failed to save sessions" warnings.
- **Empty `allowedOrigins: []` edge case** — jq uses length-check instead of `//` coalescing, so an explicit empty array is correctly replaced with defaults.
- **Non-Docker installs** — Added `gateway.controlUi` block to all 3 config templates (linux, mac, gateway-only) and safe-merge logic in `setup.mjs`. Bare-metal users now get the same crash protection.
- **Safe config merge** — Docker entrypoint and setup.mjs both preserve user-customized `allowedOrigins` and `dangerouslyAllowHostHeaderOriginFallback` values instead of overwriting.

### Changed
- Linux config template now includes `dangerouslyDisableDeviceAuth: true` (headless/container environments where device auth flow doesn't work)
- Failure banner shows 3 actionable quick fixes (delete config + restart, check origins, report on GitHub)
- Auto-config log line `🔧 Auto-configured gateway.controlUi for container environment` for transparency

## [2026.3.25] - 2026-03-19

### Added
- **Bootstrap Micro-Funding System** — Zero-friction onboarding: new users receive 0.0008 ETH + 2.00 USDC on Base mainnet automatically
  - `scripts/bootstrap-client.mjs` (NEW) — Client-side bootstrap with PoW anti-Sybil, machine fingerprint dedup, macOS keychain integration
  - Auto-bootstrap integrated into `scripts/everclaw-wallet.mjs` setup flow (1-line, graceful failure)
  - API live at `api.everclaw.xyz` (Vercel + Upstash Redis)
  - X post verification for +1 USDC bonus via Twitter Syndication API
  - 6 verified real transfers on Base mainnet during testing

### Security
- PoW challenge: 6 leading zeros SHA-256, 60s window
- Machine fingerprint deduplication (macOS ioreg → /etc/machine-id → hostname fallback)
- 500 bootstraps/day global cap (atomic Redis Lua)
- Tweet reuse prevention, bonus double-claim prevention
- Partial failure handling (ETH sent but USDC failed → logged to Redis for manual retry)

## [2026.3.24] - 2026-03-17

### Added
- **agent-chat v0.2.0** — XMTP transport upgrade for Wire↔Ember interop
  - `src/peers.mjs` (NEW) — Peer registry with relationship-based trust (unknown/stranger/colleague/friend/family), JSON fallback + bagman detection, atomic writes, normalized peer shape
  - `src/paths.mjs` (NEW) — Shared path helpers (single source of truth for all XMTP dirs)
  - `src/agent.mjs` — 3-tier guard adapter: Tier 3 (full V6 + comms-guard), Tier 2 (lenient V6 + rate limit + PII), Tier 1 (plaintext fallback)
  - `src/consent.mjs` — EIP-191 handshake protocol wiring (challenge/sign/verify via comms-guard), auto-discovery, timeout/retry
  - `src/router.mjs` — Tier + relationship-aware dispatch, COMMAND demotion by protocol tier AND relationship, atomic inbox writes
  - `src/bridge.mjs` — Outbound reply blocking (canReply gate), failed/ directory for retry, polling fallback for fs.watch reliability, TTL-based dedup
  - `src/health.mjs` — Message counter export, runtime path resolution
  - `cli.mjs` — `trust-peer` (--as/--name), `peers list/show`, `send` (offline outbox queuing)
  - `config/default.json` — New fields: handshake, discovery, tiers, bridge polling
  - 86 tests (48 existing + 38 new: unit, integration, adversarial)

### Fixed
- **install.sh** — Auto-discovers and installs deps for skills with their own package.json (agent-chat, future skills)
- **agent-chat: agentInstance.inboxId** → `agentInstance.client?.inboxId` (Agent wraps client)
- **agent-chat: Module-level XMTP_DIR** → runtime `getXmtpDir()` in 4 files (stale on env change)
- **agent-chat: Router writeInbox** — Added error handling (disk full no longer crashes middleware)
- **agent-chat: CLI --name flag** — Greedy parsing fixed (stops at next -- flag)
- **agent-chat: Tier 2 hot path** — Cached rateLimit/piiCheck at module level (was re-importing every message)
- **agent-chat: startAgent** — Wrapped in try/catch with diagnostic error message

### Security
- COMMAND execution blocked at both protocol tier (tier 1/2) AND relationship (unknown/stranger)
- Outbound replies blocked for unknown peers (canReply enforcement in bridge)
- Path traversal sanitized in correlationId + atomic writes prevent partial corruption
- Handshake replay protection: 256-bit nonce, 90s freshness, 3 retry max per peer
- peers.json: chmod 600, atomic write with serialized flush lock
- PII scan: 0 findings, example addresses genericized in CLI help
- Cross-model audit: GLM-5 + Grok 4.2 + Claude Opus 4.6 (15 fixes, 3 false positives caught)

### Dependencies
- Zero new runtime dependencies (same as v0.1.0: @xmtp/agent-sdk, viem, uuid, xmtp-comms-guard peer)

## [2026.3.23] - 2026-03-17

### Added
- **agent-chat skill v0.1.0**: Real-time XMTP E2E-encrypted messaging
  - Always-on daemon with `@xmtp/agent-sdk` v2.3.0
  - Filesystem bridge (outbox/inbox) for OpenClaw IPC
  - 3-policy consent system (open/handshake/strict)
  - Middleware chain: Consent → CommsGuard V6 → Router
  - Two-tier identity: 28 flavor canonical + per-user wallets
  - launchd (macOS) + systemd (Linux) service templates
  - CLI: status, health, groups, setup commands
  - 36-test suite (unit + adversarial, 114ms)

### Security
- **agent-chat router.mjs**: Path traversal vulnerability fixed — `correlationId` sanitized to `[a-zA-Z0-9_-]` before inbox file write
- **agent-chat identity.mjs**: Runtime warning when wallet key length ≠ 66 (catches truncated keys)
- **agent-chat setup-identity.mjs**: Post-setup PII sanity check scans source files for leaked address

### Process
- Full SOP-001 pipeline: Research → Architecture (v2.3) → Code (Phases A/B/C) → Cross-model audit (Grok 4.2 + Claude 4.6) → Testing (36/36) → PII scan → Deploy → Ecosystem sync (30/31)

## [2026.3.22] - 2026-03-16

### Security
- **everclaw-wallet.mjs (Stage 2)**: Fix private key leak in `cmdSetup` — capture `keychainStore` return, fallback to encrypted file, banner shows actual backend
- **everclaw-wallet.mjs (Stage 3)**: Add simulation + rich confirmation to `cmdSwap` — shows amount in, expected out, min after slippage
- **everclaw-wallet.mjs (Stage 4)**: Add simulation + unlimited approval warning to `cmdApprove` — CRITICAL WARNING for `maxUint256` approvals
- **everclaw-wallet.mjs (Stage 5)**: Double confirmation for `export-key` — "YES I UNDERSTAND" exact match + 5-second countdown + Ctrl+C abort
- **everclaw-wallet.mjs (Dry-run)**: `--dry-run` flag gates `writeContract` calls in cmdSwap and cmdApprove; simulation + confirmation still execute

### Process
- Phase 2 Stages 2–5 + dry-run — audited by Claude 4.6, tested 7/7 PASS, PII scan PASS
- `isUnlimited` fix: uses `!amountStr` (not `=== "unlimited"` which would crash `parseEther`)

## [2026.3.21] - 2026-03-16

### Security
- **safe-transfer.mjs**: Add `simulateContract` before `writeContract` (catches reverts before gas spend)
- **safe-transfer.mjs**: Add interactive confirmation prompt before on-chain execution
- **safe-transfer.mjs**: Remove no-op signature packing code (dead variables `sortedSignature`, `encodedSignature`)
- **safe-transfer.mjs**: Replace `encodedSignature` with `signature` in writeContract args (fixes potential ReferenceError)
- **safe-transfer.mjs**: Replace hardcoded `gas: 200000n` with dynamic estimation (`gas: undefined`)

### Process
- Phase 2 Stage 1 — audited by Claude 4.6, tested 5/5 PASS, PII scan PASS
- SOP-001 pipeline with dedicated agents (Architect, Coder, Auditor, Tester, PII Checker, Deployer)

## [2026.3.20] - 2026-03-15

### Added
- **Comprehensive documentation suite** — 22 documents covering all aspects of EverClaw
  - Getting started: installation, quick-start, configuration
  - Features: inference, wallet, fallback, ollama, x402-payments, erc8004-registry
  - Scripts: overview and reference for 43 scripts
  - Operations: monitoring, three-shifts, troubleshooting
  - Reference: API, models, contracts, acquiring-mor, economics
  - Security: security overview, shield policy
- Total: 5,412 lines, 17,422 words, 596 KB

### Changed
- Docker image version bumped to 2026.3.20

---

## [2026.3.19] - 2026-03-15

### Fixed
- **morpheus-proxy.mjs** — Model refresh was parsing router response incorrectly
  - Router returns `{ models: [...] }` but code expected raw array
  - Fix: `const data = JSON.parse(res.body.toString()); const models = Array.isArray(data) ? data : (data.models || []);`
  - Result: Model list now refreshes correctly, showing 40 models including GLM-5
  - Backwards compatible — handles both array and object formats

### Changed
- Docker image version bumped to 2026.3.19

---

## [2026.3.18] - 2026-03-15

### Security — Phase 1 Audit Hardening (morpheus-proxy.mjs)
- **CRITICAL: Auth bypass removed** — `PROXY_API_KEY` no longer defaults to `"morpheus-local"`. Proxy now requires a strong key via env var or exits on startup.
- **Cookie caching** — `getBasicAuth()` now caches the `.cookie` file read for 60 seconds instead of reading disk on every request. Cache invalidated on error.
- **Persistent sessions** — Sessions saved to `~/.morpheus/sessions.json` on every mutation (`set`/`delete`) and on graceful shutdown (SIGTERM/SIGINT). Loaded on startup. Proxy restarts no longer lose active sessions.
- **Rate limiting + body size protection** — New `securityMiddleware` runs before auth: 30 req/min per IP, 1MB body limit, smart cleanup at 800+ entries to prevent memory leaks.
- File grew from 833 → 924 lines. Zero new dependencies. All 36 existing tests pass.

### Fixed
- **morpheus-proxy.mjs** — Model refresh was parsing router response incorrectly
  - Router returns `{ models: [...] }` but code expected raw array
  - Fix: `const data = JSON.parse(res.body.toString()); const models = Array.isArray(data) ? data : (data.models || []);`
  - Result: Model list now refreshes correctly, showing 40 models including GLM-5
  - Backwards compatible — handles both array and object formats

---

## [2026.3.17] - 2026-03-15

### Changed
- **install-with-deps.sh** — Complete zero-prompt rewrite (5-stage build)
  - `curl -fsSL https://get.everclaw.xyz | bash` now fully unattended
  - Hardware detection (RAM, disk, GPU) ported from setup-ollama.sh
  - All dependencies auto-install without prompts (Homebrew, Node.js, git, curl, OpenClaw)
  - EverClaw clone/update is automatic (no "Update? [y/N]" prompt)
  - Bootstrap key provisioned automatically (failure is non-fatal)
  - Morpheus proxy-router auto-installs when ≥2 GB disk free
  - Ollama local fallback auto-installs when ≥5 GB disk + ≥2 GB RAM
  - Config merge via setup.mjs --apply --restart runs automatically
  - Dashboard auto-opens after successful install (macOS/Linux)
  - Dynamic success banner shows installed components + inference chain
  - New flags: --skip-ollama, --skip-proxy (--auto-install now legacy no-op)
  - --check-only shows hardware stats + gating preview for all components
  - Zero `read -p` prompts in entire script (was 3)
  - PII scan clean, bash -n syntax verified

---

## [2026.3.15] - 2026-03-12

### Added
- **setup-ollama.sh** — Hardware-aware local Ollama inference fallback
  - Auto-detects OS, CPU arch, total/available RAM, GPU (Apple Metal, NVIDIA CUDA, AMD ROCm)
  - Selects optimal Qwen3.5 model (0.8B–35B) based on available resources
  - Model sizes verified against Ollama registry (0.8b, 2b, 4b, 9b, 27b, 35b)
  - Installs Ollama, pulls model, configures OpenClaw provider + fallback chain
  - Sets up auto-start service (launchd on macOS, systemd on Linux)
  - Tests inference after setup, dry-run by default
  - `--uninstall` cleanly removes from config without touching Ollama binary
  - Never exceeds 70% of total RAM — safe for all hardware
- **setup.mjs --with-ollama** — Integrated Ollama setup into main config flow
- **Config templates** — Both mac and linux templates now include ollama provider + fallback

---

## [2026.3.14] - 2026-03-12

### Fixed
- **BUG-002** — balance.sh session count parsing (jq newline in arithmetic)
- **BUG-003** — bootstrap-everclaw --status/--test showing undefined values
- **BUG-004** — session.sh missing `status` command (balance + session summary)
- **BUG-006** — pii-scan.sh now detects phone numbers in --text and stdin modes (4 patterns)
- **BUG-007** — Boot templates now include 7 `__PLACEHOLDER__` tokens for automated setup
- **BUG-009** — Website footer release link points to valid v2026.3.13 tag
- **BUG-010** — Website "What's New" section updated from v0.9.x to 2026.3.x scheme
- **BUG-011** — SmartAgent gateway-guardian synced to v5 (was stale v4)
- **BUG-013** — Dockerfile versions updated (OpenClaw v2026.3.2, EverClaw 2026.3.13)

---

## [2026.3.13] - 2026-03-11

### Fixed
- **Version alignment** — SKILL.md, package.json, and git tag now all match
- **Removed duplicate security/ directory** — skills/ is canonical; security/ was a stale copy with diverging content
- **Bootstrap version updated** — was hardcoded to v2026.2.26
- **CHANGELOG backfilled** — added missing v2026.3.11 and v2026.3.12 entries
- **install.sh error handling** — added curl/unzip pre-checks, improved GitHub API rate limit diagnostics

---

## [2026.3.12] - 2026-03-09

### Added
- **morpheus-session-mgr.mjs** — CLI for Morpheus P2P session management (7 commands: status, balance, models, sessions, estimate, fund, logs)
- **safe-transfer.mjs** — EIP-712 Safe→Router MOR transfers via 1Password key injection
- **inference-balance-tracker.mjs** — Daily MOR+ETH balance tracker with CoinGecko prices

### Changed
- **morpheus-proxy.mjs** — Added MOR balance monitoring, P2P→Gateway fallback, session tracking, health endpoint with balance/session/fallback fields
- **SOP-002 v1.1** — Documented Morpheus P2P staking model (MOR is staked, not spent)
- **All personal wallet addresses removed** — scripts require env vars (MORPHEUS_WALLET_ADDRESS, MORPHEUS_SAFE_ADDRESS)
- **1Password references configurable** — OP_KEYCHAIN_ACCOUNT, OP_VAULT, OP_ITEM via env vars

---

## [2026.3.11] - 2026-03-09

### Added
- **Wallet safety suite** — receipt verification via `waitAndVerify()`, slippage protection via Uniswap QuoterV2, configurable gas limits (EVERCLAW_MAX_GAS), confirmation tracking (EVERCLAW_CONFIRMATIONS), slippage tolerance (EVERCLAW_SLIPPAGE_BPS)
- **36 automated tests** — split across A (offline), B (balance+approve), C (swap+slippage)

---

## [2026.3.10] - 2026-03-08

### Changed
- **Morpheus Proxy Router reference updated to v5.14.0** (was v5.12.0)
  - Fix: Approve overflow during session creation (#623)
  - Fix: NaN provider scores blocking session creation (#631)
  - Fix: BadgerDB boot corruption (#632)
  - Fix: Badger file cleanup on restart (#635)
  - Feat: End-to-end request_id tracing for debugging (#625)
  - Feat: Random request ID generation + improved logging (#628)
  - Upstream: https://github.com/MorpheusAIs/Morpheus-Lumerin-Node/releases/tag/v5.14.0

---

## [2026.3.9] - 2026-03-08

### Changed
- **Bagman upgraded to v2.0 Multi-Backend**
  - Full sync from `zscole/bagman-skill` upstream
  - NEW: macOS Keychain backend (zero setup, native)
  - NEW: Encrypted file backend via `age` (portable, git-friendly)
  - NEW: Environment variables backend (CI/CD, containers)
  - NEW: Auto-detect best available backend (no 1Password required)
  - NEW: Python examples — secret_manager, sanitizer, validator, session_keys, test_suite
  - NEW: Backend implementations — keychain, encrypted_file, env, onepassword, auto
  - NEW: Autonomous operation documentation
  - NEW: Delegation Framework integration tests (TypeScript)
  - NEW: BIP-39 wordlist for key validation
  - NEW: Pre-commit hook for secret leak prevention
  - Upstream: https://github.com/zscole/bagman-skill

---

## [2026.3.8] - 2026-03-08

### Changed
- **PromptGuard upgraded to v3.3.0**
  - Full sync from `seojoonkim/prompt-guard` with our external content detection PR
  - New package structure (`prompt_guard/` module with scripts/ backward compatibility)
  - SHIELD.md standard compliance (11 threat categories)
  - **External Content Detection** — identifies injection from GitHub issues, PRs, emails, Slack, Discord, social media
  - **Multi-language urgency patterns** — EN/KO/JA/ZH urgency + command detection
  - **Context-aware severity elevation** — external source + instruction = CRITICAL
  - ~130 new patterns for external content injection attacks
  - Upstream PR: https://github.com/seojoonkim/prompt-guard/pull/18

---

## [2026.3.6] - 2026-03-05

### Added
- **Guided Installer** (`scripts/install-with-deps.sh`)
  - One-line install: `curl -fsSL https://get.everclaw.xyz | bash`
  - Automatic dependency detection (curl, git, Node.js, npm, Homebrew, OpenClaw)
  - Platform-specific install commands (macOS, Ubuntu, Fedora, Arch)
  - `--check-only` flag to verify environment
  - `--auto-install` flag for unattended setup
  - `--skip-openclaw` flag for existing installations
  - Bootstrap key integration (free GLM-5 starter key)

- **Bootstrap Key System** (`scripts/bootstrap-everclaw.mjs`)
  - Device fingerprint generation (hostname + MAC + platform)
  - Key request from `keys.everclaw.xyz`
  - Key storage in `~/.openclaw/.bootstrap-key`
  - GLM-5 configuration via mor-gateway provider
  - Commands: `--setup`, `--status`, `--test`, `--revoke`
  - Graduation flow: remove bootstrap key when user provides own key

- **GitHub Actions CI**
  - Automated testing on Ubuntu and macOS
  - Dependency check tests
  - Bootstrap script tests
  - Shell syntax validation

- **CloudFlare Redirect**
  - `get.everclaw.xyz` points to installer script

### Changed
- **SKILL.md**: Added Prerequisites section with dependency table
- **README.md**: Added one-line install, prerequisites table, installer options
- **bootstrap-gateway.mjs**: Removes `.bootstrap-key` when user sets own key

### Fixed
- Gateway PR #10: Auto-detect OpenClaw launchd service label (gateway vs node)

---

## [2026.2.26] - 2026-02-26

### Added
- PII Guard v2 with enhanced scanning
- ClawHub dependencies wired across 19 primary flavors
- Docker clean integration
- Three-Shifts v2 cyclic execution engine

### Changed
- Date-based versioning (YYYY.M.D format)

### Fixed
- PII purge across workspace + 34 repos + git history

---

## [2026.2.23] - 2026-02-23

### Added
- Multi-key auth rotation v2
- Gateway Guardian v5 with direct curl inference probes
- Smart session archiver

---

For earlier versions, see git history.