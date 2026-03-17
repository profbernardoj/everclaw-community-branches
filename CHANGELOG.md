# EverClaw Changelog

All notable changes to EverClaw are documented here.

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