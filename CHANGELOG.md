# EverClaw Changelog

All notable changes to EverClaw are documented here.

## [2026.3.14] - 2026-03-12

### Fixed
- **BUG-001: bash arithmetic crash** — chat.sh `declare -A` with hyphenated keys + `set -u` caused parsing crash; replaced with case statement
- **BUG-002: balance.sh jq parsing** — SESSION_COUNT newline parsing fixed with `-r` flag
- **BUG-003: bootstrap undefined values** — Added model fallback chain in testKey() + defensive displays for status/test
- **BUG-004: session.sh missing commands** — Added `status` command for balance + session summary
- **BUG-005: update check garbled** — Completely rewritten openclaw-update-check.sh from scratch (was single-line mangled JSON)
- **BUG-006: pii-scan phone detection** — Added 4 builtin phone regex patterns (E.164, intl, US formats)
- **BUG-007: boot templates empty** — Added 7 `__PLACEHOLDER__` tokens across 4 templates
- **BUG-008: website stale version** — Updated hero from v0.9.8.2 to v2026.3.14, rewrote What's New section
- **BUG-009: footer link broken** — Release link updated to v2026.3.14
- **BUG-010: website version scheme** — Migrated What's New history to 2026.x.x date-based scheme
- **BUG-011: gateway-guardian drift** — Synced SmartAgent copy to v5 (was 43 lines behind)
- **BUG-012: key-api server truncated** — Restored from minified root file, beautified
- **BUG-013: Dockerfile stale versions** — Updated OPENCLAW=v2026.3.2, EVERCLAW=2026.3.14
- **BUG-014: GLM-5 gateway fallback** — Added gateway routing for mor-gateway/glm-5 model IDs
- **BUG-015: default model mismatch** — Set glm-5 as default in morpheus-proxy.mjs

### Changed
- **Website refreshed** — Hero, What's New, and footer all updated for v2026.3.14
- **14 files changed** — +165/-60 lines across scripts, templates, website, Dockerfile

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