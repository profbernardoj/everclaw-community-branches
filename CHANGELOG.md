# EverClaw Changelog

All notable changes to EverClaw are documented here.

## [2026.11.13.2110] - 2026-11-13 — OpenClaw pin v2026.7.1-2 → v2026.10.9 (security-dep upgrade + fleet blockers)

### Changed — OpenClaw Pin v2026.7.1-2 → v2026.10.9

- **Dockerfile:** OpenClaw build target updated to `v2026.10.9`
- **docker-compose.yml:** Image tag, OPENCLAW_VERSION arg, and EVERCLAW_VERSION updated
- **Node base upgraded:** Builder, auth-proxy, and production stages from `node:22.23.4` to `node:24.22.2` (v2026.10.9 engine floor ≥24.22.1)
- **Bun pinned to v1.4.2:** Latest release assets (v1.4.3/v1.4.4) return 504 from GitHub CDN

### Upstream Highlights (OpenClaw v2026.7.1-2 → v2026.10.9)

#### New Features & Changes
- **Security:** patched fast-uri (MCP schema validation), Zod collection overflow, nodemailer 10.1.4 IMAP sender-spoofing gate, MSAL Node 7.1.1
- **Credential hygiene:** live credentials kept out of MCP CLI inspection; Google OAuth secrets masked in logs
- **SQLite tokenizer recovery:** memory DB integrity after failed updates
- **Large-transcript migration:** handles oversized session files
- **Disk-full recovery:** graceful handling on full volumes

#### Fixes
- **Retired config field:** `gateway.controlUi.allowInsecureAuth` removed upstream — removed from all templates, entrypoint, and setup.mjs
- **SSO /auth/handoff:** verified end-to-end on staging canary (no v2026.6.8 regression class)
- **Control-UI 503:** fixed by exporting `OPENCLAUD_BUILD_TIMESTAMP` across build:docker + ui:build (shared identity stamps)
- **Device pairing wall:** `gateway.auth.trustedProxy.deviceAutoApprove` enabled for IOC users (no shell access)
- **Exec-approvals migration:** `doctor --fix` runs pre-gateway to import legacy exec-approvals.json to SQLite
- **Build hardening:** timeout-minutes 90, runner disk free + 8GB swapfile for cold CI builds

### Upstream Reference
https://github.com/openclaw/openclaw/releases/tag/v2026.10.9

## [2026.10.27.1656] - 2026-10-27 — Fix: auth-proxy login modal follows Privy dashboard methods (login parity)

### Fixed — hardcoded loginMethods drifted from the Privy dashboards (2026-10-27)

- **packages/core/auth-proxy/login-app.jsx:** removed the hardcoded
  `loginMethods: ['wallet', 'google', 'email', 'apple']` from the PrivyProvider
  config. The agent login modal now renders the methods enabled on each
  vertical's Privy app (server-driven) — the same mechanism the main sites use.
- **Bug class fixed:** config drift between the image and the Privy dashboards.
  The Apple button rendered but `apple_oauth` is disabled on both apps (dead
  button), and X/GitHub/Discord were never offered at the agent URL — a user
  who signed up with those methods on the main site could not sign in to
  their agent.
- **test-proxy.mjs:** three drift guards — served bundle has no
  `loginMethods:[` array literal, SDK server-driven fallback branch present,
  login-app.jsx source has no hardcoded list. Suite 87/87 (baseline 84/84).
- Companion: InstallHermes Privy app flags enabled server-side (google,
  twitter, discord, github, passkey); InstallHermes Lovable frontend list
  update tracked in the SOP-001 task record.

## [2026.10.23.0148] - 2026-10-23 — Fix: strip unsupported web_search providers at boot (SEC-WAVE fleet incident)

### Fixed — Gateway boot crash on configs referencing unbundled web_search providers (David GO 19:39 CDT)

- **docker-entrypoint.sh:** added a boot-time sanitizer that strips `tools.web.search.provider`
  unless the provider is bundled in the image (searxng / kimi / firecrawl — the only providers
  OpenClaw v2026.7.1-2 accepts without an external plugin, verified via `openclaw doctor --lint`).
- **Root cause:** OpenClaw hard-fails config validation when the provider's plugin is not
  available (e.g. `parallel-free` from the external `@openclaw/parallel-plugin`, or
  tavily/exa/perplexity). This crash-looped 2 fleet leases on image 2026.10.21.2345 and
  reproduced on every restore/upgrade carrying such configs. The gateway now boots with web
  search unconfigured (the image default) instead of exiting.
- **Hardening:** extracted shared `repair_json_config()` for atomic config repair; sanitizer
  is jq 1.6-safe (explicit-root form) and covered by a 17-case regression test that pins the
  allowlist against the live entrypoint.
- **Tests:** `tests/entrypoint-websearch-sanitizer.test.mjs` — 17 tests, all passing.

## [2026.10.21.2345] - 2026-10-21 — Fix: ENV EVERCLAW_VERSION literal (runtime banner)

### Fixed — Dockerfile ARG→ENV propagation (canary E2E finding, David GO 23:42 CDT)

- **Dockerfile:331:** `ENV EVERCLAW_VERSION=2026.9.10.2207` was a hardcoded literal instead of
  `${EVERCLAW_VERSION}` — the CI `--build-arg EVERCLAW_VERSION=…` never propagated to runtime.
  Effect: every image since the 2026.9.10.2207 release printed "EverClaw v2026.9.10.2207" in the
  boot banner regardless of the actual image version (2026.10.21.1450 and 2026.10.21.1940 included).
  Image LABEL `org.opencontainers.image.version` was always correct — only the runtime ENV was stale.
- **Blast radius (verified):** exactly one consumer — docker-entrypoint.sh:33 banner echo.
  No functional usage of the variable anywhere in the runtime tree.
- **Fix:** `ENV EVERCLAW_VERSION=${EVERCLAW_VERSION}` (+ ARG default refreshed to this version).
  Found by the Stage 3 single-instance canary E2E; missed by both model audits (outside the diff
  context — lesson recorded).
- Base image pin unchanged from 2026.10.21.1940: node:22.23.4-bookworm(-slim). No other changes.

## [2026.10.21.1940] - 2026-10-21 — Security: Node.js 22.23.4 base pin (Oct 21 patch wave)

### Security — Node.js runtime patch (David GO 2026-10-21 19:27 CDT)

- **Dockerfile:** pinned `node:22-bookworm` → `node:22.23.4-bookworm` (openclaw-builder)
  and `node:22-bookworm-slim` → `node:22.23.4-bookworm-slim` (auth-proxy-builder,
  production). Node.js security release 22.23.4 (2026-10-21) fixes 10 CVEs including
  the Brotli decoder out-of-bounds write RCE (CVE-2026-111497), DNS NUL truncation
  (CVE-2026-105482), and TLS certificate hostname bypasses (CVE-2026-105483,
  CVE-2026-106069). Docker Hub pushed the patched `node:22` images at 14:38 UTC today;
  the floating tag already resolved to the patched digest (sha256:82693da9…) — the
  explicit pin makes the security provenance deterministic for this and future builds.
- **npm audit fix:** ws 8.x HIGH (uninitialized memory disclosure GHSA-58qx-3vcg-4xpx,
  memory-exhaustion DoS GHSA-96hv-2xvq-fx4p) via viem → ws 8.21.0, viem 2.57.8, ox
  0.14.56. viem is a devDependency, so shipped images were never exposed; build
  tooling is patched regardless. Lockfile version field reconciled (was stale at
  2026.6.1-2.1829).
- No application-code changes — runtime code is identical to v2026.10.21.1450
  (Grok 4.20 ×2 + Claude Opus 4.8 ×3 audited today, suite 84/84, PII scan clean).

## [Unreleased] - 2026-10-21

### Added — OpenClaw mascot logo for the auth-proxy login page (img: brand-icon mode)

**InstallOpenClaw.xyz rebrand (David GO 2026-10-21):** the Privy/Fred/Manifest login page
(served by the auth-proxy inside each container — not the Lovable frontend) now brands
with real artwork instead of the lobster emoji default.

- `assets/logo.png` (auth-proxy): legacy 500×110 "InstallOpenClaw" wordmark banner →
  new OpenClaw mascot (480×480 transparent PNG, 64,009 bytes). Served at the existing
  public `/auth/logo.png` route; the Privy login modal logo (`login-app.jsx`) picks it
  up too.
- `server.mjs`: `BRAND_ICON="img:<path>"` convention — renders an `<img>` instead of
  an escaped text glyph. Detection is trim + case-insensitive; the src must be a strict
  local image-asset path (leading `/`, not protocol-relative `//` or backslash `/\`,
  URL path+query charset, path portion ending `.png`/`.svg`/`.webp`) — external URLs,
  `javascript:`/`data:` URIs, and non-image same-origin GETs all fall back to the
  escaped-text path. Plain text values (emoji `🦞`, Hermes `☤`) keep the old path
  unchanged. All five placeholder replacements now use function form (`$&`/`$'`/"$`"
  sequences in env-set brand values can no longer splice surrounding HTML), and the
  two Privy-ID placeholders are JS-literal encoded (`JSON.stringify` + `<` → `\u003c`)
  — env values can never break out of the `<script>` block that feeds the bundled
  login app.
- `login.html`: `<title>` now follows `__BRAND_NAME__` (footer stays "Powered by OpenClaw
  & Privy" as tech attribution, Hermes pattern). `.logo-icon .logo-img` CSS — 64px white
  app-icon chip, radius 16, object-fit contain.
- `login-app.jsx`: Privy modal logo now `/auth/logo.png?v=20261021` — one-time cache-bust
  so returning users (who pinned the old wordmark under the previous `immutable` 7-day
  header) see the mascot immediately; the logo route drops `immutable` and serves
  `Cache-Control: public, max-age=86400` so future rebrands need no bust.
- `test-proxy.mjs`: new test 18 — img-mode renders the `<img>` tag (src/class/alt),
  title interpolation, no emoji glyph, `/auth/logo.png` serves the exact 64,009-byte
  mascot with PNG magic bytes and the 1-day cache header; hostile-src guards
  (`img:javascript:`, `img:https:`, `img:data:`, `img://`, `img:/\`, bare `img:`,
  `img:/../secret`, `img:*.js`) fall back to escaped text; whitespace-trim and
  case-insensitive and query-string positives; `$`-bearing brand renders literally
  (no splice duplication); hostile `PRIVY_APP_ID` values render as inert JS literals
  (exactly two script blocks, no `</script><script>` breakout). Fixed 7 stale
  pre-rebrand assertions ('EverClaw'/'Sign in' → 'OpenClaw'/'Sign In'; identical 7
  failed on baseline). Suite: 84/84.

**Audit trail:** Grok 4.20 (xAI API): R1 Excellent (C=2 S=1 Y=2) → fixes → R2
Excellent/SHIP (C=0 S=0 Y=2). Claude Opus 4.8 cross-model (Venice): R1 Good — found
protocol-relative/backslash guard bypass + `$`-replacement injection + immutable-cache
staleness (all fixed); R2 Good — found Privy-ID raw injection into `<script>` context
(fixed with JS-literal encoding + template quote removal) + transition cache-bust
(fixed with `?v=20261021` + no-immutable header); R3 Excellent — VERDICT: SHIP (all
prior-round blockers resolved, fix code sound, remaining items non-blocking backlog). See
memory/projects/everclaw/logo-rebrand-2026-10-21/audit/. Stage 6 PII scan: 0 findings.
CSP header deferred (needs inline-script nonce + Privy domain enumeration + E2E; both
blocking injection vectors closed) — backlogged.

**Deploy order (matters):** new GHCR image tag lands first (Supabase `OPENCLAW_IMAGE`
bump), then `BRAND_ICON=img:/auth/logo.png` env flip, then buffer rebuild + container
upgrades — old image + new env would render the legacy wordmark.

## [Unreleased] - 2026-09-10

### Fixed — migrate-import tar type-field parsing + SOP-001 Stage 5 hardening

**Implementation (re-audited, Claude Opus 4.8: Excellent / 0 blocking):**

- `TAR_TVF_TYPE` regex now tolerates one optional trailing `+` (GNU ACL) or `.` (SELinux) marker after the 9 permission chars in `tar -tvf` listings. GNU tar appends these on systems with ACLs/SELinux; the old regex aborted the whole listing (fail-closed, but broke legitimate GNU-tar exports). The suffix cannot enter the type or perms captures; the field delimiter remains mandatory.

**Test coverage (Grok 4.5 review R1 Flawed → R3 PASS / 0 blocking; suite 33 → 39 tests):**

- Real hostile fixtures replace synthetic checks: workspace tar with symlink member (rejected, nothing extracted); outer bundle with an **allowlisted member name but hostile type** (symlink named `RUNBOOK.md` → `unsafe bundle: member type 'l' not allowed`); hostile outer member names rejected.
- `unpackBundle`: happy path, out-of-band checksum mismatch, wrong passphrase (generic error, no oracle), missing `checksums` object, **phantom checksum entry** (checksums key for a file absent from the tar → `missing` branch), tampered payload (decrypt → modify → re-encrypt), unsupported schema version.
- `importMigrateBundle` end-to-end: dry-run writes nothing; happy path restores config/workspaces/skills/runbook; **passphrase gate** (missing or <16 chars refused before any work); **preflight hard block** (existing config + no force → refused, file untouched); **keychain seam** (`keychain.json.enc` → decrypt → `security add-generic-password` with decrypted value + source account, verified via `security` shim); **cron staging** (`pending-cron-import.json` written — primary keeps enablement, worker disables all, L4/L5).
- Unit coverage added for `preflight`, `restoreConfig`, `restoreKeychain`, `reenableSkills`, `stageCronImport`.
- Regression gate: baseline == post-change (337/317/20, zero new failures). Stage 6 PII: 0 findings.

## [Unreleased] - 2026-09-08

### Fixed — Stale IDENTITY.md upgrade: EverClaw → resolved agent name (BACK-IOC-012 follow-up)

Warm buffers and containers provisioned from older images kept showing "EverClaw" in the Control UI chat welcome heading even after the first BACK-IOC-012 fix: their persistent volumes already contain an `IDENTITY.md` scaffolded by the old template (whose default was `EverClaw`), and the entrypoint only fixes the default for *fresh* scaffolds. The chat welcome heading reads the agent identity name parsed from this file.

- Entrypoint now runs an idempotent startup upgrade: any `Name:` line whose value is exactly `EverClaw` is rewritten to the resolved `TPL_AGENT_NAME` (same `AGENT_NAME` → `EVERCLAW_AGENT_NAME` → `OpenClaw` priority chain as fresh scaffolding, via the pre-escaped `SED_AGENT_NAME`).
- Line-anchored exact-value match (`EverClaw[[:space:]]*$`): deliberate custom names like `EverClawBot` or `MyEverClaw` are never mangled. Covers all label forms the IDENTITY.md parser accepts (`**Name:**`, `**Name**:`, `Name:`, `name:`), optional `-`/`*`/`+` bullets, any spacing, and CRLF files (trailing CR preserved, not stripped).
- Atomic write: upgraded copy goes to a temp file, then `mv` over the original; a mid-write failure under `set -e` leaves the original intact (no zero-byte truncation). `mv` failure is on the failure path (temp cleaned, warning logged).
- Skipped when the resolved name is itself `EverClaw` (whitespace-tolerant guard) so the rewrite can never re-log on every start.
- Detection and rewrite EREs are structurally identical (no match-without-rewrite divergence); both pinned to `LC_ALL=C`.

## [Unreleased] - 2026-09-07

### Fixed — Default agent name "OpenClaw" + AGENT_NAME env wiring (BACK-IOC-012)

Deployed InstallOpenClaw containers showed "EverClaw" as the agent heading in the chat UI. The entrypoint only read `EVERCLAW_AGENT_NAME` (defaulting to "EverClaw") while provisioning functions set `AGENT_NAME` — so custom agent names never applied and the image-brand default leaked into the UI.

- Entrypoint now resolves: `AGENT_NAME` (provisioner) → `EVERCLAW_AGENT_NAME` (legacy alias) → default `OpenClaw`.
- Fail-closed sanitization mirrors `sanitize-agent-name.ts` (ASCII allowlist `^[a-zA-Z0-9 _-]+$` under `LC_ALL=C`, newline/CR strip, 50-char cap, whitespace-only rejection).
- Sed replacement metacharacters (`&`, `\`) escaped before `__AGENT_NAME__` substitution into boot templates.
- Dockerfile env docs updated (`AGENT_NAME` primary, `EVERCLAW_AGENT_NAME` legacy alias).

## [Unreleased] - 2026-09-04

### Added — Download Agent v2 (Egress-Proof Pull Path): Container → Edge Function → signed URL

Replaces the push-path (container → Supabase) with a pull-path that works regardless of container egress policy. The Supabase Edge Functions gateway hangs on request bodies >= ~1 MB, blocking the old push path. The pull path reverses the direction: Edge Function fetches the bundle from the container via a single-use token, then uploads to Storage.

**New auth-proxy routes:**

- **`GET /internal/diag` (binding secret):** Bounded egress diagnostics — 8 probes (DNS, TCP, HTTP GET/POST, large POST, Storage PUT, control host, export size probe). Results cached 5 min. Read-only, no side effects.
- **`POST /internal/export/start` (binding secret):** Runs `migrate-export.mjs --agentic` (no upload). Returns `{ bundleToken, sizeBytes, passphrase, expiresAt }`. Single-use token (randomUUID, 24-byte hex), 10-min TTL (env-configable `BUNDLE_TOKEN_TTL_MS`), stored in-memory Map. 409 on concurrent export (in-flight guard). 120s timeout + `SIGKILL` + tree-kill on process group + 5s safety net (`unref`'d). Passphrase never written to disk/logs.
- **`GET /internal/export/bundle?token=` (binding secret):** Streams encrypted bundle (`createReadStream`, `Content-Length`, `octet-stream`). Single-use token consumed before streaming. 410 on expiry, 404 on bogus/replayed token. File deleted on ALL paths (success, error, client disconnect, timeout). Proxy-owned path only — child-reported `outputPath` must match or 500.

**Edge Function changes (InstallOpenClaw):**

- **`agent-export` (modified):** Pull orchestration — calls `/internal/export/start` → streams bundle from `/internal/export/bundle` → uploads to Storage → creates 1h signed URL → returns `{ download_url, passphrase, expires_at }`. Retry budget: 3 attempts within the Edge Function timeout.
- **`agent-export-upload` (unchanged):** 100 MB cap, `.tar.gz.enc` suffix + min-1KB validation, private `agent-exports` bucket, 1h signed URL.
- **`test-agent-export-cap.test.ts` (new):** 6 Deno tests for the 100 MB bundle cap (over-cap 413, at-cap, under-cap, <1KB 400, wrong-suffix 400, constant verified).

**auth-proxy hardening (Grok R6 + Claude R3 audited):**

- `egress-probes.mjs` (new): 8 bounded probes with deps injection for hermetic unit tests. Fixed targets (no SSRF). DNS, TCP, HTTP GET/POST/PUT, export size probe.
- `migrate-export.mjs`: `--diag-size-probe` subcommand, `--agentic` JSON contract, upload retry with backoff, phase-trace instrumentation.
- `staging-verify.sh`: Test 18 egress probe (`/internal/diag` artifact), 16/16 PASS.
- Process-group kill (`killExportTree`): `detached: true` + `process.kill(-pid, 'SIGKILL')` for tar grandchild. In-callback tree-kill (not external timer). All 12 `unlink` sites use `.catch` (`fs/promises` ignores callbacks).
- `BUNDLE_TOKEN_TTL_MS` env-configable (default 10 min). Background expiry sweep every 60s + startup stale-bundle sweep.

**Tests (25 automated + 6 Deno):**

- `test-export-v2.mjs`: 25 tests — auth (401, timingSafeEqual 4 cases), token lifecycle (200, 404 replay, 404 bogus, 400 missing, 409 concurrent, 410 TTL expiry), streaming (exact bytes, decrypt round-trip), cleanup (abort-mid-stream, spawn-failure guard, timeout ceiling), egress-probes (5 unit tests with deps injection, real-network smoke), size equality (probe == start == actual bytes).
- `test-agent-export-cap.test.ts`: 6 Deno tests for cap enforcement.

**Audit trail:**

- Grok 4.20 code audit: R6 Excellent (0 blocking). 20 commits.
- Claude Opus 4.8 cross-model: R3 Excellent (0 Correctness / 0 Security). 10 fixes (C1-C10).
- Grok 4.20 coverage review: R3 Excellent (0 blocking, 0 major, 2 minor). 7 findings closed across R1-R3.
- PII Guard V2: 0 findings across 13 files.

### Added — Download Agent (Phase 2 Direct, superseded by v2)

- **auth-proxy `/internal/export` route (new):** Trigger agent export from the Lovable Dashboard without an LLM in the loop. Binding-secret auth (timing-safe `timingSafeEqual` + length pre-check), `execFile` child (no shell) running `migrate-export.mjs --agentic --upload --callback-url`, 120s timeout + `SIGKILL` + independent +5s safety net (`unref`'d), randomized `/tmp` output path, `unlink` on every path (including safety net), 10 MB stdout `maxBuffer`, stderr swallowed unless `AGENT_EXPORT_DEBUG=1`, fail-closed guards for missing `expires_at` / missing `passphrase`.
- **`agent-export` Edge Function (new, InstallOpenClaw):** Privy JWT verification, scoped to the caller's single active deployment; calls container `/internal/export` with `x-binding-secret`; strictly validates the returned download URL (Supabase hostname + per-user path prefix + token); returns `{ download_url, passphrase, expires_at }` to the Dashboard. Passphrase is NEVER persisted.
- **`agent-export-upload` Edge Function (new):** Container upload auth via `deployments.binding_secret` DB lookup (UNIQUE constraint); 100 MB cap, `.tar.gz.enc` suffix + min-1KB validation; private `agent-exports` bucket; 1-hour signed URL (`SIGNED_URL_TTL_SECONDS = 3600` — single canonical TTL).
- **`20260902_agent_exports.sql` migration (new):** private storage bucket, service_role-only policy, `binding_secret` partial index + UNIQUE constraint (duplicate-resolution guarded by constraint-exists check so re-runs are no-ops).
- **`migrate-export.mjs`:** `--agentic` non-interactive JSON contract + `--upload` FormData/Blob upload (Node 22 globals with `undici` fallback); `OPENCLAW_BINDING_SECRET` from env only (never argv); bundle kept on disk unless upload actually succeeded.
- **docker-entrypoint.sh:** exports `AGENT_EXPORT_UPLOAD_URL` (defaults to production Supabase endpoint) for the auth-proxy when the export route is used.
- **New test:** `supabase/scripts/test-download-url.mjs` (8 assertions — DID `did:privy:` colon path-prefix lock, IDOR, traversal, token/host checks).
- **Audit:** Grok 4.20 R7 Excellent + Claude Opus 4.8 C3 Excellent (0 Correctness / 0 Security / 0 Style). PII Guard clean.

## [2026.8.20.0917] - 2026-08-20

### Changed — Docker bind-mount fixes + Tool Calling Rule promotion

- Fix: `mkdir workspace` before template scaffold (empty bind-mount crash).
- Fix: ship boot templates + skill OUTSIDE the persistent volume (Barney bind-mount shadow).
- Fix: ship templates/boot into the image so entrypoint scaffolds AGENTS/SOUL.
- Add: Tool Calling Rule to AGENTS + SOUL boot templates (buffer pool instances).
- OpenClaw pinned at v2026.7.1-2 (unchanged). Docker base image Node 22 (bookworm).
- Promoted from staging (production E2E verified) to main → `:latest`.

## [2026.8.12.2040] - 2026-08-12

### Changed — OpenClaw Pin v2026.5.27 → v2026.7.1-2

- **Dockerfile:** OpenClaw build target updated to `v2026.7.1-2`; replaced stale SSO blocker pin comment with a promotion note (SSO `/auth/handoff` verified end-to-end on the staging image 2026-08-12). `EVERCLAW_VERSION` default aligned to `2026.8.12.2040`.
- **docker-compose.yml:** Image tag and `OPENCLAW_VERSION`/`EVERCLAW_VERSION` build args updated.
- **package.json:** Version bump to `2026.8.12.2040`.
- **VERSION:** Updated to `v2026.8.12.2040`.
- **SKILL.md (root):** Version frontmatter, section headers, diagnostics JSON, and changelog updated.
- **packages/core/version.json:** Version/buildDate updated.
- **CHANGELOG.md:** New entry.

### Upstream Highlights (OpenClaw v2026.7.1-2)

#### Fixes
- **npm plugin updates:** Accept singleton-array metadata from newer npm clients so tracked official plugins can install and update to correction releases. ([#108336](https://github.com/openclaw/openclaw/pull/108336))

(Reference: https://github.com/openclaw/openclaw/releases/tag/v2026.7.1-2)

---

## [Unreleased] - 2026-07-26

### Added — KAT-Coder RL Reward Patterns library (OSSAI-016)

- **scripts/lib/rewards.mjs (new):** Deterministic reward-signal reference library from the
  Kwaipilot KAT-Coder-V2.5-Dev RL post-mortem (69.4% SWE-bench Verified). Implements the four
  penalty signals + hierarchical credit that prevented agentic collapse under binary rewards:
  `parallelToolCallPenalty` (leading indicator, highest default weight 0.70), `failedToolCallPenalty`,
  `emptyToolBlockPenalty`, `repetitionPenalty`, `hierarchicalCredit`, and a `scoreTrajectory` composer
  that folds them into a single reward in [-1,1] with an inspectable per-component breakdown.
  Pure functions, zero runtime deps, additive/opt-in — for OpenClaw agent-behavior analysis / future
  agentic RL. No existing behavior changed.
- **tests/rewards.mjs (new):** 29 unit tests, all passing (NaN/negative-input hardening, weight
  overrides, reward-inversion guard, hierarchical-credit bound).

### Added — Manifest Retention Partitioning

- **docker-compose.yml:** Added `morpheus-openclaw` label to the `everclaw` service for Manifest platform retention partitioning. Each customer gets their own guaranteed restore quota for soft-deleted leases (5 most-recent closed leases per customer). Defaults to a per-installation hostname-derived ID (`${HOSTNAME:-everclaw}`) so no config is required and no breakage occurs on existing deployments; override `MORPHEUS_OPENCLAW_LABEL` with a stable per-customer ID (A-Z a-z 0-9 . _ -, 1-64 chars) for explicit control.

### Fixed

- **docker-compose.yml:** Fixed invalid service name `everclaw:2026.7.11.0248` → `everclaw` (colon is invalid in YAML/docker-compose service names, introduced in v2026.7.11.0248).

## [Unreleased] - 2026-07-17

### Added — Full Container Capability Upgrade

- **Dockerfile:** Merged all packages from `Dockerfile.optimized` into the production Dockerfile. InstallOpenClaw.xyz containers now ship with a complete toolset:
  - **python3 + pip** — Python execution for agents (allowlisted in security tier)
  - **zip + unzip** — Archive operations (allowlisted in security tier)
  - **ffmpeg** — Audio/video processing (voice notes, video frames skill)
  - **gnupg** — GPG key management (required for Adoptium Java repo)
  - **Java 21 (Temurin JRE)** — Runtime for signal-cli
  - **signal-cli v0.14.5** — Signal messaging (SHA256 checksum verified)
  - **GitHub CLI (gh)** — Git platform operations (allowlisted in security tier)
  - **Brave Browser** — Headless browser automation (OpenClaw browser tool)
  - **openai-whisper** — Speech-to-text (CPU-only torch, model downloads on demand)
- **scripts/docker-entrypoint.sh:** Default security tier changed from `recommended` to `low`. All 54 exec-allowlisted binaries (ls, cat, grep, node, python3, git, curl, etc.) now run without approval prompts. Money operations remain gated at the application layer (everclaw-wallet.mjs) regardless of tier.

### Changed

- **Dockerfile:** `EVERCLAW_SECURITY_TIER` default updated from `recommended` to `low` with warning comments.
- **scripts/docker-entrypoint.sh:** `SECURITY_TIER` default updated from `recommended` to `low` with explanatory comments.

## [2026.7.11.0248] - 2026-07-11

### Changed — GLM-5.2 Default + Bootstrap Reset Hardening

- **scripts/docker-entrypoint.sh:** Updated fallback default model from `glm-5.1` to `glm-5.2`. This aligns the Docker image default with the Free tier configuration in `provision-buffer` (`EVERCLAW_DEFAULT_MODEL=glm-5.2`). The env var override still takes precedence; this only affects containers without the env var set.
- **scripts/docker-entrypoint.sh:** Hardened bootstrap session reset from a one-shot `sleep 20` to a polling loop (3 iterations × 20s = 60s). Fixes race condition where Morpheus P2P inference failures that arrive after the 20s window left "assistant turn failed" errors visible to users.
  - Added `OPENCLAW_OWNER_PRIVY_ID` guard: only runs on unclaimed buffer containers (`buffer-unassigned`), preventing accidental session wipes during Manifest node migrations on claimed containers.
  - Added `command -v` guards for `jq` and `node` with diagnostic output instead of silent failure.
  - Fixed JSON injection risk: session keys now passed via `jq -nc --arg` instead of string interpolation.
  - Added `|| true` pipeline guard for `set -e` compatibility.

## [2026.6.26.2131] - 2026-06-26

### Fixed — Reset Dashboard Session (not main)

- **scripts/docker-entrypoint.sh:** Fixed the bootstrap session reset to target the correct session key. The Control UI uses `agent:main:dashboard:<uuid>` session keys, not `agent:main:main`. The previous fix reset `main` which had no effect on the UI. Now the script lists all sessions, finds dashboard session keys, and resets each one.

## [2026.6.26.2008] - 2026-06-26

### Fixed — Simplified Bootstrap Session Reset

- **scripts/docker-entrypoint.sh:** Simplified the Bootstrap Session Reset from 73 lines of conditional query+grep+reset logic to a straightforward unconditional reset. The previous approach silently failed when the `sessions.get` query didn't find the error string (e.g., auth issues, wrong port, timeout), leaving the broken session visible to users. The new approach: wait 20s after gateway health, then unconditionally call `sessions.reset` with `reason:"new"`. Buffer pool containers sit warm for minutes before being claimed, so there is no user content to destroy. Removed the `sessions.get` query, grep conditional, named constants, and if/elif/else branching.

## [2026.6.26.0606] - 2026-06-26

### Fixed — Bootstrap Session Reset for InstallOpenClaw.xyz Cold Start

- **scripts/docker-entrypoint.sh:** Added Bootstrap Session Reset block. After the gateway becomes healthy, a background process waits 20s for the initial bootstrap agent turn to complete, queries `sessions.get` to check if the main session has the "assistant turn failed before producing content" error, and if detected, calls `sessions.reset` with `reason:"new"` to clear the failed session. This gives users a fresh, clean session when they first open the Control UI instead of seeing a broken error message. The reset is conditional — if the bootstrap succeeded or the user already started chatting, the reset is skipped. Handles both legacy token auth (port 18789) and Privy trusted-proxy mode (port 18790).

## [2026.6.23.1642] - 2026-06-23

### Added — GLM-5.2 for Free Tier

- **config/openclaw-default.json:** Added `glm-5.2` model to both `mor-gateway` and `morpheus-local` providers with `reasoning: false` and `streaming: true`. Free tier users can now select GLM-5.2 as an alternative to DeepSeek V4 Flash. Default model remains `deepseek-v4-flash` (set by `provision-buffer` `EVERCLAW_DEFAULT_MODEL` env var).
- **supabase/functions/cig-inference/index.ts:** Added `glm-5.2` (and all prefixed variants) to `RESERVE_ESTIMATES_USD` with $0.005 per-request reserve estimate (same tier as GLM-5.1).
- **supabase/migrations/20260623_add_glm52_free_tier.sql:** Updated `check_and_charge_usage()` free tier allowlist to include `glm-5.2` and all prefix variants (`morpheus/glm-5.2`, `mor-gateway/glm-5.2`, `morpheus-local/glm-5.2`). Added `insert_usage_log()` RPC function for idempotent usage log writes. Added `model_prices` entries for all four name variants.

### Fixed — "assistant turn failed" Regression

- **supabase/migrations/20260623_add_glm52_free_tier.sql:** Fixed critical parameter name typo in `check_and_charge_usage()` — `v_cost_usd` was used in 5 places instead of `p_cost_usd`, causing SQL error `column "v_cost_usd" does not exist` on ALL inference calls. The function body has been restored to the proven June 22 version with only the GLM-5.2 allowlist addition.
- **supabase/functions/cig-inference/index.ts:** Added `daily_limit_exceeded` to the error reason mapping (maps to 429 `daily_limit_or_credits_exhausted`). Previously only `insufficient_credits` was mapped, causing `daily_limit_exceeded` to fall through as a raw 403.

## [2026.6.18.2357] - 2026-06-18

### Bug Fixes — Revert OpenClaw Pin + CIG Model Prefix

- **Dockerfile:** Reverted `OPENCLAW_VERSION` from `v2026.6.8` → `v2026.5.27`. OpenClaw v2026.6.8 broke the SSO Session Bridge (auth-proxy trusted-proxy mode). Reverting restores SSO functionality. Update banner is suppressed via `update.checkOnStart=false` in openclaw-default.json (from v2026.6.18.2214).
- **supabase/functions/cig-inference/index.ts:** Strip provider prefix from model name before tier check (carried forward from v2026.6.18.2214). OpenClaw sends `mor-gateway/deepseek-v4-flash` but CIG expects bare `deepseek-v4-flash`. Uses `lastIndexOf("/")` with unconditional `reqBody.model = model` normalization.

## [2026.6.18.2214] - 2026-06-18

### Bug Fixes — Update Banner + CIG Model Prefix

- **Dockerfile:** Bumped `OPENCLAW_VERSION` from `v2026.5.27` → `v2026.6.8`. Resolves stale "Update available" banner on InstallOpenClaw.xyz containers.
- **config/openclaw-default.json:** Added `update.checkOnStart: false`. Suppresses the in-app "Update Now" button that fails with `checkout-failed` on Docker containers (containers are immutable images and cannot self-update via git checkout).
- **supabase/functions/cig-inference/index.ts:** Strip provider prefix from model name before tier check. OpenClaw sends `mor-gateway/deepseek-v4-flash` but CIG's free-tier allowlist and Morpheus API expect bare `deepseek-v4-flash`. Without stripping, the first check fails, triggers a downgrade retry, and the initial response shows "assistant turn failed before producing content". Fix uses `lastIndexOf("/")` with empty fallback to `"default"`.

## [2026.6.18.1803] - 2026-06-18

### SSO Session Bridge (Single Sign-In)

- **packages/core/auth-proxy/server.mjs:** Added `POST /auth/handoff` route for SSO session bridge. Accepts short-lived HS256 JWT via form-urlencoded POST body, verifies signature with dedicated `HANDOFF_SIGNING_SECRET`, validates FQDN match, calls `consume-handoff-token` Edge Function for DB-backed atomic single-use enforcement, verifies ownership via `verify-owner`, then sets session cookie and 302 redirects to `/`. Falls back to login page on any error. SSO auto-disables if `HANDOFF_SIGNING_SECRET` not set.
- **supabase/functions/generate-handoff-token/index.ts:** New Edge Function. Verifies Privy JWT, validates deployment ownership, cleans up expired tokens, dedup check with unique partial index handling, generates 90s TTL HS256 JWT with JTI, stores in `handoff_tokens` table.
- **supabase/functions/consume-handoff-token/index.ts:** New Edge Function. Atomic single-use consumption via `UPDATE WHERE consumed_at IS NULL AND expires_at > now()`. Returns 409 on already-consumed. Authenticated via `VERIFY_OWNER_SECRET`.
- **supabase/migrations/20260618_handoff_tokens.sql:** New table with `jti` PK, `privy_user_id`, `fqdn`, `consumed_at`, `expires_at`. Unique partial index on `(privy_user_id, fqdn) WHERE consumed_at IS NULL` prevents concurrent active tokens. RLS enabled.
- **supabase/functions/provision-buffer/index.ts:** Passes `HANDOFF_SIGNING_SECRET` and `CONSUME_HANDOFF_URL` env vars to container manifest.
- **supabase/functions/deploy-agent/index.ts:** Same env var passthrough for cold deploy path.

### Security

- Dedicated `HANDOFF_SIGNING_SECRET` for HS256 JWT signing (separate from `VERIFY_OWNER_SECRET`)
- 90-second TTL on handoff tokens (immediate handoff expected)
- Single-use enforcement: in-memory Map (fast path) + DB atomic consume (survives restarts)
- FQDN binding prevents token reuse across containers
- Defense-in-depth: `verify-owner` call on success path
- POST body delivery (not URL query param) prevents token leakage in browser history/referer

## [2026.6.16.2136] - 2026-06-16

### Added

- **Tiered Installer** (`scripts/install-tiered.sh`): New unified installer with three tiers:
  - **Minimal** (default): Core deps only — Node.js 24.x LTS, jq, git, curl, Morpheus proxy (~200MB)
  - **Standard** (`--standard`): + Ollama/Gemma 4 12B, Signal, ffmpeg (~8.6GB)
  - **Full** (`--full`): + Brave, Whisper, Gemma 4 26B, GitHub CLI, all channels (~19.6GB)
  - **Custom** (`--with X,Y,Z`): Pick specific components
  - Supports `--dry-run` to preview without installing and `--list` to show available components

- **Component Libraries** (`scripts/lib/`):
  - `install-core.sh` — Node.js, jq, git, curl with Homebrew/apt/dnf/pacman support
  - `install-ollama.sh` — Ollama engine + model downloads (Gemma 4 12B, Gemma 4 26B)
  - `install-signal.sh` — signal-cli with Java 21, version checking (≥0.14.3 required)
  - `install-media.sh` — ffmpeg, Whisper (mlx-whisper on Apple Silicon), yt-dlp
  - `install-browser.sh` — Brave Browser for web automation
  - `install-channels.sh` — Setup instructions for Telegram, Discord, Slack, Matrix
  - `install-dev.sh` — GitHub CLI for repository and issue management
  - `install-utils.sh` — Logging, platform detection, size estimation

- **Docker Optimized Image** (`everclaw-docker/Dockerfile.optimized`):
  - Multi-stage build for smaller image size (~900 MB total)
  - Node 20-slim base (avoids Node.js v25 SSE bugs)
  - Includes: signal-cli 0.14.5 + Java 21, GitHub CLI, Brave Browser, Whisper, ffmpeg
  - Pre-configured for containerized operation (bind 0.0.0.0, Morpheus provider)
  - Non-root user for security
  - Health check endpoint
  - No Ollama/local models (uses Morpheus P2P for inference)

- **Signal Troubleshooting Docs** (`docs/docs/operations/signal-troubleshooting.md`):
  - signal-cli ≥0.14.3 requirement documented
  - Node.js v25 SSE bug warning and workarounds
  - Common issues: inbound not working, NullPointerException, SSE drops
  - Verification commands and container mode alternative

### Security

- signal-cli Linux installer now uses jq for safe JSON parsing (with grep/sed fallback)
- Added file type validation before extracting downloaded archives
- Graceful process termination (SIGTERM before SIGKILL) in troubleshooting docs

### Fixed

- Pure bash `format_size()` implementation (no bc dependency)
- Component name trimming for `--with` flag (handles spaces)
- Proxy installation error handling with proper exit code capture

---

## [2026.5.28.1854] - 2026-05-28

### OpenClaw Pin Bump v2026.5.22 → v2026.5.27

- **packages/core/Dockerfile:** OpenClaw build target updated to `v2026.5.27`; `EVERCLAW_VERSION` default re-aligned with release version (was desynchronized at `2026.5.20.1645` since v2026.5.24.0400 release)
- **packages/core/docker-compose.yml:** Image tag, `OPENCLAW_VERSION` build arg, and `EVERCLAW_VERSION` updated
- **package.json:** Version bump to `2026.5.28.1854`
- **SKILL.md (root):** Version stamp and embedded diagnostics JSON updated
- **packages/core/SKILL.md:** Version stamp and embedded diagnostics JSON updated
- **CHANGELOG.md:** Added this entry with upstream highlights and security/new-feature/fix sections

> This is a pure pin-bump release — no EverClaw code logic changes.

### Upstream Highlights (OpenClaw v2026.5.22 → v2026.5.27)

#### Security
- **Content boundaries:** Group prompt text routed outside system prompts, repeated-dot hostnames normalized, side-effecting command wrappers blocked, unsafe Node runtime env overrides rejected
- **Access control:** No-auth Tailscale exposure rejected, node/device-role approvals require admin authority, QQBot fallback approval buttons honor slash-command auth
- **Channels:** Untrusted Microsoft Teams service URLs blocked, /allowlist configWrites origin policy enforced, Discord guild requester checks tightened

#### New Features
- **Embedding providers:** Core OpenAI-compatible embedding provider for local and hosted endpoints with config, doctor, and docs support
- **Pixverse:** Video generation provider with API region selection and external plugin packaging
- **DeepInfra:** Full credential-aware model catalog browsing during onboarding
- **ClawHub:** Plugin display metadata for cleaner catalog/package listing names
- **Plugin SDK:** Plugin approval action metadata exposed; memory-specific embedding registration deprecated (compat preserved)
- **Agents:** Heartbeat runtime template split out of docs assets with legacy repair

#### Fixes
- **Codex:** Runtime model resolution before generic routing, workspace memory routed through tools, shared app-server client resilience, native hook relay generation survival across restarts
- **Providers/models:** VLLM thinking params wired, Claude CLI OAuth overlays for PI auth profiles, bare direct Anthropic model ids, OpenAI gpt-5.5 resolution without cached catalog
- **Channels:** Telegram durable sendMessage delivery, iMessage duplicate suppression, Slack final reply preservation during late cleanup, Matrix mention-inert previews, Discord tool-warning artifact recovery, Google Chat thread DM fix
- **Gateway/performance:** Read-only session metadata borrowing, plugin metadata fingerprint caching, auto-enabled plugin config caching, browser token expiry after auth rotation
- **Memory:** QMD search JSON salvaged after nonzero exits
- **Install/CI:** npm globstar exclusion matching, shrinkwrap override pin merging, Docker runtime workspace template packaging and smoke testing

(Reference: https://github.com/openclaw/openclaw/releases/tag/v2026.5.27)

---

## [2026.5.24.0400] - 2026-05-24

### OpenClaw Pin Bump v2026.5.12 → v2026.5.22

- **packages/core/Dockerfile:** OpenClaw build target updated to `v2026.5.22`; version-prefix policy comment block moved to top of file (single source of truth for EverClaw vs OpenClaw prefix rules)
- **packages/core/docker-compose.yml:** Image tag, `OPENCLAW_VERSION` build arg, and `EVERCLAW_VERSION` updated with inline policy comments
- **SKILL.md (root):** Version stamp and embedded diagnostics JSON updated; added bidirectional description-sync YAML comment (also aligns version from stale `2026.5.15.1418` to current release)
- **packages/core/SKILL.md:** Version stamp and embedded diagnostics JSON updated; added bidirectional description-sync YAML comment; removed erroneous `v` prefix to comply with documented pinning policy
- **package.json:** Version bump to `2026.5.24.0400`

> This is a pure pin-bump release — no EverClaw code logic changes.

### Upstream Highlights (OpenClaw v2026.5.12 → v2026.5.22)

#### New Features
- **Meeting Notes plugin:** External source-only plugin with auto-start capture, manual transcript imports, CLI access, and Discord voice as first live source
- **Control UI chat search:** Search and "Load More" pagination in session picker for bounded initial loads
- **Plugin SDK poll sender:** Generic channel-message poll sender so channel plugins can expose poll delivery
- **Embedding providers contract:** General `embeddingProviders` capability contract and registration API for reusable embedding surfaces outside memory adapters
- **xAI/Grok:** OAuth auth profiles reused for web_search, Grok model aliases, and active-agent auth threaded through web search
- **Plugin SDK session helpers:** Row-level session workflow helpers deprecating `loadSessionStore` whole-store reads

#### Fixes
- **Models:** Pruned retired Groq, GitHub Copilot, OpenAI, xAI, and old Claude catalog entries; doctor migration upgrades existing configs
- **Gateway lifecycle:** Provider timeouts now persist failed session state instead of leaving sessions stuck; internal stream-error placeholders no longer replayed as model text
- **Sessions:** Write-lock max-hold policy enforced during acquisition so stale locks can be reclaimed
- **Telegram:** Local path/filePath and structured attachment media sent from sendMessage actions instead of text-only
- **Ollama:** Local embedding origins bypass managed proxy correctly
- **Directive tags:** Message and content-part object identity preserved when display stripping makes no changes
- **Gateway state dir:** Relative `OPENCLAW_STATE_DIR` overrides pinned to absolute path at startup

#### Performance
- **Model list pre-warm:** `/models` calls reduced from ~20s to ~5ms by pre-warming CLI discovery on startup, config reload, and install
- **Gateway startup:** Lazy-load startup-idle plugin work, core method handlers, and embedded ACPX runtime so health/ready signals no longer wait on unused handler trees
- **Plugin metadata snapshots:** Immutable snapshots reused across startup, config, model, channel, setup, and secret metadata readers
- **Process-stable channel catalog:** Avoid repeated bundled-channel boundary checks

#### Security and Packaging
- **Release packaging:** npm shrinkwrap + `engines.npm` lock + `node_modules` bundled in tarball for locked dependency graphs
- **npm tarball:** Documentation images and assets excluded, reducing published package size

(Reference: https://github.com/openclaw/openclaw/releases/tag/v2026.5.22)

## [2026.5.20.1645] - 2026-05-20

### Changed — Default Model Upgrade to GLM-5.1

- **Primary model** changed from GLM-5 to GLM-5.1 across all deployment modalities
- **Fallback chain** updated: GLM-5.1 → GLM-5 → Kimi K2.5 → GLM 4.7 Flash
- **Model config:** GLM-5.1 added to both `mor-gateway` and `morpheus-local` provider model lists
- **Streaming config:** GLM-5.1 streaming entries added to all templates
- **Documentation:** Updated comments and descriptions to reference GLM-5.1 as default

### Files Modified

- `packages/core/config/openclaw-default.json` — Docker default config
- `packages/core/scripts/docker-entrypoint.sh` — EVERCLAW_DEFAULT_MODEL env var
- `packages/core/templates/openclaw-config-gateway-only.json` — Gateway-only template
- `packages/core/templates/openclaw-config-linux.json` — Linux install template
- `packages/core/templates/openclaw-config-mac.json` — macOS install template

## [2026.5.18] - 2026-05-18

### Fixed — Monorepo URL Migration

- **28 URL references** updated from `EverClaw/EverClaw` to `profbernardoj/morpheus-skill` (canonical repo) across 12 files
- **4 path corrections** in root `SKILL.md`: `main/scripts/` → `main/packages/core/scripts/` (old path returned 404)
- **Install one-liner** now resolves correctly: `curl -fsSL https://get.everclaw.xyz | bash`
- **CI:** `test-installer.yml` paths already correct (uses `packages/core/scripts/`)
- **Cloudflare redirect** at `get.everclaw.xyz` updated to point to canonical repo (separate change)
- **New doc:** `packages/core/docs/docs/operations/URL-MIGRATION.md` — canonical URL patterns & migration record

### Files Modified

- `SKILL.md` (root) — 7 fixes (repo + path + URLs)
- `packages/core/SKILL.md` — 6 fixes
- `packages/core/CLAWHUB_WARNING.md` — 2 fixes
- `packages/core/scripts/install-everclaw.sh` — 3 fixes (comment, REPO_URL, API URL)
- `packages/core/scripts/install-with-deps.sh` — 1 fix (git clone URL)
- `packages/core/scripts/everclaw-deps.mjs` — 1 fix (dependency metadata)
- `packages/core/docs/docs/getting-started/installation.md` — 1 fix
- `packages/core/docs/docs/index.md` — 2 fixes
- `packages/core/docs/docs/scripts/reference.md` — 1 fix
- `packages/core/docs/docs/docker-flavors.md` — 1 fix
- `packages/core/docs/docs/operations/troubleshooting.md` — 1 fix
- `flavors/buddybots.org/buddy-bots-install.sh` — 1 fix
- `smartagent/install.sh` — 1 fix
- `skills/xmtp-comms-guard/PUBLISH-CHECKLIST.md` — 1 fix

## [2026.5.15.1418] - 2026-05-15

### Changed — OpenClaw Pin v2026.5.7 → v2026.5.12

- **Dockerfile:** OpenClaw build target updated from `v2026.5.7` to `v2026.5.12`
- **docker-compose.yml:** Image tag and build arg updated

### Upstream Highlights (OpenClaw v2026.5.7 → v2026.5.12)

#### New Features
- **Per-sender tool policies:** Operators can restrict dangerous tools by requester identity across all tool surfaces
- **Per-agent message restrictions:** Sandboxed agents can restrict message sends to current conversation only
- **Cron get:** Direct `cron.get` and `openclaw cron get` for inspecting stored jobs by id
- **ACP session lineage:** Clients can render subagent graphs without private Gateway side channels
- **Exec command highlighting:** Parser-derived command highlighting in approval prompts
- **Agent ping-pong:** `maxPingPongTurns` raised to 20 (default still 5)
- **Fal image editing:** GPT Image 2 and Nano Banana 2 reference-image edit routing
- **iMessage:** Channel status filtering and BlueBubbles-to-imsg cutover docs
- **Control UI recovery:** HTML recovery panel for blank dashboard pages
- **Fly Machines:** Container environment detection from runtime env vars

#### Build & Dependencies
- **pnpm 11:** Workspace package management upgraded to pnpm 11.1.0
- **TypeScript 6.0.3:** Stricter compiler checks for implicit returns, overrides, unused code
- **Hard-pinned deps:** Non-peer direct dependency specs hard-pinned for reproducible installs
- **OpenAI SDK 6.37.0**, Anthropic SDK 0.95.1, Google GenAI 2.0.1, Kysely 0.29.0
- **Peekaboo 3.0.0** macOS bridge update

#### Fixes
- **Gateway HTTP:** Honor max_completion_tokens and max_tokens on inbound /v1/chat/completions
- **Compaction scope:** Background exec/process session references preserved across compaction
- **Doctor migrations:** Safe legacy migrations committed even with unrelated validation issues
- **Codex OAuth:** Route preservation during doctor --fix (reverts v2026.5.5 regression)
- **Cron model repair:** Bad `payload.model` values (null/blank/"default") cleaned up by doctor
- **Plugin SDK cleanup:** Provider-specific helpers moved back to provider-owned modules

(Reference: https://github.com/openclaw/openclaw/releases/tag/v2026.5.12)

## [2026.5.11.1938] - 2026-05-11

### Changed — OpenClaw Pin v2026.4.29 → v2026.5.7

- **Dockerfile:** OpenClaw build target updated to `v2026.5.7`
- **docker-compose.yml:** Image tag and build arg updated

### Upstream Highlights (OpenClaw v2026.4.29 → v2026.5.7)

#### New Features
- **xAI/Grok 4.3** — Default xAI chat model with image generation, TTS, STT
- **OpenAI Chat-Latest** — Support for chat-latest model aliases
- **Google Meet/Voice Call** — Twilio dial-in improvements, realtime Gemini voice bridge
- **Local Service Startup** — On-demand local model servers before OpenAI-compatible requests
- **Plugin SDK Session Actions** — scheduleSessionTurn, sendSessionAttachment
- **Discord Voice** — Realtime voice diagnostics, allowedChannels config
- **Slack Enhancements** — unfurlLinks/unfurlMedia config, replyBroadcast, App Home tab
- **WhatsApp Channel/Newsletter** — Explicit @newsletter outbound targets
- **Context Map** — `/context map` command for session context treemap visualization
- **Git Plugin Installs** — First-class `git:` plugin installs with ref checkout

#### Fixes
- **WhatsApp** — libsignal-node dependency fix
- **Gateway/systemd** — Secrets preservation across restarts
- **Feishu** — Thread ID hydration fix
- **LINE** — dmPolicy validation fix
- **Doctor/OpenAI Codex** — OAuth route revert fix
- **Release/Plugin Publishing** — Publishing fixes for npm-first cutover
- **Cron CLI** — Improvements for job management
- **Gateway Startup** — Leaner hot paths, scoped plugin preloads
- **Control UI/WebChat** — Sessions, Cron, long-running WebSocket resilience
- **Messaging** — Telegram topic commands, Discord delivery edge cases, Signal group/media routing
- **Provider Fixes** — OpenAI-compatible TTS/Realtime, OpenRouter/DeepSeek replay, Anthropic streaming

#### Infrastructure
- **pnpm 11** — Workspace upgrade
- **Plugin Registry** — npm-first cutover, ClawPack metadata, cold registry improvements
- **Dependencies** — TypeBox 1.1.37, AWS SDK 3.1041.0, OpenAI 6.35.0, Codex 0.128.0, Zod 4.4.1

(Reference: https://github.com/openclaw/openclaw/releases)

## [2026.4.30.2333] - 2026-04-30

### Changed — OpenClaw Pin v2026.4.26 → v2026.4.29

- **Dockerfile:** OpenClaw build target updated from `v2026.4.26` to `v2026.4.29`
- **docker-compose.yml:** Image tag and build arg updated

### Upstream Highlights (OpenClaw v2026.4.26 → v2026.4.29)

#### New Features
- **NVIDIA provider:** API-key onboarding, static model catalog, literal model-ref picker
- **Commitments system:** Opt-in inferred follow-up commitments with hidden batched extraction, per-agent/per-channel scoping, heartbeat delivery, CLI management, `commitments.enabled`/`commitments.maxPerDay` config
- **Memory wiki:** People metadata, provenance views, relationship graphs, per-conversation Active Memory filters, partial recall on timeout, bounded REM preview diagnostics
- **Active-run steering:** Default active-run queueing to steer with 500ms debounce fallback, dedicated steering queue docs
- **Spawned subagent routing:** Subagent metadata propagated for visible-reply enforcement

#### Fixes
- **Tool profile safety:** Configured tool sections (tools.exec, tools.fs) no longer implicitly widen restrictive profiles; startup warning identifies affected configs
- **Stale-session recovery:** Orphan recovery bounded with persisted attempts and wedged-session tombstone; task doctor reconciles automatically
- **Browser config refresh:** CLI status/start honors configured executablePath, headless, and noSandbox instead of stale auto-detection
- **systemd exit codes:** Exit 78 for lock/EADDRINUSE conflicts stops Restart=always loops
- **Telegram group fix:** Blank visible user prompts skipped at embedded-runner boundary (no more raw empty-input provider errors)
- **Discord/Slack fallback:** Auto-reply falls back to automatic source delivery when message tool unavailable
- **Codex streams:** Existing wrapped Codex streams preserved during OpenAI attribution; unsupported Codex-only fields stripped without touching custom endpoints
- **Token budget:** Tool-result overflow uses resolved runtime context token budget (no more early compaction)

#### Security
- **OpenGrep scanning:** Precise rulepack, source-rule compiler, provenance metadata check, PR/full scan workflows with SARIF upload to GitHub Code Scanning
- **GHSA triage refinement:** Media/base64 decode overhead classified as performance-only unless demonstrating limit bypass, crash, exhaustion, or data exposure
- **Web-fetch IPv6:** ULA opt-in for trusted proxy stacks

#### Channels
- **Slack:** Block Kit section limits enforced
- **Telegram:** Proxy/webhook/polling/send resilience improvements
- **Discord:** Startup and rate-limit handling fixes
- **WhatsApp:** Delivery and liveness improvements
- **Teams/Matrix/Feishu:** Edge case fixes

#### Performance
- Reusable model catalogs, event-loop readiness diagnostics, runtime-dependency repair, version-scoped update caches

(Reference: https://github.com/openclaw/openclaw/releases/tag/v2026.4.29)

## [2026.4.28.1255] - 2026-04-28

### Fixed — Monorepo Path Resolution (Regression from v2026.4.22)

The April 22 monorepo restructure moved all runtime scripts from `scripts/` to `packages/core/scripts/`, but installer scripts, documentation, and diagnostics still referenced the old paths. This caused:

- **404 errors** on `curl | bash` install URLs documented in SKILL.md
- **"file not found" errors** for setup.mjs, setup-ollama.sh, install.sh, bootstrap-everclaw.mjs during installation
- **Broken fix suggestions** in diagnose.sh

#### Changes

- **install-with-deps.sh:** Added `SCRIPTS_DIR` auto-detection for monorepo vs composed flavor layouts; all `scripts/` references now use resolved paths
- **install-everclaw.sh:** Same `SCRIPTS_DIR` resolution after clone/update
- **diagnose.sh:** Updated all `fix` suggestions to use `$SCRIPT_DIR` (resolves to script's containing directory)
- **SKILL.md:** Fixed curl URLs from `scripts/` to `packages/core/scripts/`

#### Testing

- Verified corrected URLs return HTTP 200 from GitHub raw CDN
- Bash syntax check passed on all modified scripts
- SCRIPTS_DIR resolution verified for both monorepo and composed flavor structures
- Pre-existing test failures (mempalace-bridge, security-tier) unchanged

## [2026.4.28.0352] - 2026-04-28

### Changed — OpenClaw Pin v2026.4.25 → v2026.4.26

- **Dockerfile:** OpenClaw build target updated from `v2026.4.25` to `v2026.4.26`
- **docker-compose.yml:** Image tag and build arg updated

### Upstream Highlights (OpenClaw v2026.4.25 → v2026.4.26)

#### New Features
- **Cerebras provider:** Bundled plugin with onboarding, static model catalog, and manifest-owned endpoint metadata
- **Asymmetric embeddings:** `memorySearch.inputType`, `queryInputType`, `documentInputType` config for smarter memory search with asymmetric embedding endpoints
- **Ollama query prefixes:** Model-specific retrieval prefixes for nomic-embed-text, qwen3-embedding, and mxbai-embed-large
- **Transcript compaction preflight:** Opt-in `maxActiveTranscriptBytes` auto-compacts when JSONL grows too large
- **Claude + Hermes importers:** `openclaw migrate` with plan, dry-run, JSON output, and pre-migration backup
- **Matrix E2EE:** One-command Matrix encryption setup with bootstrap recovery
- **Config diff panel:** Control UI shows pending config changes with JSON5 parsing and sensitive value redaction
- **Google Live Talk:** Browser realtime transport with constrained ephemeral tokens and Gateway relay
- **Plugin layered deps:** `OPENCLAW_PLUGIN_STAGE_DIR` supports read-only preinstalled deps before writable root

#### Fixes (30+ Ollama fixes)
- Custom provider prefix stripping, native thinking effort levels, VRAM/context defaults, auth scoping, vision modality preservation, web search routing, timeout/keepalive threading, embedding endpoint migration, duplicate model ID prevention, and more
- **EPIPE crash guard:** Broken-pipe stream errors no longer crash the Gateway
- **Bonjour hardening:** Cancellation handlers preserved across advertiser restarts
- **Cron isolation:** Isolated cron jobs get run-scoped context keys (no prior-run bleed)
- **sessions_spawn aliases:** Bare model aliases now resolve correctly for subagent overrides
- **npm update safety:** Updates use temp prefix before swapping package tree
- **Link understanding:** URL-bearing messages no longer dropped after stale runtime chunk upgrades
- **Docker CA certs:** Slim runtime image now includes CA certificate bundle for HTTPS
- **Chokidar v5 hot reloads:** Skill and memory file watching restored

#### Security
- Device token echo fix (rotated tokens no longer leaked in shared/admin responses)
- Transcript redaction patterns now applied to persisted JSONL
- Exec approvals accept symlinked `OPENCLAW_HOME` while rejecting symlinked path components below it

(Reference: https://github.com/openclaw/openclaw/releases/tag/v2026.4.26)

## [2026.4.28.0145] - 2026-04-28

### Changed — OpenClaw Pin v2026.4.23 → v2026.4.25

- **Dockerfile:** OpenClaw build target updated from `v2026.4.23` to `v2026.4.25`
- **docker-compose.yml:** Image tag and build arg updated

### Upstream Highlights (OpenClaw v2026.4.23 → v2026.4.25)

#### New Features
- **TTS overhaul:** `/tts latest` read-aloud, `/tts chat on|off` session-scoped auto-TTS, per-agent voice overrides, 6 new TTS providers (Azure Speech, Xiaomi, Local CLI, Inworld, Volcengine, ElevenLabs v3)
- **Plugin cold registry:** Persisted registry eliminates broad manifest scans, faster boot, deterministic provider discovery
- **OpenTelemetry expansion:** Spans across model calls, token usage, tool loops, harness runs, exec, delivery, context assembly, memory pressure; Prometheus scrape plugin; W3C traceparent propagation
- **Browser automation:** Iframe-aware role snapshots, safe tab URLs, CDP readiness tuning for slow hosts, headless one-shot launch, `doctor --deep` probing
- **Control UI:** PWA install + Web Push notifications, Crestodian TUI first-run setup, context mode selector
- **Google Meet:** Calendar-backed attendance export workflows, meeting record tools

#### Fixes
- **DeepSeek V4:** Venice passthrough fix for `reasoning_content` replay turns (eliminates need for local patch)
- **Cron hardening:** Jobs interrupted by restart recorded as failed, one-shots disabled after interruption
- **Install hardening:** Windows/macOS/Linux/Docker improvements, Node service restarts, LaunchAgent token rotation, mixed-version gateway verification
- **Bonjour/mDNS:** Broken plugin self-disables after repeated failures (EverClaw also auto-disables preemptively)

#### Security
- Device token scope containment (pairing-only sessions can't mutate operator tokens)
- Configured redaction patterns now applied to persisted session transcripts
- Gateway rejects older binary from mutating newer-version services

(References: https://github.com/openclaw/openclaw/releases/tag/v2026.4.24, https://github.com/openclaw/openclaw/releases/tag/v2026.4.25)

## [2026.4.25.1719] - 2026-04-25

### Added — BACK-006: First-Run Security Guidance Banner

- **Feature:** Docker containers now show a one-time security guidance banner on first startup, recommending localhost access and explaining HTTPS reverse proxy options (Caddy, Traefik, Nginx, SSH tunnel).
- **Sentinel:** Banner is suppressed on subsequent starts via `~/.openclaw/.first-run-complete` marker file. If the marker cannot be created (read-only volume), a warning is logged and the banner reappears.
- **Port-aware:** Banner uses `OPENCLAW_GATEWAY_PORT` env var (default 18789) for all URLs and SSH tunnel examples.
- **Files:** `packages/core/scripts/docker-entrypoint.sh` (+27/-2)
- **SOP-001:** Stages 0-7 complete. Grok 4.20: 2 rounds → Perfect. Cross-model (Claude Opus 4.6): Perfect. PII scan: clean.

## [2026.4.25.0441] - 2026-04-25

### Fixed — BACK-015: install-with-deps.sh False-Positive Dependency Reporting

- **Bug:** `verify_installed()` return values were discarded in `install_dep()` for `curl`, `git`, `npm`, and `OpenClaw` cases. The function could return 0 (success) even when dependency installation failed, causing confusing output where users saw checkmarks but dependencies were missing.
- **Fix:** All `verify_installed` calls now propagate their return values via `|| return 1`:
  - `curl`: added `|| return 1` after verify call
  - `git` (macOS with brew): moved verify inside brew branch with `|| return 1`
  - `git` (macOS without brew): changed to `log_err` + `return 1` (was `log_warn` only)
  - `git` (Linux): moved verify inside Linux branch with `|| return 1`
  - `npm`: restructured as early-return-on-success, install path with `|| return 1`
  - `OpenClaw`: added `|| return 1` after verify call
- **Files:** `packages/core/scripts/install-with-deps.sh` (17 insertions, 14 deletions)
- **SOP-001:** Stages 0-7 complete. Grok 4.20: Perfect. Cross-model (DeepSeek V4 Pro): Perfect.

## [2026.4.25.0259] - 2026-04-25

### Fixed — Monorepo Path Issues

- **npm test now works from monorepo root:** Added symlink `tests -> packages/core/tests` so the test glob in package.json finds tests in the monorepo. Previously `npm test` found 0 tests because `tests/` only existed in `packages/core/`.
- **version-stamp.sh finds package.json in monorepo:** Added monorepo detection that looks for package.json at the repo root (two levels up from REPO_DIR) when running from packages/core/. Previously the script could only find 3/4 files (SKILL.md, Dockerfile, docker-compose.yml in packages/core/) but missed package.json at repo root.

**Note:** users running macOS should run `git config core.symlinks true` to ensure the symlink works correctly on checkout. Windows users should enable Developer Mode for symlink support.

## [2026.4.25.0136] - 2026-04-25

### Fixed — Monorepo Bootstrap Wrapper

- **Added wrapper** at `scripts/bootstrap-gateway.mjs` that forwards to `packages/core/scripts/bootstrap-gateway.mjs`
- **Issue:** Users cloning the monorepo (`EverClaw/EverClaw`) got `MODULE_NOT_FOUND` when running `npm run bootstrap` because the actual script lives in `packages/core/scripts/`
- **Fix:** Thin ESM wrapper at monorepo root forwards CLI args to the real script in `packages/core/`
- **Composed flavor repos unaffected:** `flavor-compose.sh` copies `packages/core/scripts/` to output root (not monorepo root `scripts/`), so flavor installs already had the real script

## [2026.4.24.1832] - 2026-04-24

### Changed — OpenClaw Pin v2026.4.21 → v2026.4.23

- **Dockerfile:** OpenClaw build target updated to `v2026.4.23`
- **docker-compose.yml:** Image tag and build arg updated

### Upstream Highlights (OpenClaw v2026.4.21 → v2026.4.23)

#### New Features
- **Image Generation:** gpt-image-2 via Codex OAuth (no API key needed), OpenRouter image models, quality/format hints
- **Subagents:** Optional forked context for `sessions_spawn` — child inherits parent transcript
- **Tools:** Per-call `timeoutMs` for image, video, music, and TTS generation
- **Memory:** Configurable `memorySearch.local.contextSize` (4096 default) for constrained hosts
- **Dependencies:** Pi packages updated to 0.70.0
- **Codex Harness:** Structured debug logging for harness selection decisions

#### Fixes
- **Block Streaming:** Suppress duplicate replies after partial block-delivery aborts
- **Slack:** Classify MPIM group DMs as group chat, suppress verbose tool progress in rooms
- **Telegram:** Parse markdown image syntax into outbound media payloads
- **WhatsApp:** Unified outbound media normalization across sends and auto-replies
- **WebChat:** Surface non-retryable provider failures (billing, auth, rate-limit) with model-switch hints
- **Memory CLI:** Local embedding provider resolution for standalone commands
- **Codex/Windows:** Resolve npm-installed codex.cmd shims through PATHEXT
- **Media Understanding:** Honor explicit imageModel config before native-vision skips
- **Image Attachments:** Preserve for text-only models via media ref offloading

#### Security
- **Teams:** Cross-bot token replay blocked via verified appid/azp
- **Android:** Loopback-only cleartext gateway connections required
- **Pairing:** Private-IP or loopback required for cleartext mobile pairing
- **QA Channel:** Non-HTTP(S) inbound attachment URLs rejected
- **Claude CLI:** `bypassPermissions` derived from OpenClaw exec policy
- **Plugins:** Setup-api lookup hardening

(Reference: https://github.com/openclaw/openclaw/releases/tag/v2026.4.23)


## [2026.4.22.1820] - 2026-04-22

### Changed — Skill Frontmatter & Cleanup

Cherry-picked improvements from community PR #15 (yogesh-tessl):

- **Added YAML frontmatter** to 5 skills: `agent-chat`, `night-shift`, `pii-guard`, `prompt-guard`, `xmtp-comms-guard`
  - Structured `name` and `description` with `Use when` clauses for agent discovery
  - Consistent double-quoted string format across all skills
  - EverClaw branding standardized across all descriptions
- **Removed duplicate section** from `agent-chat/SKILL.md`: second "Daemon Management" block (88 lines) was identical to the first
- **Preserved all security content** in `prompt-guard/SKILL.md`: inline detection patterns, changelogs, and incident context retained (rejected PR's removal of these)


## [2026.4.22.1638] - 2026-04-22

### Changed — Monorepo Restructure

**Architecture overhaul:** Reorganized flat repo into monorepo with composed flavor deployment.

- **New `packages/core/`:** All common Morpheus infrastructure (scripts, tests, references, docs, templates, Docker, config)
- **New `flavors/`:** 29 thin per-flavor directories with `flavor.json` + `README.md` + optional templates
- **New `scripts/flavor-compose.sh`:** Composes core + flavor overlay into a deployable repo
- **Rewritten `scripts/ecosystem-sync.sh`:** Canonical remotes get full monorepo; flavor remotes get composed artifacts
- **New `archive/`:** Deprecated content (alternative installers, marketing, analytics, one-time tools)
- **Removed `claw-repos/`:** Per-flavor duplicated directories eliminated (was 28 × full copy)
- **Moved `everclaw-docker/` and `everclaw-key-api/`:** Now under `packages/core/` for automatic inclusion in composed flavors
- All flavor READMEs note they are generated from the monorepo
- Root README updated with monorepo architecture, "Adding a New Flavor" guide
- Uses `rsync` for robust core copying (new files auto-included), `jq` for JSON parsing

## [2026.4.22.1314] - 2026-04-22

### Changed — OpenClaw Pin v2026.4.15 → v2026.4.21

- **Dockerfile:** OpenClaw build target updated to `v2026.4.21`
- **docker-compose.yml:** Image tag and build arg updated

### Upstream Highlights (OpenClaw v2026.4.15 → v2026.4.21)

#### New Features
- **Image generation:** Defaults to `gpt-image-2` (OpenAI)
- **Skill Workshop plugin:** Captures workflow corrections as reusable skills
- **Kimi K2.6:** Added to Fireworks provider catalog
- **Preview streaming:** Discord, Slack, Telegram show tool progress in live edits
- **QQBot:** Self-contained engine with QR-code onboarding

#### Performance
- **Plugin startup:** Discord 98% faster, Telegram 14s faster, Matrix 1.8s faster
- **Bundled plugin loading:** 82-90% faster via native Jiti

#### Fixes
- **ACP/subagents:** Parent→child echo loop fix on `sessions_send`
- **Subagents:** Terminal failures no longer freeze or replay stale output
- **Security:** External content strips chat-template special tokens (Qwen/ChatML, Llama, Gemma, Mistral)
- **npm:** Fixed `node-domexception` deprecation warning chain

(Reference: https://github.com/openclaw/openclaw/releases/tag/v2026.4.21)

## [2026.4.19.0439] - 2026-04-19

### Added — Per-Agent Inference Quota Management

- **`buddy-quotas.mjs`** (960 lines) — CLI + library for per-agent inference quota tracking
  - Per-agent token counters in `~/.everclaw/quotas/usage/{agent-id}.json`
  - Configurable daily/monthly limits with per-agent overrides
  - Alert threshold (default 80%) with host notification
  - Graceful degradation to lighter model at 90% (configurable)
  - Three cutoff actions: `degrade`, `block`, `warn`
  - Automatic daily/monthly rollover with 30-day history retention
  - Provider + model breakdown tracking (morpheus/venice/ollama)
  - Export/import for data portability
  - `initializeAgent()` / `removeAgentData()` for provision/deprovision integration
  - Lock-free file-per-agent design (zero contention between concurrent bots)
  - Zero npm dependencies (Node built-ins only)
- **50 tests** — library + CLI coverage including rollover, validation, thresholds, export roundtrip

### Grok 4.20 Audit
- 3 rounds → **Perfect** (both files)
- R1: Fixed redundant ternary, defensive config guard, robust filename parsing
- R2: Fixed test SCRIPT path resolution, removed dead config mutation code
- R3: Perfect — zero remaining issues

## [2026.4.18.0201] - 2026-04-18

### Added — MOR Staking Session Management

- **On-chain session pagination:** `session.sh cleanup` and `morpheus-session-mgr.mjs cleanup` enumerate ALL sessions via Diamond contract `getUserSessions(addr, offset, limit)` — the proxy-router `/sessions/user` endpoint has a hidden ~100 session limit
- **Stale session cleanup:** Automatically closes orphaned sessions, keeps only the latest per model. Frees locked MOR.
- **Pre-open cleanup:** `session.sh open` now runs cleanup before opening new sessions (best-effort, requires `cast`)
- **GLM-5 + GLM-5.1:web:** Added to model ID map in `session.sh`
- **Staking monitor cron pack:** `cron-packs/packs/staking-monitor.json` — nightly cleanup + 6-hourly balance alerts
- **Troubleshooting entries:** "Insufficient MOR" and "Sessions not showing" root-cause docs with pagination fix

### Fixed

- **Port consistency:** `morpheus-session-mgr.mjs` uses `API_BASE` (default 8082) everywhere — no more mixed 8082/8083 references
- **Bash 3.2 compatibility:** `session.sh cleanup` uses indexed arrays (no `declare -A`), works on macOS default bash
- **cast output parsing:** Properly strips quotes from `cast call` output (was silently returning 0 sessions)
- **Cookie parsing:** Handles both `user:pass` and plain-password cookie formats
- **[REDACTED] placeholders:** All removed from troubleshooting.md, replaced with "Morpheus" / "proxy-router"
- **Stale MOR rate:** Updated default from 633 to 1268 MOR/day

### Security

- Zero PII — no personal addresses, only public contract addresses (Diamond, MOR token) and on-chain model IDs
- All user-specific values from environment variables
- Grok 4.2 reasoning audit: 5 rounds, 4/4 files rated **Perfect**

## [2026.4.17.0050] - 2026-04-17

### Changed — OpenClaw Pin v2026.4.14 → v2026.4.15

- **Dockerfile:** OpenClaw build target updated to `v2026.4.15`
- **docker-compose.yml:** Image tag and build arg updated

### Upstream Highlights (OpenClaw v2026.4.14 → v2026.4.15)

#### New Features
- **Anthropic/models:** Claude Opus 4.7 defaults, opus aliases, bundled image understanding
- **Google/TTS:** Gemini text-to-speech in bundled google plugin
- **Control UI/Overview:** Model Auth status card (OAuth health + rate-limit pressure)
- **Memory/LanceDB:** Cloud storage support for durable memory indexes
- **GitHub Copilot/memory search:** Copilot embedding provider for memory search
- **Agents/local models:** `localModelLean: true` flag drops heavyweight tools for weaker setups
- **Packaging/plugins:** Localized bundled plugin runtime deps, leaner published builds

#### Fixes
- **Ollama/chat:** Provider prefix stripped from model IDs (fixes 404 on `ollama/` refs)
- **Dreaming/memory-core:** Storage mode defaults to `separate` (daily files no longer dominated by dream blocks)
- **Gateway/skills:** Snapshot version bumped on config writes (removed skills take effect immediately)
- **Agents/tool-loop:** Unknown-tool loop guard enabled by default (stops "Tool not found" loops)
- **Cron/announce:** NO_REPLY leak fixed (isolated cron replies no longer leak summary text)
- **Agents/replay recovery:** 401 "input item ID" now gives /new guidance
- **Agents/failover:** HTML provider error pages treated as transport failures
- **Agents/tools:** Host tilde paths resolve correctly when OPENCLAW_HOME differs
- **Speech/TTS:** Auto-enable bundled providers, route directive tokens through correct provider
- **Agents/CLI transcripts:** CLI-backed turns persist to session history
- **BlueBubbles/catchup:** Retry ceiling for persistently-failing messages
- **OpenAI Codex/models:** Stale transport metadata self-heals to canonical Codex endpoint
- **WhatsApp/web-session:** Auth race fix on reconnect

#### Security
- **Gateway/tools:** MEDIA: trust anchor on exact registered built-in tool names
- **Gateway/webchat:** localRoots containment on audio embedding
- **Matrix/pairing:** DM pairing-store blocked from room control commands
- **Docker/build:** pnpm v10+ native bindings path fix

(Reference: https://github.com/openclaw/openclaw/releases/tag/v2026.4.15)

## [2026.4.14.1520] - 2026-04-14

### Changed — OpenClaw Pin v2026.4.12 → v2026.4.14

- **Dockerfile:** OpenClaw build target updated to `v2026.4.14`
- **docker-compose.yml:** Image tag and build arg updated

### Upstream Highlights (OpenClaw v2026.4.12 → v2026.4.14)

#### New Features
- **OpenAI Codex/models:** Forward-compat support for GPT-5.4-pro (pricing, limits, catalog visibility)
- **Telegram/forum topics:** Human topic names surfaced in agent context and persisted across restarts

#### Fixes
- **Ollama/timeout:** Configured embedded-run timeout forwarded to undici stream timeout (no more premature cutoff)
- **Ollama/streaming:** `stream_options.include_usage` sent for streaming completions (prevents bogus token counts and premature compaction)
- **Ollama/slug generation:** Session-memory slug honors `timeoutSeconds` override (no more 15s abort)
- **Memory/embeddings:** Non-OpenAI provider prefixes preserved during normalization (fixes "Unknown memory embedding provider")
- **Media/transcription:** `.aac` filenames remapped to `.m4a` for MIME-sensitive endpoints
- **Agents/context engine:** Tool-loop sessions compact from first delta, preserving ingest fallback
- **Agents/subagents:** Registry lazy-runtime stub emitted on stable dist path (ERR_MODULE_NOT_FOUND fix)
- **Gateway/update:** Unified service entrypoint resolution for update/reinstall/doctor
- **Browser/SSRF:** Navigation restored under default policy; strict mode preserved for legacy configs
- **UI/chat:** marked.js → markdown-it (ReDoS prevention)

#### Security Hardening
- Gateway tool rejects dangerous config flag changes from model-facing calls
- Media attachments fail closed on realpath errors
- Heartbeat forces owner downgrade for untrusted hook:wake events
- Browser SSRF policy enforced on snapshot/screenshot/tab routes
- MS Teams sender allowlist on SSO signin
- Config redacts sourceConfig/runtimeConfig alias fields

(Reference: https://github.com/openclaw/openclaw/releases/tag/v2026.4.14)

## [2026.4.14.0206] - 2026-04-14

### Changed — OpenClaw Pin v2026.4.11 → v2026.4.12

- **Dockerfile:** OpenClaw build target updated to `v2026.4.12`
- **docker-compose.yml:** Image tag and build arg updated

### Upstream Highlights (OpenClaw v2026.4.11 → v2026.4.12)

#### New Features
- **Active Memory plugin:** Dedicated memory sub-agent that auto-pulls relevant context/preferences before replies. Configurable modes, `/verbose` inspection.
- **Codex provider:** Bundled provider for `codex/gpt-*` models with native auth, threads, and compaction
- **LM Studio provider:** Bundled provider for local/self-hosted OpenAI-compatible models with auto-discovery
- **macOS Talk Mode:** Experimental local MLX speech provider for Talk Mode
- **Exec policy CLI:** `openclaw exec-policy` command for syncing exec approvals with config
- **Plugin loading overhaul:** Manifest-declared activation scopes, narrower loading boundaries
- **Per-provider allowPrivateNetwork:** Trusted self-hosted endpoints opt-in
- **Gateway commands.list RPC:** Remote clients can discover runtime commands

#### Fixes
- **Security:** busybox/toybox removed from safe bins, empty approver list fix, shell-wrapper injection block, placeholder credential startup block
- **Dreaming:** Promotion threshold raised (fixes zero-candidate stalls), light-sleep confidence from all signals, narrative cleanup hardened, no re-ingesting own transcripts
- **Memory/QMD:** Better recall defaults, Unicode slug fix, nested daily notes support, direct memory dir watching (fixes macOS + Node 25 glob issue)
- **Agents:** Orphaned user text carried into next prompt (fixes mid-run dropped messages), Anthropic replay safety
- **Gateway:** Keepalive ticks no longer droppable, sidecar-gated startup, cron config persistence across reloads
- **WhatsApp:** Fallback to first mediaUrls entry (fixes silently dropped attachments)
- **CLI update:** Stale chunk import fix after self-update

(Reference: https://github.com/openclaw/openclaw/releases/tag/v2026.4.12)

## [2026.4.12.1825] - 2026-04-12

### Changed — OpenClaw Pin v2026.4.9 → v2026.4.11

- **Dockerfile:** OpenClaw build target updated to `v2026.4.11`
- **docker-compose.yml:** Image tag and build arg updated

### Upstream Highlights (OpenClaw v2026.4.10–v2026.4.11)

#### New Features
- **Dreaming/memory-wiki:** ChatGPT import ingestion with Imported Insights and Memory Palace diary subtabs for inspecting imported chats and compiled wiki pages directly from the UI
- **Control UI/webchat:** `[embed ...]` rich output tag, structured chat bubbles for media/reply/voice directives, external embed URL gating
- **video_generate:** URL-only asset delivery, typed providerOptions, reference audio inputs, per-asset role hints, adaptive aspect-ratio support
- **Plugin manifests:** Activation and setup descriptors for declarative auth/pairing/config flows
- **Ollama:** Context-window and capability metadata caching during model discovery
- **Microsoft Teams:** Reaction support with delegated OAuth
- **Feishu:** Richer document comment sessions with reactions and typing feedback

#### Fixes
- **Agent timeouts:** Explicit run timeouts honored in LLM idle watchdog — slow models work until configured limit
- **ACP child relay:** Internal progress chatter from spawned child runs no longer leaks into parent stream
- **Agent failover:** Cross-provider fallback scoped to current attempt instead of stale session history
- **Audio transcription:** Pinned DNS disabled only for OpenAI-compatible multipart requests
- **WhatsApp:** Default account honored, react routed through gateway, image attachment paths preserved
- **Telegram:** Topic-scoped session initialization stays on canonical transcript path
- **Codex OAuth:** Upstream authorize URL scopes no longer rewritten
- **macOS Talk Mode:** Microphone permission continues startup without double-toggle

## [2026.4.9.1656] - 2026-04-09

### Fixed — Morpheus Gateway Error Unwrapping (Issues #1 & #2)

- **Issue #1: LiteLLM wraps 429 rate limits as HTTP 400** — Venice backend rate limits were returned as HTTP 400 with `providerModelError` wrapper, preventing OpenClaw's retry/fallback chain from triggering.
  - **Fix:** `normalizeLitellmError()` detects wrapped 429 errors (via `code === "429"`, `"RateLimitError"`, `"overloaded"`, `"throttling_error"`) and rewrites to proper HTTP 429.
  - **Impact:** OpenClaw now retries with backoff and triggers model-group fallbacks correctly.

- **Issue #2: LiteLLM "division by zero" server errors wrapped as HTTP 400** — Internal LiteLLM bugs (RPM/TPM math errors when backend reports 0) returned as HTTP 400.
  - **Fix:** Same unwrapping logic detects `code === "500"` or `"division by zero"` and returns HTTP 503 (service unavailable - retryable).

- **New `callGatewayWithRetry()` wrapper** — All 4 gateway call sites now retry transient errors (429, 500, 502, 503) with exponential backoff (1s → 2s → 4s, capped at 10s) before giving up.

- **Streaming safe** — Successful SSE streams pass through immediately; only failed requests trigger retry logic.

- **Zero breaking changes** — Non-provider errors, genuine 400s, and streaming success paths unchanged.

## [2026.4.9.1449] - 2026-04-09 — Windows Detection & OpenClaw URL Fix

### Fixed
- **Windows (Git Bash / MSYS / Cygwin) now shows helpful error** — Instead of a generic "Unsupported OS" message, Windows users are directed to install WSL 2 with a link to Microsoft docs. Consistent messaging across all 4 installer scripts (`install-with-deps.sh`, `install.sh`, `restore-agent.sh`, `setup-ollama.sh`). Thanks to Kyrin for the report.
- **Dead `get.openclaw.ai` URL replaced** — All references updated to the current `openclaw.ai/install.sh` with `--install-method git`. The old `get.openclaw.ai` domain no longer resolves (NXDOMAIN). Fixed in `restore-agent.sh`, `SKILL.md`, and `docs/getting-started/installation.md`.

### Added
- **Explicit platform requirements in docs** — Prerequisites section in SKILL.md and installation.md now clearly states: "Supported platforms: macOS, Linux, Windows via WSL 2."

## [2026.4.9.1353] - 2026-04-09 — OpenClaw v2026.4.9 Pin

### Changed
- **OpenClaw pin** `v2026.4.8` → `v2026.4.9`
  - Dreaming REM backfill lane + `rem-harness --path` for historical daily notes (MemPalace users can now replay old diary entries into Dreams without a second memory stack)
  - Agent idle timeout now correctly inherits `agents.defaults.timeoutSeconds` (we ship 300s) — eliminates false idle-timeout kills for Morpheus P2P users during slow inference; watchdog disabled for cron runs
  - npm packaging fixes for channel plugin deps (validates our Issue #17 Docker workaround)
  - Security & stability: Browser SSRF recheck, dotenv runtime-control blocking, node exec event sanitization, NO_REPLY token stripping, and auto-fallback model override cleared on `/reset`

**Notes**
Pure version pin bump. No breaking changes, no template modifications, no code changes required in EverClaw. Dry run confirmed clean with zero conflicts.

## [2026.4.9.1327] - 2026-04-09 — Docker Channel Plugin Fix

### Fixed
- **Docker image missing channel plugin dependencies** (Issue #17) — OpenClaw v2026.4.8 loads all bundled channel plugins at startup (Telegram, Discord, Slack, Feishu, etc.) but their runtime deps (`grammy`, `@buape/carbon`, `@slack/web-api`, `@larksuiteoapi/node-sdk`, etc.) were not installed in the Docker image. Root cause: OpenClaw's `postinstall-bundled-plugins.mjs` script detects source checkouts (via `src/` + `extensions/` dirs) and skips dep installation. Since the Dockerfile builds from a git clone, these dirs exist and the postinstall silently skips. Fix: remove `src/` and `extensions/` (build-only artifacts, not needed at runtime) after `pnpm build`, then run the postinstall script. This also reduces image size. Thanks to @robkay01 (Bobski) for the detailed bug report.

## [2026.4.8.1910] - 2026-04-08

### Changed
- **OpenClaw pin v2026.4.5 → v2026.4.8** — Dockerfile `OPENCLAW_VERSION` and `docker-compose.yml` `EVERCLAW_VERSION` env updated. SKILL.md version header and diagnostics examples updated to match.
