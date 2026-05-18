# URL Migration Guide

**Date:** 2026-05-18
**Scope:** Repository URL migration from `EverClaw/EverClaw` to `profbernardoj/morpheus-skill`

## Summary

The EverClaw monorepo has been migrated to the canonical repository at
`profbernardoj/morpheus-skill`. All GitHub URLs — including raw content links,
clone URLs, and API endpoints — were updated across 12 files (28 total
replacements).

## What Changed

### Repository URL

| Old | New |
|-----|-----|
| `github.com/EverClaw/EverClaw` | `github.com/profbernardoj/morpheus-skill` |
| `raw.githubusercontent.com/EverClaw/EverClaw` | `raw.githubusercontent.com/profbernardoj/morpheus-skill` |
| `api.github.com/repos/EverClaw/EverClaw` | `api.github.com/repos/profbernardoj/morpheus-skill` |

### Path Correction

The root `SKILL.md` previously referenced scripts under `main/scripts/`, but
the actual location in the monorepo is `main/packages/core/scripts/`. All raw
content URLs in the root `SKILL.md` were corrected to include the full
`packages/core/` path. The `packages/core/SKILL.md` already used the correct
path and required only the org/repo portion to be updated.

### Files Modified

| # | File | Changes |
|---|------|---------|
| 1 | `SKILL.md` (root) | 7 fixes — org/repo in metadata, 3 raw URLs with path correction, install-everclaw.sh raw URL, git clone URL |
| 2 | `packages/core/SKILL.md` | 6 fixes — org/repo in metadata, 3 install-with-deps.sh raw URLs, install-everclaw.sh raw URL, git clone URL |
| 3 | `packages/core/CLAWHUB_WARNING.md` | 2 fixes — repo URL, git clone URL |
| 4 | `packages/core/scripts/install-everclaw.sh` | 3 fixes — comment URL, REPO_URL variable, GitHub API URL |
| 5 | `packages/core/scripts/install-with-deps.sh` | 1 fix — git clone URL |
| 6 | `packages/core/docs/docs/getting-started/installation.md` | 1 fix — git clone URL |
| 7 | `packages/core/docs/docs/index.md` | 2 fixes — changelog link, GitHub link |
| 8 | `packages/core/docs/docs/scripts/reference.md` | 1 fix — raw URL with path correction |
| 9 | `flavors/buddybots.org/buddy-bots-install.sh` | 1 fix — EVERCLAW_REPO variable |
| 10 | `smartagent/install.sh` | 1 fix — EVERCLAW_REPO variable |
| 11 | `packages/core/docs/docs/docker-flavors.md` | 1 fix — GitHub Actions URL |
| 12 | `packages/core/docs/docs/operations/troubleshooting.md` | 1 fix — GitHub Issues URL |
| 13 | `packages/core/scripts/everclaw-deps.mjs` | 1 fix — dependency metadata (line 72) |
| 14 | `skills/xmtp-comms-guard/PUBLISH-CHECKLIST.md` | 1 fix — checklist URL (line 11) |

## Canonical URL Patterns Going Forward

All new references must use:

- **GitHub repo:** `https://github.com/profbernardoj/morpheus-skill`
- **Git clone:** `https://github.com/profbernardoj/morpheus-skill.git`
- **Raw content:** `https://raw.githubusercontent.com/profbernardoj/morpheus-skill/main/packages/core/scripts/<script>.sh`
- **GitHub API:** `https://api.github.com/repos/profbernardoj/morpheus-skill/releases/latest`
- **Issues:** `https://github.com/profbernardoj/morpheus-skill/issues`
- **Actions:** `https://github.com/profbernardoj/morpheus-skill/actions`

**Important:** Script raw URLs must always include the `packages/core/` prefix
after the branch name. The scripts directory lives at
`packages/core/scripts/`, not at the repository root `scripts/`.

## Files Intentionally Not Modified

The following files still reference `EverClaw/EverClaw` for historical or
archival reasons and should NOT be updated:

- `archive/` — archived/one-time tools, historical reference only
- `CHANGELOG.md` — historical record, old org name is correct in context
- CI workflow files — use repo-specific secrets and variables
- Skill attribution comments — identity/reference metadata

## Migration Checklist for New Files

When adding new files that reference the repository:

1. Use `profbernardoj/morpheus-skill` as the org/repo
2. For script URLs, always use the full path: `main/packages/core/scripts/...`
3. Run `grep -r "EverClaw/EverClaw" --include='*.md' --include='*.sh' --include='*.mjs'`
   to catch any accidental use of the old URL
4. Do NOT update archive/ files, CHANGELOG.md, or CI workflows
