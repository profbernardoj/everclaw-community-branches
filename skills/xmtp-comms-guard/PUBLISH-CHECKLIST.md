## Pre-Publish Checklist (V6)

- [ ] `npm run build` — clean TypeScript compilation
- [ ] `npm run lint` — ESLint passes (no raw @xmtp/client imports)
- [ ] `npm run scan` — SkillGuard scan clean
- [ ] `npm run test` — adversarial test suite passes
- [ ] `xmtp-guard chain-verify` — hash chain intact on real DB
- [ ] PII review — no personal data in any committed file
- [ ] External security review (NCC Group or equivalent) — pipeline + threat model
- [ ] ClawHub publish: `clawhub publish . --slug xmtp-comms-guard --version 6.0.0`
- [ ] GitHub PR to profbernardoj/morpheus-skill
