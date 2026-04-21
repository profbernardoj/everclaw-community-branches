---
name: xmtp-comms-guard
description: "Enforce security middleware for all XMTP agent-to-agent and user-to-agent messaging. Use when setting up guarded XMTP client, configuring encrypted messaging middleware, reviewing three-shift approval flows, or auditing fail-closed security conditions for the EverClaw communication layer."
user-invocable: false
triggers:
  - "xmtp security"
  - "comms guard"
  - "messaging middleware"
  - "xmtp setup"
  - "message security"
---

# xmtp-comms-guard — Skill Integration Guide (V6)

**Type:** Critical Security
**Version:** 6.0.0
**Required peer dependencies:** bagman, pii-guard, prompt-guard

## Setup Workflow

1. **Install peer dependencies**: Ensure [bagman](../bagman/SKILL.md), [pii-guard](../pii-guard/SKILL.md), and [prompt-guard](../prompt-guard/SKILL.md) are available
2. **Create guarded client** in your application code:
   ```ts
   import { createGuardedXmtpClient } from "xmtp-comms-guard";
   const { client, middleware } = await createGuardedXmtpClient(rawClient, userWallet);
   ```
3. **Verify enforcement**: Run `npx eslint --rule 'no-restricted-imports: error' src/` to confirm raw `@xmtp/client` imports are blocked
4. **Run SkillGuard scan**: `node skills/skillguard/scan.js skills/xmtp-comms-guard/` to validate no bypass patterns exist

## Three-Shift Integration

EverClaw's standard approval flow for security-sensitive actions:

| Decision | Effect | Use case |
|----------|--------|----------|
| **Approve** | Allow the action | Trusted peer messages |
| **Redact** | Downgrade/sanitize | Strip sensitive metadata |
| **Block** | Deny the action | Unknown sender or policy violation |

Applied to: peer revocation review, key rotation re-approval, introduction chain re-evaluation.

## Enforcement Model

Convention-based + build-time gates. See [enforcement.md](enforcement.md) for full details.

- **ESLint rule** blocks `@xmtp/client` direct imports
- **SkillGuard scan** detects raw client usage patterns
- No runtime interception of raw imports (honestly documented)

## Fail-Closed Conditions

The skill refuses to operate when any of these checks fail:

| Condition | What triggers it |
|-----------|-----------------|
| Hash chain integrity | Chain validation fails on startup |
| SQLCipher encryption | Database encryption check fails |
| Nonce cache replay | Duplicate nonce within 90s TTL |
| Unknown topic | Message topic not in allowed set |
| Unknown sensitivity | Unrecognized sensitivity level |
| Message size | Exceeds 64KB limit |
| Protocol mismatch | Version is not "6.0" |
| Peer not trusted | Peer not in registry or blocked |

**On failure**: All conditions trigger a hard block — no fallback, no degraded mode. Investigate and resolve the root cause before retrying.

## Threat Model

See [threat-model.md](threat-model.md) for full analysis.

| Threat | Mitigation |
|--------|-----------|
| Malicious external agent | Schema validation + security checks |
| Compromised internal agent | Middleware chain + SkillGuard gates |
| Host compromise | Bagman + HMAC chain + fail-closed |
| Replay attacks | Nonce cache (90s TTL) + hash chain |
| Data exfiltration | PII Guard + trust context rules |
