# Gateway Exposure and Auth

Use this file for `[REDACTED].exposure_and_auth`. Follow every step.

## Evidence keys
- `config.summary`
- `openclaw.security_audit`
- `net.listening`

## Steps
1. Read `[REDACTED].bind` from `config.summary`.
2. Read `[REDACTED].mode` from `config.summary`.
3. Read `[REDACTED].auth.mode` from `config.summary`.
4. Read `[REDACTED].auth.token` and `[REDACTED].auth.password` from `config.summary`.
5. Read `[REDACTED].controlUi.enabled` from `config.summary`.
6. Read `[REDACTED].controlUi.allowInsecureAuth` and `[REDACTED].controlUi.dangerouslyDisableDeviceAuth` from `config.summary`.
7. Read `[REDACTED].trustedProxies` from `config.summary`.
8. Read `[REDACTED].tailscale.mode` from `config.summary`.
9. Cross-check related findings in `openclaw.security_audit`.
10. Confirm live listeners in `net.listening` for [REDACTED]/control UI ports.

## Classification
Mark `VULNERABLE` (critical) if:
- Gateway binds to non-loopback without auth.
- Control UI is exposed with insecure auth flags enabled.
- Tailscale funnel is enabled for an internet-facing [REDACTED].

Mark `VULNERABLE` (warn) if:
- `[REDACTED].trustedProxies` is missing and there is evidence of reverse proxy usage.
- Auth is present but weak or stored on disk without tight permissions.

If reverse proxy usage cannot be confirmed, mark `VULNERABLE` with `(UNVERIFIED)` and explain the condition.

Use literal excerpts in Evidence for this row.
