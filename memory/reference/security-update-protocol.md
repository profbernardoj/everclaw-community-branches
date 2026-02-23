---
tags: [security, openclaw, updates, openai]
created: 2026-02-15
updated: 2026-02-21
status: active
---
# OpenClaw Update Security Protocol

**Context:** OpenClaw creator Peter was hired by OpenAI (Feb 2026). Must verify trust on every update.

**Fork:** https://github.com/profbernardoj/openclaw — preserved pre-OpenAI version as backup

## Mandatory Pre-Update Checks
1. **License verification:** `git log --follow -p -- LICENSE | head -50` — confirm MIT license unchanged
2. **No OpenAI defaults:** `grep -ri "openai" packages/ --include="*.js" --include="*.json" | grep -v node_modules`
3. **Package dependencies:** Check for new dependencies on `openai` npm package or OpenAI-specific SDKs
4. **Default model config:** Verify default provider/model hasn't changed to OpenAI

## Post-Update Verification
- Run `openclaw status` and verify providers
- Check `~/.openclaw/openclaw.json` for any new OpenAI-related fields
- Review changelog for concerning changes

**If any check fails:** Do NOT update. Investigate. Consider pinning to last known-good version.
