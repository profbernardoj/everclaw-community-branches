# ACCOUNTS.md - Service Accounts & Access

*Tracks which services have dedicated accounts for Bernardo (the agent) vs. David's personal accounts.*

---

## Guiding Principles

- **Isolation:** Bernardo should have dedicated accounts separate from David's personal credentials
- **Privacy:** Minimize exposure of David's identity in public registries
- **Security:** Dedicated accounts limit blast radius if compromised

---

## Account Status

### ✅ Configured (Dedicated)

| Service | Account | Notes |
|---------|---------|-------|
| Signal | +14432859111 | Dedicated number for agent communication |
| Venice AI | (API key configured) | Inference provider |

### 🔲 Planned / Pending

| Service | Purpose | Privacy Considerations | Status |
|---------|---------|------------------------|--------|
| Base Wallet | x402 payments + 8004 registration | Dedicated wallet for Bernardo; David holds private key backup | **Next step** |
| ERC-8004 Registry | Agent identity on Base | Register as "Bernardo" — plan what metadata is public before registration | Planning |
| GitHub | Code repos, skill contributions | Dedicated account needed | Pending |
| X/Twitter | Bird CLI access | David to log into Safari on Mac mini with dedicated account tonight | **Tonight** |

### ⏸️ Using David's Accounts (Temporary)

| Service | Notes | Migrate to Dedicated? |
|---------|-------|----------------------|
| (none currently identified) | | |

---

## ERC-8004 Registration Planning

**Agent Name:** Bernardo

**Before registering, decide:**
- [ ] What `description` to use (avoid revealing David's identity)
- [ ] Which `services` endpoints to expose (MCP? A2A? Just wallet?)
- [ ] Which wallet to use as `agentWallet` (dedicated wallet, not David's main)
- [ ] What trust models to advertise (`supportedTrust`)
- [ ] Whether to verify endpoint domain ownership

**Public vs. Private:**
- Registration file is public (linked via tokenURI)
- Reputation and validation records are public
- Need to ensure no PII or links back to David's identity

---

## x402 Payment Rail

**What:** Open HTTP-native payment standard for internet payments, built for agentic use.

**How it works:**
1. Client sends HTTP request
2. Server responds with `HTTP 402 Payment Required` if payment needed
3. Client pays instantly with stablecoins on Base
4. Access granted — no API keys, accounts, or KYC

**Why it matters:**
- Zero protocol fees (just network gas)
- Zero friction (no signups, no API key management)
- Works for both humans and AI agents
- Neutral, open standard — not tied to any specific network

**Integration:** Once Bernardo has a Base wallet with stablecoins, x402-enabled services can be accessed programmatically. The middleware handles payment negotiation automatically.

**Docs:** https://www.x402.org/

---

## Notes

*Add notes about account setup, credentials storage, etc.*

- David will hold private key backup for Bernardo's Base wallet
- Wallet will be used for both x402 payments and ERC-8004 agent registration

---

*Last updated: 2026-02-03*
