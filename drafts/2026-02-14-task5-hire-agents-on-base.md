# Task 5: Hire Agents on Base — Research Brief

**Date:** 2026-02-14
**Status:** Complete
**For:** [REDACTED]

---

## Executive Summary

The infrastructure for hiring AI agents on Base is rapidly crystallizing around three complementary standards: **x402** (payments), **ERC-8004** (identity/discovery), and **A2A** (agent-to-agent protocol). Stripe's Feb 11 x402 launch on Base and Coinbase's x402 Bazaar (70+ APIs) make this immediately actionable. Everclaw v0.7 already includes both x402 client and ERC-8004 registry reader — David is ahead of the curve.

---

## The Stack for Hiring Agents

### 1. Discovery: ERC-8004 Agent Registry

**How to find agents:**
- **8004scan.io** — public explorer for the ERC-8004 Identity Registry on Base
- Identity Registry: `0x8004A169FB4a3325136EB29fA0ceB6D2e539a432` (same on all EVM chains)
- Each agent is an NFT with a `tokenURI` pointing to a registration file containing:
  - Name, description, services/endpoints
  - x402 support flag
  - Trust signals (reputation, crypto-economic)
- **Reputation Registry:** `0x8004BAa17C55a88189AE136b182e5fdA19dE9b63` — on-chain feedback scores
- **Everclaw already reads this:** `node scripts/agent-registry.mjs discover <id>`

**Recent momentum (Feb 2026):**
- Bankless podcast (1 week ago): Austin Griffith & Davide Crapis discussed ERC-8004 + x402 integration
- Warden protocol ($4M raise, $200M valuation, Jan 2026) — building agent creation studio with ERC-8004 auth
- Venice.AI participated in Warden's funding round — connection to David's network

### 2. Payment: x402 Protocol

**How to pay agents:**
- HTTP-native: server returns 402 → agent signs USDC payment → retries with proof
- **Coinbase facilitator:** `https://api.cdp.coinbase.com/platform/v2/x402`
- Supports Base (sub-cent gas) and SKALE (zero gas)
- **Everclaw already supports this:** `node scripts/x402-client.mjs GET <url>`

**Major launches (past week!):**
- **Stripe x402 on Base** (Feb 11, 2026) — "machine payments" tool, lets developers charge AI agents directly in USDC
- **x402 Bazaar** — 70+ APIs for AI agents, pay-per-request USDC micropayments
- Services available: web search, scraping, translation, weather, crypto prices, image generation, and more

### 3. Communication: A2A Protocol (Google)

**How agents talk to agents:**
- Agent-to-Agent protocol for task delegation
- `.well-known/agent-card.json` discovery format
- Some ERC-8004 registrations include A2A endpoints in their services list

---

## x402 Bazaar: Available Services (Feb 2026)

The x402 Bazaar (x402-api.onrender.com) offers 70+ pay-per-request APIs:

| Category | Examples | Typical Price |
|----------|----------|--------------|
| Web Search | Brave Search, Google | $0.005-0.01/query |
| Web Scraping | Page content extraction | $0.005/page |
| Translation | Multi-language | $0.01/request |
| Image Generation | DALL-E, Stable Diffusion | $0.02-0.05/image |
| Data Feeds | Crypto prices, weather | $0.001-0.01/call |
| Summarization | Text/URL summarization | $0.01/request |

### How an Agent "Hires" a Service

```
1. Agent queries x402 Bazaar catalog: GET /api/services
2. Agent picks a service based on task needs
3. Agent calls the endpoint: POST /api/services/search
4. Server returns 402 + payment requirements (price, wallet, chain)
5. Agent signs USDC transfer (EIP-3009 TransferWithAuthorization)
6. Agent retries with payment proof in PAYMENT-SIGNATURE header
7. Server verifies payment, returns data
```

Total time: ~200ms on Base (sub-cent gas).

---

## The Current Agent Ecosystem on Base

### Key Players

| Project | What They Do | ERC-8004 | x402 |
|---------|-------------|----------|------|
| **Coinbase/Base** | Infrastructure (x402 facilitator, Base L2) | ✅ | ✅ |
| **Stripe** | Payment processing for AI agents | — | ✅ |
| **Warden** | Agent creation studio ($200M valuation) | ✅ | ✅ |
| **Venice.AI** | Private inference + agent hosting | — | — |
| **Morpheus** | Decentralized inference marketplace | — | Possible |
| **Eco** | x402 documentation + tooling | ✅ | ✅ |
| **ClawNews** | Agent #1 on ERC-8004 registry | ✅ | — |

### What's Missing

1. **Agent-to-agent task delegation** — x402 handles payment, but there's no standard for complex multi-step task delegation between agents
2. **Reputation bootstrapping** — ERC-8004 Reputation Registry exists but has very few entries; agents need more feedback data
3. **Agent SLAs** — no standard for guarantees on response time, quality, availability
4. **Agent discovery UX** — 8004scan exists but isn't designed for agent-to-agent discovery (it's for humans)

---

## What David Can Do Now

### Immediate (This Week)
1. **Register Everclaw as an ERC-8004 agent on Base** — already discussed as a future goal. Would be one of the first utility-focused agents in the registry
2. **Test x402 Bazaar integration** — Everclaw's x402 client should work with the Bazaar out of the box. Test with a web search API to validate

### Short-Term (This Month)
3. **Create a "hire an agent" tutorial** for SmartAgent — show how a personal agent can discover and pay for services via x402
4. **Build an x402 service wrapper** for Morpheus inference — let other agents pay for inference from Morpheus providers via x402 on Base
5. **Connect with Warden team** — Venice.AI invested in them; natural partnership for ERC-8004 + Morpheus integration

### Strategic
6. **Position Morpheus as the inference backend for x402 agents** — if every agent needs AI inference, and Morpheus provides decentralized inference, then Morpheus is infrastructure for the agent economy
7. **Johnston's Law applied:** "Everything that can be decentralized will be decentralized" — agent hiring/services is the next frontier

---

## Relationship to Everclaw

Everclaw v0.7 already ships x402 + ERC-8004. The pieces are in place:
- `x402-client.mjs` — can pay any x402-enabled endpoint
- `agent-registry.mjs` — can discover agents on Base
- Budget controls ($1/request, $10/day) — prevent runaway spending
- Wallet management — USDC signing built in

**The gap:** Everclaw doesn't yet expose x402 services. It's a consumer, not a provider. Making Morpheus inference available via x402 would close this loop.
