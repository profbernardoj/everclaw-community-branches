# Coinbase Agentic Wallets Research

**Date:** 2026-02-13  
**Requested by:** [REDACTED]  
**Status:** Breaking news — Coinbase just launched this 2 days ago (Feb 11, 2026)

---

## Executive Summary

Coinbase has just launched **Agentic Wallets** — a purpose-built wallet infrastructure for AI agents. This is a significant development that directly competes with DIY approaches like the EOA + Safe + 1Password setup currently used by Bernardo. The product is built on their existing AgentKit SDK and the x402 payment protocol.

**Bottom line for SmartAgent users:** This could be very useful for users who want managed infrastructure without self-hosting keys. It's a tradeoff: convenience and security features vs. custody trust and vendor lock-in to Coinbase/Base.

---

## What Coinbase Has Shipped

### 1. Agentic Wallets (NEW - Feb 11, 2026)
A standalone wallet designed specifically for AI agents:
- **Purpose-built** — "not an SDK, not a library — it's a purpose-built wallet to work with an agent" per Erik Reppel (Coinbase)
- **Base-only for now** — operates only on Base (Coinbase's L2), with gasless transactions
- **CLI/MCP interface** — agents invoke via `npx awal send`, `npx awal trade`, etc.
- **Skill-based** — install agent skills via `npx skills add coinbase/agentic-wallet-skills`

### 2. AgentKit SDK (Nov 2024, ongoing)
The underlying toolkit that powers Agentic Wallets:
- **Framework-agnostic** — works with LangChain, OpenAI Agents SDK, Vercel AI SDK, Model Context Protocol, Eliza, etc.
- **Wallet-agnostic** — supports CDP wallets, Privy, Viem
- **50+ onchain actions** in TypeScript, 30+ in Python
- **Languages:** TypeScript (npm) and Python (pip/poetry)
- **Networks:** All EVM chains + Solana

### 3. x402 Payment Protocol
The machine-to-machine payment standard underpinning agent commerce:
- Uses HTTP 402 Payment Required status code
- Enables pay-per-API-call, micropayments, agent-to-agent commerce
- Already has 50M+ transactions according to Coinbase
- Free tier: 1,000 transactions/month via CDP facilitator, then $0.001/tx

### 4. Smart Wallets (ERC-4337)
Account abstraction wallets with:
- Batch transactions
- Paymaster (gas sponsorship) — gasless on Base Sepolia, configurable on mainnet
- Single address across all EVM networks
- Currently supports Base Mainnet and Base Sepolia

---

## Key Security Architecture

### How Keys Are Managed
1. **TEE Isolation** — Private keys stored in Trusted Execution Environments within Coinbase infrastructure
2. **Never exposed to LLM** — The agent only sees wallet addresses, never keys
3. **MPC (Multi-Party Computation)** — No single party (including Coinbase) holds the complete private key
4. **Email OTP + Session Keys** — Authentication handled separately from wallet operations

### Guardrails
- **Spending limits** — Programmable caps per session and per transaction
- **KYT (Know Your Transaction) screening** — Automatic blocking of high-risk interactions
- **Session caps** — Time-limited autonomous operation

### Self-Custody Claim
Coinbase describes this as "self-custodial" because:
- Users can export wallets off Coinbase
- MPC means Coinbase doesn't hold complete keys
- However, keys reside in Coinbase infrastructure (TEEs)

---

## Comparison: Coinbase vs. EOA + Safe + 1Password

| Aspect | Coinbase Agentic Wallets | DIY (EOA + Safe + 1Password) |
|--------|-------------------------|------------------------------|
| **Key Storage** | Coinbase TEEs (MPC) | 1Password vault (you control) |
| **Custody Model** | "Non-custodial" via MPC | True self-custody |
| **Key Exposure to Agent** | Never (address only) | Key retrieved at runtime |
| **Setup Complexity** | Very low (npm/CLI) | Medium (Safe deployment, 1Password service account) |
| **Networks** | Base only (Agentic), EVM+Solana (AgentKit) | Any EVM chain |
| **Multisig Support** | Smart Wallet (1-of-N owners) | Safe (M-of-N, flexible) |
| **Human Override** | Via CDP portal, guardrails | Safe signer (hardware wallet) |
| **Gas Costs** | Free on Base (sponsored) | Standard gas costs |
| **Vendor Lock-in** | Yes (Coinbase infrastructure) | No (fully portable) |
| **Compliance** | Built-in KYT, screening | DIY or none |
| **Export/Portability** | Exportable (claimed) | Fully portable |
| **Trust Assumption** | Trust Coinbase TEEs | Trust 1Password, your infra |

### When Coinbase Makes Sense
- **Quick prototyping** — Get an agent wallet in minutes
- **Base-focused projects** — Free gas is compelling
- **Compliance needs** — Built-in KYT screening
- **Non-technical users** — No key management burden
- **Agent commerce** — x402 integration is native

### When DIY Makes Sense
- **True self-custody** — You hold the keys
- **Multi-chain needs** — Not locked to Base
- **Flexible multisig** — Custom M-of-N configurations
- **Privacy** — Keys never touch third-party infra
- **Existing Safe setup** — Already have Safe ecosystem integrations

---

## SDKs and APIs

### AgentKit (TypeScript)
```bash
npm install @coinbase/agentkit @coinbase/agentkit-langchain
```

### AgentKit (Python)
```bash
pip install coinbase-agentkit coinbase-agentkit-langchain
```

### Agentic Wallet CLI
```bash
npx awal status        # Check auth
npx awal send 1 vitalik.eth   # Send USDC
npx awal trade 5 usdc eth     # Swap tokens
```

### Key Repos
- **AgentKit:** https://github.com/coinbase/agentkit
- **Agent Wallet Skills:** https://github.com/coinbase/agentic-wallet-skills
- **x402 Protocol:** https://github.com/coinbase/x402
- **Smart Wallet Contracts:** https://github.com/coinbase/smart-wallet

### API Requirements
- CDP API Key (from Coinbase Developer Platform)
- OpenAI/Anthropic API key (for the LLM backing your agent)

---

## Relevance to SmartAgent/Morpheus Users

### If SmartAgent = Morpheus Smart Agents
The Morpheus ecosystem (which powers your current setup) has a different philosophy:
- **MOR staking** for inference access
- **Decentralized providers** vs. Coinbase infrastructure
- **Self-hosted** by default

Coinbase's approach could complement this for users who:
1. Want managed wallet infrastructure without key management
2. Need built-in compliance/KYT for regulated use cases
3. Are primarily operating on Base
4. Want to use x402 for agent-to-agent payments

### Integration Possibilities
AgentKit is explicitly wallet-agnostic. In theory, one could:
- Use AgentKit's action providers with a different wallet backend
- Integrate x402 payments into a Morpheus-based agent
- Use CDP's Smart Wallet alongside existing Safe setup

### Limitations for Morpheus Users
- **Network focus** — Heavy Base focus doesn't align with multi-chain DeFi
- **Centralization** — Contradicts Morpheus's decentralization ethos
- **Vendor dependency** — Relies on Coinbase CDP infrastructure

---

## Pricing (Best Available Info)

| Service | Free Tier | Paid |
|---------|-----------|------|
| x402 Facilitator | 1,000 tx/month | $0.001/tx |
| Smart Wallet (Base Sepolia) | Gas sponsored | — |
| Smart Wallet (Base Mainnet) | Requires your own Paymaster | Custom |
| AgentKit SDK | Open source | — |
| CDP API | Generous free tier | Usage-based |

---

## Key Takeaways

1. **This is very new** — Launched Feb 11, 2026; expect rapid iteration
2. **Base-centric** — Clearly designed to drive Base adoption
3. **Security model is different, not better** — TEE + MPC vs. true self-custody are different threat models
4. **Not mutually exclusive** — Could use AgentKit actions with your own wallet
5. **x402 is interesting** — The payment protocol could become a standard regardless of wallet choice
6. **SmartAgent angle** — Good for users who don't want key management; less relevant for power users already comfortable with Safe + 1Password

---

## Sources

- Coinbase Agentic Wallet docs: https://docs.cdp.coinbase.com/agentic-wallet/welcome
- AgentKit docs: https://docs.cdp.coinbase.com/agent-kit/welcome
- x402 docs: https://docs.cdp.coinbase.com/x402/welcome
- AgentKit GitHub: https://github.com/coinbase/agentkit
- Decrypt coverage: https://decrypt.co/357813/coinbase-launches-wallet-ai-agents-built-in-guardrails
- The Block coverage: https://www.theblock.co/post/389524/coinbase-rolls-out-ai-tool-to-give-any-agent-a-wallet

---

*Research compiled 2026-02-13 by Bernardo*
