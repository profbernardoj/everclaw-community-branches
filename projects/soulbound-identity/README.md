# Soulbound Agent Identity

On-chain identity binding for OpenClaw agents using ERC-8004 + ERC-6551 + ERC-5192.

## Architecture

Each agent's core identity files (SOUL.md, USER.md, IDENTITY.md) are hash-anchored
on-chain via an ERC-8004 Identity Registry NFT on Base. The NFT is soulbound (ERC-5192)
— permanently locked to the user's wallet. Each NFT gets a Token Bound Account (ERC-6551)
that serves as the agent's on-chain wallet.

## Standards Stack

| Standard | Purpose |
|----------|---------|
| ERC-8004 | Identity Registry — agent NFT with URI pointing to registration file |
| ERC-6551 | Token Bound Accounts — each NFT gets its own smart contract wallet |
| ERC-5192 | Soulbound — NFTs are non-transferable, permanently bound to owner |
| ERC-721  | Base NFT standard (used by all above) |

## Agent Roster

### Business Agents (Mac Mini #1)
1. **Web3 Agent** — Morpheus ecosystem, decentralized inference
2. **Agentic AI Agent** — EverClaw, 28 flavors, ClawHub
3. **Corporate Agent** — Based AI, enterprise
4. **Advisor Agent** — External project advisory
5. **David Agent** — Public-facing David clone (March project)

### Personal Agents (Mac Mini #2)
6-12. Owner, Family Member 1-6 (personal agents)

## Directory Structure

```
contracts/          Solidity contracts (SoulboundIdentityNFT)
scripts/            CLI tools for registration, verification, updates
lib/                Shared libraries (hashing, IPFS, chain interaction)
test/               Local tests
config/             Agent registration configs
```

## Key Addresses (Base Mainnet)

- Identity Registry: `0x8004A169FB4a3325136EB29fA0ceB6D2e539a432`
- Reputation Registry: `0x8004BAa17C55a88189AE136b182e5fdA19dE9b63`
- ERC-6551 Registry: `0x000000006551c19487814612e58FE06813775758`
- ERC-6551 Account Implementation: `0x55266d75D1a14E4572138116aF39863Ed6596E7F`

## Status

⚠️ LOCAL DEVELOPMENT ONLY — no public pushes until agents are separated.
