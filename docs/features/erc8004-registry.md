# ERC-8004 Agent Registry

EverClaw includes a reader for the [ERC-8004](https://eips.ethereum.org/EIPS/eip-8004) protocol — on-chain registries for agent discovery and trust on Base mainnet.

## Overview

| Aspect | Details |
|--------|---------|
| **Protocol** | ERC-8004 — Agent Identity & Reputation |
| **Chain** | Base mainnet |
| **Registries** | Identity, Reputation, Validation |
| **Use Case** | Discover agents, verify trust signals |

---

## What Is ERC-8004?

ERC-8004 defines three on-chain registries:

| Registry | Type | Purpose |
|----------|------|---------|
| **Identity** | ERC-721 | Agent NFTs with metadata (name, services, endpoints) |
| **Reputation** | Custom | Client feedback (value + tags) for agents |
| **Validation** | Custom | Stake-secured re-execution, zkML verification |

Agents are:
- **Discoverable** — Query by ID or owner
- **Portable** — Transferable NFTs
- **Verifiable** — Trust signals on-chain

---

## CLI Usage

```bash
# Look up an agent by ID
node skills/everclaw/scripts/agent-registry.mjs lookup 1

# Get reputation data
node skills/everclaw/scripts/agent-registry.mjs reputation 1

# Full discovery (identity + registration + reputation)
node skills/everclaw/scripts/agent-registry.mjs discover 1

# List agents in a range
node skills/everclaw/scripts/agent-registry.mjs list 1 10

# Get total registered agents
node skills/everclaw/scripts/agent-registry.mjs total
```

---

## Programmatic Usage

```javascript
import { 
  lookupAgent, 
  getReputation, 
  discoverAgent, 
  totalAgents, 
  listAgents 
} from './scripts/agent-registry.mjs';

// Look up identity
const agent = await lookupAgent(1);
// {
//   agentId: 1,
//   owner: "0x89E9...",
//   uri: "data:application/json;base64,...",
//   wallet: "0x89E9...",
//   registration: {
//     name: "ClawNews",
//     description: "Hacker News for AI agents...",
//     services: [{ name: "web", endpoint: "https://clawnews.io" }, ...],
//     x402Support: true,
//     active: true,
//     supportedTrust: ["reputation"]
//   }
// }

// Get reputation
const rep = await getReputation(1);
// {
//   agentId: 1,
//   clients: ["0x3975...", "0x718B..."],
//   feedbackCount: 2,
//   summary: { count: 2, value: "100", decimals: 0 },
//   feedback: [{ client: "0x3975...", value: "100", tag1: "tip", tag2: "agent" }, ...]
// }

// Full discovery
const full = await discoverAgent(1);
// Combines identity, registration, services, and reputation

// List agents
const agents = await listAgents(1, 10);
// [agent1, agent2, ..., agent10]

// Total count
const total = await totalAgents();
// 42
```

---

## Registration File Format

Agent registration files (from `tokenURI`) follow ERC-8004:

```json
{
  "type": "https://eips.ethereum.org/EIPS/eip-8004#registration-v1",
  "name": "MyAgent",
  "description": "What the agent does",
  "image": "https://example.com/logo.png",
  "services": [
    {
      "name": "web",
      "endpoint": "https://myagent.com"
    },
    {
      "name": "A2A",
      "endpoint": "https://agent.example/.well-known/agent-card.json",
      "version": "0.3.0"
    },
    {
      "name": "MCP",
      "endpoint": "https://mcp.agent.eth/",
      "version": "2025-06-18"
    }
  ],
  "x402Support": true,
  "active": true,
  "supportedTrust": ["reputation", "crypto-economic"]
}
```

### URI Types Supported

| Type | Example | Resolution |
|------|---------|------------|
| `data:` | `data:application/json;base64,...` | Decoded from base64 |
| `ipfs://` | `ipfs://Qm...` | Via public IPFS [REDACTED] |
| `https://` | `https://example.com/agent.json` | Direct HTTP fetch |

---

## Contract Addresses

Same addresses across all EVM chains:

| Registry | Address |
|----------|---------|
| Identity | `0x8004A169FB4a3325136EB29fA0ceB6D2e539a432` |
| Reputation | `0x8004BAa17C55a88189AE136b182e5fdA19dE9b63` |

**Networks:** Ethereum, Base, Arbitrum, Polygon, Optimism, Linea, Avalanche

---

## Combining with x402

Discover agents and pay for their services:

```javascript
import { discoverAgent } from './scripts/agent-registry.mjs';
import { makePayableRequest } from './scripts/x402-client.mjs';

// 1. Discover an agent
const agent = await discoverAgent(42);

// 2. Find x402-enabled service
const apiEndpoint = agent.services.find(s => s.name === "A2A")?.endpoint;

// 3. Make a paid request
if (agent.x402Support && apiEndpoint) {
  const result = await makePayableRequest(apiEndpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ task: "Analyze this data..." }),
    maxAmount: 0.50,
  });
  
  console.log(result.body);
}
```

---

## Trust Signals

### Reputation

The Reputation Registry stores feedback from clients:

```javascript
const rep = await getReputation(42);
// {
//   summary: { count: 15, value: "1250" },
//   feedback: [
//     { client: "0x...", value: "100", tag1: "quality", tag2: "fast" },
//     ...
//   ]
// }
```

### Supported Trust Types

| Type | Description |
|------|-------------|
| `reputation` | Client feedback scores |
| `crypto-economic` | Staked security |
| `validation` | Re-execution proofs |

---

## Use Cases

### Discover Agents

```javascript
// Find agents offering web services
const agents = await listAgents(1, 100);
const webAgents = agents.filter(a => 
  a.registration?.services?.some(s => s.name === "web")
);
```

### Verify Trust

```javascript
// Check if agent has good reputation
const agent = await discoverAgent(42);
const rep = agent.reputation?.summary;
if (rep && rep.count > 10 && parseInt(rep.value) > 500) {
  console.log("Trusted agent");
}
```

### Find Payment-Enabled Agents

```javascript
// Find agents that accept x402 payments
const payableAgents = agents.filter(a => a.registration?.x402Support);
```

---

## Troubleshooting

### "Agent not found"

The agent ID doesn't exist or hasn't been registered:
```bash
node scripts/agent-registry.mjs total  # Check total registered
```

### "URI resolution failed"

The registration file couldn't be fetched:
- Check if the `tokenURI` is accessible
- IPFS [REDACTED] may be rate-limited

### "Contract call failed"

RPC endpoint issues:
- Check `ETH_NODE_ADDRESS` in your environment
- Try a different RPC provider

---

## Next Steps

- [x402 Payments](x402-payments.md) — Pay discovered agents
- [Wallet Management](wallet.md) — Check USDC balance for payments