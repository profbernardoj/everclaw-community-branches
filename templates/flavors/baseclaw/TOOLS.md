# TOOLS.md — BaseClaw

## Required Skills

### web_search (Brave Search)
- **What:** Base ecosystem news, protocol research, Farcaster activity
- **Install:** Built into OpenClaw
- **Use:** Protocol research, ecosystem tracking, market analysis

### web_fetch
- **What:** Fetch data from BaseScan, DeFi dashboards, Farcaster
- **Install:** Built into OpenClaw
- **Use:** Contract verification, TVL data, social protocol content

## EverClaw Modules

### finance-tracker
- Included in EverClaw
- Daily portfolio snapshots via x402 micropayments on Base

### agent-registry (scripts/agent-registry.mjs)
- Included in EverClaw
- Read ERC-8004 Identity and Reputation registries on Base

## Free Data Sources

### Explorers
- `https://basescan.org` — primary Base explorer

### DeFi
- `https://defillama.com/chain/Base` — TVL and yields
- `https://aerodrome.finance` — leading Base DEX
- `https://app.aave.com` — Aave on Base
- `https://app.morpho.org` — Morpho lending

### Agent Economy
- ERC-8004 Identity Registry: `0x8004A169FB4a3325136EB29fA0ceB6D2e539a432`
- ERC-8004 Reputation Registry: `0x8004BAa17C55a88189AE136b182e5fdA19dE9b63`
- USDC on Base: `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`
- x402 Facilitator: `https://api.cdp.coinbase.com/platform/v2/x402`

### Social
- `https://warpcast.com` — Farcaster client
- `https://dune.com/browse/dashboards?q=base` — Base analytics

### Bridges
- `https://bridge.base.org` — official Base bridge
- `https://across.to` — fast bridge
- `https://relay.link` — Relay bridge

## Optional Skills (install via ClawHub)

### crypto-watcher
- `clawhub install crypto-watcher`
- Real-time price monitoring

## Configuration

### Holdings
```
holdings:
  eth:
    amount: 0
    wallet: ""              # watch-only
  usdc:
    amount: 0
  tokens:
    - symbol: "AERO"
      amount: 0
    - symbol: "DEGEN"
      amount: 0
```

### DeFi Positions
```
defi:
  - protocol: "Aerodrome"
    type: "liquidity_pool"
    pairs: []
  - protocol: "Aave V3"
    type: "lending"
    assets: []
  - protocol: "Morpho"
    type: "lending"
    assets: []
```

### Agent Registry
```
agent_registry:
  tracked_agents: []
  # - agent_id: 1
  #   name: "ClawNews"
  own_agent_id: null          # your agent's ID once registered
```

### Alert Thresholds
```
alerts:
  eth_daily_move: 5
  token_daily_move: 10
  critical_move: 15
  sequencer_down: true
```

### Coinbase Integration
```
coinbase:
  smart_wallet: false         # using Coinbase Smart Wallet?
  fiat_onramp: true           # show fiat onramp guidance
```
