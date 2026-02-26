# TOOLS.md — ArbClaw

## Required Skills

### web_search (Brave Search)
- **What:** Arbitrum ecosystem news, protocol research, governance
- **Install:** Built into OpenClaw
- **Use:** Protocol research, DAO proposals, ecosystem developments

### web_fetch
- **What:** Fetch data from Arbiscan, DeFi dashboards, governance portals
- **Install:** Built into OpenClaw
- **Use:** Contract verification, proposal details, TVL data

## Free Data Sources

### Explorers
- `https://arbiscan.io` — primary Arbitrum explorer
- `https://nova.arbiscan.io` — Arbitrum Nova explorer

### DeFi
- `https://defillama.com/chain/Arbitrum` — TVL and yields
- `https://app.gmx.io` — GMX perpetuals and GLP
- `https://app.camelot.exchange` — Camelot DEX
- `https://app.pendle.finance` — Pendle yield trading
- `https://app.aave.com` — Aave on Arbitrum

### Governance
- `https://www.tally.xyz/gov/arbitrum` — ARB DAO governance
- `https://snapshot.org/#/arbitrumfoundation.eth` — Snapshot votes
- `https://forum.arbitrum.foundation` — governance forum

### Bridges
- `https://bridge.arbitrum.io` — native bridge (7-day withdrawal)
- `https://across.to` — fast bridge
- `https://stargate.finance` — cross-chain bridge
- `https://app.hop.exchange` — Hop Protocol bridge

## Optional Skills (install via ClawHub)

### crypto-watcher
- `clawhub install crypto-watcher`
- Real-time price monitoring

### defi-yield-scanner
- `clawhub install defi-yield-scanner`
- Scan Arbitrum protocols for yield opportunities

## Configuration

### Holdings
```
holdings:
  arb:
    amount: 0
    staked: 0
    delegated_to: ""
    wallet: ""              # watch-only address
  tokens:
    - symbol: "GMX"
      amount: 0
    - symbol: "GLP"
      amount: 0
    - symbol: "MAGIC"
      amount: 0
```

### DeFi Positions
```
defi:
  - protocol: "GMX"
    type: "perpetuals"
    chain: "arbitrum"
    positions: []
  - protocol: "Aave V3"
    type: "lending"
    chain: "arbitrum"
    assets: []
  - protocol: "Camelot"
    type: "liquidity_pool"
    chain: "arbitrum"
    pairs: []
```

### Bridge Tracking
```
bridges:
  pending_transfers: []
  # - bridge: "native"
  #   direction: "arb_to_eth"
  #   amount: "1 ETH"
  #   initiated: "2026-02-20"
  #   claimable: "2026-02-27"
  preferred_bridge: "across"    # for fast transfers
```

### Alert Thresholds
```
alerts:
  arb_daily_move: 5
  token_daily_move: 10
  critical_move: 15
  gas_low_threshold: 0.1       # gwei — Arbitrum gas is cheap
  sequencer_down: true          # always alert
```

### Governance
```
governance:
  delegate: ""                  # address you've delegated to
  track_proposals: true
  vote_reminder_hours: 24       # remind X hours before vote ends
  forum_topics: []              # specific topics to monitor
```
