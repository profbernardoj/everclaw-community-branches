# TOOLS.md — SolanaClaw

## Required Skills

### web_search (Brave Search)
- **What:** Solana ecosystem news, protocol research, market analysis
- **Install:** Built into OpenClaw
- **Use:** Project research, airdrop tracking, governance proposals

### web_fetch
- **What:** Fetch data from Solana explorers, DeFi dashboards, project sites
- **Install:** Built into OpenClaw
- **Use:** Transaction details, protocol data, validator stats

## Free Data Sources

### Explorers
- `https://solscan.io` — primary Solana explorer
- `https://explorer.solana.com` — official explorer
- `https://xray.helius.xyz` — transaction viewer

### DeFi
- `https://defillama.com/chain/Solana` — TVL and yields
- `https://jup.ag` — Jupiter aggregator (swap routes)
- `https://app.marinade.finance` — liquid staking
- `https://drift.trade` — perpetuals

### Staking
- `https://stakewiz.com` — validator comparison
- `https://solanabeach.io/validators` — validator dashboard

### NFTs
- `https://magiceden.io` — primary NFT marketplace
- `https://tensor.trade` — NFT trading and analytics

## Optional Skills (install via ClawHub)

### crypto-watcher
- `clawhub install crypto-watcher`
- Real-time price monitoring for SOL and SPL tokens

### finance-tracker (EverClaw)
- Included in EverClaw
- Daily portfolio snapshots

## Configuration

### SOL Holdings
```
holdings:
  sol:
    staked: 0
    liquid: 0
    wallet: ""           # watch-only address
    validator: ""
    validator_name: ""
  spl_tokens:
    - symbol: "JUP"
      amount: 0
    - symbol: "BONK"
      amount: 0
    - symbol: "JTO"
      amount: 0
```

### DeFi Positions
```
defi:
  - protocol: "Marinade"
    type: "liquid_staking"
    asset: "mSOL"
    amount: 0
  - protocol: "Raydium"
    type: "liquidity_pool"
    pair: "SOL/USDC"
    amount: 0
  - protocol: "Drift"
    type: "perps"
    positions: []
```

### Alert Thresholds
```
alerts:
  sol_daily_move: 5
  token_daily_move: 10
  critical_move: 15
  validator_skip_rate_max: 5     # percent
  network_tps_min: 1000          # alert below this
```

### NFT Collections (optional)
```
nfts:
  tracked_collections: []
  # - collection: "Mad Lads"
  #   floor_alert_below: 50    # SOL
```
