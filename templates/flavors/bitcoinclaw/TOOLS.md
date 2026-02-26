# TOOLS.md — BitcoinClaw

## Required Skills

### web_search (Brave Search)
- **What:** Bitcoin news, analysis, protocol developments
- **Install:** Built into OpenClaw
- **Use:** Market research, BIP tracking, ecosystem developments

### web_fetch
- **What:** Fetch data from mempool explorers, block explorers, news sites
- **Install:** Built into OpenClaw
- **Use:** mempool.space data, block explorer lookups, full article reads

## Optional Skills (install via ClawHub)

### crypto-watcher
- `clawhub install crypto-watcher`
- Real-time price monitoring and alerts

### summarize
- Built into OpenClaw
- Summarize long Bitcoin discussions, whitepapers, podcast transcripts

## Free Data Sources (no API key needed)

### mempool.space API
- `https://mempool.space/api/v1/fees/recommended` — fee estimates
- `https://mempool.space/api/block-height/tip` — current block height
- `https://mempool.space/api/mempool` — mempool stats
- `https://mempool.space/api/tx/{txid}` — transaction lookup

### Blockchain.info
- `https://blockchain.info/ticker` — BTC price in multiple currencies
- `https://blockchain.info/q/hashrate` — current hashrate

### Blockstream.info
- `https://blockstream.info/api/blocks/tip/height` — block height
- `https://blockstream.info/api/address/{addr}` — address lookup (watch-only)

## Configuration

### Price Alerts
```
alerts:
  daily_move_threshold: 5     # alert on >5% 24h move
  critical_threshold: 10      # alert even during quiet hours
  target_prices:
    - price: 100000
      direction: "above"
      note: "Six figures"
    - price: 75000
      direction: "below"
      note: "Support level"
```

### DCA Schedule
```
dca:
  enabled: false
  frequency: "weekly"          # daily | weekly | biweekly | monthly
  day: "Monday"
  amount_usd: 100
  exchange: ""                 # where you execute (manual reminder only)
  started: "2025-01-01"
```

### Halving Tracker
```
halving:
  last_halving_block: 840000
  last_halving_date: "2024-04-20"
  next_halving_block: 1050000
  blocks_per_day: 144
  current_subsidy_btc: 3.125
```

### Watch-Only Addresses (optional, opt-in only)
```
# WARNING: Adding addresses here creates a privacy tradeoff.
# Only add if you want balance/UTXO monitoring.
watch_only:
  enabled: false
  addresses: []
```

### Privacy Preferences
```
privacy:
  track_addresses: false     # set to true only if explicitly opted in
  avoid_address_reuse: true
  coin_selection: "manual"   # manual | automatic
  tor_enabled: false         # for API calls through Tor
```
