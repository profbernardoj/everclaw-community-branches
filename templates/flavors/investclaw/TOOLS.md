# TOOLS.md — InvestClaw

## Required Skills

### web_search (Brave Search)
- **What:** Market news, earnings reports, research
- **Install:** Built into OpenClaw
- **Use:** Market research, news monitoring, company lookups

### web_fetch
- **What:** Fetch detailed content from financial sites
- **Install:** Built into OpenClaw
- **Use:** Read full articles, research reports, SEC filings

### finance-tracker (EverClaw)
- **What:** Daily portfolio tracking via x402 micropayments to CoinGecko
- **Install:** Included in EverClaw
- **Setup:** Requires funded agent wallet (USDC on Base, ~$0.01/request)
- **Use:** Automated daily price snapshots, portfolio value tracking

## Optional Skills (install via ClawHub)

### crypto-watcher
- `clawhub install crypto-watcher`
- Real-time crypto price monitoring and alerts

### defi-yield-scanner
- `clawhub install defi-yield-scanner`
- Scan DeFi protocols for yield opportunities

### summarize
- Built into OpenClaw
- Summarize earnings calls, research reports, long articles

## Configuration

### Portfolio Holdings
<!-- Track your positions here -->
```
portfolio:
  crypto:
    - symbol: "BTC"
      amount: 0.5
      cost_basis: 45000
    - symbol: "ETH"
      amount: 10
      cost_basis: 2800
    - symbol: "MOR"
      amount: 9000
      cost_basis: 12.50
      staking: true
  stocks:
    - symbol: "AAPL"
      shares: 100
      cost_basis: 175
  # Add your actual positions
```

### Watchlist
<!-- Assets you're monitoring but don't hold -->
```
watchlist:
  - symbol: "SOL"
    target_buy: 80
    notes: "Waiting for pullback"
  - symbol: "AAVE"
    target_buy: 200
    notes: "DeFi rotation thesis"
```

### Alert Thresholds
```
alerts:
  portfolio_move: 5       # alert if any position moves >5% in a day
  watchlist_target: true   # alert when watchlist item hits target price
  market_move: 2           # alert on broad market >2% daily move
  critical_move: 10        # always alert, even during quiet hours
```

### Tracking Preferences
```
preferences:
  base_currency: "USD"
  snapshot_frequency: "daily"
  tax_jurisdiction: "US"
  fiscal_year_end: "12-31"
  investment_style: "long-term"  # day-trade | swing | long-term | hodl
```
