# HEARTBEAT.md — InvestClaw

## Price Alert Check
- Check current prices for portfolio holdings against alert thresholds in TOOLS.md
- Alert if any position moved >5% since last check
- Alert if any watchlist item hit a target price

## Portfolio Snapshot
- If last snapshot is >24h old, take a new one and save to `memory/portfolio/`

## Market Context
- Quick check: is the broad market (S&P, BTC, ETH) making a significant move today (>2%)?
- If yes, provide brief context

## Quiet Hours
- Between 22:00–07:00 local time: only alert for moves >10%
- Weekends: reduce check frequency, crypto only (traditional markets closed)
