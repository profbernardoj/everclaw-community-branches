# HEARTBEAT.md — BitcoinClaw

## Price Check
- Check BTC price; alert if 24h move exceeds threshold in TOOLS.md (default >5%)
- Check if price hit any target levels set in watchlist

## Mempool Status
- Check mempool congestion and current fee estimates
- If a pending transaction is tracked, check confirmation status

## Network Health
- Check if blocks are coming in on schedule (~10 min average)
- Flag if hashrate dropped significantly or difficulty adjustment is imminent

## DCA Reminder
- If a DCA schedule is set, remind when it's time to execute

## Quiet Hours
- Between 23:00–07:00: only alert for moves >10% or tracked transaction confirmations
