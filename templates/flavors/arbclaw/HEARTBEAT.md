# HEARTBEAT.md — ArbClaw

## Price Check
- Check ARB price; alert if 24h move >5%
- Check tracked Arbitrum tokens against alert thresholds

## DeFi Positions
- Check health of tracked positions (GMX, lending, LPs)
- Alert on liquidation proximity, significant yield changes, or IL thresholds

## Bridge Monitor
- Check for any pending bridge transfers (native bridge has 7-day delay)
- Alert when a bridge transfer is claimable

## Governance
- Check for active ARB DAO proposals
- Alert if a vote is ending within 24 hours

## Network Status
- Check sequencer status — alert if down
- Note if gas is unusually low (good time for transactions)

## Quiet Hours
- Between 23:00–07:00: only alert for >10% moves, liquidation risk, sequencer outage, or claimable bridge transfers
