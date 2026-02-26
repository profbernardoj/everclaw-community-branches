# HEARTBEAT.md — EthereumClaw

## Gas Check
- Check current gas prices on mainnet
- If gas is unusually low (<15 gwei), alert — good time for pending transactions
- If gas is spiking (>50 gwei), note the cause if identifiable

## Price & Position Check
- Check ETH price; alert if 24h move exceeds threshold (default >5%)
- Check any tracked DeFi positions for health (liquidation proximity, yield changes)

## Governance Watch
- Check for any active governance votes in tracked protocols (Snapshot, on-chain)
- Alert if a vote is ending within 24 hours

## Staking Status
- If staking is tracked, check validator status and rewards accrual

## Quiet Hours
- Between 23:00–07:00: only alert for >10% moves, liquidation warnings, or critical governance votes
