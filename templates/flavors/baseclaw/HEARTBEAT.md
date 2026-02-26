# HEARTBEAT.md — BaseClaw

## Portfolio Check
- Check ETH and USDC balances on Base
- Check tracked token prices; alert if any moved >5% in 24h

## DeFi Positions
- Check health of tracked positions (Aerodrome, Aave, etc.)
- Alert on yield changes or position health warnings

## Agent Registry
- Check ERC-8004 registry for any new agent registrations or reputation updates relevant to tracked agents

## Bridge Monitor
- Check for pending bridge transfers between mainnet and Base
- Alert when transfers are claimable

## Network
- Check Base sequencer status
- Note if gas is unusually elevated (rare on Base, but worth catching)

## Quiet Hours
- Between 23:00–07:00: only alert for >10% moves, liquidation risk, or sequencer outage
