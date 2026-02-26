# HEARTBEAT.md — SolanaClaw

## Price Check
- Check SOL price; alert if 24h move >5%
- Check tracked SPL tokens against alert thresholds

## Staking Status
- Check staking rewards and validator performance
- Flag if selected validator's skip rate is increasing or commission changed

## DeFi Positions
- Check health of any tracked DeFi positions (LP, lending, perps)
- Alert on significant yield changes or impermanent loss thresholds

## Network Health
- Check Solana TPS and slot times
- Alert if network is degraded or experiencing congestion

## Quiet Hours
- Between 23:00–07:00: only alert for >10% moves, liquidation risk, or network outages
