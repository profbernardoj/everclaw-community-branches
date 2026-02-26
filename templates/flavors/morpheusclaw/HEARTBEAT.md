# HEARTBEAT.md — MorpheusClaw

## Node Health
- Check local proxy router status (http://127.0.0.1:8083/v1)
- Verify at least one model is responding (GLM-5, Kimi K2.5, etc.)
- If node is down, alert immediately

## MOR Token Check
- Check MOR price; alert if 24h move >10%
- Check staking rewards accrual if tracked

## Network Status
- Check Morpheus API Gateway availability (https://api.mor.org)
- Note any new models added to the network

## Quiet Hours
- Between 23:00–07:00: only alert if local node is down or MOR moves >15%
