# HEARTBEAT.md — MiniMaxClaw

## Model Availability
- Check MiniMax M2.5 availability on Morpheus Gateway
- Check Venice for MiniMax M2.1 availability
- Alert if all providers are unreachable

## Latency Check
- If MiniMax is available, note current response latency
- Flag if latency is significantly higher than baseline (>2x normal)

## Quality Check
- If quality logging is enabled, review recent response scores
- Flag any degradation

## Quiet Hours
- Between 23:00–07:00: only alert if all MiniMax endpoints are down
