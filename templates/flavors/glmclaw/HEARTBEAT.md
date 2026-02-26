# HEARTBEAT.md — GLMClaw

## Model Availability
- Check Morpheus local proxy for GLM-5 and GLM 4.7 Flash availability
- If local node is down, check Morpheus Gateway as backup
- Alert if both are unreachable

## Inference Quality
- If quality logging is enabled, check recent response scores
- Flag any quality degradation trend

## New Releases
- Weekly check for new GLM model releases from Zhipu

## Quiet Hours
- Between 23:00–07:00: only alert if all GLM inference endpoints are down
