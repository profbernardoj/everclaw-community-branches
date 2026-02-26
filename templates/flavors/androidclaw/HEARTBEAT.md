# HEARTBEAT.md — AndroidClaw

## Device Health
- Check battery level — if <20%, reduce background activity
- Check storage — alert if <2GB free
- Check connectivity status (wifi/cellular/offline)

## Queued Tasks
- Check for any tasks queued during offline periods
- Execute queued items if now connected

## Termux Services
- Verify any background Termux services are running (sshd, crond, etc.)
- Alert if a critical service stopped

## Quiet Hours
- Between 23:00–07:00: suppress all non-critical alerts
- Battery-critical alerts (<5%) always come through
