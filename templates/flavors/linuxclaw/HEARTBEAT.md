# HEARTBEAT.md — LinuxClaw

## System Health
- Check disk usage — alert if any partition is >85% full
- Check for failed systemd services (`systemctl --failed`)
- Check system load average — alert if >80% sustained

## Security
- Check for pending security updates (`apt list --upgradable` or equivalent)
- Check fail2ban status — any recent bans?
- Check SSH auth log for unusual login attempts

## Docker (if applicable)
- Check for containers in unhealthy or restarting state
- Check disk usage of Docker volumes

## Backup Verification
- Check when the last backup ran (from `memory/backups/` log)
- Alert if last backup is >24h old (or whatever the configured interval is)

## Quiet Hours
- No quiet hours for server monitoring — alert anytime for critical issues
- Non-critical items (pending updates, routine stats) only during business hours
