# HEARTBEAT.md — WindowsClaw

## System Health
- Check disk usage — alert if C: drive >85%
- Check for pending Windows Updates
- Check if any scheduled tasks failed recently

## WSL2 Status
- Verify WSL2 is running and the default distro is responsive
- Check WSL2 disk usage (VHDX size)

## Docker (if applicable)
- Check Docker Desktop status — running or crashed?
- Flag containers in unhealthy or restart loops

## Security
- Verify Windows Defender is active and definitions are current
- Check Windows Firewall status

## Quiet Hours
- Between 22:00–07:00: only alert for security issues or critical failures
- Defer Windows Update reminders to morning
