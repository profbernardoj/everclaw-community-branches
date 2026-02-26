# HEARTBEAT.md — AppleClaw

## System Health
- Check disk usage — alert if boot volume >85%
- Check for pending macOS updates (`softwareupdate -l`)
- Check Time Machine — when was the last successful backup?

## Apple Services
- Check iCloud storage usage — alert if >90%
- Verify key services running (Finder, Dock, WindowServer)

## Reminders & Notes
- Check Apple Reminders for items due today
- Flag any overdue reminders

## Homebrew
- Check for outdated Homebrew packages (weekly, not every heartbeat)
- Alert on security-related updates only

## Quiet Hours
- Between 22:00–07:00: only alert for critical system issues or Time Machine failures
