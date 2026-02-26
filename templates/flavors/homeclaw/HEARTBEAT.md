# HEARTBEAT.md — HomeClaw

## Device Health Check
- Check for any offline or unresponsive devices
- Flag any device with low battery (<20%)
- If a critical device (lock, camera, thermostat) is offline, alert immediately

## Energy Snapshot
- If energy monitoring is configured, check for unusual usage spikes
- Compare today's usage to the 7-day average

## Security Status
- Verify all door/window sensors are in expected state
- If the house is in "away" mode and motion is detected, alert

## Climate Check
- Check indoor temperature and humidity against comfort thresholds
- If outdoor weather is changing significantly, suggest HVAC adjustments

## Quiet Hours
- Between 22:00–06:00: only alert for security events or critical device failures
