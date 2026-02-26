# HEARTBEAT.md — BookingClaw

## Upcoming Trip Check
- Check `memory/travel/` for trips in the next 14 days
- If a trip is <72 hours away, verify: flights confirmed, hotel confirmed, check-in available
- If a trip is <24 hours away, remind about check-in, packing, and travel documents

## Price Watch
- Check `memory/travel/price-watches.md` for active fare monitors
- If a tracked flight/hotel dropped >10% from last check, alert the user
- Remove watches for trips that have been booked

## Quiet Hours
- Between 22:00–07:00 local time: only alert for day-of travel issues (delays, cancellations, gate changes)
