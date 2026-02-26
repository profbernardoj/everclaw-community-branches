# TOOLS.md — BookingClaw

## Required Skills

### web_search (Brave Search)
- **What:** Search for flights, hotels, activities, travel info
- **Install:** Built into OpenClaw
- **Use:** Primary research tool for travel options and pricing

### web_fetch
- **What:** Fetch detailed content from travel sites
- **Install:** Built into OpenClaw
- **Use:** Read full hotel descriptions, flight details, destination guides

### gog (Google Workspace CLI)
- **What:** Calendar integration for trip dates and reminders
- **Install:** Built into OpenClaw
- **Use:** Block travel dates on calendar, set check-in reminders

## Optional Skills (install via ClawHub)

### travel-concierge
- `clawhub install travel-concierge`
- Structured travel planning with comparison tables

### weather
- Built into OpenClaw
- Destination weather forecasts for packing and planning

### summarize
- Built into OpenClaw
- Summarize hotel reviews, destination guides, travel articles

## Configuration

### Travel Preferences
<!-- Your default preferences for travel search -->
```
preferences:
  flights:
    seat: "aisle"              # window | aisle | no_preference
    class: "economy"           # economy | premium_economy | business | first
    direct_only: false
    max_layover_hours: 3
    preferred_airlines: []     # e.g., ["United", "Delta"]
    avoided_airlines: []
    home_airport: "AUS"        # IATA code
  hotels:
    style: "mid-range"         # budget | mid-range | upscale | luxury
    preferred_chains: []
    min_rating: 4.0            # out of 5
    must_have: ["wifi", "breakfast"]
  general:
    currency: "USD"
    passport_country: "US"
    passport_expiry: "2030-01-01"
    tsa_precheck: false
    global_entry: false
```

### Loyalty Programs
<!-- Track loyalty memberships -->
```
loyalty:
  - program: "United MileagePlus"
    number: "XXXXXXXXX"
    status: "Gold"
  - program: "Marriott Bonvoy"
    number: "XXXXXXXXX"
    status: "Platinum"
```

### Budget Defaults
```
budget:
  domestic_flight_max: 500
  international_flight_max: 1500
  hotel_per_night_max: 200
  daily_food_budget: 75
  trip_total_default: 3000
```
