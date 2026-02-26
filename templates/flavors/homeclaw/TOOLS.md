# TOOLS.md — HomeClaw

## Required Skills

### weather
- **What:** Weather forecasts for climate automation
- **Install:** Built into OpenClaw
- **Use:** Adjust recommendations based on outdoor conditions

## Recommended Skills (install based on your platform)

### Home Assistant
- `clawhub install homeassistant-skill` or `clawhub install homeassistant-assist`
- **What:** Full Home Assistant integration — devices, automations, scenes
- **Setup:** Requires Home Assistant instance with Long-Lived Access Token
- **Config:** Set HA URL and token in skill config

### OpenHue
- Built into OpenClaw (`openhue`)
- **What:** Philips Hue lights control
- **Setup:** Press bridge button during pairing

### Homey
- `clawhub install homey-cli`
- **What:** Homey hub integration
- **Setup:** Requires Homey account credentials

### Google Home
- `clawhub install google-home-control`
- **What:** Google Nest/Home device control
- **Setup:** Requires Google Home API access

### Xiaomi Home
- `clawhub install xiaomi-home`
- **What:** Xiaomi/Mi Home ecosystem devices
- **Setup:** Requires Xiaomi account credentials

## Configuration

### Home Layout
<!-- Define rooms and their devices -->
```
rooms:
  living_room:
    lights: ["ceiling", "lamp_left", "lamp_right"]
    thermostat: "main_thermostat"
    speakers: ["sonos_living"]
    sensors: ["motion_living", "temp_living"]
  bedroom:
    lights: ["overhead", "bedside_left", "bedside_right"]
    sensors: ["motion_bedroom"]
  kitchen:
    lights: ["ceiling", "under_cabinet"]
    appliances: ["coffee_maker"]
  front_door:
    lock: "front_lock"
    camera: "doorbell_cam"
    sensor: "door_contact"
```

### Scenes
<!-- Pre-defined scenes -->
```
scenes:
  good_morning:
    - lights: "kitchen.ceiling ON 80%"
    - lights: "living_room.ceiling ON 60%"
    - coffee_maker: "ON"
    - thermostat: "72F"
  good_night:
    - lights: "ALL OFF"
    - lock: "front_lock LOCK"
    - thermostat: "68F"
  movie_time:
    - lights: "living_room.ceiling OFF"
    - lights: "living_room.lamp_left ON 20%"
  away:
    - lights: "ALL OFF"
    - thermostat: "65F"
    - lock: "ALL LOCK"
```

### Comfort Thresholds
```
comfort:
  temperature:
    min: 68
    max: 76
    unit: "F"
  humidity:
    min: 30
    max: 60
```

### Maintenance Schedule
```
maintenance:
  - item: "HVAC filter"
    interval_days: 90
    last_replaced: "2026-01-15"
  - item: "Smoke detector batteries"
    interval_days: 180
    last_replaced: "2025-12-01"
  - item: "Water filter"
    interval_days: 60
    last_replaced: "2026-02-01"
```
