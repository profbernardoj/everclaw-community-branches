# TOOLS.md — AndroidClaw

## Required Skills

### exec (Shell Access via Termux)
- **What:** Full Linux shell on Android
- **Install:** Install Termux from F-Droid (not Play Store — F-Droid version gets updates)
- **Setup:** `pkg update && pkg upgrade` then `pkg install openssh python nodejs git`
- **Use:** Primary tool — bash scripts, cron, ssh, dev tools

## Key Termux Packages
```bash
# Essentials
pkg install termux-api       # Android API access (notifications, clipboard, sensors)
pkg install openssh           # SSH client/server
pkg install git               # Version control
pkg install nodejs            # Node.js runtime (for OpenClaw)
pkg install python            # Python runtime
pkg install cronie            # Cron daemon for scheduled tasks

# Useful extras
pkg install termux-tools      # termux-reload-settings, etc.
pkg install jq                # JSON processing
pkg install curl wget         # HTTP tools
pkg install rsync             # File sync
pkg install neovim            # Text editor
```

## Termux:API Commands
```bash
termux-battery-status         # Battery level and charging state
termux-notification           # Send Android notifications
termux-clipboard-get/set      # System clipboard access
termux-toast                  # Quick toast messages
termux-wifi-connectioninfo    # WiFi details
termux-location               # GPS location (permission required)
termux-camera-photo           # Take a photo (permission required)
termux-sms-list               # Read SMS (permission required)
termux-tts-speak              # Text-to-speech
termux-vibrate                # Vibration feedback
termux-storage-get            # Access shared storage
```

## Optional Skills (install via ClawHub)

### summarize
- Built into OpenClaw
- Quick content summaries optimized for mobile reading

### weather
- Built into OpenClaw
- Lightweight weather checks

## Configuration

### Device Info
```
device:
  model: ""
  android_version: ""
  termux_version: ""
  storage_total_gb: 0
  storage_warning_gb: 2
  battery_warning_percent: 20
```

### SSH Tunnels
```
# Access home/work servers from mobile
tunnels:
  - name: "home-server"
    host: ""
    port: 22
    user: ""
    key: "~/.ssh/id_ed25519"
    local_port: 8080
    remote_port: 8080
```

### Sync Config
```
sync:
  method: "rsync"  # rsync | git | syncthing
  targets:
    - name: "workspace"
      local: "~/.openclaw/workspace"
      remote: ""
      frequency: "on-wifi"  # on-wifi | manual | hourly
```

### Power Profiles
```
# Adjust behavior based on battery level
power_profiles:
  normal:
    battery_above: 50
    heartbeat_interval: 30    # minutes
    sync: true
    background_tasks: true
  low_power:
    battery_above: 20
    heartbeat_interval: 60
    sync: false
    background_tasks: false
  critical:
    battery_above: 0
    heartbeat_interval: 0     # disabled
    sync: false
    background_tasks: false
```
