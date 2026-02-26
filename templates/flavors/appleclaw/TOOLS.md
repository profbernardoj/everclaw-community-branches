# TOOLS.md — AppleClaw

## Built-in Skills (macOS)

### apple-reminders
- **What:** Create, list, complete, and manage Apple Reminders
- **Install:** Built into OpenClaw
- **Use:** Task management via native Reminders app — syncs to all devices

### apple-notes
- **What:** Create, search, edit, and organize Apple Notes
- **Install:** Built into OpenClaw
- **Use:** Note-taking that syncs across Mac, iPhone, iPad

### peekaboo
- **What:** Capture and automate macOS UI
- **Install:** Built into OpenClaw
- **Use:** Screenshot workflows, UI element inspection, accessibility automation

### exec (Shell Access)
- **What:** Full terminal access including AppleScript via `osascript`
- **Install:** Built into OpenClaw
- **Use:** System automation, Homebrew, AppleScript, shell scripts

## Key macOS Commands
```bash
# System Info
sw_vers                           # macOS version
system_profiler SPHardwareDataType  # hardware specs
pmset -g batt                     # battery status (laptops)
df -h                             # disk usage
top -l 1 -n 10                    # process overview

# Updates
softwareupdate -l                 # list available updates
softwareupdate -ia                # install all updates

# Homebrew
brew update && brew outdated      # check for updates
brew upgrade                      # upgrade all
brew cleanup                      # free disk space

# AppleScript (via osascript)
osascript -e 'display notification "Hello" with title "AppleClaw"'
osascript -e 'tell app "Finder" to get name of every disk'
osascript -e 'tell app "System Events" to get name of every process'

# Time Machine
tmutil latestbackup               # last backup timestamp
tmutil listbackups                # all backups

# Spotlight
mdfind "kind:pdf created:today"   # search via Spotlight
```

## Optional Skills (install via ClawHub)

### gog (Google Workspace)
- Built into OpenClaw
- For users who mix Apple Calendar with Google Workspace

### weather
- Built into OpenClaw
- Siri-like weather queries from the terminal

### sonoscli / openhue
- Built into OpenClaw
- Control Sonos speakers and Hue lights from Mac

## Configuration

### System Monitoring
```
monitoring:
  disk_warning_percent: 85
  icloud_warning_percent: 90
  time_machine_max_age_hours: 24
  check_homebrew_weekly: true
```

### Automation Preferences
```
automation:
  applescript_enabled: true
  shortcuts_integration: true    # bridge to Apple Shortcuts
  focus_modes:
    - name: "Work"
      hours: "09:00-17:00"
      silence_notifications: true
    - name: "Personal"
      hours: "17:00-22:00"
      silence_notifications: false
```

### Homebrew Packages to Monitor
```
homebrew:
  critical:
    - "openclaw"
    - "signal-cli"
    - "git"
    - "node"
  optional:
    - "ffmpeg"
    - "imagemagick"
    - "jq"
```

### Backup Config
```
backup:
  time_machine: true
  time_machine_disk: ""           # disk name
  additional:
    - method: "rsync"
      destination: ""
      frequency: "daily"
```
