#!/bin/bash
# always-on.sh — Configure macOS to never sleep (for 24/7 agent operation)
#
# Sets up power management for always-on Mac Mini / Mac Studio:
# - disables sleep entirely (SleepDisabled = 1)
# - Disables standby/hibernation
# - Enables Power Nap for network wake
# - Enables Wake on Mobile / remote access
# - Sets auto-restart after power failure
#
# Usage: sudo bash scripts/always-on.sh [--restore]
#
# --restore: Reset to default power settings
#
# Requires: macOS, sudo

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo "╔══════════════════════════════════════════╗"
echo "║  Everclaw — Always-On Setup for macOS    ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# Check for macOS
if [[ "$(uname)" != "Darwin" ]]; then
  echo -e "${RED}Error: This script is for macOS only.${NC}"
  echo "For Linux, use systemd to prevent sleep or run headless."
  echo ""
  echo "Linux equivalent:"
  echo "  sudo systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target"
  exit 1
fi

# Check for sudo
if [[ $EUID -ne 0 ]]; then
  echo -e "${RED}Error: This script requires sudo to modify power settings.${NC}"
  echo "Run: sudo bash $0 $@"
  exit 1
fi

# Get the actual user (not root)
ACTUAL_USER="${SUDO_USER:-$USER}"
USER_HOME=$(eval echo ~"$ACTUAL_USER")

# --- Restore mode ---
if [[ "${1:-}" == "--restore" ]]; then
  echo -e "${YELLOW}Restoring default power settings...${NC}"
  echo ""
  
  # Re-enable sleep
  pmset -a disablesleep 0 2>/dev/null || true
  
  # Re-enable standby
  pmset -a standby 1 2>/dev/null || true
  pmset -a autopoweroff 1 2>/dev/null || true
  
  # Default display sleep
  pmset -a displaysleep 10 2>/dev/null || true
  
  echo -e "${GREEN}✓ Power settings restored to defaults.${NC}"
  echo ""
  pmset -g
  exit 0
fi

# --- Check current settings ---
echo "📋 Current power settings:"
echo ""
pmset -g
echo ""

# --- Apply always-on settings ---
echo -e "${YELLOW}Applying always-on power settings...${NC}"
echo ""

# 1. Disable sleep entirely (system-wide)
echo "   Disabling system sleep..."
pmset -a disablesleep 1

# 2. Disable standby/hibernation (prevents deep sleep)
echo "   Disabling standby and hibernation..."
pmset -a standby 0
pmset -a autopoweroff 0
pmset -a hibernatemode 0

# 3. Keep display awake (optional but helpful for monitoring)
# Set to 0 for never, or a reasonable timeout like 10 minutes
echo "   Setting display sleep to 10 minutes..."
pmset -a displaysleep 10

# 4. Enable Power Nap (allows network activity while display off)
echo "   Enabling Power Nap..."
pmset -a powernap 1

# 5. Enable Wake on LAN / remote access
echo "   Enabling Wake on LAN..."
pmset -a womp 1

# 6. Enable auto-restart after power failure
echo "   Enabling auto-restart after power failure..."
pmset -a autorestart 1

# 7. Keep network connections alive
echo "   Enabling network keepalive..."
pmset -a tcpkeepalive 1
pmset -a networkoversleep 0

# 8. Keep disks spinning (prevents spin-up delays)
echo "   Setting disk sleep to 0 (never spin down)..."
pmset -a disksleep 0

echo ""
echo -e "${GREEN}✓ Always-on settings applied successfully!${NC}"
echo ""

# --- Show new settings ---
echo "📋 New power settings:"
echo ""
pmset -g
echo ""

# --- Verify SleepDisabled is set ---
SLEEP_DISABLED=$(pmset -g | grep "SleepDisabled" | awk '{print $2}')
if [[ "$SLEEP_DISABLED" == "1" ]]; then
  echo -e "${GREEN}✓ Verified: System sleep is DISABLED${NC}"
else
  echo -e "${RED}⚠ Warning: SleepDisabled is not set to 1. Sleep may still occur.${NC}"
fi

# --- Create a LaunchAgent to prevent display sleep when logged in ---
LAUNCH_AGENT="$USER_HOME/Library/LaunchAgents/com.everclaw.alwayson.plist"
echo ""
echo -e "${YELLOW}Creating LaunchAgent to prevent system sleep while OpenClaw runs...${NC}"

mkdir -p "$USER_HOME/Library/LaunchAgents"

cat > "$LAUNCH_AGENT" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.everclaw.alwayson</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/caffeinate</string>
        <string>-i</string>
        <string>-d</string>
        <string>-s</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ProcessType</key>
    <string>Background</string>
    <key>LowPriorityIO</key>
    <true/>
</dict>
</plist>
EOF

# Fix ownership
chown "$ACTUAL_USER:staff" "$LAUNCH_AGENT"
chmod 644 "$LAUNCH_AGENT"

echo "   ✓ Created $LAUNCH_AGENT"

# Load the LaunchAgent
launchctl unload "$LAUNCH_AGENT" 2>/dev/null || true
launchctl load "$LAUNCH_AGENT"
echo "   ✓ Loaded LaunchAgent"

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo -e "${GREEN}✅ Your Mac is now configured for 24/7 operation!${NC}"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "What changed:"
echo "  • System sleep: DISABLED"
echo "  • Standby/hibernate: DISABLED"
echo "  • Power Nap: ENABLED (network activity while display off)"
echo "  • Wake on LAN: ENABLED (remote wake)"
echo "  • Auto-restart: ENABLED (after power failure)"
echo "  • Caffeinate agent: RUNNING (prevents system sleep)"
echo ""
echo "Your agent can now run 24/7 without interruption."
echo ""
echo "To restore default power settings:"
echo "  sudo bash $0 --restore"
echo ""