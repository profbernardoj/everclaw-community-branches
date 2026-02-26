# TOOLS.md — InstallOpenClaw

## Getting Started

### What is OpenClaw?
OpenClaw is a self-hosted AI agent that runs on your own hardware. It connects to your services (email, calendar, smart home, crypto wallets, etc.) and automates tasks while keeping your data private.

### What is EverClaw?
EverClaw is a skill pack for OpenClaw that adds decentralized AI inference via the Morpheus network. Instead of paying per-query to OpenAI or Anthropic, you stake MOR tokens and own your inference permanently.

## Installation

### Quick Install (macOS/Linux)
```bash
curl -fsSL https://installopenclaw.xyz | bash
```

### Manual Install
```bash
npm install -g openclaw
openclaw doctor
openclaw setup
```

### System Requirements
- **macOS:** Apple Silicon (M1+) or Intel, macOS 13+
- **Linux:** Ubuntu 22.04+, Debian 12+, or any modern distro
- **Windows:** WSL2 required (see WindowsClaw flavor for setup)
- **RAM:** 8GB minimum, 16GB recommended
- **Storage:** 2GB for OpenClaw + space for models if running locally

## First Skills to Set Up

### 1. Weather (easiest — no API key needed)
```
Just ask "What's the weather?" — it works out of the box.
```

### 2. Web Search (requires free API key)
```
Sign up at brave.com/search/api for a free search API key.
OpenClaw setup wizard will walk you through adding it.
```

### 3. Email (Google Workspace)
```
Run: gog auth
Follow the OAuth flow to connect your Gmail account.
Then ask: "Check my email"
```

### 4. Calendar (Google Workspace)
```
Same auth as email — if you did gog auth, calendar works too.
Ask: "What's on my calendar today?"
```

### 5. Apple Reminders (macOS only)
```
Works immediately — no setup needed.
Ask: "Show my reminders" or "Add a reminder to..."
```

## Flavor Discovery

### Not sure which flavor to use? Here's a quick guide:

| I want to... | Try this flavor |
|---|---|
| Manage my inbox | EmailClaw |
| Stay organized at work | OfficeClaw |
| Get daily news briefings | BriefingClaw |
| Manage family schedules | FamilyClaw |
| Track investments | InvestClaw |
| Plan travel | BookingClaw |
| Control smart home | HomeClaw |
| Track Bitcoin | BitcoinClaw |
| Use Ethereum/DeFi | EthereumClaw |
| Run on Linux | LinuxClaw |
| Run on Android | AndroidClaw |
| Manage social media (X) | GrokClaw |

### Install a Flavor
```
# Coming soon:
everclaw init --flavor emailclaw
```

## Configuration

### Setup Progress Tracking
```
# The agent tracks your setup journey here
setup:
  install_date: ""
  first_skill_configured: ""
  skills_active: []
  flavor_selected: ""
  setup_complete: false
  next_step: "Connect your first service"
```

### User Skill Level
```
# Helps the agent calibrate explanations
user:
  technical_level: "beginner"   # beginner | intermediate | advanced
  platform: ""                  # macos | linux | windows-wsl
  goals: []                     # what the user wants to accomplish
```
