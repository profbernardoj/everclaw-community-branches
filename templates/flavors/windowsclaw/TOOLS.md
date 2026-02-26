# TOOLS.md — WindowsClaw

## Required Skills

### exec (Shell Access)
- **What:** PowerShell and WSL2 bash access
- **Install:** Built into OpenClaw
- **Use:** System administration, scripting, automation
- **Note:** Use `wsl` prefix for Linux commands, direct for PowerShell

## Key PowerShell Commands
```powershell
# System Info
Get-ComputerInfo | Select-Object OsName, OsVersion, CsProcessors, CsTotalPhysicalMemory
Get-Volume | Format-Table DriveLetter, Size, SizeRemaining  # disk usage
Get-Process | Sort-Object CPU -Descending | Select-Object -First 10

# Windows Update
Get-WindowsUpdate                           # requires PSWindowsUpdate module
Install-WindowsUpdate -AcceptAll -AutoReboot

# Services
Get-Service | Where-Object Status -eq Stopped
Restart-Service <name>

# Defender
Get-MpComputerStatus                        # Defender status
Update-MpSignature                          # update definitions

# Firewall
Get-NetFirewallProfile | Format-Table Name, Enabled
Get-NetFirewallRule | Where-Object Enabled -eq True | Measure-Object

# Scheduled Tasks
Get-ScheduledTask | Where-Object State -eq 'Ready'
Get-ScheduledTask | Where-Object LastTaskResult -ne 0  # failed tasks
```

## Key WSL2 Commands
```bash
# From Windows side
wsl --list --verbose              # list distros and status
wsl --status                      # WSL2 configuration
wsl --shutdown                    # stop all distros
wsl --update                      # update WSL kernel

# Inside WSL2 — standard Linux commands
uname -a && lsb_release -a       # distro info
df -h                             # disk usage (Linux side)
docker ps                         # Docker containers (if using WSL2 backend)
```

## Optional Skills (install via ClawHub)

### github
- Built into OpenClaw
- Works in both PowerShell and WSL2 environments

### summarize
- Built into OpenClaw
- Summarize logs, documents, and research

## Configuration

### Environment Setup
```
environment:
  primary_shell: "powershell"    # powershell | wsl-bash
  wsl_distro: "Ubuntu-24.04"
  windows_terminal: true
  vscode_installed: true
  docker_backend: "wsl2"         # wsl2 | hyper-v
```

### Monitoring Thresholds
```
thresholds:
  disk_c_warning_percent: 85
  wsl_vhdx_max_gb: 50           # WSL2 virtual disk size warning
  memory_warning_percent: 90
  defender_definitions_max_days: 3
```

### WSL2 File Sharing
```
# Paths for cross-environment access
paths:
  windows_from_wsl: "/mnt/c/Users/{{USERNAME}}"
  wsl_from_windows: "\\\\wsl$\\Ubuntu-24.04\\home\\{{USERNAME}}"
  shared_workspace: "/mnt/c/Users/{{USERNAME}}/.openclaw/workspace"
```

### Scheduled Tasks
```
# Windows Scheduled Tasks managed by this agent
tasks:
  - name: "OpenClaw Gateway"
    trigger: "at_logon"
    action: "start OpenClaw gateway service"
  - name: "WSL2 Startup"
    trigger: "at_logon"
    action: "wsl -d Ubuntu-24.04 -- service cron start"
```
