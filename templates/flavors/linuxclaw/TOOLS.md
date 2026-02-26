# TOOLS.md — LinuxClaw

## Required Skills

### exec (Shell Access)
- **What:** Direct shell command execution
- **Install:** Built into OpenClaw
- **Use:** System administration, scripting, monitoring — this is your primary tool

### github
- **What:** Git operations, repo management
- **Install:** Built into OpenClaw
- **Use:** Code deployment, dotfile management, script versioning

## Optional Skills (install via ClawHub)

### healthcheck (EverClaw)
- Built into OpenClaw
- Host security hardening and periodic system audits

### tmux
- Built into OpenClaw
- Terminal multiplexer management for persistent sessions

## Key Commands Reference

### System Info
```bash
uname -a                    # kernel version
lsb_release -a              # distro info
uptime                      # uptime and load
free -h                     # memory usage
df -h                       # disk usage
top -bn1 | head -20         # process overview
```

### Service Management
```bash
systemctl status <service>
systemctl list-units --failed
journalctl -u <service> --since "1 hour ago"
```

### Security
```bash
sudo apt list --upgradable             # pending updates (Debian/Ubuntu)
sudo fail2ban-client status            # fail2ban overview
sudo lastb | head -20                  # failed login attempts
sudo ss -tulpn                         # listening ports
```

### Docker
```bash
docker ps -a                           # all containers
docker stats --no-stream               # resource usage
docker system df                       # disk usage
docker logs --tail 50 <container>      # recent logs
```

### Networking
```bash
ip addr show                           # interfaces
ss -tulpn                              # listening ports
curl -sI https://example.com           # test connectivity
dig example.com                        # DNS lookup
sudo ufw status verbose                # firewall (Ubuntu)
```

## Configuration

### Monitored Services
```
services:
  - name: "nginx"
    critical: true
  - name: "docker"
    critical: true
  - name: "fail2ban"
    critical: true
  - name: "openclaw"
    critical: true
  - name: "unattended-upgrades"
    critical: false
```

### Alert Thresholds
```
thresholds:
  disk_usage_percent: 85
  memory_usage_percent: 90
  load_average_warn: 2.0     # per CPU core
  failed_ssh_attempts: 10    # per hour before alerting
```

### Backup Config
```
backups:
  method: "rsync"            # rsync | restic | borgbackup | rclone
  schedule: "daily"
  destination: ""            # remote path or bucket
  retention_days: 30
  verify_after: true
  last_verified: ""
```

### SSH Hardening Checklist
```
ssh_hardening:
  - password_auth: false     # use keys only
  - root_login: false
  - port: 22                 # or custom port
  - fail2ban: true
  - key_type: "ed25519"
  - mfa: false               # optional TOTP
```
