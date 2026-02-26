# Workflows — WindowsClaw

## Example Use Cases

### 1. System Health Check
> "How's my PC doing?"

Agent checks: Windows version, uptime, disk usage, memory, CPU, Windows Update status, Defender health, WSL2 status, Docker status. Dashboard format.

### 2. WSL2 Setup
> "Set up WSL2 with Ubuntu"

Agent walks through: enabling WSL2 feature, installing Ubuntu distro, initial setup, essential packages (git, node, python, docker), and configuring file sharing between Windows and WSL2.

### 3. Docker Troubleshooting
> "Docker Desktop won't start"

Agent diagnoses: WSL2 backend status, Hyper-V settings, Docker service state, resource allocation, and common fixes. Step-by-step resolution.

### 4. Windows Update Management
> "What updates are pending?"

Agent lists pending updates, categorizes by type (security, feature, driver), notes any known issues, and recommends install timing.

### 5. PowerShell Scripting
> "Write a script to clean up temp files older than 30 days"

Agent writes a PowerShell script with proper error handling, logging, and a dry-run mode. Explains what it does before execution.

### 6. Dev Environment Setup
> "Set up a Node.js dev environment"

Agent configures: nvm in WSL2, Node LTS, VS Code with Remote-WSL extension, git config, and project scaffolding. Works across both Windows and WSL2.

### 7. Network Diagnostics
> "I can't reach my home server"

Agent runs: ping, traceroute, DNS resolution, firewall rule check, and port scan. Identifies where the connection is failing.

### 8. Registry Backup and Edit
> "I need to change [registry setting]"

Agent creates a registry backup first, explains what the change does and its risks, then applies with confirmation. Verifies the change took effect.

### 9. Scheduled Task Management
> "Create a task to start my dev tools at login"

Agent creates a Windows Scheduled Task with the correct trigger, action, and permissions. Verifies it works with a test run.

### 10. Cross-Environment Workflow
> "Build in WSL2 and deploy to Windows"

Agent orchestrates workflows that span both environments — building in Linux, copying artifacts to Windows paths, and running Windows-native deployment steps.
