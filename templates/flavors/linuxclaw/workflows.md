# Workflows — LinuxClaw

## Example Use Cases

### 1. System Health Check
> "How's the server doing?"

Agent runs a full health check: uptime, load, CPU, memory, disk, network, failed services, pending updates. Presents a traffic-light dashboard.

### 2. Deploy an Application
> "Deploy the latest version of [app]"

Agent pulls the latest code, runs tests if configured, builds Docker image (if containerized), and deploys with a rollback plan. Each step confirmed before proceeding.

### 3. Troubleshoot a Service
> "Nginx is returning 502s"

Agent checks: nginx status, error logs, upstream service health, port conflicts, config syntax. Diagnoses the root cause and suggests fixes.

### 4. Security Hardening
> "Harden this server"

Agent runs through a checklist: SSH config, firewall rules, fail2ban, unattended upgrades, open ports audit, user permissions, and generates a report with recommended changes.

### 5. Docker Management
> "Show me all running containers"

Agent lists containers with status, resource usage, uptime, and health check results. Flags any in unhealthy or restarting state.

### 6. Write a Script
> "Write a backup script for the database"

Agent writes a bash script with proper error handling, logging, rotation, and offsite copy. Includes a cron entry for scheduling.

### 7. Disk Cleanup
> "Disk is getting full — help me clean up"

Agent identifies: old logs, Docker dangling images/volumes, package cache, temp files, large files. Presents candidates for deletion with sizes. Never deletes without confirmation.

### 8. SSL Certificate Management
> "Check my SSL certificates"

Agent checks expiration dates for all configured domains, flags any expiring within 30 days, and verifies auto-renewal is working.

### 9. Log Analysis
> "What happened at 3am?"

Agent searches system logs, application logs, auth logs, and Docker logs for the specified time window. Correlates events and presents a timeline.

### 10. Performance Tuning
> "The server feels slow"

Agent profiles: CPU usage by process, memory consumption, disk I/O, network throughput, and swap usage. Identifies the bottleneck and suggests optimizations.
