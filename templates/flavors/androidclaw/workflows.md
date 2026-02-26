# Workflows — AndroidClaw

## Example Use Cases

### 1. Termux Setup
> "Set up my Termux environment"

Agent walks through a complete setup: package installation, SSH key generation, storage permissions, cron daemon, and OpenClaw installation. Tailored to the device's capabilities.

### 2. SSH to Home Server
> "Connect to my home server"

Agent establishes an SSH tunnel to the configured server. Can forward ports for accessing web UIs, databases, or other services remotely.

### 3. Quick Capture
> "Save this for later" (paste text or idea)

Agent saves the note to the workspace with a timestamp. Syncs to other devices when on WiFi.

### 4. Device Health Check
> "How's my phone doing?"

Agent runs: battery status, storage breakdown, running processes, network status. Suggests cleanup if storage is low or identifies battery drain sources.

### 5. File Transfer
> "Send this file to my desktop"

Agent uses rsync or scp to transfer files between phone and configured remote machines. Queues transfer if currently on cellular (to save data).

### 6. Offline Task Queue
> "Do this when I'm back on WiFi"

Agent queues the task and executes it when connectivity is restored. Useful for syncs, uploads, and API calls.

### 7. Script Runner
> "Run my backup script"

Agent executes saved scripts from the Termux environment, with output captured and battery impact monitored.

### 8. Notification Summary
> "Summarize what I missed"

Agent reviews queued notifications and messages, categorizes by priority, and presents a concise summary.
