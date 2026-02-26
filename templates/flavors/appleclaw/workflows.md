# Workflows — AppleClaw

## Example Use Cases

### 1. System Status
> "How's my Mac doing?"

Agent checks: macOS version, uptime, disk usage, memory, CPU, Time Machine status, iCloud storage, and pending updates. Clean dashboard output.

### 2. Apple Notes Search
> "Find my notes about the project proposal"

Agent searches Apple Notes by keyword, presents matching notes with titles and previews. Can read full content of a specific note.

### 3. Reminders Management
> "Add a reminder to call the dentist on Friday"

Agent creates the reminder in Apple Reminders with the due date. Syncs to all devices immediately.

### 4. Homebrew Management
> "Update all my packages"

Agent runs `brew update`, shows what's outdated, and upgrades with your approval. Runs cleanup afterward and reports space saved.

### 5. AppleScript Automation
> "Close all Finder windows and empty the trash"

Agent writes and executes the AppleScript to perform the requested action. Confirms before executing.

### 6. File Organization
> "Organize my Downloads folder"

Agent scans Downloads, categorizes files by type (images, PDFs, archives, installers, etc.), and proposes a folder structure. Moves files with approval.

### 7. Backup Verification
> "When was my last backup?"

Agent checks Time Machine for the most recent backup, its size, and the backup disk's remaining space. Alerts if backup is stale.

### 8. Multi-Device Workflow
> "Create a note on my phone from this text"

Agent creates the note in Apple Notes, which syncs to iPhone via iCloud automatically. Confirms creation.

### 9. macOS Update Management
> "What updates are available?"

Agent lists pending macOS and app updates, notes which are security-critical, and offers to install with approval.

### 10. Focus Mode Integration
> "I'm starting deep work"

Agent activates the configured Focus mode, silences notifications, closes distracting apps (with approval), and sets a timer for the work session.
