
<img src="https://github.com/user-attachments/assets/3de8f61e-3228-4f14-a54d-24779c2e8251" width="400" />

  # ClawdStrike Skill

  ClawdStrike is a defensive OpenClaw skill designed to help operators **verify their environment and configuration** before attackers
  do. It focuses on the most common real‑world compromise paths seen in the ecosystem: **malicious skills, open ports, exposed control
  UIs, weak tool policies, and plaintext secrets**.

  ## How to use

1) navigate to your openclaw workspace.
```
cd /home/<user>/.openclaw/workspace
```

2) ensure the skills directory exists.
```
mkdir -p skills
```

3) clone the clawdstrike repository files into the folder.
```
git clone https://github.com/cantinaxyz/clawdstrike.git skills/clawdstrike
```

4) restart openclaw
```
openclaw gateway restart
```

  ## Why this exists
  OpenClaw installations often run with broad permissions and access to sensitive credentials. In practice, many compromises happen
  because:
  - users install **malicious or backdoored skills**
  - gateways or control interfaces are **publicly exposed**
  - tools are enabled without proper allowlists or sandboxing
  - secrets and session data live **in plaintext on disk**

  ClawdStrike helps detect those risks early and provides concrete fixes.

  ## What it checks (high level)
  - Internet exposure (gateway / control UI / browser control)
  - Tool policies and elevated execution scope
  - Skill/plugin supply‑chain risks (hidden files, remote payloads)
  - Secrets on disk + weak file permissions
  - Network and firewall posture

  ## Intended use
  Run it as a **defensive audit** before installing new skills, after configuration changes, or on a schedule. The goal is to reduce the
  blast radius of known attack paths.
