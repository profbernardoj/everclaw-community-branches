# Secure Storage Patterns for Agent Secrets

## 1Password CLI Integration

### Setup (One-time)

```bash
# Install CLI
brew install 1password-cli

# Enable biometric unlock in 1Password app:
# Settings → Developer → "Integrate with 1Password CLI"

# Verify setup
op signin
op whoami
```

### Creating Agent Credential Vault

```bash
# Create isolated vault for agent credentials
op vault create "Agent-Credentials" \
  --description "Credentials for autonomous agents - session keys only, no master keys"

# Set vault permissions (only specific service accounts)
op vault group grant \
  --vault "Agent-Credentials" \
  --group "Automation" \
  --permissions "read_items,create_items"
```

### Storing Session Keys

**Best practice**: Store session keys with metadata about their scope and expiry.

```bash
op item create \
  --vault "Agent-Credentials" \
  --category "API Credential" \
  --title "trading-agent-session-v1" \
  --tags "agent,trading,sepolia" \
  'session-key[password]=0xabc123...' \
  'smart-account=0xdef456...' \
  'chain-id=11155111' \
  'expires=2026-02-15T00:00:00Z' \
  'spending-limit=1000 USDC/day' \
  'allowed-contracts=0xUniswap,0xAave' \
  'allowed-methods=swap,supply,withdraw' \
  'notes=Trading agent for DeFi operations on Sepolia testnet'
```

### Retrieving at Runtime

```bash
# Get specific field
SESSION_KEY=$(op read "op://Agent-Credentials/trading-agent-session-v1/session-key")

# Get full item as JSON (for validation)
op item get "trading-agent-session-v1" \
  --vault "Agent-Credentials" \
  --format json
```

### Using `op run` for Environment Injection

Instead of storing secrets in `.env` files, use `op run` with a template:

```bash
# Create .env.tpl (checked into git - no secrets)
# File: .env.tpl
PRIVATE_KEY=op://Agent-Credentials/trading-agent-session-v1/session-key
RPC_URL=op://Agent-Credentials/infura/api-url
CHAIN_ID=11155111

# Run with secrets injected (never touch disk)
op run --env-file=.env.tpl -- node agent.js
```

### Python Integration

```python
import subprocess
import json
from datetime import datetime
from typing import Optional

class SecretManager:
    """1Password-backed secret manager for agents."""
    
    VAULT = "Agent-Credentials"
    
    @classmethod
    def get_session_key(cls, item_name: str) -> dict:
        """Retrieve and validate session key from 1Password."""
        try:
            result = subprocess.run(
                ["op", "item", "get", item_name, 
                 "--vault", cls.VAULT, 
                 "--format", "json"],
                capture_output=True, 
                text=True, 
                check=True,
                timeout=30
            )
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to retrieve secret: {e.stderr}")
        
        item = json.loads(result.stdout)
        fields = {f["label"]: f.get("value") for f in item.get("fields", [])}
        
        # Validate expiry
        expires_str = fields.get("expires")
        if expires_str:
            expires = datetime.fromisoformat(expires_str.replace("Z", "+00:00"))
            if datetime.now(expires.tzinfo) > expires:
                raise ValueError(f"Session key '{item_name}' has expired")
        
        return {
            "session_key": fields.get("session-key"),
            "smart_account": fields.get("smart-account"),
            "chain_id": int(fields.get("chain-id", 1)),
            "expires": expires_str,
            "spending_limit": fields.get("spending-limit"),
            "allowed_contracts": fields.get("allowed-contracts", "").split(","),
            "allowed_methods": fields.get("allowed-methods", "").split(","),
        }
    
    @classmethod
    def read_secret(cls, reference: str) -> str:
        """Read a single secret value."""
        result = subprocess.run(
            ["op", "read", reference],
            capture_output=True,
            text=True,
            check=True,
            timeout=30
        )
        return result.stdout.strip()
```

### TypeScript/Node Integration

```typescript
import { execSync } from 'child_process';

interface SessionKey {
  sessionKey: string;
  smartAccount: string;
  chainId: number;
  expires: string;
  spendingLimit: string;
  allowedContracts: string[];
  allowedMethods: string[];
}

function getSessionKey(itemName: string): SessionKey {
  const vault = "Agent-Credentials";
  
  const output = execSync(
    `op item get "${itemName}" --vault "${vault}" --format json`,
    { encoding: 'utf-8', timeout: 30000 }
  );
  
  const item = JSON.parse(output);
  const fields: Record<string, string> = {};
  
  for (const field of item.fields || []) {
    if (field.label && field.value) {
      fields[field.label] = field.value;
    }
  }
  
  // Validate expiry
  if (fields.expires) {
    const expires = new Date(fields.expires);
    if (new Date() > expires) {
      throw new Error(`Session key '${itemName}' has expired`);
    }
  }
  
  return {
    sessionKey: fields['session-key'],
    smartAccount: fields['smart-account'],
    chainId: parseInt(fields['chain-id'] || '1'),
    expires: fields.expires,
    spendingLimit: fields['spending-limit'],
    allowedContracts: (fields['allowed-contracts'] || '').split(',').filter(Boolean),
    allowedMethods: (fields['allowed-methods'] || '').split(',').filter(Boolean),
  };
}
```

---

## Alternative: Environment Variables (Less Secure)

If 1Password isn't available, use environment variables with strict controls:

### Systemd Service with Credentials

```ini
# /etc/systemd/system/trading-agent.service
[Service]
Type=simple
User=agent
LoadCredential=session-key:/etc/agent/session-key

ExecStart=/usr/bin/node /opt/agent/index.js
Environment=SESSION_KEY_PATH=%d/session-key

# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
```

### AWS Secrets Manager

```python
import boto3
from botocore.exceptions import ClientError

def get_secret(secret_name: str) -> str:
    client = boto3.client('secretsmanager')
    try:
        response = client.get_secret_value(SecretId=secret_name)
        return response['SecretString']
    except ClientError as e:
        raise RuntimeError(f"Failed to retrieve secret: {e}")
```

### HashiCorp Vault

```bash
# Read from Vault
export SESSION_KEY=$(vault kv get -field=session_key secret/agents/trading-bot)
```

---

## Anti-Patterns to Avoid

### ❌ Keys in Config Files
```yaml
# config.yaml - NEVER DO THIS
agent:
  private_key: "0xabc123..."
```

### ❌ Keys in Docker Environment
```yaml
# docker-compose.yaml - NEVER DO THIS
services:
  agent:
    environment:
      - PRIVATE_KEY=0xabc123...
```

### ❌ Keys in Build Arguments
```dockerfile
# Dockerfile - NEVER DO THIS
ARG PRIVATE_KEY
ENV PRIVATE_KEY=$PRIVATE_KEY
```

### ❌ Keys Committed to Git (Even Encrypted)
```bash
# Even with git-crypt or SOPS, keys shouldn't be in repo
# Use external secret management
```

---

## Audit Trail

1Password provides audit logs for all secret access:

```bash
# View recent activity
op events-api summary

# Get detailed events
op events-api events --start "2026-02-01"
```

Set up alerts for:
- Access outside normal hours
- Access from new IPs/devices
- Failed access attempts
- Bulk secret reads
