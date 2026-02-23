# Leak Prevention for Agent Secrets

## Pre-commit Hooks

### Git Hook Installation

```bash
# Create hooks directory if needed
mkdir -p .git/hooks

# Create pre-commit hook
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
# Secret Detection Pre-commit Hook

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

echo "🔍 Scanning for secrets..."

declare -a PATTERNS=(
    '0x[a-fA-F0-9]{64}'                      # ETH private keys
    'PRIVATE_KEY=.{20,}'                     # Generic private key
    'sk-[a-zA-Z0-9]{48,}'                    # OpenAI
    'sk-ant-api[0-9]{2}-[a-zA-Z0-9\-_]{80,}' # Anthropic
    'gsk_[a-zA-Z0-9]{48,}'                   # Groq
    'AKIA[0-9A-Z]{16}'                       # AWS Access Key
    'ghp_[a-zA-Z0-9]{36}'                    # GitHub PAT
)

FILES=$(git diff --cached --name-only --diff-filter=ACM)
FOUND_SECRETS=0

for file in $FILES; do
    if [[ "$file" =~ \.(png|jpg|gif|ico|woff|ttf|lock)$ ]]; then
        continue
    fi
    
    for pattern in "${PATTERNS[@]}"; do
        if git diff --cached "$file" | grep -qE "$pattern"; then
            echo -e "${RED}❌ Potential secret in: $file${NC}"
            echo "   Pattern: $pattern"
            FOUND_SECRETS=1
        fi
    done
done

if [ $FOUND_SECRETS -eq 1 ]; then
    echo -e "${RED}⚠️  Secrets detected! Commit blocked.${NC}"
    echo "Bypass with: git commit --no-verify"
    exit 1
fi

echo -e "${GREEN}✅ No secrets detected${NC}"
EOF

chmod +x .git/hooks/pre-commit
```

### Enhanced Detection with gitleaks

```bash
# Install
brew install gitleaks

# Run
gitleaks detect --source . --verbose

# As pre-commit
gitleaks protect --staged
```

---

## Output Sanitization

### Python Implementation

```python
import re
from typing import List, Tuple

class OutputSanitizer:
    """Sanitize agent outputs to prevent secret leakage."""
    
    SECRET_PATTERNS: List[Tuple[str, str]] = [
        (r'0x[a-fA-F0-9]{64}', '[ETH_KEY_REDACTED]'),
        (r'0x[a-fA-F0-9]{40}', lambda m: m.group()[:6] + '...' + m.group()[-4:]),
        (r'sk-proj-[a-zA-Z0-9_-]{48,}', '[OPENAI_KEY_REDACTED]'),
        (r'sk-[a-zA-Z0-9]{48,}', '[OPENAI_KEY_REDACTED]'),
        (r'sk-ant-api\d{2}-[a-zA-Z0-9\-_]{80,}', '[ANTHROPIC_KEY_REDACTED]'),
        (r'gsk_[a-zA-Z0-9]{48,}', '[GROQ_KEY_REDACTED]'),
        (r'AKIA[0-9A-Z]{16}', '[AWS_KEY_REDACTED]'),
        (r'ghp_[a-zA-Z0-9]{36}', '[GITHUB_TOKEN_REDACTED]'),
    ]
    
    @classmethod
    def sanitize(cls, text: str) -> str:
        if not text:
            return text
        for pattern, replacement in cls.SECRET_PATTERNS:
            if callable(replacement):
                text = re.sub(pattern, replacement, text)
            else:
                text = re.sub(pattern, replacement, text)
        return text
    
    @classmethod
    def contains_secret(cls, text: str) -> bool:
        return any(re.search(p, text) for p, _ in cls.SECRET_PATTERNS)


# Usage
def respond(content: str) -> str:
    if OutputSanitizer.contains_secret(content):
        log_security_event("Secret in output attempt")
    return OutputSanitizer.sanitize(content)
```

### TypeScript Implementation

```typescript
const SECRET_PATTERNS: Array<[RegExp, string | ((m: string) => string)]> = [
  [/0x[a-fA-F0-9]{64}/g, '[ETH_KEY_REDACTED]'],
  [/0x[a-fA-F0-9]{40}/g, (m) => `${m.slice(0, 6)}...${m.slice(-4)}`],
  [/sk-proj-[a-zA-Z0-9_-]{48,}/g, '[OPENAI_KEY_REDACTED]'],
  [/sk-[a-zA-Z0-9]{48,}/g, '[OPENAI_KEY_REDACTED]'],
  [/sk-ant-api\d{2}-[a-zA-Z0-9\-_]{80,}/g, '[ANTHROPIC_KEY_REDACTED]'],
  [/gsk_[a-zA-Z0-9]{48,}/g, '[GROQ_KEY_REDACTED]'],
];

function sanitize(text: string): string {
  let result = text;
  for (const [pattern, replacement] of SECRET_PATTERNS) {
    if (typeof replacement === 'function') {
      result = result.replace(pattern, replacement);
    } else {
      result = result.replace(pattern, replacement);
    }
  }
  return result;
}
```

---

## .gitignore Essentials

```gitignore
# === SECRETS ===
.env
.env.*
!.env.example
!.env.tpl

# Keys
*.pem
*.key
*.p12
id_rsa*
id_ed25519*

# Credentials
secrets/
credentials/
.credentials/
private/
keystore/
wallet.json

# === AGENT STATE ===
memory/*.json
memory/*.md
!memory/README.md
session-state.json
.session/
wallet-state.json
session-keys/

# === LOGS ===
*.log
logs/

# === BUILD ===
node_modules/
dist/
__pycache__/
```

---

## GitHub Repository Settings

1. **Enable Secret Scanning**: Settings → Code security → Secret scanning ✓
2. **Enable Push Protection**: Blocks pushes with detected secrets
3. **Add GitHub Action**:

```yaml
# .github/workflows/secret-scan.yml
name: Secret Scan
on: [push, pull_request]
jobs:
  gitleaks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

---

## Incident Response

When a secret is leaked:

1. **Immediate (0-5 min)**
   - Revoke the credential
   - Force-push to remove from git history
   - Rotate related credentials

2. **Investigation (5-30 min)**
   - Check access logs
   - Review transaction history
   - Identify leak source

3. **Remediation**
   - Issue new credentials (tighter scope)
   - Update detection rules
   - Document incident

```bash
# Remove from git history
git filter-branch --force --index-filter \
  "git rm --cached --ignore-unmatch path/to/secret" \
  --prune-empty --tag-name-filter cat -- --all

git push origin --force --all
```
