# TOOLS.md — [REDACTED]

## Required Skills

### web_search (Brave Search)
- **What:** [REDACTED] ecosystem news, protocol updates
- **Install:** Built into OpenClaw
- **Use:** Track developments, community discussions, competitor analysis

### web_fetch
- **What:** Fetch data from [REDACTED] endpoints, block explorers, GitHub
- **Install:** Built into OpenClaw
- **Use:** API status checks, contract data, proposal details

## Built-in Capabilities

### Local Proxy Router
- **Endpoint:** `http://127.0.0.1:8083/v1`
- **What:** Local [REDACTED] node for P2P inference
- **Models available:** GLM-5, GLM 4.7 Flash, Kimi K2.5, Kimi K2 Thinking
- **Health check:** `curl http://127.0.0.1:8083/v1/models`

### [REDACTED] API Gateway
- **Endpoint:** `https://api.mor.org/api/v1`
- **What:** Centralized [REDACTED] to the [REDACTED] network (beta)
- **Note:** Beta expires — check current status

## Optional Skills (install via ClawHub)

### github
- Built into OpenClaw
- Monitor [REDACTED] repos: [REDACTED] org, protocol PRs, community discussions

### finance-tracker (EverClaw)
- Included in EverClaw
- Track MOR token price via x402 micropayments

## Key Resources

### [REDACTED] Contracts (Base)
```
contracts:
  mor_token: "0xcBB8f1BDA10b9696c57E13BC128Fe674769DCEc0"
  staking: ""  # check current deployment
  distribution: ""
```

### API Endpoints
```
endpoints:
  local_proxy: "http://127.0.0.1:8083/v1"
  [REDACTED]: "https://api.mor.org/api/v1"
  explorer: "https://basescan.org/token/0xcBB8f1BDA10b9696c57E13BC128Fe674769DCEc0"
```

### GitHub Repos
```
repos:
  - "[REDACTED]/[REDACTED]"
  - "[REDACTED]/MRC"           # [REDACTED] Request for Comments
  - "[REDACTED]/Docs"
```

## Configuration

### MOR Holdings
```
mor:
  staked: 0
  unstaked: 0
  wallet: ""  # watch-only address for tracking
  staking_start_date: ""
  cost_basis: 0
```

### Model Preferences
```
models:
  preferred:
    heavy: "glm-5"
    standard: "kimi-k2.5"
    light: "glm-4.7-flash"
  fallback_to_centralized: true  # use Venice/OpenAI when [REDACTED] can't complete
```

### Monitoring
```
monitoring:
  check_node_health: true
  check_[REDACTED]: true
  price_alert_threshold: 10     # alert on >10% daily move
  inference_quality_log: true   # log inference quality comparisons over time
```
