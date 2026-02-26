# TOOLS.md — EthereumClaw

## Required Skills

### web_search (Brave Search)
- **What:** Ethereum news, DeFi research, protocol updates
- **Install:** Built into OpenClaw
- **Use:** Protocol research, governance tracking, ecosystem news

### web_fetch
- **What:** Fetch data from Etherscan, DeFi dashboards, governance portals
- **Install:** Built into OpenClaw
- **Use:** Contract verification, proposal details, yield data

## Optional Skills (install via ClawHub)

### ethereum-wingman
- `clawhub install ethereum-wingman`
- Ethereum transaction research and wallet analysis

### defi-yield-scanner
- `clawhub install defi-yield-scanner`
- Scan protocols for yield opportunities with risk assessment

### crypto-watcher
- `clawhub install crypto-watcher`
- Real-time price monitoring for ETH and tokens

### zapper
- `clawhub install zapper`
- Multi-chain DeFi portfolio dashboard integration

## Free Data Sources (no API key needed)

### Gas Tracking
- `https://api.etherscan.io/api?module=gastracker&action=gasoracle` (free tier)
- `https://ethgasstation.info/api/ethgasAPI.json`

### L2 Fees
- `https://l2fees.info` — comparative L2 fee tracker

### DeFi Data
- `https://defillama.com/` — TVL and yield data across protocols
- `https://app.aave.com/` — Aave lending rates
- `https://compound.finance/` — Compound rates

### Block Explorers
- Mainnet: `https://etherscan.io`
- Base: `https://basescan.org`
- Arbitrum: `https://arbiscan.io`
- Optimism: `https://optimistic.etherscan.io`

## Configuration

### Tracked Wallets (watch-only)
```
# WARNING: Adding wallet addresses has privacy implications.
# Only add addresses you want monitored.
wallets:
  - address: "0x..."
    label: "Main Wallet"
    chains: ["mainnet", "base", "arbitrum"]
  - address: "0x..."
    label: "Safe Multisig"
    chains: ["mainnet"]
```

### DeFi Positions
```
defi:
  - protocol: "Aave V3"
    chain: "mainnet"
    type: "lending"
    assets: ["ETH", "USDC"]
    notes: "Supplied ETH, borrowed USDC"
  - protocol: "Lido"
    chain: "mainnet"
    type: "staking"
    assets: ["stETH"]
    notes: "Liquid staking"
```

### Governance Tracking
```
governance:
  - protocol: "Aave"
    snapshot: "aave.eth"
    delegate: ""
  - protocol: "Uniswap"
    snapshot: "uniswapgovernance.eth"
    delegate: ""
```

### Alert Thresholds
```
alerts:
  eth_daily_move: 5           # alert on >5% daily move
  gas_low_threshold: 15       # alert when gas is cheap (gwei)
  gas_high_threshold: 50      # alert when gas is expensive
  liquidation_warning: 80     # alert when health factor approaches risk (%)
  critical_move: 10           # always alert, even quiet hours
```

### Token Approval Policy
```
approvals:
  flag_unlimited: true        # always flag unlimited token approvals
  review_frequency: "monthly" # how often to audit active approvals
  revoke_tool: "https://revoke.cash"
```
