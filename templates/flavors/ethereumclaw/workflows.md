# Workflows — EthereumClaw

## Example Use Cases

### 1. Gas Timing
> "Is now a good time to do my transaction?"

Agent checks current gas prices, recent trend, and time-of-day patterns. Advises whether to send now or wait for a cheaper window. Includes estimated cost at current gas.

### 2. Portfolio Overview
> "Show me my positions"

Agent reads tracked wallets and DeFi positions from TOOLS.md, fetches current values across mainnet and L2s, and presents a consolidated view with P&L.

### 3. DeFi Position Health Check
> "How's my Aave position?"

Agent checks health factor, collateral value, borrow amount, liquidation price, and current interest rates. Flags if the position is approaching risk thresholds.

### 4. Token Approval Audit
> "Check my token approvals"

Agent reviews active approvals for tracked wallets, flags any unlimited approvals, identifies approvals to contracts that are unaudited or inactive, and suggests revocations.

### 5. Protocol Research
> "Research this DeFi protocol: [name or address]"

Agent checks audit status, TVL, team background, time in production, recent incidents, governance activity, and community sentiment. Presents a risk assessment.

### 6. Governance Participation
> "What votes are active right now?"

Agent checks Snapshot and on-chain governance for tracked protocols. Presents active proposals with summaries, current vote counts, and time remaining.

### 7. L2 Bridge Comparison
> "I need to bridge ETH to Base — what's the cheapest route?"

Agent compares bridge options (native bridge, Across, Stargate, etc.) for fees, speed, and security tradeoffs.

### 8. Yield Comparison
> "Where can I get the best yield on USDC right now?"

Agent scans major lending protocols (Aave, Compound, Morpho) across mainnet and L2s, ranks by APY, and notes risk factors for each option.

### 9. Staking Dashboard
> "How are my validators doing?"

Agent checks validator status, attestation performance, rewards accrued, and withdrawal queue status. Flags any missed attestations or sync committee duties.

### 10. Airdrop Check
> "Am I eligible for any airdrops?"

Agent checks tracked wallet addresses against known airdrop criteria and claim pages. Notes unclaimed drops and deadlines.
