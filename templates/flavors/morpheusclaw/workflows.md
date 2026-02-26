# Workflows — MorpheusClaw

## Example Use Cases

### 1. Node Status
> "Is my node running?"

Agent pings the local proxy router, reports which models are responding, latency for each, and overall health status.

### 2. MOR Portfolio
> "How's my MOR position?"

Agent reports: MOR price, staking status, rewards accrued, estimated APY, and comparison to cost basis. Includes network emission schedule context.

### 3. Model Comparison
> "Compare GLM-5 on Morpheus vs Claude on Venice"

Agent runs the same prompt through both, compares response quality, speed, and cost. Presents a fair comparison with specific observations.

### 4. Staking Analysis
> "Should I stake more MOR?"

Agent presents: current staking rewards, APY, lock-up terms, opportunity cost, and inference value per staked MOR. Does NOT say "you should stake" — presents data for the human to decide.

### 5. Network Explorer
> "What models are available on Morpheus right now?"

Agent queries local node and gateway, lists all available models with their capabilities, context windows, and current response times.

### 6. MRC Tracker
> "What MRCs are being discussed?"

Agent checks the MorpheusAIs/MRC repo for active proposals, summarizes each with status and community sentiment.

### 7. Inference Cost Calculator
> "How much am I saving with Morpheus vs OpenAI?"

Agent calculates: inference volume (from usage logs if available), equivalent cost on centralized APIs, cost via Morpheus (MOR staking value), and net savings.

### 8. Troubleshooting
> "My inference is slow today"

Agent checks: node status, available models, network congestion, gateway status, and recent changes. Suggests diagnosis steps.

### 9. Provider Analysis
> "Who are the top inference providers on the network?"

Agent researches active providers, their uptime, model offerings, and reputation if available through on-chain data.

### 10. Ecosystem Map
> "Give me the full Morpheus ecosystem picture"

Agent presents: protocol architecture, key smart contracts, active MRCs, governance structure, token economics, and competitive positioning in the decentralized AI landscape.
