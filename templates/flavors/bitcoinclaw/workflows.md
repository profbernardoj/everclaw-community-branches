# Workflows — BitcoinClaw

## Example Use Cases

### 1. Price Check
> "How's Bitcoin doing?"

Current price in USD, 24h/7d/30d change, sats per dollar, and brief market context.

### 2. Fee Estimation
> "What would it cost to send a transaction right now?"

Agent checks mempool.space for current fee estimates at different priority levels (next block, ~30 min, ~1 hour, economy). Recommends timing if fees are temporarily elevated.

### 3. Transaction Tracking
> "Track this transaction: [txid]"

Agent monitors the transaction through confirmation. Reports when it hits 1, 3, and 6 confirmations. Alerts if it's stuck in the mempool.

### 4. Mempool Analysis
> "Is now a good time to send?"

Agent checks mempool congestion, recent fee trends, and upcoming difficulty adjustment. Advises on whether to send now or wait for lower fees.

### 5. DCA Performance
> "How's my DCA doing?"

If DCA tracking is active, agent reports total invested, total BTC accumulated, average cost per BTC, and current P&L.

### 6. Halving Countdown
> "When's the next halving?"

Agent calculates estimated date based on current block height and average block time. Includes current subsidy and what it will change to.

### 7. Network Deep Dive
> "Give me the full network health picture"

Hashrate, difficulty, block times, mempool depth, fee trends, and any notable changes from recent weeks.

### 8. Research a Topic
> "Explain the Lightning Network" / "What's happening with Ordinals?"

Agent provides a clear, balanced explanation drawing from recent sources. Distinguishes between established technology and emerging/controversial topics.

### 9. Security Audit Prompt
> "Help me verify my backup"

Agent walks through a security checklist: seed phrase backup verified, multisig setup reviewed, hardware wallet firmware current, passphrase recorded separately. Never asks to see or input actual secrets.
