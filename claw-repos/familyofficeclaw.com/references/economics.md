# Everclaw — MOR Staking Economics

How MOR tokens power decentralized inference on the Morpheus network.

---

## Core Concept: Stake, Don't Spend

MOR is **staked (locked), not spent** for inference. When you open a session, MOR is locked in the Diamond contract for the session duration. When the session ends or you close it, the MOR is **returned to your wallet** (minus a small usage fee).

This means you can **recycle MOR indefinitely**: open a session → use it → close it → re-stake the returned MOR into a new session.

**Result: effectively unlimited inference with a fixed MOR balance.**

---

## Session Economics

### Opening a Session

When you open a session:

1. **Approve transaction** — Allows the Diamond contract to transfer MOR on your behalf
2. **Open session transaction** — Locks MOR proportional to `duration × price_per_second`

Both transactions cost gas (ETH on Base).

### How Much MOR Is Staked?

The amount staked depends on:

- **Session duration** (in seconds)
- **Provider's price per second** (set by the provider, varies by model)

```
MOR staked = duration × price_per_second
```

Example: A provider charges 0.001 MOR/second for kimi-k2.5:web
- 1 hour (3600s): 3.6 MOR staked
- 1 day (86400s): 86.4 MOR staked

### Closing a Session

When a session closes (manually or by expiry):

- Staked MOR is **returned** to your wallet
- A small portion may be deducted as a usage fee (proportional to actual usage)
- The returned MOR can immediately be re-staked into new sessions

---

## Cost Breakdown

| Cost Type | Paid In | Amount | When |
|-----------|---------|--------|------|
| Session stake | MOR | Varies (duration × rate) | Locked at open, returned at close |
| Gas (open session) | ETH | ~0.0001-0.001 ETH | Per session open |
| Gas (close session) | ETH | ~0.0001-0.0005 ETH | Per session close |
| Gas (approve MOR) | ETH | ~0.0001 ETH | Once (or when allowance runs out) |
| Usage fee | MOR | Tiny fraction of stake | Deducted at close |

---

## Getting Started

### Minimum Requirements

| Token | Minimum | Recommended | Purpose |
|-------|---------|-------------|---------|
| MOR | ~10 MOR | 50-100 MOR | Session staking |
| ETH (Base) | 0.005 ETH | 0.05 ETH | Gas for transactions |

### Where to Get MOR

- MOR is the native token of the Morpheus network
- Available on decentralized exchanges on Base (Uniswap, Aerodrome)
- MOR token contract: `0x7431aDa8a591C955a994a21710752EF9b882b8e3` (Base)
- Check current price at https://mor.org

### Where to Get ETH on Base

- Bridge ETH from Ethereum mainnet to Base via the official Base Bridge
- Or buy ETH directly on Base through exchanges that support it
- Gas on Base is very cheap (typically <$0.01 per transaction)

---

## Staking Strategies

### Short Sessions (1 hour)

- **Best for:** Testing, one-off queries, experimenting with models
- **MOR locked:** Small (~1-5 MOR)
- **Gas cost:** ~$0.01 per open/close cycle
- **Tradeoff:** More gas spent on frequent open/close, but less MOR locked at any time

### Long Sessions (24 hours)

- **Best for:** Sustained use, running agents, batch processing
- **MOR locked:** Larger (~50-100 MOR)
- **Gas cost:** ~$0.01 per day (one open, one close)
- **Tradeoff:** More MOR locked, but amortized gas cost is negligible

### Multiple Concurrent Sessions

- You can have sessions open with multiple models simultaneously
- Each session locks its own MOR independently
- Close sessions you're not actively using to free up MOR
- Monitor with: `bash skills/everclaw/scripts/balance.sh`

---

## MOR Recycling — The Key Insight

The most powerful aspect of Morpheus economics:

```
1. You have 100 MOR
2. Open a session staking 10 MOR → 90 MOR free
3. Use the session for inference
4. Close the session → ~10 MOR returned → back to ~100 MOR
5. Open a new session with a different model
6. Repeat indefinitely
```

Your MOR balance stays roughly constant. You're paying only:
- **Gas fees** (ETH, very small on Base)
- **Tiny usage fees** (small fraction of staked MOR, deducted at close)

Over time, your MOR balance decreases very slowly from usage fees, but the rate is so low that even moderate MOR holdings provide months or years of inference.

---

## Economic Comparison

| Approach | Cost Model | Monthly Cost (moderate use) |
|----------|-----------|----------------------------|
| OpenAI API | Pay per token | $50-200+ |
| Claude API | Pay per token | $50-200+ |
| Morpheus | Stake MOR + gas | ~$1-5 in gas (MOR recycled) |
| Self-hosted | Hardware + electricity | $100-500+ |

The catch: you need to acquire MOR upfront. But once you have it, ongoing costs are minimal.

---

## Session Expiry

- Sessions have a fixed duration set at creation time
- When the duration elapses, the session **automatically expires**
- Staked MOR is returned to your wallet
- You don't need to manually close expired sessions (but you can close early)
- The router loses track of expired sessions — re-open if you need to continue

---

## Risks

| Risk | Likelihood | Mitigation |
|------|-----------|------------|
| MOR price drops | Medium | Only stake what you need; MOR is returned |
| Provider goes offline mid-session | Low | Close session, open with different provider |
| Smart contract bug | Very low | Contracts are audited; Diamond pattern is upgradeable |
| Gas spike on Base | Very low | Base gas is consistently cheap |
| Network congestion | Low | Sessions still work; new opens may take longer |

---

## Key Takeaway

MOR staking for inference is economically efficient because:
1. **MOR is locked, not burned** — you get it back
2. **Base gas is cheap** — transactions cost fractions of a cent
3. **Recycling is unlimited** — close → re-open → repeat
4. **No per-token pricing** — stake covers the session duration regardless of usage volume
