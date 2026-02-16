# Task 2: Morpheus Capital Contracts — Research Brief

**Date:** 2026-02-14
**Status:** Complete
**For:** [REDACTED] (Morpheus lead code maintainer)

---

## Executive Summary

Morpheus capital contracts allow users to deposit yield-bearing assets (stETH, USDC, USDT, wBTC) and redirect the yield to the Morpheus protocol in exchange for daily MOR token emissions. The depositor's principal is never touched — only the yield is diverted. This creates a non-dilutive funding model where the protocol is sustained by DeFi yield rather than token sales.

---

## How Capital Contracts Work

### The Core Mechanism

1. **User deposits** a supported asset (stETH, USDC, USDT, wBTC) into a `DepositPool` contract on Ethereum
2. **Assets are forwarded** to the `Distributor` contract, which deposits them into **Aave** lending markets to generate yield
3. **Yield accrues** via Aave interest rates (and stETH rebasing for ETH deposits)
4. **Yield is captured** by the protocol — converted to wstETH via Uniswap v3, bridged to Arbitrum via LayerZero
5. **On Arbitrum**, yield is used to buy MOR on the open market + provide protocol-owned liquidity
6. **MOR emissions** are distributed daily to capital providers proportional to the yield their deposit generates
7. **User can withdraw** their principal at any time (7-day lock on initial deposit for stETH)

### Key Principle: No Principal Risk

The depositor's principal is **never sold or spent**. Only the yield (interest, staking rewards) flows to the protocol. Users keep full custody of their assets and receive MOR in exchange for contributing yield.

---

## Contract Architecture

### Ethereum (L1) Core Contracts

| Contract | Role |
|----------|------|
| **DepositPool** | Entry point for user deposits. One instance per supported token (stETH, USDC, etc.). Handles user interactions, multipliers, lock logic |
| **Distributor (v1/v2)** | Calculates total MOR yield per pool. Deposits user assets into Aave. Uses Chainlink oracles for cross-asset normalization |
| **ChainLinkDataConsumer** | Normalizes yield from different assets to a common base (USD) using Chainlink price feeds |
| **RewardPool** | Contains the MOR emission curve logic (linear decay over 16 years) |
| **L1SenderV2** | Bridges reward data (via LayerZero) and yield (via Arbitrum bridge) from L1 to L2 |

### Arbitrum (L2) Core Contracts

| Contract | Role |
|----------|------|
| **L2MessageReceiver** | Receives LayerZero messages from L1, triggers MOR minting |
| **L2TokenReceiverV2** | Receives bridged yield (wstETH), swaps to MOR, adds to liquidity pools |

### Key Contract Addresses

| Contract | Chain | Address |
|----------|-------|---------|
| **Distribution (Capital)** | Ethereum | `0x47176B2Af9885dC6C4575d4eFd63895f7Aaa4790` |
| Diamond (Compute/Inference) | Base | `0x6aBE1d282f72B474E54527D93b979A4f64d3030a` |
| MOR Token | Base | `0x7431aDa8a591C955a994a21710752EF9b882b8e3` |
| MOR Token | Arbitrum | OFT standard (bridged via LayerZero) |
| MOR Token | Ethereum | OFT standard |

**Important distinction:** The Diamond contract on Base (`0x6aBE...`) is the **Compute Marketplace Router** (Lumerin integration) for inference. Capital deposit contracts live on **Ethereum L1**. MOR token is cross-chain via LayerZero OFT.

---

## MOR Token Economics

### Supply & Emission

- **Total supply cap:** 42,000,000 MOR (over ~16 years)
- **No pre-mine, no ICO** — fair launch on Feb 8, 2024
- **Emission curve:** Linear decrease — daily emissions decrease over time
- **Emission split:**
  - **24% Capital Providers** — deposit yield-bearing assets
  - **24% Code Providers** — develop Morpheus codebase
  - **24% Compute Providers** — provide AI inference compute
  - **24% Community** — builders creating frontends, tools, agents
  - **4% Protection Fund** — bug bounties, audits, security

### Yield → MOR Calculation

1. Each `DepositPool` tracks total deposits and generated yield
2. Chainlink oracles convert all yields to USD-equivalent base
3. MOR emissions for capital providers (24% of daily emissions) are split proportionally based on each depositor's share of total USD-normalized yield
4. **Power Factor multipliers** boost rewards for long-term reward staking (up to 10.7x for longest durations)
5. **Referral multipliers** provide additional boost
6. **Yield split:** 50% of captured yield buys MOR on open market, 50% pairs with MOR in Uniswap V3 as Protocol Owned Liquidity

### Capital Contract v2 (Sept 2025 Upgrade)

Quoted from David in the GlobeNewsWire announcement:
> "Today marks a significant milestone: the completion of Morpheus' Serenity Phase, moving Morpheus beyond a single yield source (Lido stETH) and opening it up to yield from many sources."

**Key changes in v2:**
- **Multi-asset staking**: USDC, USDT, wBTC added alongside stETH
- **Aave integration**: All assets deposited into Aave lending markets for yield
- **Chainlink oracles**: Real-time normalization of cross-asset yields to USD
- **No lock-up requirement** for new asset pools (stETH retains 7-day lock)
- **Buyback mechanism**: All yield is used to buy MOR on open market + provide protocol-owned liquidity

---

## Key Metrics

| Metric | Value | Source |
|--------|-------|--------|
| stETH attracted in first week | ~60,000 stETH (~$165M) | GlobeNewsWire Sept 2025 |
| Total ETH flowed through contracts | 320,000+ ETH | GlobeNewsWire Sept 2025 |
| Capital providers | 6,500+ | GlobeNewsWire Sept 2025 |
| MOR price (current) | ~$0.76 | CoinMarketCap |
| MOR circulating supply | Growing (emission curve) | — |
| MOR max supply | 42,000,000 | Whitepaper |

---

## How It Relates to Everclaw / David's Work

The capital contracts fund the **supply side** of Morpheus (compute providers get 24% of emissions, incentivizing providers to serve inference). Everclaw connects to the **demand side** — consuming that inference via MOR staking.

The virtuous cycle:
1. Capital providers deposit yield → earn MOR
2. MOR emissions incentivize compute providers → more inference supply
3. Users (via Everclaw) stake MOR → consume inference
4. MOR is returned after sessions → restaked → continuous demand
5. Increased inference demand → more compute providers needed → more MOR staked → price support

---

## Actionable Insights

1. **David is quoted in the official v2 announcement** — he has authority to drive narrative around capital contracts
2. **The multi-asset expansion (Sept 2025) is the biggest upgrade since launch** — worth creating Everclaw content explaining how capital flows become inference
3. **Protocol-owned liquidity via yield buybacks** creates a self-sustaining MOR market — this is a key differentiator vs inflationary token models
4. **Lock multipliers** mean long-term stakers earn disproportionately more — relevant for David's own MOR strategy
5. **Cross-chain architecture** (Ethereum deposits → Arbitrum distribution → Base inference) creates some complexity for new users — Everclaw could bridge this with better documentation
