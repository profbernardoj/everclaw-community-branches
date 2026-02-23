# Everclaw — Acquiring MOR Tokens

You need MOR tokens on Base to use Everclaw. Here's how to get them.

---

## Quick Start (Fastest Path)

If you already have ETH, USDC, or USDT on Base:

```bash
# Swap ETH for MOR using the Everclaw swap script
bash skills/everclaw/scripts/swap.sh eth 0.01

# Swap USDC for MOR
bash skills/everclaw/scripts/swap.sh usdc 50

# Swap USDT for MOR
bash skills/everclaw/scripts/swap.sh usdt 50
```

If you don't have anything on Base yet, start with Option 1 or 2 below.

---

## Option 1: Buy on a Centralized Exchange

The simplest path for newcomers.

### Steps
1. Create an account on a supported exchange
2. Buy MOR (or ETH) with fiat currency
3. Withdraw MOR (or ETH) to your agent wallet on **Base network**

### Supported Exchanges
| Exchange | MOR Listed | Notes |
|----------|-----------|-------|
| [Uniswap](https://app.uniswap.org/explore/tokens/base/0x7431ada8a591c955a994a21710752ef9b882b8e3) | Yes (DEX) | Swap ETH/USDC → MOR on Base |
| [Aerodrome](https://aerodrome.finance/swap?from=eth&to=0x7431ada8a591c955a994a21710752ef9b882b8e3) | Yes (DEX) | Native Base DEX, often best liquidity |
| Coinbase | ETH/USDC | Buy ETH or USDC, send to Base, then swap to MOR |

⚠️ When withdrawing from an exchange, make sure to select **Base** as the network, not Ethereum mainnet. Base gas fees are fractions of a cent vs $5+ on Ethereum.

---

## Option 2: Bridge + Swap (If You Have Crypto on Other Chains)

If you have ETH, USDC, or USDT on Ethereum mainnet or another chain:

### Steps
1. Bridge to Base using the [official Base Bridge](https://bridge.base.org) or a fast bridge like [Across](https://across.to)
2. Swap to MOR on Base using the Everclaw swap script or a DEX (see below)

### Bridge Options
| Bridge | Speed | Cost |
|--------|-------|------|
| [Base Bridge](https://bridge.base.org) | ~10 minutes | Gas only |
| [Across Protocol](https://across.to) | ~2 minutes | Small fee |
| [Stargate](https://stargate.finance) | ~1 minute | Small fee |

---

## Option 3: Swap on Base (Recommended for Agents)

If your wallet already has ETH, USDC, or USDT on Base, swap directly for MOR.

### Automated (Everclaw Script)

```bash
# Swap 0.01 ETH → MOR
bash skills/everclaw/scripts/swap.sh eth 0.01

# Swap 50 USDC → MOR
bash skills/everclaw/scripts/swap.sh usdc 50

# Check how much MOR you'd get (dry run)
bash skills/everclaw/scripts/swap.sh eth 0.01 --quote
```

### Manual (Web UI)

**Uniswap:**
- Direct link: [MOR on Uniswap (Base)](https://app.uniswap.org/explore/tokens/base/0x7431ada8a591c955a994a21710752ef9b882b8e3)
- Select ETH → MOR, enter amount, confirm swap

**Aerodrome:**
- Direct link: [MOR on Aerodrome](https://aerodrome.finance/swap?from=eth&to=0x7431ada8a591c955a994a21710752ef9b882b8e3)
- Native Base DEX with deep MOR liquidity

---

## Key Token Addresses (Base)

| Token | Address | Decimals |
|-------|---------|----------|
| MOR | `0x7431aDa8a591C955a994a21710752EF9b882b8e3` | 18 |
| WETH | `0x4200000000000000000000000000000000000006` | 18 |
| USDC | `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913` | 6 |
| USDT | `0xfde4C96c8593536E31F229EA8f37b2ADa2699bb2` | 6 |

---

## How Much MOR Do I Need?

| Use Case | MOR Needed | Approximate Cost |
|----------|-----------|-----------------|
| Quick test (1-hour session) | 5-10 MOR | ~$5-10 |
| Daily use (24h sessions) | 50-100 MOR | ~$50-100 |
| Heavy use (multiple concurrent models) | 200-500 MOR | ~$200-500 |
| Set and forget (large stake, recycle) | 500+ MOR | ~$500+ |

Remember: MOR is **staked, not spent**. You get it back when sessions close. Once you acquire MOR, your ongoing costs are just Base gas fees (fractions of a cent per transaction).

---

## How Much ETH Do I Need for Gas?

Base gas is extremely cheap. Budget:

| Amount | Lasts |
|--------|-------|
| 0.005 ETH (~$15) | Weeks of moderate use |
| 0.01 ETH (~$30) | Months of moderate use |
| 0.05 ETH (~$150) | Effectively forever |

---

## For OpenClaw Agents: Onboarding Flow

The recommended flow for setting up a new agent with Everclaw:

1. **Fund agent wallet with ETH on Base** (send from your personal wallet or exchange)
2. **Run the swap script** to convert some ETH to MOR: `bash skills/everclaw/scripts/swap.sh eth 0.05`
3. **Approve MOR** for the Diamond contract (done automatically on first session open)
4. **Open a session** and start inference

The entire process takes about 5 minutes once ETH is in the wallet.
