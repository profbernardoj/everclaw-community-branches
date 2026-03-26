# Wallet Management

EverClaw includes a self-contained wallet manager for MOR tokens on Base mainnet. No external dependencies required— just Node.js (bundled with OpenClaw).

## Overview

| Feature | Description |
|---------|-------------|
| **Key Storage** | macOS Keychain (encrypted, Touch ID protected) |
| **Supported Assets** | ETH, MOR, USDC on Base |
| **Swap Integration** | Uniswap V3 (no external DEX needed) |
| **Staking** | Diamond contract approval for [REDACTED] sessions |

---

## Setup

### Generate New Wallet

```bash
node skills/everclaw/scripts/everclaw-wallet.mjs setup
```

This generates a new Ethereum wallet and stores the private key in macOS Keychain.

### Import Existing Wallet

```bash
node skills/everclaw/scripts/everclaw-wallet.mjs import-key 0xYOUR_PRIVATE_KEY
```

### Show Wallet Address

```bash
node skills/everclaw/scripts/everclaw-wallet.mjs address
```

---

## Checking Balances

```bash
node skills/everclaw/scripts/everclaw-wallet.mjs balance
```

Output:
```
Wallet: 0x1234...5678
ETH:   0.0123
MOR:   5234.56
USDC:  150.00
MOR Allowance: 10000.00(approved for Diamond)
```

### Via Script

```bash
node skills/everclaw/scripts/balance.sh
```

---

## Acquiring MOR

You need MOR tokens to stake for P2P inference. MOR is on Base mainnet.

### Swap ETH for MOR

```bash
# Swap 0.01 ETH for MOR
node skills/everclaw/scripts/everclaw-wallet.mjs swap eth 0.01
```

### Swap USDC for MOR

```bash
# Swap 50 USDC for MOR
node skills/everclaw/scripts/everclaw-wallet.mjs swap usdc 50
```

### Manual Swap (DEX)

1. Go to [Uniswap on Base](https://app.uniswap.org/explore/tokens/base/0x7431ada8a591c955a994a21710752ef9b882b8e3)
2. Connect your wallet
3. Swap ETH or USDC for MOR

### How Much MOR?

| Duration | MOR Needed(approx) |
|----------|---------------------|
| Casual use | 100-500 MOR |
| Daily use | 500-2000 MOR |
| Heavy use | 2000+ MOR |

**Remember:** MOR is staked, not spent. You get it back when sessions close.

---

## Approving MOR for Staking

Before opening sessions, approve the Diamond contract:

```bash
node skills/everclaw/scripts/everclaw-wallet.mjs approve
```

This approves 10,000 MOR by default. Approve more if needed:

```bash
node skills/everclaw/scripts/everclaw-wallet.mjs approve 50000
```

### What Approval Does

Approval allows the Diamond contract to transfer MOR on your behalf for session staking. This is a standard ERC20 allowance.

---

## Session Staking

When you open a P2P session:

1. MOR is **staked** (locked) for the session duration
2. You send inference requests
3. Session closes or expires
4. MOR is **returned** to your wallet(minus tiny usage fees)

### Session Costs

| Duration | MOR Staked | Gas Cost |
|----------|------------|----------|
| 1 hour | ~50 MOR | ~0.001 ETH |
| 24 hours | ~500-1000 MOR | ~0.001 ETH |
| 7 days | ~4000 MOR | ~0.001 ETH |

The MOR is returned when the session ends. You only lose:
- A small amount to provider fees (fractions of MOR)
- ETH for gas (one transaction per session)

---

## Security Model

### Key Storage

Private keys are stored in **macOS Keychain**:

| Aspect | Implementation |
|--------|----------------|
| Encryption | AES-256 at rest |
| Access Control | Touch ID / login password |
| Memory Safety | Key injected at runtime, immediately unset |
| Disk Safety | Never written to plaintext files |

### Key Lifecycle

```
1. Generate/Import → macOS Keychain (encrypted)
2. Session Starts → Key loaded into memory
3. Transaction Signed → Key used once
4. Session Ends → Key cleared from memory
```

### 1Password Fallback

For advanced users, 1Password CLI is supported:

```bash
export OP_SERVICE_ACCOUNT_TOKEN=$(security find-generic-password -a "op" -s "token" -w)
export WALLET_PRIVATE_KEY=$(op item get "[REDACTED] Wallet" --fields "Private Key" --reveal)
```

---

## Contract Addresses

All contracts are on Base mainnet:

| Contract | Address |
|----------|---------|
| Diamond | `0x6aBE1d282f72B474E54527D93b979A4f64d3030a` |
| MOR Token | `0x7431aDa8a591C955a994a21710752EF9b882b8e3` |
| MOR/ETH Pool | `0x...` (Uniswap V3) |

---

## Command Reference

| Command | Description |
|---------|-------------|
| `setup` | Generate new wallet, store in Keychain |
| `address` | Show wallet address |
| `balance` | Show ETH, MOR, USDC balances + allowance |
| `swap eth <amount>` | Swap ETH → MOR via Uniswap V3 |
| `swap usdc <amount>` | Swap USDC → MOR via Uniswap V3 |
| `approve [amount]` | Approve MOR for [REDACTED] staking (default: 10000) |
| `export-key` | Print private key (use with caution) |
| `import-key <0xkey>` | Import existing private key |

---

## Troubleshooting

### "Insufficient ETH for gas"

Add ETH to your wallet on Base:
```bash
# Check ETH balance
node skills/everclaw/scripts/everclaw-wallet.mjs balance
```

You need ~0.005 ETH for months of gas fees.

### "ERC20: transfer amount exceeds balance"

Close old sessions to free staked MOR:
```bash
node skills/everclaw/scripts/session.sh list
node skills/everclaw/scripts/session.sh close 0xSESSION_ID
```

### "Execution reverted"

Usually means:
1. Insufficient MOR allowance → run `approve`
2. Insufficient MOR balance → swap or acquire more
3. Session already closed → check active sessions

---

## Next Steps

- [Inference](inference.md) — Open sessions, send requests
- [Acquiring MOR](../reference/acquiring-mor.md) — Detailed token guide
- [Contracts](../reference/contracts.md) — Full contract reference