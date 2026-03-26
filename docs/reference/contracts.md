# Contracts Reference

Smart contract addresses on Base mainnet for [REDACTED] and related protocols.

---

## [REDACTED] Protocol

All [REDACTED] contracts are on Base mainnet (chain ID: 8453).

| Contract | Address | Purpose |
|----------|---------|---------|
| **Diamond** | `0x6aBE1d282f72B474E54527D93b979A4f64d3030a` | Main entry point for session management |
| **MOR Token** | `0x7431aDa8a591C955a994a21710752EF9b882b8e3` | MOR ERC20 token |
| **Implementation** | `0x093cCad61A3245Fb677a401069F8Aa30AFC4f34e` | Diamond implementation |

### Diamond Facets

The Diamond uses the EIP-2535 multi-facet pattern:

| Facet | Purpose |
|-------|---------|
| `SessionFacet` | Open/close inference sessions |
| `BalanceFacet` | Check MOR/ETH balances |
| `AllowanceFacet` | Approve MOR for staking |
| `ModelFacet` | Query available models |

---

## Token Addresses

| Token | Address | Chain |
|-------|---------|-------|
| MOR | `0x7431aDa8a591C955a994a21710752EF9b882b8e3` | Base |
| ETH | Native | Base |
| USDC | `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913` | Base |
| WETH | `0x4200000000000000000000000000000000000006` | Base |

---

## ERC-8004 Agent Registry

| Contract | Address | Purpose |
|----------|---------|---------|
| Identity Registry | `0x8004A169FB4a3325136EB29fA0ceB6D2e539a432` | Agent NFTs + metadata |
| Reputation Registry | `0x8004BAa17C55a88189AE136b182e5fdA19dE9b63` | Client feedback scores |

**Note:** Same addresses on all EVM chains (Ethereum, Base, Arbitrum, Polygon, Optimism, Linea, Avalanche).

---

## x402 Payment Protocol

| Component | Address/URL |
|-----------|-------------|
| USDC (Base) | `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913` |
| Coinbase Facilitator | `https://api.cdp.coinbase.com/platform/v2/x402` |
| Base Chain ID | `8453` (CAIP-2: `eip155:8453`) |

---

## DEX Addresses

For swapping tokens to MOR:

| DEX | Router Address |
|-----|----------------|
| Uniswap V3 | `0x2626664c2603336E57B271c5C0b26F421741e481` |
| Aerodrome | `0xcF77a3Ba9A5CA399B7c97c74d54e5b1Beb874E43` |

---

## Common Operations

### Check MOR Balance

```javascript
const morAddress = '0x7431aDa8a591C955a994a21710752EF9b882b8e3';
const balance = await provider.getBalance(walletAddress);
const morBalance = await new ethers.Contract(morAddress, erc20Abi, provider)
  .balanceOf(walletAddress);
```

### Check MOR Allowance

```javascript
const diamond = '0x6aBE1d282f72B474E54527D93b979A4f64d3030a';
const allowance = await new ethers.Contract(morAddress, erc20Abi, provider)
  .allowance(walletAddress, diamond);
```

### Approve MOR for Staking

```javascript
const amount = ethers.parseUnits('10000', 18); // 10,000 MOR
await new ethers.Contract(morAddress, erc20Abi, signer)
  .approve(diamond, amount);
```

---

## Chain Configuration

### Base Mainnet

```json
{
  "chainId": 8453,
  "name": "Base",
  "rpcUrl": "https://base-mainnet.public.blastapi.io",
  "blockExplorer": "https://basescan.org",
  "nativeCurrency": {
    "name": "Ether",
    "symbol": "ETH",
    "decimals": 18
  }
}
```

### Alternative RPC Endpoints

| Provider | URL |
|----------|-----|
| BlastAPI | `https://base-mainnet.public.blastapi.io` |
| Alchemy | `https://base-mainnet.g.alchemy.com/v2/YOUR_KEY` |
| Infura | `https://base-mainnet.infura.io/v3/YOUR_KEY` |
| Base | `https://mainnet.base.org` |

---

## Block Explorers

| Network | Explorer |
|---------|----------|
| Base | [basescan.org](https://basescan.org) |
| Base Sepolia | [sepolia.basescan.org](https://sepolia.basescan.org) |

**Useful Links:**
- [MOR Token on Basescan](https://basescan.org/token/0x7431ada8a591c955a994a21710752ef9b882b8e3)
- [Diamond Contract on Basescan](https://basescan.org/address/0x6abe1d282f72b474e54527d93b979a4f64d3030a)

---

## Gas Considerations

- Base uses EIP-1559 gas pricing
- Session open/close costs ~0.0001-0.001 ETH
- Keep at least 0.01 ETH on Base for operations
- Gas is cheaper during off-peak hours

---

## Next Steps

- [Wallet Management](../features/wallet.md) — Managing MOR and ETH
- [Inference](../features/inference.md) — Opening sessions
- [API Reference](api.md) — Using the contracts via API