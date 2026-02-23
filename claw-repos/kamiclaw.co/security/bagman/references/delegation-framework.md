# Delegation Framework Integration (EIP-7710)

Production-grade permission management for AI agents using MetaMask's Delegation Framework.

## Overview

The Delegation Framework enables **on-chain enforced permissions** for AI agents. Instead of relying solely on pattern-matching and software limits, delegations are cryptographically signed and enforced at the smart contract level.

```
┌─────────────────────────────────────────────────────────────┐
│                      User (Delegator)                       │
│                   DeleGator Smart Account                   │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ Creates Delegation
                              │ (signed, with caveats)
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                     AI Agent (Delegate)                     │
│              Holds delegation, redeems when needed          │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ Redeems Delegation
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                   Delegation Manager                        │
│  1. Validates signature                                     │
│  2. Checks caveats (AllowedTargets, SpendLimit, Expiry)    │
│  3. Executes if all checks pass                            │
└─────────────────────────────────────────────────────────────┘
```

## Why Delegation Framework?

| Bagman Pattern Matching | + Delegation Framework |
|------------------------|------------------------|
| Blocks "transfer all" text | On-chain enforces max spend per tx |
| In-memory session keys | Cryptographic delegations with revocation |
| Software rate limits | Contract-enforced daily/per-tx limits |
| Trust the agent's code | Trust the blockchain |

## Prerequisites

1. **User needs a DeleGator Smart Account** (ERC-4337 compatible)
2. **Deployed Delegation Manager** on your target chain
3. **Foundry** for contract interaction (or viem/ethers.js)

### Deployments

See [MetaMask Deployments](https://github.com/MetaMask/delegation-framework/blob/main/documents/Deployments.md) for addresses.

## Caveat Enforcers

Caveats are restrictions attached to delegations. Multiple caveats combine to create fine-grained permissions.

### Essential Caveats for AI Agents

| Caveat | Purpose | Example |
|--------|---------|---------|
| `AllowedTargetsEnforcer` | Whitelist contracts agent can call | Only USDC, Uniswap |
| `AllowedMethodsEnforcer` | Whitelist function selectors | Only `transfer`, `approve` |
| `ValueLteEnforcer` | Max ETH per transaction | ≤ 0.1 ETH |
| `ERC20BalanceChangeEnforcer` | Max token movement | ≤ 1000 USDC decrease |
| `TimestampEnforcer` | Delegation expiry | Valid for 24 hours |
| `NonceEnforcer` | Enable revocation | Increment nonce to revoke |
| `LimitedCallsEnforcer` | Max number of executions | 10 calls total |
| `NativeTokenPaymentEnforcer` | Require payment to redeem | Pay 0.001 ETH to use |

### Caveat Combinations

```solidity
// Agent can:
// - Call ONLY Uniswap and USDC contracts
// - Execute ONLY swap() and transfer() methods  
// - Move max 500 USDC per transaction
// - For 24 hours
// - Up to 20 total calls

Caveat[] memory caveats = new Caveat[](5);
caveats[0] = Caveat(allowedTargetsEnforcer, abi.encode([UNISWAP, USDC]));
caveats[1] = Caveat(allowedMethodsEnforcer, abi.encode([SWAP_SELECTOR, TRANSFER_SELECTOR]));
caveats[2] = Caveat(erc20BalanceChangeEnforcer, abi.encode(USDC, 500e6, false)); // max 500 decrease
caveats[3] = Caveat(timestampEnforcer, abi.encode(block.timestamp + 24 hours));
caveats[4] = Caveat(limitedCallsEnforcer, abi.encode(20));
```

## Integration with Bagman

Bagman provides **defense in depth**:
1. **Input Validation** (bagman) - Block suspicious prompts before they reach wallet code
2. **Output Sanitization** (bagman) - Prevent key leakage in responses
3. **On-chain Enforcement** (Delegation Framework) - Cryptographic guarantees on execution

```
USER INPUT
    │
    ▼
┌────────────────────────────┐
│ Bagman Input Validator     │  ← Block "transfer all", injection attempts
└────────────────────────────┘
    │
    ▼
┌────────────────────────────┐
│ Agent Logic                │  ← Decides what to execute
└────────────────────────────┘
    │
    ▼
┌────────────────────────────┐
│ Delegation Framework       │  ← On-chain enforcement of limits
└────────────────────────────┘
    │
    ▼
┌────────────────────────────┐
│ Bagman Output Sanitizer    │  ← Redact any secrets in response
└────────────────────────────┘
    │
    ▼
OUTPUT TO USER
```

## Creating a Delegation (Foundry)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Delegation} from "delegation-framework/src/utils/Types.sol";
import {IDelegationManager} from "delegation-framework/src/interfaces/IDelegationManager.sol";

contract AgentDelegationCreator {
    IDelegationManager public delegationManager;
    
    // Enforcer addresses (from deployments)
    address public allowedTargetsEnforcer;
    address public erc20BalanceChangeEnforcer;
    address public timestampEnforcer;
    address public limitedCallsEnforcer;
    
    function createAgentDelegation(
        address agent,
        address[] calldata allowedContracts,
        address token,
        uint256 maxTokenDecrease,
        uint256 validForSeconds,
        uint256 maxCalls
    ) external returns (bytes32 delegationHash) {
        Caveat[] memory caveats = new Caveat[](4);
        
        // Whitelist contracts
        caveats[0] = Caveat({
            enforcer: allowedTargetsEnforcer,
            terms: abi.encode(allowedContracts)
        });
        
        // Max token movement
        caveats[1] = Caveat({
            enforcer: erc20BalanceChangeEnforcer,
            terms: abi.encode(token, maxTokenDecrease, false) // false = decrease
        });
        
        // Expiry
        caveats[2] = Caveat({
            enforcer: timestampEnforcer,
            terms: abi.encode(block.timestamp + validForSeconds)
        });
        
        // Max calls
        caveats[3] = Caveat({
            enforcer: limitedCallsEnforcer,
            terms: abi.encode(maxCalls)
        });
        
        Delegation memory delegation = Delegation({
            delegate: agent,
            delegator: msg.sender,
            authority: bytes32(0), // Root delegation
            caveats: caveats,
            salt: uint256(keccak256(abi.encodePacked(block.timestamp, agent))),
            signature: "" // Will be signed by delegator
        });
        
        // Sign and store delegation
        // (In practice, this is signed off-chain and stored by the agent)
        delegationHash = delegationManager.getDelegationHash(delegation);
        return delegationHash;
    }
}
```

## Creating a Delegation (TypeScript/viem)

```typescript
import { encodeFunctionData, parseAbi } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

// Delegation Framework types
interface Caveat {
  enforcer: `0x${string}`;
  terms: `0x${string}`;
}

interface Delegation {
  delegate: `0x${string}`;
  delegator: `0x${string}`;
  authority: `0x${string}`;
  caveats: Caveat[];
  salt: bigint;
  signature: `0x${string}`;
}

// Create delegation for AI agent
async function createAgentDelegation(
  userAccount: ReturnType<typeof privateKeyToAccount>,
  agentAddress: `0x${string}`,
  config: {
    allowedTargets: `0x${string}`[];
    maxTokenDecrease: bigint;
    token: `0x${string}`;
    validForSeconds: number;
    maxCalls: number;
  }
): Promise<Delegation> {
  const now = Math.floor(Date.now() / 1000);
  
  // Encode caveat terms
  const caveats: Caveat[] = [
    {
      enforcer: ALLOWED_TARGETS_ENFORCER,
      terms: encodeAbiParameters(
        [{ type: 'address[]' }],
        [config.allowedTargets]
      ),
    },
    {
      enforcer: ERC20_BALANCE_CHANGE_ENFORCER,
      terms: encodeAbiParameters(
        [{ type: 'address' }, { type: 'uint256' }, { type: 'bool' }],
        [config.token, config.maxTokenDecrease, false]
      ),
    },
    {
      enforcer: TIMESTAMP_ENFORCER,
      terms: encodeAbiParameters(
        [{ type: 'uint256' }],
        [BigInt(now + config.validForSeconds)]
      ),
    },
    {
      enforcer: LIMITED_CALLS_ENFORCER,
      terms: encodeAbiParameters(
        [{ type: 'uint256' }],
        [BigInt(config.maxCalls)]
      ),
    },
  ];
  
  const delegation: Delegation = {
    delegate: agentAddress,
    delegator: userAccount.address,
    authority: '0x0000000000000000000000000000000000000000000000000000000000000000',
    caveats,
    salt: BigInt(Date.now()),
    signature: '0x',
  };
  
  // Sign delegation using EIP-712
  const signature = await userAccount.signTypedData({
    domain: {
      name: 'DelegationManager',
      version: '1',
      chainId: 1, // or your chain
      verifyingContract: DELEGATION_MANAGER,
    },
    types: {
      Delegation: [
        { name: 'delegate', type: 'address' },
        { name: 'delegator', type: 'address' },
        { name: 'authority', type: 'bytes32' },
        { name: 'caveats', type: 'Caveat[]' },
        { name: 'salt', type: 'uint256' },
      ],
      Caveat: [
        { name: 'enforcer', type: 'address' },
        { name: 'terms', type: 'bytes' },
      ],
    },
    primaryType: 'Delegation',
    message: delegation,
  });
  
  delegation.signature = signature;
  return delegation;
}
```

## Redeeming a Delegation (Agent Side)

```typescript
// Agent redeems delegation to execute action
async function executeWithDelegation(
  delegation: Delegation,
  execution: {
    target: `0x${string}`;
    value: bigint;
    callData: `0x${string}`;
  }
) {
  // Encode the delegation chain (just one delegation in this case)
  const delegationChain = [delegation];
  const permissionContext = encodeDelegationChain(delegationChain);
  
  // Call redeemDelegations on DelegationManager
  const tx = await walletClient.writeContract({
    address: DELEGATION_MANAGER,
    abi: DELEGATION_MANAGER_ABI,
    functionName: 'redeemDelegations',
    args: [
      [permissionContext],          // bytes[] permissionContexts
      [SINGLE_EXECUTION_MODE],      // ModeCode[] modes
      [encodeExecution(execution)], // bytes[] executionCallDatas
    ],
  });
  
  return tx;
}
```

## Revoking a Delegation

Users can revoke delegations at any time:

```typescript
// Revoke a specific delegation
await walletClient.writeContract({
  address: DELEGATION_MANAGER,
  abi: DELEGATION_MANAGER_ABI,
  functionName: 'disableDelegation',
  args: [delegation],
});
```

Or using nonces (revoke all delegations with lower nonce):

```typescript
// Increment nonce to invalidate old delegations
await walletClient.writeContract({
  address: NONCE_ENFORCER,
  abi: NONCE_ENFORCER_ABI,
  functionName: 'incrementNonce',
  args: [delegationManager],
});
```

## Security Considerations

### Defense in Depth

1. **Bagman validates input** - Catches injection attempts, suspicious patterns
2. **Delegation caveats enforce limits** - Even if agent is compromised, limits hold
3. **User can revoke anytime** - Single tx to disable all agent permissions

### Recommended Caveat Stack for AI Agents

```solidity
// Minimum recommended caveats for any AI agent delegation
Caveat[] memory safeCaveats = new Caveat[](5);

// 1. ALWAYS whitelist target contracts
safeCaveats[0] = Caveat(allowedTargetsEnforcer, allowedTargets);

// 2. ALWAYS set expiry (max 24-48 hours recommended)
safeCaveats[1] = Caveat(timestampEnforcer, expiry);

// 3. ALWAYS limit value per transaction
safeCaveats[2] = Caveat(valueLteEnforcer, maxEthPerTx);

// 4. ALWAYS limit total calls
safeCaveats[3] = Caveat(limitedCallsEnforcer, maxTotalCalls);

// 5. Use nonce for easy revocation
safeCaveats[4] = Caveat(nonceEnforcer, currentNonce);
```

### What NOT to Do

❌ **Don't create delegations without caveats** - Default is full access
❌ **Don't use long expiries** - 24 hours max for autonomous agents
❌ **Don't skip AllowedTargetsEnforcer** - Agent could call any contract
❌ **Don't trust input validation alone** - On-chain enforcement is the backstop

## Open Delegations

For multi-agent systems, you can create "open delegations" that any agent can redeem:

```solidity
// Open delegation - any address can redeem
Delegation memory openDelegation = Delegation({
    delegate: address(0xa11), // Special "anyone" address
    delegator: userAccount,
    authority: bytes32(0),
    caveats: caveats,  // Caveats still enforced!
    salt: salt,
    signature: signature
});
```

This is useful for:
- Agent swarms where any agent can execute
- Backup agents if primary is unavailable
- Delegation marketplaces

## Resources

- [Delegation Framework GitHub](https://github.com/MetaMask/delegation-framework)
- [EIP-7710 Specification](https://eips.ethereum.org/EIPS/eip-7710)
- [MetaMask Smart Accounts Kit](https://docs.metamask.io/smart-accounts-kit)
- [Gator Early Access](https://gator.metamask.io) - JS SDK beta

## Next Steps

1. Deploy a DeleGator Smart Account for your user
2. Create delegation with appropriate caveats
3. Store delegation securely (1Password via bagman patterns)
4. Integrate delegation redemption into your agent's execution flow
5. Combine with bagman input validation for defense in depth
