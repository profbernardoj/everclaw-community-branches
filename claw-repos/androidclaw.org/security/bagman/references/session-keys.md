# Session Keys for Agent Wallet Access

## Why Session Keys?

Instead of giving agents full control of a wallet's master private key, use **session keys** - delegated credentials with:

- **Time bounds**: Expire after N hours/days
- **Value limits**: Max spend per transaction or period
- **Scope restrictions**: Only specific contracts/methods
- **Revocability**: Can be invalidated without changing master key

## ERC-4337 Smart Account Session Keys

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│                Smart Account (ERC-4337)                  │
├─────────────────────────────────────────────────────────┤
│  validateUserOp() → SessionKeyValidator Module          │
│                          │                               │
│                          ↓                               │
│  ┌─────────────────────────────────────────────────┐    │
│  │ Session Key Registry                             │    │
│  │                                                  │    │
│  │  Session #1: 0xAgent1...                        │    │
│  │    ├─ validUntil: 1707955200                    │    │
│  │    ├─ validAfter: 1707868800                    │    │
│  │    ├─ spendingLimit: 1000 USDC/day              │    │
│  │    ├─ allowedTargets: [0xDEX, 0xLending]        │    │
│  │    └─ allowedSelectors: [swap, supply]          │    │
│  │                                                  │    │
│  │  Session #2: 0xAgent2...                        │    │
│  │    └─ ...different permissions...               │    │
│  └─────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
```

### Creating Session Keys with ZeroDev

```typescript
import { createKernelAccount, createKernelAccountClient } from "@zerodev/sdk";
import { createSessionKeyValidator, SessionKeyPlugin } from "@zerodev/session-key";
import { toFunctionSelector, parseAbi } from "viem";

// 1. Create the smart account (one-time setup by operator)
const kernelAccount = await createKernelAccount(publicClient, {
  plugins: {
    sudo: ecdsaValidator,  // Master key (hardware wallet)
    regular: sessionKeyValidator,
  },
});

// 2. Issue session key for agent
const sessionKey = generatePrivateKey();  // Agent's session key
const sessionPublicKey = privateKeyToAddress(sessionKey);

// 3. Define session permissions
const sessionKeyPermissions = {
  validUntil: Math.floor(Date.now() / 1000) + 86400,  // 24 hours
  validAfter: Math.floor(Date.now() / 1000),
  permissions: [
    // Allow USDC transfers up to 1000 per tx
    {
      target: USDC_ADDRESS,
      valueLimit: 0n,
      sig: toFunctionSelector(parseAbi(["function transfer(address,uint256)"])),
      rules: [
        { condition: "LESS_THAN_OR_EQUAL", value: 1000_000000n, offset: 36 }  // amount < 1000 USDC
      ]
    },
    // Allow swaps on approved DEX
    {
      target: UNISWAP_ROUTER,
      valueLimit: ethers.parseEther("0.1"),  // Max 0.1 ETH in value
      sig: toFunctionSelector(parseAbi(["function exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))"])),
    }
  ],
  paymaster: PAYMASTER_ADDRESS,  // Optional: sponsored gas
};

// 4. Enable session key (signed by master key)
const enableTx = await kernelAccountClient.enableSessionKey({
  sessionKeyAddress: sessionPublicKey,
  permissions: sessionKeyPermissions,
});

// 5. Store session key for agent (in 1Password)
// Agent receives: sessionKey (private), kernelAccount.address, permissions, validUntil
```

### Agent Using Session Key

```typescript
import { createKernelAccountClient } from "@zerodev/sdk";
import { sessionKeyToAccount } from "@zerodev/session-key";

// Agent retrieves session credentials
const sessionCreds = await getFrom1Password("trading-agent-session");

// Validate not expired
if (Date.now() / 1000 > sessionCreds.validUntil) {
  throw new Error("Session expired - request renewal from operator");
}

// Create session key signer
const sessionAccount = sessionKeyToAccount({
  privateKey: sessionCreds.sessionKey,
  smartAccountAddress: sessionCreds.smartAccount,
  permissions: sessionCreds.permissions,
});

// Create client with session key
const sessionClient = createKernelAccountClient({
  account: sessionAccount,
  chain: sepolia,
  transport: http(RPC_URL),
  paymaster: createZeroDevPaymasterClient({
    chain: sepolia,
    transport: http(PAYMASTER_URL),
  }),
});

// Execute operation (within session bounds)
const txHash = await sessionClient.sendUserOperation({
  userOperation: {
    callData: await sessionAccount.encodeCallData({
      to: USDC_ADDRESS,
      value: 0n,
      data: encodeFunctionData({
        abi: erc20Abi,
        functionName: "transfer",
        args: [recipient, parseUnits("100", 6)],  // 100 USDC
      }),
    }),
  },
});
```

### Session Key Lifecycle

```
┌─────────────────────────────────────────────────────────────────┐
│  OPERATOR (Human + Hardware Wallet)                             │
│                                                                 │
│  1. Create Smart Account (one-time)                             │
│     └─ Master key stays in hardware wallet                      │
│                                                                 │
│  2. Issue Session Key                                           │
│     └─ Sign enableSessionKey tx with master key                 │
│     └─ Define time/value/scope limits                           │
│     └─ Store session private key in 1Password for agent         │
│                                                                 │
│  3. Monitor                                                     │
│     └─ Review transaction logs                                  │
│     └─ Check spending against limits                            │
│                                                                 │
│  4. Renew or Revoke                                             │
│     └─ Issue new session before expiry                          │
│     └─ Revoke immediately if compromise suspected               │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  AGENT (Autonomous)                                             │
│                                                                 │
│  1. Retrieve session key from 1Password at startup              │
│  2. Validate expiry before use                                  │
│  3. Execute transactions within permitted scope                 │
│  4. If expired: stop operations, notify for renewal             │
│  5. Never store session key in persistent memory files          │
└─────────────────────────────────────────────────────────────────┘
```

---

## Permission Patterns

### Trading Agent

```typescript
const tradingPermissions = {
  validUntil: now + 86400,  // 24 hours
  permissions: [
    // Approve DEX to spend tokens
    { target: USDC_ADDRESS, sig: "approve(address,uint256)", rules: [...] },
    // Execute swaps
    { target: UNISWAP_ROUTER, sig: "exactInputSingle(...)", valueLimit: 0.1 ETH },
    // Provide liquidity
    { target: POOL_ADDRESS, sig: "addLiquidity(...)", rules: [...] },
  ],
  spendingLimits: [
    { token: USDC_ADDRESS, limit: 10000_000000n, period: 86400 },  // 10k USDC/day
  ]
};
```

### DeFi Yield Agent

```typescript
const yieldPermissions = {
  validUntil: now + 604800,  // 7 days
  permissions: [
    // Supply to lending protocol
    { target: AAVE_POOL, sig: "supply(address,uint256,address,uint16)", rules: [...] },
    // Withdraw
    { target: AAVE_POOL, sig: "withdraw(address,uint256,address)", rules: [...] },
    // Claim rewards
    { target: REWARDS_CONTROLLER, sig: "claimRewards(...)", rules: [...] },
  ],
  spendingLimits: [
    { token: WETH_ADDRESS, limit: parseEther("5"), period: 604800 },  // 5 ETH/week
  ]
};
```

### Payment Agent

```typescript
const paymentPermissions = {
  validUntil: now + 2592000,  // 30 days
  permissions: [
    // USDC transfers only
    { 
      target: USDC_ADDRESS, 
      sig: "transfer(address,uint256)",
      rules: [
        { offset: 36, condition: "LESS_THAN", value: 500_000000n }  // Max 500 USDC/tx
      ]
    },
  ],
  spendingLimits: [
    { token: USDC_ADDRESS, limit: 5000_000000n, period: 86400 },  // 5k USDC/day
  ]
};
```

---

## Revoking Session Keys

### Immediate Revocation

```typescript
// Operator revokes compromised session
await kernelAccountClient.disableSessionKey({
  sessionKeyAddress: compromisedSessionPublicKey,
});

// Or invalidate all sessions
await kernelAccountClient.disableAllSessionKeys();
```

### Emergency: Smart Account Upgrade

In extreme cases, upgrade the smart account's validation logic:

```typescript
// Change session key validator module (invalidates all sessions)
await kernelAccountClient.changeValidator({
  newValidator: newSessionKeyValidatorAddress,
});
```

---

## Best Practices

1. **Short Expiry**: Prefer 24-hour sessions over 30-day
2. **Tight Scope**: Only permit necessary contracts/methods
3. **Value Limits**: Set per-tx and daily spending caps
4. **Monitor**: Review all session key transactions
5. **Automate Renewal**: Set up alerts before expiry
6. **Separate Test/Prod**: Different session keys for different environments
7. **Document**: Keep clear records of active sessions and their permissions
