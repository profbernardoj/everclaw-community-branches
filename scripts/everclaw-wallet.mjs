#!/usr/bin/env node
/**
 * everclaw-wallet.mjs — Self-contained wallet management for Everclaw
 *
 * Replaces: 1Password, Foundry/cast, Safe Wallet, jq
 * Uses: viem (bundled with OpenClaw), macOS Keychain (built-in)
 *
 * Commands:
 *   setup                    Generate wallet, store in Keychain, print address
 *   address                  Show wallet address
 *   balance                  Show ETH, MOR, USDC balances
 *   swap eth <amount>        Swap ETH for MOR via Uniswap V3
 *   swap usdc <amount>       Swap USDC for MOR via Uniswap V3
 *   approve [amount]         Approve MOR spending for Morpheus Diamond contract
 *   export-key               Print private key (use with caution)
 *   import-key <key>         Import existing private key into Keychain
 */

import { execSync } from "node:child_process";
import { createPublicClient, createWalletClient, http, formatEther, parseEther, formatUnits, parseUnits, encodeFunctionData, parseAbi, maxUint256 } from "viem";
import { base } from "viem/chains";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

// --- Configuration ---
const KEYCHAIN_ACCOUNT = process.env.EVERCLAW_KEYCHAIN_ACCOUNT || "everclaw-agent";
const KEYCHAIN_SERVICE = process.env.EVERCLAW_KEYCHAIN_SERVICE || "everclaw-wallet-key";
const RPC_URL = process.env.EVERCLAW_RPC || "https://base-mainnet.public.blastapi.io";

// --- Contract Addresses (Base Mainnet) ---
const MOR_TOKEN = "0x7431aDa8a591C955a994a21710752EF9b882b8e3";
const USDC_TOKEN = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const WETH_TOKEN = "0x4200000000000000000000000000000000000006";
const DIAMOND_CONTRACT = "0x6aBE1d282f72B474E54527D93b979A4f64d3030a";
const UNISWAP_ROUTER = "0x2626664c2603336E57B271c5C0b26F421741e481"; // SwapRouter02 on Base
const UNISWAP_QUOTER = "0x3d4e44Eb1374240CE5F1B871ab261CD16335B76a"; // QuoterV2 on Base

// --- ABIs ---
const ERC20_ABI = parseAbi([
  "function balanceOf(address) view returns (uint256)",
  "function approve(address spender, uint256 amount) returns (bool)",
  "function allowance(address owner, address spender) view returns (uint256)",
  "function decimals() view returns (uint8)",
]);

const SWAP_ROUTER_ABI = parseAbi([
  "function exactInputSingle((address tokenIn, address tokenOut, uint24 fee, address recipient, uint256 amountIn, uint256 amountOutMinimum, uint160 sqrtPriceLimitX96)) payable returns (uint256 amountOut)",
]);

// --- Keychain Helpers ---
function keychainStore(key) {
  try {
    // Try update first, then add
    try {
      execSync(
        `security add-generic-password -a "${KEYCHAIN_ACCOUNT}" -s "${KEYCHAIN_SERVICE}" -w "${key}" -U`,
        { stdio: "pipe" }
      );
    } catch {
      // If add fails, try delete + add
      try { execSync(`security delete-generic-password -a "${KEYCHAIN_ACCOUNT}" -s "${KEYCHAIN_SERVICE}"`, { stdio: "pipe" }); } catch {}
      execSync(
        `security add-generic-password -a "${KEYCHAIN_ACCOUNT}" -s "${KEYCHAIN_SERVICE}" -w "${key}"`,
        { stdio: "pipe" }
      );
    }
    return true;
  } catch (e) {
    console.error("❌ Failed to store key in Keychain:", e.message);
    return false;
  }
}

function keychainRetrieve() {
  try {
    const key = execSync(
      `security find-generic-password -a "${KEYCHAIN_ACCOUNT}" -s "${KEYCHAIN_SERVICE}" -w`,
      { stdio: "pipe", encoding: "utf-8" }
    ).trim();
    return key;
  } catch {
    return null;
  }
}

function keychainExists() {
  return keychainRetrieve() !== null;
}

// --- Viem Clients ---
function getPublicClient() {
  return createPublicClient({
    chain: base,
    transport: http(RPC_URL),
  });
}

function getWalletClient(privateKey) {
  const account = privateKeyToAccount(privateKey);
  return createWalletClient({
    account,
    chain: base,
    transport: http(RPC_URL),
  });
}

function getAccount(privateKey) {
  return privateKeyToAccount(privateKey);
}

// --- Commands ---

async function cmdSetup() {
  if (keychainExists()) {
    const existing = keychainRetrieve();
    const account = getAccount(existing);
    console.log("⚠️  Wallet already exists in Keychain.");
    console.log(`   Address: ${account.address}`);
    console.log("   Use 'import-key' to replace it, or 'address' to view it.");
    return;
  }

  console.log("🔐 Generating new Ethereum wallet...");
  const privateKey = generatePrivateKey();
  const account = getAccount(privateKey);

  if (!keychainStore(privateKey)) {
    console.error("❌ Failed to store in Keychain. Wallet NOT saved.");
    console.error("   You would need to save this key manually (NEVER share it):");
    console.error(`   ${privateKey}`);
    process.exit(1);
  }

  console.log("");
  console.log("╔══════════════════════════════════════════════════════════════╗");
  console.log("║  ♾️  Everclaw Wallet Created                                ║");
  console.log("╠══════════════════════════════════════════════════════════════╣");
  console.log(`║  Address: ${account.address}  ║`);
  console.log("║                                                              ║");
  console.log("║  Private key stored in macOS Keychain (encrypted at rest).   ║");
  console.log("║  Protected by your login password / Touch ID.                ║");
  console.log("║                                                              ║");
  console.log("║  NEXT STEPS:                                                 ║");
  console.log("║  1. Send ETH to the address above (for gas + MOR swap)      ║");
  console.log("║  2. Run: node everclaw-wallet.mjs swap eth 0.05             ║");
  console.log("║  3. Run: node everclaw-wallet.mjs approve                   ║");
  console.log("║  4. Start inference: bash start.sh                           ║");
  console.log("╚══════════════════════════════════════════════════════════════╝");
}

async function cmdAddress() {
  const key = keychainRetrieve();
  if (!key) {
    console.error("❌ No wallet found. Run 'setup' first.");
    process.exit(1);
  }
  const account = getAccount(key);
  console.log(account.address);
}

async function cmdBalance() {
  const key = keychainRetrieve();
  if (!key) {
    console.error("❌ No wallet found. Run 'setup' first.");
    process.exit(1);
  }
  const account = getAccount(key);
  const client = getPublicClient();

  console.log(`\n💰 Balances for ${account.address}\n`);

  // ETH balance
  const ethBalance = await client.getBalance({ address: account.address });
  console.log(`   ETH:  ${formatEther(ethBalance)}`);

  // MOR balance
  const morBalance = await client.readContract({
    address: MOR_TOKEN,
    abi: ERC20_ABI,
    functionName: "balanceOf",
    args: [account.address],
  });
  console.log(`   MOR:  ${formatEther(morBalance)}`);

  // USDC balance
  const usdcBalance = await client.readContract({
    address: USDC_TOKEN,
    abi: ERC20_ABI,
    functionName: "balanceOf",
    args: [account.address],
  });
  console.log(`   USDC: ${formatUnits(usdcBalance, 6)}`);

  // MOR allowance for Diamond
  const allowance = await client.readContract({
    address: MOR_TOKEN,
    abi: ERC20_ABI,
    functionName: "allowance",
    args: [account.address, DIAMOND_CONTRACT],
  });
  console.log(`\n   MOR allowance (Diamond): ${formatEther(allowance)}`);
  console.log("");
}

async function cmdSwap(tokenIn, amountStr) {
  if (!tokenIn || !amountStr) {
    console.error("Usage: everclaw-wallet.mjs swap <eth|usdc> <amount>");
    process.exit(1);
  }

  const key = keychainRetrieve();
  if (!key) {
    console.error("❌ No wallet found. Run 'setup' first.");
    process.exit(1);
  }

  const account = getAccount(key);
  const publicClient = getPublicClient();
  const walletClient = getWalletClient(key);

  const isETH = tokenIn.toLowerCase() === "eth";
  const isUSDC = tokenIn.toLowerCase() === "usdc";

  if (!isETH && !isUSDC) {
    console.error("❌ Supported tokens: eth, usdc");
    process.exit(1);
  }

  const tokenInAddress = isETH ? WETH_TOKEN : USDC_TOKEN;
  const decimals = isETH ? 18 : 6;
  const amountIn = isETH ? parseEther(amountStr) : parseUnits(amountStr, 6);
  const fee = 10000; // 1% fee tier (most common for MOR pairs)

  console.log(`\n🔄 Swapping ${amountStr} ${tokenIn.toUpperCase()} → MOR on Uniswap V3...\n`);

  // For USDC, approve the router first
  if (isUSDC) {
    console.log("   Approving USDC for swap router...");
    const approveTx = await walletClient.writeContract({
      address: USDC_TOKEN,
      abi: ERC20_ABI,
      functionName: "approve",
      args: [UNISWAP_ROUTER, amountIn],
    });
    console.log(`   Approve tx: ${approveTx}`);
    await publicClient.waitForTransactionReceipt({ hash: approveTx });
    console.log("   ✓ Approved\n");
  }

  // Execute swap
  const swapParams = {
    tokenIn: tokenInAddress,
    tokenOut: MOR_TOKEN,
    fee,
    recipient: account.address,
    amountIn,
    amountOutMinimum: 0n, // Accept any amount (slippage tolerance for simplicity)
    sqrtPriceLimitX96: 0n,
  };

  console.log("   Executing swap...");

  try {
    const tx = await walletClient.writeContract({
      address: UNISWAP_ROUTER,
      abi: SWAP_ROUTER_ABI,
      functionName: "exactInputSingle",
      args: [swapParams],
      value: isETH ? amountIn : 0n, // Send ETH value for ETH swaps
    });

    console.log(`   Swap tx: ${tx}`);
    const receipt = await publicClient.waitForTransactionReceipt({ hash: tx });

    if (receipt.status === "success") {
      // Check new MOR balance
      const morBalance = await publicClient.readContract({
        address: MOR_TOKEN,
        abi: ERC20_ABI,
        functionName: "balanceOf",
        args: [account.address],
      });
      console.log(`\n   ✅ Swap successful!`);
      console.log(`   MOR balance: ${formatEther(morBalance)}`);
    } else {
      console.error("\n   ❌ Swap transaction reverted.");
    }
  } catch (e) {
    console.error(`\n   ❌ Swap failed: ${e.shortMessage || e.message}`);
    process.exit(1);
  }
  console.log("");
}

async function cmdApprove(amountStr) {
  const key = keychainRetrieve();
  if (!key) {
    console.error("❌ No wallet found. Run 'setup' first.");
    process.exit(1);
  }

  const publicClient = getPublicClient();
  const walletClient = getWalletClient(key);

  // Default: approve max (so user doesn't have to re-approve)
  const amount = amountStr ? parseEther(amountStr) : maxUint256;
  const displayAmount = amountStr || "unlimited";

  console.log(`\n🔓 Approving MOR for Morpheus Diamond contract...`);
  console.log(`   Amount: ${displayAmount}`);
  console.log(`   Spender: ${DIAMOND_CONTRACT}\n`);

  try {
    const tx = await walletClient.writeContract({
      address: MOR_TOKEN,
      abi: ERC20_ABI,
      functionName: "approve",
      args: [DIAMOND_CONTRACT, amount],
    });

    console.log(`   Tx: ${tx}`);
    await publicClient.waitForTransactionReceipt({ hash: tx });
    console.log("   ✅ MOR approved for staking.\n");
  } catch (e) {
    console.error(`   ❌ Approve failed: ${e.shortMessage || e.message}`);
    process.exit(1);
  }
}

async function cmdExportKey() {
  const key = keychainRetrieve();
  if (!key) {
    console.error("❌ No wallet found. Run 'setup' first.");
    process.exit(1);
  }
  const account = getAccount(key);
  console.log(`\n⚠️  PRIVATE KEY — DO NOT SHARE THIS WITH ANYONE\n`);
  console.log(`   Address: ${account.address}`);
  console.log(`   Key:     ${key}\n`);
}

async function cmdImportKey(privateKey) {
  if (!privateKey) {
    console.error("Usage: everclaw-wallet.mjs import-key <0x...private_key>");
    process.exit(1);
  }

  if (!privateKey.startsWith("0x")) {
    privateKey = "0x" + privateKey;
  }

  try {
    const account = getAccount(privateKey);
    if (!keychainStore(privateKey)) {
      console.error("❌ Failed to store key in Keychain.");
      process.exit(1);
    }
    console.log(`\n✅ Key imported successfully.`);
    console.log(`   Address: ${account.address}`);
    console.log(`   Stored in macOS Keychain.\n`);
  } catch (e) {
    console.error(`❌ Invalid private key: ${e.message}`);
    process.exit(1);
  }
}

function showHelp() {
  console.log(`
♾️  Everclaw Wallet — Self-sovereign key management

Commands:
  setup                    Generate wallet, store in macOS Keychain
  address                  Show wallet address
  balance                  Show ETH, MOR, USDC balances
  swap eth <amount>        Swap ETH for MOR via Uniswap V3
  swap usdc <amount>       Swap USDC for MOR via Uniswap V3
  approve [amount]         Approve MOR for Morpheus staking
  export-key               Print private key (use with caution)
  import-key <0xkey>       Import existing private key

Environment:
  EVERCLAW_RPC             Base RPC URL (default: public blastapi)
  EVERCLAW_KEYCHAIN_ACCOUNT  Keychain account name (default: everclaw-agent)
  EVERCLAW_KEYCHAIN_SERVICE  Keychain service name (default: everclaw-wallet-key)

Examples:
  node everclaw-wallet.mjs setup
  node everclaw-wallet.mjs swap eth 0.05
  node everclaw-wallet.mjs balance
`);
}

// --- Main ---
const [,, command, ...args] = process.argv;

switch (command) {
  case "setup":
    cmdSetup().catch(console.error);
    break;
  case "address":
    cmdAddress().catch(console.error);
    break;
  case "balance":
    cmdBalance().catch(console.error);
    break;
  case "swap":
    cmdSwap(args[0], args[1]).catch(console.error);
    break;
  case "approve":
    cmdApprove(args[0]).catch(console.error);
    break;
  case "export-key":
    cmdExportKey().catch(console.error);
    break;
  case "import-key":
    cmdImportKey(args[0]).catch(console.error);
    break;
  default:
    showHelp();
}
