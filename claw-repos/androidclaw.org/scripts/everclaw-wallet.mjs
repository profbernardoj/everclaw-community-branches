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
import { existsSync, readFileSync, writeFileSync, mkdirSync, chmodSync } from "node:fs";
import { join } from "node:path";
import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from "node:crypto";
import { createPublicClient, createWalletClient, http, formatEther, parseEther, formatUnits, parseUnits, encodeFunctionData, parseAbi, maxUint256 } from "viem";
import { base } from "viem/chains";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { platform } from "node:os";

// --- Configuration ---
const KEYCHAIN_ACCOUNT = process.env.EVERCLAW_KEYCHAIN_ACCOUNT || "everclaw-agent";
const KEYCHAIN_SERVICE = process.env.EVERCLAW_KEYCHAIN_SERVICE || "everclaw-wallet-key";
const RPC_URL = process.env.EVERCLAW_RPC || "https://base-mainnet.public.blastapi.io";
const KEY_STORE_PATH = process.env.EVERCLAW_KEY_STORE || join(process.env.HOME || "", ".everclaw", "wallet.enc");

// --- Cross-platform key storage backend ---
const OS = platform();

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

// --- Cross-Platform Key Storage ---
// Backend priority:
//   macOS  → macOS Keychain (security CLI)
//   Linux  → libsecret (secret-tool CLI) if available
//   All    → encrypted file fallback (~/.everclaw/wallet.enc)

// -- macOS Keychain backend --
function macKeychainStore(key) {
  try {
    try {
      execSync(
        `security add-generic-password -a "${KEYCHAIN_ACCOUNT}" -s "${KEYCHAIN_SERVICE}" -w "${key}" -U`,
        { stdio: "pipe" }
      );
    } catch {
      try { execSync(`security delete-generic-password -a "${KEYCHAIN_ACCOUNT}" -s "${KEYCHAIN_SERVICE}"`, { stdio: "pipe" }); } catch {}
      execSync(
        `security add-generic-password -a "${KEYCHAIN_ACCOUNT}" -s "${KEYCHAIN_SERVICE}" -w "${key}"`,
        { stdio: "pipe" }
      );
    }
    return true;
  } catch (e) {
    console.error("❌ macOS Keychain store failed:", e.message);
    return false;
  }
}

function macKeychainRetrieve() {
  try {
    return execSync(
      `security find-generic-password -a "${KEYCHAIN_ACCOUNT}" -s "${KEYCHAIN_SERVICE}" -w`,
      { stdio: "pipe", encoding: "utf-8" }
    ).trim();
  } catch {
    return null;
  }
}

// -- Linux libsecret backend (secret-tool) --
function hasSecretTool() {
  try {
    execSync("which secret-tool", { stdio: "pipe" });
    return true;
  } catch {
    return false;
  }
}

function libsecretStore(key) {
  try {
    execSync(
      `echo -n "${key}" | secret-tool store --label="Everclaw Wallet" service "${KEYCHAIN_SERVICE}" account "${KEYCHAIN_ACCOUNT}"`,
      { stdio: "pipe", input: key }
    );
    return true;
  } catch (e) {
    console.error("❌ secret-tool store failed:", e.message);
    return false;
  }
}

function libsecretRetrieve() {
  try {
    return execSync(
      `secret-tool lookup service "${KEYCHAIN_SERVICE}" account "${KEYCHAIN_ACCOUNT}"`,
      { stdio: "pipe", encoding: "utf-8" }
    ).trim();
  } catch {
    return null;
  }
}

// -- Encrypted file backend (universal fallback) --
// Uses AES-256-GCM with a key derived from machine-id + username.
// This is NOT as secure as Keychain/libsecret (key derivation input is guessable),
// but it's far better than plaintext and works on headless servers.
function getFileEncryptionKey() {
  // Derive from machine-id + username — stable across reboots, unique per machine
  let machineId = "everclaw-fallback";
  try {
    if (existsSync("/etc/machine-id")) {
      machineId = readFileSync("/etc/machine-id", "utf-8").trim();
    } else if (existsSync("/var/lib/dbus/machine-id")) {
      machineId = readFileSync("/var/lib/dbus/machine-id", "utf-8").trim();
    }
  } catch {}
  const salt = `everclaw-${KEYCHAIN_ACCOUNT}-${process.env.USER || "agent"}`;
  return scryptSync(machineId, salt, 32);
}

function encryptedFileStore(key) {
  try {
    const dir = join(process.env.HOME || "", ".everclaw");
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true, mode: 0o700 });
    }

    const encKey = getFileEncryptionKey();
    const iv = randomBytes(16);
    const cipher = createCipheriv("aes-256-gcm", encKey, iv);
    const encrypted = Buffer.concat([cipher.update(key, "utf-8"), cipher.final()]);
    const authTag = cipher.getAuthTag();

    // Store as: iv (16) + authTag (16) + ciphertext
    const blob = Buffer.concat([iv, authTag, encrypted]);
    writeFileSync(KEY_STORE_PATH, blob);
    chmodSync(KEY_STORE_PATH, 0o600);
    return true;
  } catch (e) {
    console.error("❌ Encrypted file store failed:", e.message);
    return false;
  }
}

function encryptedFileRetrieve() {
  try {
    if (!existsSync(KEY_STORE_PATH)) return null;
    const blob = readFileSync(KEY_STORE_PATH);
    if (blob.length < 33) return null; // iv(16) + authTag(16) + at least 1 byte

    const iv = blob.subarray(0, 16);
    const authTag = blob.subarray(16, 32);
    const encrypted = blob.subarray(32);

    const encKey = getFileEncryptionKey();
    const decipher = createDecipheriv("aes-256-gcm", encKey, iv);
    decipher.setAuthTag(authTag);
    const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    return decrypted.toString("utf-8");
  } catch {
    return null;
  }
}

// -- Unified interface --
function keychainStore(key) {
  if (OS === "darwin") {
    return macKeychainStore(key);
  }
  if (OS === "linux" && hasSecretTool()) {
    if (libsecretStore(key)) return true;
    // Fall through to file backend on failure
  }
  return encryptedFileStore(key);
}

function keychainRetrieve() {
  if (OS === "darwin") {
    return macKeychainRetrieve();
  }
  if (OS === "linux" && hasSecretTool()) {
    const val = libsecretRetrieve();
    if (val) return val;
    // Fall through to check file backend (migration case)
  }
  return encryptedFileRetrieve();
}

function keychainExists() {
  return keychainRetrieve() !== null;
}

function getBackendName() {
  if (OS === "darwin") return "macOS Keychain";
  if (OS === "linux" && hasSecretTool()) return "libsecret (secret-tool)";
  return `encrypted file (${KEY_STORE_PATH})`;
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

  const backend = getBackendName();
  console.log("");
  console.log("╔══════════════════════════════════════════════════════════════╗");
  console.log("║  ♾️  Everclaw Wallet Created                                ║");
  console.log("╠══════════════════════════════════════════════════════════════╣");
  console.log(`║  Address: ${account.address}  ║`);
  console.log("║                                                              ║");
  console.log(`║  Key stored via: ${backend.padEnd(42)}║`);
  console.log("║  Encrypted at rest.                                          ║");
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
    console.log(`   Backend: ${getBackendName()}\n`);
  } catch (e) {
    console.error(`❌ Invalid private key: ${e.message}`);
    process.exit(1);
  }
}

function showHelp() {
  console.log(`
♾️  Everclaw Wallet — Self-sovereign key management

Commands:
  setup                    Generate wallet, store securely
  address                  Show wallet address
  balance                  Show ETH, MOR, USDC balances
  swap eth <amount>        Swap ETH for MOR via Uniswap V3
  swap usdc <amount>       Swap USDC for MOR via Uniswap V3
  approve [amount]         Approve MOR for Morpheus staking
  export-key               Print private key (use with caution)
  import-key <0xkey>       Import existing private key

Key Storage Backends (auto-detected):
  macOS    → macOS Keychain (security CLI)
  Linux    → libsecret/secret-tool if available, encrypted file fallback
  Other    → encrypted file (~/.everclaw/wallet.enc)

Environment:
  EVERCLAW_RPC               Base RPC URL (default: public blastapi)
  EVERCLAW_KEY_STORE         Override encrypted file path (default: ~/.everclaw/wallet.enc)
  EVERCLAW_KEYCHAIN_ACCOUNT  Keychain/libsecret account name (default: everclaw-agent)
  EVERCLAW_KEYCHAIN_SERVICE  Keychain/libsecret service name (default: everclaw-wallet-key)

Current backend: ${getBackendName()}

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
