#!/usr/bin/env node
/**
 * x402 Payment Client for Everclaw
 *
 * Makes HTTP requests that automatically handle x402 (HTTP 402) payment flows.
 * Signs USDC payments on Base using the agent's wallet (retrieved from 1Password
 * at runtime — never stored on disk).
 *
 * Flow:
 *   1. Send HTTP request to endpoint
 *   2. If 402 returned, parse PAYMENT-REQUIRED header
 *   3. Sign EIP-712 payment authorization via viem
 *   4. Retry with PAYMENT-SIGNATURE header
 *   5. Return response + payment receipt
 *
 * Usage:
 *   node x402-client.mjs GET https://api.example.com/endpoint
 *   node x402-client.mjs --dry-run GET https://api.example.com/endpoint
 *   node x402-client.mjs --max-amount 0.10 POST https://api.example.com/endpoint '{"data":"hello"}'
 *
 * Programmatic:
 *   import { makePayableRequest, createX402Client } from './x402-client.mjs';
 *
 * @license MIT
 * @see https://docs.cdp.coinbase.com/x402/welcome
 * @see https://x402.org
 */

import { createWalletClient, http, parseAbi } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { base } from "viem/chains";
import { execSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

// ─── Config ─────────────────────────────────────────────────────────────────

const USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const BASE_CHAIN_ID = 8453;
const CAIP2_BASE = "eip155:8453";
const FACILITATOR_URL = "https://api.cdp.coinbase.com/platform/v2/x402";
const USDC_DECIMALS = 6;

// Budget tracking file
const BUDGET_FILE = path.join(
  process.env.HOME || "/tmp",
  ".openclaw", "workspace", "skills", "everclaw", ".x402-budget.json"
);

// Default limits
const DEFAULT_MAX_PER_REQUEST = 1_000_000n; // $1.00 USDC (6 decimals)
const DEFAULT_DAILY_LIMIT = 10_000_000n;    // $10.00 USDC per day

// ─── EIP-712 Types for x402 "exact" scheme ──────────────────────────────────
// The "exact" EVM scheme uses an EIP-712 signature over a TransferWithAuthorization
// (EIP-3009) or a simple payment authorization struct.

const X402_PAYMENT_TYPES = {
  TransferWithAuthorization: [
    { name: "from", type: "address" },
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce", type: "bytes32" },
  ],
};

const USDC_EIP712_DOMAIN = {
  name: "USD Coin",
  version: "2",
  chainId: BASE_CHAIN_ID,
  verifyingContract: USDC_BASE,
};

// ─── Wallet / Key Management ────────────────────────────────────────────────

let _cachedKey = null;

/**
 * Retrieve the agent's private key from 1Password via macOS Keychain.
 * Cached for the process lifetime (never written to disk).
 */
function getPrivateKey() {
  if (_cachedKey) return _cachedKey;

  try {
    const token = execSync(
      'security find-generic-password -a "AGENT_USER" -s "op-service-account-token" -w',
      { encoding: "utf-8", timeout: 5000 }
    ).trim();

    const key = execSync(
      `OP_SERVICE_ACCOUNT_TOKEN=${token} op item get "Base Session Key" --vault "AGENT_VAULT" --fields "Private Key" --reveal`,
      { encoding: "utf-8", timeout: 10000, env: { ...process.env, OP_SERVICE_ACCOUNT_TOKEN: token } }
    ).trim();

    if (!key.startsWith("0x") || key.length !== 66) {
      throw new Error("Invalid private key format from 1Password");
    }

    _cachedKey = key;
    return key;
  } catch (e) {
    throw new Error(`Failed to retrieve private key from 1Password: ${e.message}`);
  }
}

// ─── Budget Tracking ────────────────────────────────────────────────────────

function loadBudget() {
  try {
    const data = JSON.parse(fs.readFileSync(BUDGET_FILE, "utf-8"));
    const today = new Date().toISOString().slice(0, 10);
    if (data.date !== today) {
      return { date: today, spent: 0n, transactions: [] };
    }
    return { ...data, spent: BigInt(data.spent) };
  } catch {
    return { date: new Date().toISOString().slice(0, 10), spent: 0n, transactions: [] };
  }
}

function saveBudget(budget) {
  const dir = path.dirname(BUDGET_FILE);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(BUDGET_FILE, JSON.stringify({
    ...budget,
    spent: budget.spent.toString(),
  }, null, 2));
}

function checkBudget(amount, maxPerRequest, dailyLimit) {
  const budget = loadBudget();
  if (amount > maxPerRequest) {
    throw new Error(
      `Payment amount $${formatUsdc(amount)} exceeds per-request limit of $${formatUsdc(maxPerRequest)}`
    );
  }
  if (budget.spent + amount > dailyLimit) {
    throw new Error(
      `Payment would exceed daily limit: spent $${formatUsdc(budget.spent)} + $${formatUsdc(amount)} > $${formatUsdc(dailyLimit)}`
    );
  }
}

function recordSpend(amount, url) {
  const budget = loadBudget();
  budget.spent = budget.spent + amount;
  budget.transactions.push({
    amount: amount.toString(),
    url,
    time: new Date().toISOString(),
  });
  saveBudget(budget);
}

function formatUsdc(amount) {
  const str = amount.toString().padStart(7, "0");
  return str.slice(0, -6) + "." + str.slice(-6);
}

// ─── x402 Protocol ──────────────────────────────────────────────────────────

/**
 * Parse the PAYMENT-REQUIRED header from a 402 response.
 */
export function parsePaymentRequired(headerValue) {
  if (!headerValue) throw new Error("No PAYMENT-REQUIRED header in 402 response");

  const parsed = typeof headerValue === "string" ? JSON.parse(headerValue) : headerValue;

  if (!parsed.accepts || !Array.isArray(parsed.accepts) || parsed.accepts.length === 0) {
    throw new Error("Invalid PAYMENT-REQUIRED: no accepts array");
  }

  // Find an "exact" EVM scheme on Base
  const baseAccept = parsed.accepts.find(a =>
    a.scheme === "exact" && a.network === CAIP2_BASE
  );

  if (!baseAccept) {
    const networks = parsed.accepts.map(a => `${a.scheme}@${a.network}`).join(", ");
    throw new Error(`No compatible payment scheme found. Available: ${networks}. We support: exact@${CAIP2_BASE}`);
  }

  return {
    scheme: baseAccept.scheme,
    network: baseAccept.network,
    amount: BigInt(baseAccept.maxAmountRequired || baseAccept.amount || "0"),
    asset: baseAccept.asset || USDC_BASE,
    recipient: baseAccept.recipient,
    extra: baseAccept.extra || {},
    x402Version: parsed.x402Version || 1,
    raw: parsed,
  };
}

/**
 * Create a signed payment payload for the x402 "exact" EVM scheme.
 * Uses EIP-3009 TransferWithAuthorization (USDC supports this natively on Base).
 */
export async function createPaymentSignature(requirements, privateKey) {
  const account = privateKeyToAccount(privateKey);

  // Generate a random nonce
  const nonceBytes = new Uint8Array(32);
  crypto.getRandomValues(nonceBytes);
  const nonce = "0x" + Array.from(nonceBytes).map(b => b.toString(16).padStart(2, "0")).join("");

  const now = Math.floor(Date.now() / 1000);
  const validAfter = BigInt(now - 60);      // Valid from 1 minute ago
  const validBefore = BigInt(now + 3600);    // Valid for 1 hour

  const message = {
    from: account.address,
    to: requirements.recipient,
    value: requirements.amount,
    validAfter,
    validBefore,
    nonce,
  };

  // Use the USDC EIP-712 domain (USDC on Base supports EIP-3009)
  const domain = {
    ...USDC_EIP712_DOMAIN,
    ...(requirements.extra?.name ? { name: requirements.extra.name } : {}),
    ...(requirements.extra?.version ? { version: requirements.extra.version } : {}),
  };

  const signature = await account.signTypedData({
    domain,
    types: X402_PAYMENT_TYPES,
    primaryType: "TransferWithAuthorization",
    message,
  });

  // Build the payment payload
  const payload = {
    x402Version: requirements.x402Version || 1,
    scheme: "exact",
    network: CAIP2_BASE,
    payload: {
      signature,
      authorization: {
        from: account.address,
        to: requirements.recipient,
        value: requirements.amount.toString(),
        validAfter: validAfter.toString(),
        validBefore: validBefore.toString(),
        nonce,
      },
    },
  };

  return {
    header: JSON.stringify(payload),
    payload,
    signer: account.address,
  };
}

/**
 * Make an HTTP request with automatic x402 payment handling.
 *
 * @param {string} url - The URL to request
 * @param {object} [options] - fetch options + x402 config
 * @param {bigint} [options.maxAmount] - Max USDC to pay (6 decimals). Default: $1.00
 * @param {bigint} [options.dailyLimit] - Daily spending limit. Default: $10.00
 * @param {boolean} [options.dryRun] - If true, show payment info without signing
 * @param {string} [options.privateKey] - Override private key (default: from 1Password)
 */
export async function makePayableRequest(url, options = {}) {
  const {
    maxAmount = DEFAULT_MAX_PER_REQUEST,
    dailyLimit = DEFAULT_DAILY_LIMIT,
    dryRun = false,
    privateKey: keyOverride,
    ...fetchOptions
  } = options;

  // Step 1: Make the initial request
  const initialRes = await fetch(url, fetchOptions);

  // If not 402, return normally
  if (initialRes.status !== 402) {
    return {
      response: initialRes,
      paid: false,
      body: await initialRes.text(),
    };
  }

  // Step 2: Parse payment requirements
  const paymentHeader = initialRes.headers.get("payment-required") ||
                         initialRes.headers.get("PAYMENT-REQUIRED");
  const requirements = parsePaymentRequired(paymentHeader);

  const humanAmount = formatUsdc(requirements.amount);
  console.error(`💰 x402 Payment Required: $${humanAmount} USDC → ${requirements.recipient}`);

  // Step 3: Check budget
  checkBudget(requirements.amount, maxAmount, dailyLimit);

  // Step 4: Dry-run check
  if (dryRun) {
    return {
      response: initialRes,
      paid: false,
      dryRun: true,
      requirements,
      wouldPay: `$${humanAmount} USDC`,
      recipient: requirements.recipient,
    };
  }

  // Step 5: Get private key and sign
  const key = keyOverride || getPrivateKey();
  const { header: paymentSignature, signer } = await createPaymentSignature(requirements, key);

  console.error(`✍️  Signed by ${signer}, retrying with payment...`);

  // Step 6: Retry with payment
  const paidRes = await fetch(url, {
    ...fetchOptions,
    headers: {
      ...fetchOptions.headers,
      "PAYMENT-SIGNATURE": paymentSignature,
    },
  });

  // Step 7: Record spend
  recordSpend(requirements.amount, url);

  // Step 8: Parse payment response
  const paymentResponse = paidRes.headers.get("payment-response") ||
                           paidRes.headers.get("PAYMENT-RESPONSE");

  const body = await paidRes.text();

  return {
    response: paidRes,
    paid: true,
    amount: `$${humanAmount}`,
    recipient: requirements.recipient,
    signer,
    paymentResponse: paymentResponse ? JSON.parse(paymentResponse) : null,
    body,
  };
}

/**
 * Create a reusable x402 client with pre-configured budget limits.
 */
export function createX402Client(config = {}) {
  const maxAmount = config.maxPerRequest
    ? BigInt(Math.round(config.maxPerRequest * 10 ** USDC_DECIMALS))
    : DEFAULT_MAX_PER_REQUEST;
  const dailyLimit = config.dailyLimit
    ? BigInt(Math.round(config.dailyLimit * 10 ** USDC_DECIMALS))
    : DEFAULT_DAILY_LIMIT;
  const dryRun = config.dryRun ?? false;

  return {
    fetch: (url, options = {}) => makePayableRequest(url, {
      ...options,
      maxAmount,
      dailyLimit,
      dryRun,
    }),
    get: (url, options = {}) => makePayableRequest(url, {
      ...options,
      method: "GET",
      maxAmount,
      dailyLimit,
      dryRun,
    }),
    post: (url, body, options = {}) => makePayableRequest(url, {
      ...options,
      method: "POST",
      body: typeof body === "string" ? body : JSON.stringify(body),
      headers: { "Content-Type": "application/json", ...options.headers },
      maxAmount,
      dailyLimit,
      dryRun,
    }),
    budget: () => {
      const b = loadBudget();
      return {
        date: b.date,
        spent: `$${formatUsdc(b.spent)}`,
        remaining: `$${formatUsdc(dailyLimit - b.spent)}`,
        limit: `$${formatUsdc(dailyLimit)}`,
        transactions: b.transactions.length,
      };
    },
  };
}

// ─── CLI ────────────────────────────────────────────────────────────────────

async function main() {
  const args = process.argv.slice(2);

  // Parse flags
  let dryRun = false;
  let maxAmount = DEFAULT_MAX_PER_REQUEST;
  const cleanArgs = [];

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--dry-run") {
      dryRun = true;
    } else if (args[i] === "--max-amount" && args[i + 1]) {
      maxAmount = BigInt(Math.round(parseFloat(args[++i]) * 10 ** USDC_DECIMALS));
    } else if (args[i] === "--budget") {
      const budget = loadBudget();
      console.log("Daily Budget:");
      console.log(`  Date:         ${budget.date}`);
      console.log(`  Spent:        $${formatUsdc(budget.spent)}`);
      console.log(`  Limit:        $${formatUsdc(DEFAULT_DAILY_LIMIT)}`);
      console.log(`  Remaining:    $${formatUsdc(DEFAULT_DAILY_LIMIT - budget.spent)}`);
      console.log(`  Transactions: ${budget.transactions.length}`);
      return;
    } else {
      cleanArgs.push(args[i]);
    }
  }

  const [method, url, body] = cleanArgs;

  if (!method || !url) {
    console.error("Usage:");
    console.error("  node x402-client.mjs [--dry-run] [--max-amount N] METHOD URL [BODY]");
    console.error("  node x402-client.mjs --budget");
    console.error("");
    console.error("Examples:");
    console.error("  node x402-client.mjs GET https://api.example.com/data");
    console.error("  node x402-client.mjs --dry-run GET https://api.example.com/data");
    console.error('  node x402-client.mjs POST https://api.example.com/do \'{"task":"hello"}\'');
    process.exit(1);
  }

  const fetchOpts = { method: method.toUpperCase() };
  if (body) {
    fetchOpts.body = body;
    fetchOpts.headers = { "Content-Type": "application/json" };
  }

  const result = await makePayableRequest(url, {
    ...fetchOpts,
    maxAmount,
    dryRun,
  });

  if (result.dryRun) {
    console.log("🔍 DRY RUN — would pay:");
    console.log(`  Amount:    ${result.wouldPay}`);
    console.log(`  Recipient: ${result.recipient}`);
    console.log(`  URL:       ${url}`);
  } else if (result.paid) {
    console.log(`✅ Paid ${result.amount} USDC to ${result.recipient}`);
    console.log(`   Signer: ${result.signer}`);
    if (result.paymentResponse) {
      console.log(`   Tx: ${JSON.stringify(result.paymentResponse)}`);
    }
    console.log("");
    console.log(result.body);
  } else {
    console.log(`HTTP ${result.response.status}`);
    console.log(result.body);
  }
}

const isMain = process.argv[1]?.endsWith("x402-client.mjs");
if (isMain) main().catch(e => { console.error(`Error: ${e.message}`); process.exit(1); });
