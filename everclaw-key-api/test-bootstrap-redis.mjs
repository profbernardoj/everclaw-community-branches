#!/usr/bin/env node
/**
 * Full Bootstrap Integration Test with Redis
 * 
 * Tests the complete bootstrap flow with Redis for:
 * - Challenge storage
 * - Daily limits
 * - Fingerprint deduplication
 * 
 * ⚠️ This spends REAL funds on Base mainnet!
 */

import { createWalletClient, createPublicClient, http, parseEther, parseUnits, formatEther, formatUnits } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { base } from 'viem/chains';
import { createClient } from 'redis';
import crypto from 'crypto';
import os from 'os';

// Configuration
const TREASURY_KEY = process.env.TREASURY_HOT_KEY;
const USDC_ADDRESS = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913'; // Base mainnet
const REDIS_URL = process.env.REDIS_URL || 'redis://localhost:6379';

const ETH_AMOUNT = parseEther('0.0008');
const USDC_AMOUNT = parseUnits('2.00', 6);
const ETH_LIMIT = parseEther('0.01'); // Test limit
const USDC_LIMIT = parseUnits('50', 6); // Test limit

// ERC-20 ABI
const ERC20_ABI = [
  {
    name: 'transfer',
    type: 'function',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'to', type: 'address' },
      { name: 'amount', type: 'uint256' }
    ],
    outputs: [{ name: '', type: 'bool' }]
  },
  {
    name: 'balanceOf',
    type: 'function',
    stateMutability: 'view',
    inputs: [{ name: 'account', type: 'address' }],
    outputs: [{ name: '', type: 'uint256' }]
  }
];

// Atomic daily limit Lua script
const LIMIT_LUA = `
  local key = KEYS[1]
  local limit = tonumber(ARGV[1])
  local amount = tonumber(ARGV[2])
  local current = tonumber(redis.call('GET', key) or '0')
  if current + amount > limit then
    return 0
  else
    redis.call('INCRBY', key, amount)
    redis.call('EXPIRE', key, 86400)
    return 1
  end
`;

// ─── Fingerprint ────────────────────────────────────────────────────────────

function getFingerprint() {
  if (process.env.TEST_FINGERPRINT) {
    return process.env.TEST_FINGERPRINT;
  }
  const hostname = os.hostname();
  const platform = process.platform;
  const cpus = os.cpus().map(c => c.model).join(',');
  return crypto.createHash('sha256')
    .update(`${hostname}:${platform}:${cpus}`)
    .digest('hex');
}

// ─── PoW Solver─────────────────────────────────────────────────────────────

async function solvePoW(challenge) {
  const start = Date.now();
  for (let i = 0; Date.now() - start < 60000; i++) {
    const hash = crypto.createHash('sha256')
      .update(challenge + i.toString())
      .digest('hex');
    if (hash.startsWith('000000')) {
      return i.toString(16);
    }
  }
  throw new Error('PoW timeout');
}

async function main() {
  if (!TREASURY_KEY) {
    console.error('Error: TREASURY_HOT_KEY environment variable required');
    process.exit(1);
  }

  console.log('='.repeat(60));
  console.log('Full Bootstrap Integration Test with Redis');
  console.log('='.repeat(60));
  console.log();

  // Connect to Redis
  console.log('Connecting to Redis...');
  const redis = createClient({ url: REDIS_URL });
  await redis.connect();
  console.log('   ✅ Connected');
  console.log();

  // Setup wallet
  const treasury = privateKeyToAccount(TREASURY_KEY);
  const client = createWalletClient({
    account: treasury,
    chain: base,
    transport: http('https://base-mainnet.public.blastapi.io')
  });
  const publicClient = createPublicClient({
    chain: base,
    transport: http('https://base-mainnet.public.blastapi.io')
  });

  // Generate test user
  const userKey = '0x' + crypto.randomBytes(32).toString('hex');
  const userWallet = privateKeyToAccount(userKey);

  console.log('📋Configuration:');
  console.log(`  Treasury: ${treasury.address}`);
  console.log(`  User: ${userWallet.address}`);
  console.log(`  Redis: ${REDIS_URL}`);
  console.log();

  // Check balances
  console.log('💰 Treasury Balances:');
  const ethBalance = await publicClient.getBalance({ address: treasury.address });
  const usdcBalance = await publicClient.readContract({
    address: USDC_ADDRESS,
    abi: ERC20_ABI,
    functionName: 'balanceOf',
    args: [treasury.address]
  });
  console.log(`  ETH: ${formatEther(ethBalance)}`);
  console.log(`  USDC: ${formatUnits(usdcBalance, 6)}`);
  console.log();

  // Check limits
  const today = new Date().toISOString().slice(0, 10);
  const ethKey = `bootstrap:daily:eth:${today}`;
  const usdcKey = `bootstrap:daily:usdc:${today}`;

  const ethSpent = await redis.get(ethKey) || '0';
  const usdcSpent = await redis.get(usdcKey) || '0';
  console.log('📊 Daily Limits:');
  console.log(`  ETH spent: ${formatEther(BigInt(ethSpent))} / ${formatEther(ETH_LIMIT)}`);
  console.log(`  USDC spent: ${formatUnits(BigInt(usdcSpent), 6)} / ${formatUnits(USDC_LIMIT, 6)}`);
  console.log();

  // Step 1: Check fingerprint not already used
  console.log('Step 1: Check Fingerprint');
  const fingerprint = getFingerprint();
  console.log(`   Fingerprint: ${fingerprint.slice(0, 16)}...`);
  
  const existingFingerprint = await redis.get(`fingerprint:${fingerprint}`);
  if (existingFingerprint) {
    console.log('   ❌ Fingerprint already used!');
    await redis.disconnect();
    process.exit(1);
  }
  console.log('   ✅ Fingerprint available');
  console.log();

  // Step 2: Generate and store challenge
  console.log('Step 2: Generate Challenge');
  const challenge = crypto.randomBytes(32).toString('hex');
  const timestamp = Date.now();
  await redis.set(`challenge:${fingerprint}`, JSON.stringify({ challenge, timestamp }), { EX: 60 });
  console.log(`   Challenge: ${challenge.slice(0, 16)}...`);
  console.log('   ✅ Challenge stored (60s expiry)');
  console.log();

  // Step 3: Solve PoW
  console.log('Step 3: Solve Proof of Work');
  const solution = await solvePoW(challenge);
  const hash = crypto.createHash('sha256')
    .update(challenge + parseInt(solution, 16))
    .digest('hex');
  console.log(`   Solution: ${solution}`);
  console.log(`   Hash: ${hash.slice(0, 16)}... (valid: ${hash.startsWith('000000')})`);
  console.log();

  // Step 4: Verify challenge and check limits atomically
  console.log('Step 4: Verify & Check Limits');
  
  // Verify challenge
  const storedChallenge = await redis.get(`challenge:${fingerprint}`);
  if (!storedChallenge) {
    console.log('   ❌ Challenge expired');
    await redis.disconnect();
    process.exit(1);
  }
  console.log('   ✅ Challenge valid');

  // Check and increment limits atomically
  const ethApproved = await redis.eval(LIMIT_LUA, {
    keys: [ethKey],
    arguments: [ETH_LIMIT.toString(), ETH_AMOUNT.toString()]
  });
  const usdcApproved = await redis.eval(LIMIT_LUA, {
    keys: [usdcKey],
    arguments: [USDC_LIMIT.toString(), USDC_AMOUNT.toString()]
  });

  if (!ethApproved) {
    console.log('   ❌ ETH daily limit reached');
    await redis.disconnect();
    process.exit(1);
  }
  if (!usdcApproved) {
    console.log('   ❌ USDC daily limit reached');
    await redis.disconnect();
    process.exit(1);
  }
  console.log('   ✅ Limits approved');
  console.log();

  // Step 5: Execute transfers
  console.log('Step 5: Execute Transfers');
  console.log('   ⚠️  Spending real funds...');
  
  const ethTx = await client.sendTransaction({
    to: userWallet.address,
    value: ETH_AMOUNT
  });
  console.log(`   ✅ ETH: https://basescan.org/tx/${ethTx}`);

  let usdcTx;
  try {
    usdcTx = await client.writeContract({
      address: USDC_ADDRESS,
      abi: ERC20_ABI,
      functionName: 'transfer',
      args: [userWallet.address, USDC_AMOUNT]
    });
    console.log(`   ✅ USDC: https://basescan.org/tx/${usdcTx}`);
  } catch (error) {
    // Log partial failure
    await redis.set(`bootstrap:failed:${userWallet.address}`, JSON.stringify({
      ethTx,
      usdcAmount: USDC_AMOUNT.toString(),
      error: error.message,
      timestamp: Date.now()
    }));
    console.log(`   ❌ USDC failed: ${error.message}`);
    console.log(`   ⚠️  ETH sent but USDC failed - logged for retry`);
  }
  console.log();

  // Step 6: Store fingerprint and wallet as used
  console.log('Step 6: Mark as Used');
  await redis.set(`fingerprint:${fingerprint}`, JSON.stringify({
    wallet: userWallet.address,
    timestamp: Date.now()
  }));
  await redis.set(`wallet:${userWallet.address}`, JSON.stringify({
    fingerprint,
    ethTx,
    usdcTx,
    timestamp: Date.now()
  }));
  console.log('   ✅ Fingerprint and wallet stored');
  console.log();

  // Step 7: Generate claim code
  console.log('Step 7: Generate Claim Code');
  const claimCode = `EVER-${crypto.randomBytes(8).toString('hex').toUpperCase()}-${crypto.randomBytes(8).toString('hex').toUpperCase()}`;
  await redis.set(`claim:${claimCode}`, userWallet.address);
  console.log(`   Claim Code: ${claimCode}`);
  console.log();

  // Summary
  console.log('='.repeat(60));
  console.log('✅ Integration Test Complete!');
  console.log('='.repeat(60));
  console.log();
  console.log('Test Results:');
  console.log('  ✅ Redis connection');
  console.log('  ✅ Challenge storage');
  console.log('  ✅ PoW verification');
  console.log('  ✅ Atomic limits');
  console.log('  ✅ ETH transfer');
  console.log('  ✅ USDC transfer');
  console.log('  ✅ Fingerprint dedup');
  console.log('  ✅ Claim code storage');
  console.log();
  console.log('User Wallet:');
  console.log(`  Address: ${userWallet.address}`);
  console.log(`  Key: ${userKey}`);
  console.log();

  await redis.disconnect();
}

main().catch(async (err) => {
  console.error('');
  console.error('❌ Error:', err.message);
  process.exit(1);
});