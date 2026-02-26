#!/usr/bin/env node
/**
 * Identity Updater — Update on-chain identity file hashes
 *
 * When SOUL.md, USER.md, or IDENTITY.md is edited locally, this script:
 * 1. Recomputes all identity file hashes
 * 2. Rebuilds the registration JSON
 * 3. Generates the unsigned transaction to update agentURI on-chain
 * 4. Optionally signs and submits (requires private key via Bagman)
 *
 * Usage:
 *   node update-identity.mjs --config config/bernardo.json --dry-run
 *   node update-identity.mjs --config config/bernardo.json --sign
 *   node update-identity.mjs --config config/bernardo.json --output tx.json
 */

import { readFile, writeFile } from "fs/promises";
import { buildRegistration, toBase64DataURI, estimateOnChainCost } from "../lib/registration-builder.mjs";
import { hashIdentityFiles } from "../lib/hash-identity.mjs";
import { ChainClient } from "../lib/chain-client.mjs";

// ─── Argument Parsing ───────────────────────────────────────────────────────

function parseArgs() {
  const args = process.argv.slice(2);
  const opts = {
    config: null,
    dryRun: false,
    sign: false,
    output: null,
    ipfs: false, // upload to IPFS instead of base64 data URI
    verbose: false,
  };

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case "--config":
      case "-c":
        opts.config = args[++i];
        break;
      case "--dry-run":
      case "-d":
        opts.dryRun = true;
        break;
      case "--sign":
      case "-s":
        opts.sign = true;
        break;
      case "--output":
      case "-o":
        opts.output = args[++i];
        break;
      case "--ipfs":
        opts.ipfs = true;
        break;
      case "--verbose":
      case "-v":
        opts.verbose = true;
        break;
    }
  }

  return opts;
}

// ─── Main ───────────────────────────────────────────────────────────────────

async function main() {
  const opts = parseArgs();

  if (!opts.config) {
    console.log(`
🔐 Soulbound Identity Updater

Usage:
  node update-identity.mjs --config <config.json> [options]

Options:
  --dry-run, -d     Show what would change without submitting
  --sign, -s        Sign and submit the transaction (requires Bagman)
  --output, -o      Write unsigned transaction JSON to file
  --ipfs            Upload registration to IPFS (vs base64 data URI)
  --verbose, -v     Show detailed output
`);
    process.exit(1);
  }

  // Load config
  const configRaw = await readFile(opts.config, "utf-8");
  const config = JSON.parse(configRaw);

  console.log(`\n🔐 Soulbound Identity Update`);
  console.log(`   Agent: ${config.name}`);
  console.log(`   Workspace: ${config.workspacePath}`);

  // ─── Step 1: Compute new hashes ─────────────────────────────────────────

  const newHashes = await hashIdentityFiles(config.workspacePath);

  console.log(`\n   📝 Current identity file hashes:`);
  for (const file of ["SOUL.md", "USER.md", "IDENTITY.md"]) {
    const h = newHashes[file];
    if (h.exists) {
      console.log(`     ${file}: ${h.hash} (${h.size} bytes)`);
    } else {
      console.log(`     ${file}: NOT FOUND`);
    }
  }
  console.log(`     composite: ${newHashes._composite.hash}`);

  // ─── Step 2: Check current on-chain state ───────────────────────────────

  let currentRegistration = null;
  let changes = [];

  if (config.agentId) {
    console.log(`\n   🔗 Checking on-chain state for agent #${config.agentId}...`);

    const chainClient = new ChainClient();
    try {
      const agent = await chainClient.lookupAgent(config.agentId);
      currentRegistration = agent.registration;

      if (currentRegistration?.identityFiles) {
        const onChain = currentRegistration.identityFiles;
        for (const file of ["SOUL.md", "USER.md", "IDENTITY.md"]) {
          const localHash = newHashes[file]?.hash;
          const chainHash = onChain[file];
          if (localHash !== chainHash) {
            changes.push({
              file,
              from: chainHash || "(not set)",
              to: localHash || "(missing)",
            });
          }
        }

        if (changes.length === 0) {
          console.log(`\n   ✅ All identity files match on-chain hashes. No update needed.\n`);
          process.exit(0);
        }

        console.log(`\n   🔄 Changes detected:`);
        for (const c of changes) {
          console.log(`     ${c.file}:`);
          console.log(`       On-chain: ${c.from}`);
          console.log(`       Local:    ${c.to}`);
        }
      } else {
        console.log(`   ⚠️  No identity hashes in current registration — first time setting them.`);
        changes = ["SOUL.md", "USER.md", "IDENTITY.md"].map((f) => ({
          file: f,
          from: "(not set)",
          to: newHashes[f]?.hash || "(missing)",
        }));
      }
    } catch (err) {
      console.log(`   ⚠️  Could not read on-chain state: ${err.message}`);
      console.log(`   Proceeding with update anyway...`);
    }
  } else {
    console.log(`\n   ℹ️  No agentId — this will be used for initial registration.`);
  }

  // ─── Step 3: Build new registration ─────────────────────────────────────

  const registration = await buildRegistration(config);

  // Choose storage method
  let agentURI;
  if (opts.ipfs) {
    // TODO: Implement IPFS upload (via Pinata, web3.storage, etc.)
    console.log(`\n   ⚠️  IPFS upload not yet implemented. Using base64 data URI.`);
    agentURI = toBase64DataURI(registration);
  } else {
    agentURI = toBase64DataURI(registration);
  }

  const cost = estimateOnChainCost(registration);
  console.log(`\n   📊 Registration file:`);
  console.log(`     JSON size: ${cost.jsonBytes} bytes`);
  console.log(`     Data URI size: ${cost.base64URIBytes} bytes`);
  console.log(`     Estimated gas: ~${cost.estimatedGas.toLocaleString()}`);

  // ─── Step 4: Build transaction ──────────────────────────────────────────

  const chainClient = new ChainClient();
  let tx;

  if (config.agentId) {
    tx = chainClient.buildUpdateURITx(config.agentId, agentURI);
    console.log(`\n   📋 Transaction: setAgentURI(${config.agentId}, <data URI>)`);
  } else {
    tx = chainClient.buildRegisterTx(agentURI);
    console.log(`\n   📋 Transaction: register(<data URI>)`);
  }

  if (opts.verbose) {
    console.log(`     To: ${tx.to}`);
    console.log(`     Data: ${tx.data.slice(0, 66)}...`);
    console.log(`     Data length: ${tx.data.length} chars`);
  }

  // ─── Step 5: Dry run, output, or sign ───────────────────────────────────

  if (opts.dryRun) {
    console.log(`\n   🏁 DRY RUN — no transaction submitted.`);

    // Save the registration JSON locally for review
    const regPath = opts.config.replace(".json", "-registration.json");
    await writeFile(regPath, JSON.stringify(registration, null, 2));
    console.log(`   📄 Registration saved to: ${regPath}`);

    // Save expected hashes for offline verification
    const hashPath = opts.config.replace(".json", "-expected-hashes.json");
    const expectedHashes = {
      "SOUL.md": newHashes["SOUL.md"]?.hash,
      "USER.md": newHashes["USER.md"]?.hash,
      "IDENTITY.md": newHashes["IDENTITY.md"]?.hash,
      _composite: newHashes._composite?.hash,
    };
    await writeFile(hashPath, JSON.stringify(expectedHashes, null, 2));
    console.log(`   📄 Expected hashes saved to: ${hashPath}\n`);

    process.exit(0);
  }

  if (opts.output) {
    const txJson = {
      ...tx,
      chainId: Number(CONTRACTS.CHAIN_ID),
      registration,
      changes,
      timestamp: new Date().toISOString(),
    };
    await writeFile(opts.output, JSON.stringify(txJson, null, 2));
    console.log(`\n   📄 Unsigned transaction saved to: ${opts.output}`);
    console.log(`   Sign with your private key and broadcast to Base.\n`);
    process.exit(0);
  }

  if (opts.sign) {
    console.log(`\n   🔑 Signing transaction...`);
    console.log(`   ⚠️  Signer integration (Bagman/1Password) not yet implemented.`);
    console.log(`   Use --output to save the unsigned tx and sign manually.\n`);
    process.exit(1);
  }

  // Default: dry run
  console.log(`\n   Use --dry-run, --output <file>, or --sign to proceed.\n`);
}

main().catch((err) => {
  console.error(`Error: ${err.message}`);
  process.exit(3);
});
