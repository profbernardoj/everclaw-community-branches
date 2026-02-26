#!/usr/bin/env node
/**
 * Identity Verification — OpenClaw Startup Verifier
 *
 * Verifies that local identity files (SOUL.md, USER.md, IDENTITY.md)
 * match the hashes anchored on-chain in the agent's ERC-8004 registration.
 *
 * Designed to be called by OpenClaw at boot or via `openclaw identity verify`.
 *
 * Exit codes:
 *   0 = verified (all hashes match)
 *   1 = mismatch (one or more files tampered with)
 *   2 = no on-chain registration found (first run or not yet registered)
 *   3 = error (network, config, etc.)
 *
 * Usage:
 *   node verify-identity.mjs --workspace /path/to/workspace --agent-id 42
 *   node verify-identity.mjs --config config/bernardo.json
 *   node verify-identity.mjs --workspace . --offline --expected-hashes hashes.json
 */

import { readFile } from "fs/promises";
import { hashIdentityFiles, verifyIdentityFiles } from "../lib/hash-identity.mjs";
import { ChainClient } from "../lib/chain-client.mjs";

// ─── Argument Parsing ───────────────────────────────────────────────────────

function parseArgs() {
  const args = process.argv.slice(2);
  const opts = {
    workspace: null,
    agentId: null,
    config: null,
    offline: false,
    expectedHashes: null,
    verbose: false,
    strict: false, // strict mode = fail if any file not on-chain
    json: false,
  };

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case "--workspace":
      case "-w":
        opts.workspace = args[++i];
        break;
      case "--agent-id":
      case "-a":
        opts.agentId = parseInt(args[++i]);
        break;
      case "--config":
      case "-c":
        opts.config = args[++i];
        break;
      case "--offline":
        opts.offline = true;
        break;
      case "--expected-hashes":
        opts.expectedHashes = args[++i];
        break;
      case "--verbose":
      case "-v":
        opts.verbose = true;
        break;
      case "--strict":
        opts.strict = true;
        break;
      case "--json":
        opts.json = true;
        break;
      default:
        if (!opts.workspace && !args[i].startsWith("-")) {
          opts.workspace = args[i];
        }
    }
  }

  return opts;
}

// ─── Main ───────────────────────────────────────────────────────────────────

async function main() {
  const opts = parseArgs();

  // Load config if provided
  if (opts.config) {
    const configRaw = await readFile(opts.config, "utf-8");
    const config = JSON.parse(configRaw);
    opts.workspace = opts.workspace || config.workspacePath;
    opts.agentId = opts.agentId || config.agentId;
  }

  if (!opts.workspace) {
    console.error("Error: --workspace is required");
    process.exit(3);
  }

  // ─── Step 1: Hash local files ───────────────────────────────────────────

  if (!opts.json) {
    console.log(`\n🔐 Soulbound Identity Verification`);
    console.log(`   Workspace: ${opts.workspace}`);
  }

  const localHashes = await hashIdentityFiles(opts.workspace);

  if (opts.verbose && !opts.json) {
    console.log(`\n   Local hashes:`);
    for (const [file, data] of Object.entries(localHashes)) {
      if (file === "_composite") continue;
      if (data.exists) {
        console.log(`     ${file}: ${data.hash}`);
      } else {
        console.log(`     ${file}: MISSING`);
      }
    }
    console.log(`     composite: ${localHashes._composite.hash}`);
  }

  // ─── Step 2: Get expected hashes ────────────────────────────────────────

  let expectedHashes = null;

  if (opts.offline && opts.expectedHashes) {
    // Offline mode — read expected hashes from local file
    const raw = await readFile(opts.expectedHashes, "utf-8");
    expectedHashes = JSON.parse(raw);
    if (!opts.json) {
      console.log(`   Mode: OFFLINE (hashes from ${opts.expectedHashes})`);
    }
  } else if (opts.agentId) {
    // Online mode — fetch from chain
    if (!opts.json) {
      console.log(`   Agent ID: ${opts.agentId}`);
      console.log(`   Mode: ON-CHAIN (Base mainnet)`);
    }

    try {
      const chainClient = new ChainClient();
      const agent = await chainClient.lookupAgent(opts.agentId);

      if (!agent.registration) {
        if (!opts.json) {
          console.log(`\n   ⚠️  No registration file found for agent #${opts.agentId}`);
        }
        process.exit(2);
      }

      if (!agent.registration.identityFiles) {
        if (!opts.json) {
          console.log(`\n   ⚠️  Registration file has no identity file hashes`);
        }
        process.exit(2);
      }

      expectedHashes = agent.registration.identityFiles;

      if (opts.verbose && !opts.json) {
        console.log(`\n   On-chain hashes:`);
        console.log(`     SOUL.md: ${expectedHashes["SOUL.md"]}`);
        console.log(`     USER.md: ${expectedHashes["USER.md"]}`);
        console.log(`     IDENTITY.md: ${expectedHashes["IDENTITY.md"]}`);
        console.log(`     composite: ${expectedHashes._composite}`);
      }
    } catch (err) {
      if (!opts.json) {
        console.error(`\n   ❌ Chain read error: ${err.message}`);
      }
      process.exit(3);
    }
  } else {
    // No agent ID and not offline — just hash and exit
    if (opts.json) {
      console.log(JSON.stringify(localHashes, null, 2));
    } else {
      console.log(`\n   No agent ID provided — showing local hashes only.`);
      console.log(`   Use --agent-id to verify against on-chain registration.\n`);
    }
    process.exit(2);
  }

  // ─── Step 3: Verify ─────────────────────────────────────────────────────

  const result = await verifyIdentityFiles(opts.workspace, expectedHashes);

  if (opts.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log(`\n   Verification Results:`);

    for (const [file, status] of Object.entries(result.files)) {
      const icon =
        status.status === "VERIFIED" ? "✅" :
        status.status === "MISMATCH" ? "❌" :
        status.status === "MISSING" ? "⛔" :
        status.status === "NO_CHAIN_HASH" ? "⚠️ " : "❓";

      console.log(`     ${icon} ${file}: ${status.status}`);

      if (status.status === "MISMATCH" && opts.verbose) {
        console.log(`        Expected: ${status.expected}`);
        console.log(`        Actual:   ${status.actual}`);
      }
    }

    if (result.composite) {
      const icon = result.composite.status === "VERIFIED" ? "✅" : "❌";
      console.log(`     ${icon} composite: ${result.composite.status}`);
    }

    console.log(`\n   ${result.verified ? "✅ IDENTITY VERIFIED" : "❌ IDENTITY VERIFICATION FAILED"}\n`);
  }

  process.exit(result.verified ? 0 : 1);
}

main().catch((err) => {
  console.error(`Error: ${err.message}`);
  process.exit(3);
});
