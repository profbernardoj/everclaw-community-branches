// fake-exporter.mjs — hermetic stand-in for migrate-export.mjs --agentic
// Used ONLY by test-export-v2.mjs via the AGENT_EXPORT_SCRIPT hook (an env
// override that must never be set from untrusted input). Writes a small
// AES-256-GCM encrypted blob to --output and prints the --agentic JSON
// contract: { outputPath, passphrase, bundleChecksum, size }.
//
// Mirrors the real exporter's streaming format: salt(16) + iv(12) +
// ciphertext + authTag(16) — decryptable by the same code path.

import { writeFileSync, readFileSync, statSync } from 'node:fs';
import { createCipheriv, scryptSync, randomBytes, createHash } from 'node:crypto';

const PASSPHRASE = process.env.FAKE_EXPORT_PASSPHRASE || 'correct-horse-battery-staple-2026';
const i = process.argv.indexOf('--output');
const outputPath = process.argv[i + 1];

// 64 KiB of known plaintext.
const payload = Buffer.concat([
  Buffer.from('FAKE-EXPORT-PAYLOAD-v2\n'),
  Buffer.alloc(64 * 1024 - 23, 0x41),
]);
const salt = randomBytes(16);
const iv = randomBytes(12);
const key = scryptSync(PASSPHRASE, salt, 32, { N: 16384, r: 8, p: 1 });
const cipher = createCipheriv('aes-256-gcm', key, iv);
const enc = Buffer.concat([cipher.update(payload), cipher.final()]);
const bundle = Buffer.concat([salt, iv, enc, cipher.getAuthTag()]);
writeFileSync(outputPath, bundle);

const size = statSync(outputPath).size;
const checksum = createHash('sha256').update(bundle).digest('hex');
process.stdout.write(JSON.stringify({ outputPath, passphrase: PASSPHRASE, bundleChecksum: checksum, size }) + '\n');