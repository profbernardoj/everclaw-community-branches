/**
 * SkillGuard Hasher — SHA-256 skill fingerprinting
 * 
 * Generates deterministic hashes of skill packages for version pinning.
 * Used by the ledger to detect silent updates after approval.
 */

import { createHash } from 'crypto';
import { readFile, readdir, stat } from 'fs/promises';
import { join, relative } from 'path';

const SKIP_DIRS = new Set(['node_modules', '.git', '__pycache__', 'venv', '.venv']);
const SKIP_FILES = new Set(['.DS_Store', 'Thumbs.db']);

/**
 * Walk directory and collect all file paths (sorted for determinism)
 */
async function walkSorted(dirPath, base = dirPath) {
  const results = [];
  let entries;
  try { entries = await readdir(dirPath, { withFileTypes: true }); }
  catch { return results; }

  for (const entry of entries) {
    if (SKIP_FILES.has(entry.name)) continue;
    const fullPath = join(dirPath, entry.name);
    const relPath = relative(base, fullPath);

    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      results.push(...await walkSorted(fullPath, base));
    } else if (entry.isFile()) {
      results.push({ relPath, fullPath });
    }
  }

  return results.sort((a, b) => a.relPath.localeCompare(b.relPath));
}

/**
 * Generate SHA-256 hash of all skill files (sorted, deterministic)
 * @param {string} skillPath — Path to skill directory
 * @returns {{ hash: string, fileCount: number, totalSize: number }}
 */
export async function hashSkill(skillPath) {
  const files = await walkSorted(skillPath);
  const hasher = createHash('sha256');
  let totalSize = 0;

  for (const { relPath, fullPath } of files) {
    const content = await readFile(fullPath);
    // Hash includes the relative path + content for path-sensitive fingerprinting
    hasher.update(`${relPath}:${content.length}\n`);
    hasher.update(content);
    totalSize += content.length;
  }

  return {
    hash: hasher.digest('hex'),
    fileCount: files.length,
    totalSize,
  };
}

/**
 * Verify skill hasn't changed since approval
 * @param {string} skillPath — Path to skill directory
 * @param {string} expectedHash — Hash from ledger
 * @returns {{ verified: boolean, currentHash: string, expectedHash: string }}
 */
export async function verifySkill(skillPath, expectedHash) {
  const { hash: currentHash } = await hashSkill(skillPath);
  return {
    verified: currentHash === expectedHash,
    currentHash,
    expectedHash,
  };
}
