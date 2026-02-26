/**
 * SkillGuard Ledger — Approved/blocked skills record
 * 
 * Maintains both a human-readable Markdown ledger and a JSON file
 * for programmatic access. Tracks approvals, blocks, and revocations.
 */

import { readFile, writeFile, mkdir } from 'fs/promises';
import { dirname } from 'path';
import { hashSkill } from './hasher.js';

const DEFAULT_JSON_PATH = process.env.HOME + '/.openclaw/workspace/.skillguard-ledger.json';
const DEFAULT_MD_PATH = process.env.HOME + '/.openclaw/workspace/memory/reference/approved-skills.md';

/**
 * @typedef {Object} LedgerEntry
 * @property {string} name — Skill name
 * @property {string} version — Version string or 'unknown'
 * @property {string} source — 'local' | 'clawhub' | slug
 * @property {number} score — Scan score (0-100)
 * @property {string} risk — LOW | MEDIUM | HIGH | CRITICAL
 * @property {string} hash — SHA-256 of skill contents
 * @property {string} date — ISO date string
 * @property {'approved'|'blocked'|'revoked'} status
 * @property {'auto'|'human'} approver
 * @property {string} [purpose] — Why this skill was installed
 * @property {number} [findingsCount] — Number of findings at scan time
 */

export class Ledger {
  /**
   * @param {Object} [options]
   * @param {string} [options.jsonPath] — Path to JSON ledger
   * @param {string} [options.mdPath] — Path to Markdown ledger
   */
  constructor(options = {}) {
    this.jsonPath = options.jsonPath || DEFAULT_JSON_PATH;
    this.mdPath = options.mdPath || DEFAULT_MD_PATH;
    this._entries = null;
  }

  /**
   * Load entries from JSON ledger
   * @returns {Promise<LedgerEntry[]>}
   */
  async load() {
    if (this._entries) return this._entries;
    try {
      const data = await readFile(this.jsonPath, 'utf-8');
      this._entries = JSON.parse(data);
    } catch {
      this._entries = [];
    }
    return this._entries;
  }

  /**
   * Save entries to both JSON and Markdown
   */
  async save() {
    const entries = await this.load();

    // Ensure directories exist
    await mkdir(dirname(this.jsonPath), { recursive: true });
    await mkdir(dirname(this.mdPath), { recursive: true });

    // Write JSON
    await writeFile(this.jsonPath, JSON.stringify(entries, null, 2));

    // Write Markdown
    const md = this._toMarkdown(entries);
    await writeFile(this.mdPath, md);
  }

  /**
   * Check if a skill (exact name + hash) is already approved
   * @param {string} name
   * @param {string} [hash] — If provided, checks exact version
   * @returns {Promise<{approved: boolean, entry?: LedgerEntry, hashMatch?: boolean}>}
   */
  async isApproved(name, hash) {
    const entries = await this.load();
    const matches = entries.filter(e => e.name === name && e.status === 'approved');
    
    if (matches.length === 0) return { approved: false };

    const latest = matches[matches.length - 1];
    
    if (hash) {
      const hashMatch = latest.hash === hash;
      return { approved: hashMatch, entry: latest, hashMatch };
    }
    
    return { approved: true, entry: latest };
  }

  /**
   * Add an entry to the ledger
   * @param {LedgerEntry} entry
   */
  async add(entry) {
    const entries = await this.load();
    
    // Add timestamp if not present
    if (!entry.date) entry.date = new Date().toISOString();
    
    entries.push(entry);
    this._entries = entries;
    await this.save();
    return entry;
  }

  /**
   * Revoke approval for a skill
   * @param {string} name
   * @returns {Promise<boolean>} — true if found and revoked
   */
  async revoke(name) {
    const entries = await this.load();
    let found = false;
    
    for (const entry of entries) {
      if (entry.name === name && entry.status === 'approved') {
        entry.status = 'revoked';
        entry.revokedAt = new Date().toISOString();
        found = true;
      }
    }
    
    if (found) {
      this._entries = entries;
      await this.save();
    }
    return found;
  }

  /**
   * List all entries, optionally filtered
   * @param {Object} [filter]
   * @param {'approved'|'blocked'|'revoked'} [filter.status]
   * @returns {Promise<LedgerEntry[]>}
   */
  async list(filter = {}) {
    const entries = await this.load();
    if (filter.status) {
      return entries.filter(e => e.status === filter.status);
    }
    return entries;
  }

  /**
   * Get summary statistics
   */
  async stats() {
    const entries = await this.load();
    return {
      total: entries.length,
      approved: entries.filter(e => e.status === 'approved').length,
      blocked: entries.filter(e => e.status === 'blocked').length,
      revoked: entries.filter(e => e.status === 'revoked').length,
    };
  }

  /**
   * Generate Markdown table from entries
   */
  _toMarkdown(entries) {
    const lines = [
      '# Approved Skills Log',
      '',
      'All skills must pass SkillGuard scan before installation. Log every install here.',
      '',
      '| Date | Skill | Source | Score | Status | Approver | Hash |',
      '|------|-------|--------|-------|--------|----------|------|',
    ];

    for (const e of entries) {
      const date = e.date ? e.date.split('T')[0] : 'unknown';
      const icon = e.status === 'approved' ? '✅' :
                   e.status === 'blocked' ? '🔴' : '⚪';
      const shortHash = e.hash ? e.hash.slice(0, 8) : 'n/a';
      lines.push(`| ${date} | ${e.name} | ${e.source || 'unknown'} | ${e.score ?? 'n/a'}/100 | ${icon} ${e.status} | ${e.approver || 'n/a'} | ${shortHash} |`);
    }

    lines.push('');
    return lines.join('\n');
  }
}
