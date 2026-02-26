/**
 * SkillGuard Diff Scanner — Version comparison analysis
 * 
 * Compares two versions of a skill to identify security-relevant changes.
 * Focuses analysis on changed content for faster, more targeted scanning.
 */

import { readFile, readdir, stat } from 'fs/promises';
import { join, relative, extname } from 'path';
import { createHash } from 'crypto';
import { SkillScanner } from './scanner.js';

const SKIP_DIRS = new Set(['node_modules', '.git', '__pycache__', 'venv', '.venv']);

/**
 * @typedef {Object} DiffResult
 * @property {string[]} added — New files
 * @property {string[]} removed — Deleted files
 * @property {string[]} modified — Changed files
 * @property {string[]} unchanged — Same hash
 * @property {Object[]} newFindings — Security findings in new/changed content
 * @property {Object[]} removedFindings — Findings no longer present
 * @property {number} riskDelta — Change in risk score (positive = worse)
 * @property {string} summary — Human-readable summary
 */

export class DiffScanner {
  /**
   * @param {Object[]} rules — Scanning rules for SkillScanner
   */
  constructor(rules) {
    this.rules = rules;
    this.scanner = new SkillScanner(rules);
  }

  /**
   * Compare two skill versions
   * @param {string} oldPath — Path to currently installed version
   * @param {string} newPath — Path to new version
   * @returns {Promise<DiffResult>}
   */
  async diff(oldPath, newPath) {
    // Build file inventories with hashes
    const oldFiles = await this._inventoryFiles(oldPath);
    const newFiles = await this._inventoryFiles(newPath);

    const added = [];
    const removed = [];
    const modified = [];
    const unchanged = [];

    // Find added and modified files
    for (const [relPath, newHash] of newFiles) {
      if (!oldFiles.has(relPath)) {
        added.push(relPath);
      } else if (oldFiles.get(relPath) !== newHash) {
        modified.push(relPath);
      } else {
        unchanged.push(relPath);
      }
    }

    // Find removed files
    for (const relPath of oldFiles.keys()) {
      if (!newFiles.has(relPath)) {
        removed.push(relPath);
      }
    }

    // Scan old and new versions
    const oldReport = await this.scanner.scanDirectory(oldPath);
    const newReport = await this.scanner.scanDirectory(newPath);

    // Identify new findings (in new version but not old)
    const oldFindingKeys = new Set(oldReport.findings.map(f => `${f.ruleId}:${f.file}:${f.line}`));
    const newFindingKeys = new Set(newReport.findings.map(f => `${f.ruleId}:${f.file}:${f.line}`));

    const newFindings = newReport.findings.filter(f => {
      const key = `${f.ruleId}:${f.file}:${f.line}`;
      return !oldFindingKeys.has(key);
    });

    const removedFindings = oldReport.findings.filter(f => {
      const key = `${f.ruleId}:${f.file}:${f.line}`;
      return !newFindingKeys.has(key);
    });

    // Focus on changes in security-sensitive areas
    const sensitiveChanges = this._analyzeSensitiveChanges(added, modified, newPath);

    const riskDelta = oldReport.score - newReport.score; // positive = new version is worse

    const summary = this._buildSummary({
      added, removed, modified, unchanged,
      newFindings, removedFindings, riskDelta,
      oldScore: oldReport.score, newScore: newReport.score,
      sensitiveChanges,
    });

    return {
      added,
      removed,
      modified,
      unchanged,
      newFindings,
      removedFindings,
      riskDelta,
      oldScore: oldReport.score,
      newScore: newReport.score,
      sensitiveChanges,
      summary,
    };
  }

  /**
   * Analyze security-sensitive changes in new/modified files
   */
  async _analyzeSensitiveChanges(added, modified, newPath) {
    const changes = [];
    const filesToCheck = [...added, ...modified];

    for (const relPath of filesToCheck) {
      const ext = extname(relPath).toLowerCase();
      const fullPath = join(newPath, relPath);
      let content;
      try { content = await readFile(fullPath, 'utf-8'); }
      catch { continue; }

      const isCode = ['.js', '.ts', '.mjs', '.cjs', '.py', '.sh'].includes(ext);
      if (!isCode && ext !== '.md') continue;

      // Check for new dangerous patterns
      const patterns = [
        { regex: /\bfetch\s*\(|axios\.\w+\(|https?:\/\/(?!localhost)/g, type: 'network', desc: 'New network call' },
        { regex: /process\.env|\.env\b|api[_-]?key|secret|token/gi, type: 'credential', desc: 'New credential access' },
        { regex: /\beval\b|\bexec\b|\bspawn\b|\bchild_process/g, type: 'exec', desc: 'New code execution' },
        { regex: /\bwriteFile\b|\bcreateWriteStream\b|fs\.\w*[Ww]rite/g, type: 'filesystem', desc: 'New file write' },
        { regex: /cron|schedule|setTimeout.*\d{4,}|setInterval/g, type: 'persistence', desc: 'New persistence/scheduling' },
      ];

      for (const { regex, type, desc } of patterns) {
        const matches = content.matchAll(regex);
        for (const match of matches) {
          const lineNum = (content.slice(0, match.index).match(/\n/g) || []).length + 1;
          changes.push({
            file: relPath,
            type,
            description: desc,
            line: lineNum,
            match: match[0],
            isNewFile: added.includes(relPath),
          });
        }
      }
    }

    return changes;
  }

  /**
   * Build a human-readable summary
   */
  _buildSummary(data) {
    const lines = [];
    lines.push(`Files: +${data.added.length} added, -${data.removed.length} removed, ~${data.modified.length} modified, ${data.unchanged.length} unchanged`);
    lines.push(`Score: ${data.oldScore} → ${data.newScore} (${data.riskDelta > 0 ? '⬇️ -' : data.riskDelta < 0 ? '⬆️ +' : '→'}${Math.abs(data.riskDelta)})`);

    if (data.newFindings.length > 0) {
      lines.push(`New findings: ${data.newFindings.length}`);
      const critical = data.newFindings.filter(f => f.severity === 'critical').length;
      const high = data.newFindings.filter(f => f.severity === 'high').length;
      if (critical > 0) lines.push(`  🔴 ${critical} CRITICAL`);
      if (high > 0) lines.push(`  🟠 ${high} HIGH`);
    }

    if (data.removedFindings.length > 0) {
      lines.push(`Resolved findings: ${data.removedFindings.length} ✅`);
    }

    if (data.sensitiveChanges.length > 0) {
      const byType = {};
      for (const c of data.sensitiveChanges) {
        byType[c.type] = (byType[c.type] || 0) + 1;
      }
      lines.push(`Sensitive changes: ${Object.entries(byType).map(([k, v]) => `${v} ${k}`).join(', ')}`);
    }

    return lines.join('\n');
  }

  /**
   * Build file inventory with content hashes
   * @returns {Promise<Map<string, string>>} — relPath → hash
   */
  async _inventoryFiles(dirPath, base = dirPath) {
    const inventory = new Map();

    const walk = async (dir) => {
      let entries;
      try { entries = await readdir(dir, { withFileTypes: true }); }
      catch { return; }

      for (const entry of entries) {
        const fullPath = join(dir, entry.name);
        const relPath = relative(base, fullPath);

        if (entry.isDirectory()) {
          if (SKIP_DIRS.has(entry.name)) continue;
          await walk(fullPath);
        } else if (entry.isFile()) {
          try {
            const content = await readFile(fullPath);
            const hash = createHash('sha256').update(content).digest('hex');
            inventory.set(relPath, hash);
          } catch { /* skip unreadable */ }
        }
      }
    };

    await walk(dirPath);
    return inventory;
  }
}
