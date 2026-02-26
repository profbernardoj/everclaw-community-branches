/**
 * SkillGuard Watcher — Post-install monitoring engine
 * 
 * Periodically re-scans installed skills to detect:
 * - Silent updates (hash changes)
 * - New security findings
 * - Runtime behavior changes
 * - Revoked approvals
 * 
 * Designed to run as a cron job or shift task.
 */

import { readdir, stat, readFile, writeFile, mkdir } from 'fs/promises';
import { join, basename } from 'path';
import { Ledger } from './ledger.js';
import { hashSkill, verifySkill } from './hasher.js';
import { SkillScanner } from './scanner.js';
import { FlowAnalyzer } from './flow-analyzer.js';

const DEFAULT_SKILLS_DIR = process.env.HOME + '/.openclaw/workspace/skills';
const DEFAULT_STATE_PATH = process.env.HOME + '/.openclaw/workspace/.skillguard-watch-state.json';

/**
 * @typedef {Object} WatchAlert
 * @property {'modified'|'new_findings'|'score_drop'|'unapproved'|'new_skill'} type
 * @property {'critical'|'high'|'medium'|'info'} severity
 * @property {string} skill — Skill name
 * @property {string} message — Human-readable alert
 * @property {Object} [details] — Additional context
 */

/**
 * @typedef {Object} WatchState
 * @property {string} lastRunAt — ISO timestamp
 * @property {Object<string, SkillState>} skills — Per-skill state
 */

/**
 * @typedef {Object} SkillState
 * @property {string} hash — Last known hash
 * @property {number} score — Last scan score
 * @property {number} findingsCount — Last findings count
 * @property {string} lastScannedAt — ISO timestamp
 */

export class Watcher {
  /**
   * @param {Object} [options]
   * @param {string} [options.skillsDir] — Directory containing installed skills
   * @param {string} [options.statePath] — Path to watch state file
   * @param {Ledger} [options.ledger]
   * @param {Object[]} [options.rules] — Scanner rules
   */
  constructor(options = {}) {
    this.skillsDir = options.skillsDir || DEFAULT_SKILLS_DIR;
    this.statePath = options.statePath || DEFAULT_STATE_PATH;
    this.ledger = options.ledger || new Ledger();
    this.rules = options.rules || null;
  }

  /**
   * Load scanning rules
   */
  async _loadRules() {
    if (this.rules) return this.rules;
    const { readFile } = await import('fs/promises');
    const { join, dirname } = await import('path');
    const { fileURLToPath } = await import('url');
    const __dirname = dirname(fileURLToPath(import.meta.url));
    const rulesPath = join(__dirname, '..', 'rules', 'dangerous-patterns.json');
    const data = JSON.parse(await readFile(rulesPath, 'utf-8'));
    this.rules = data.rules;
    return this.rules;
  }

  /**
   * Load watch state from disk
   * @returns {Promise<WatchState>}
   */
  async loadState() {
    try {
      const data = await readFile(this.statePath, 'utf-8');
      return JSON.parse(data);
    } catch {
      return { lastRunAt: null, skills: {} };
    }
  }

  /**
   * Save watch state to disk
   */
  async saveState(state) {
    await mkdir(join(this.statePath, '..'), { recursive: true }).catch(() => {});
    await writeFile(this.statePath, JSON.stringify(state, null, 2));
  }

  /**
   * Discover all installed skills
   * @returns {Promise<{ name: string, path: string }[]>}
   */
  async discoverSkills() {
    const skills = [];
    let entries;
    try { entries = await readdir(this.skillsDir, { withFileTypes: true }); }
    catch { return skills; }

    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      if (entry.name.startsWith('.')) continue;

      const skillPath = join(this.skillsDir, entry.name);
      
      // Check if it has a SKILL.md (identifies it as a skill)
      try {
        await stat(join(skillPath, 'SKILL.md'));
        skills.push({ name: entry.name, path: skillPath });
      } catch {
        // Not a skill directory, skip
        // But check for nested skills (e.g., everclaw/skills/*)
        try {
          const subEntries = await readdir(skillPath, { withFileTypes: true });
          for (const sub of subEntries) {
            if (!sub.isDirectory()) continue;
            const subPath = join(skillPath, sub.name);
            try {
              await stat(join(subPath, 'SKILL.md'));
              skills.push({ name: `${entry.name}/${sub.name}`, path: subPath });
            } catch { /* not a skill */ }
          }
        } catch { /* can't read dir */ }
      }
    }

    return skills;
  }

  /**
   * Run a full watch cycle — scan all installed skills
   * @returns {Promise<{ alerts: WatchAlert[], scanned: number, clean: number, timestamp: string }>}
   */
  async run() {
    const rules = await this._loadRules();
    const state = await this.loadState();
    const skills = await this.discoverSkills();
    const alerts = [];
    let clean = 0;

    for (const skill of skills) {
      const skillAlerts = await this._checkSkill(skill, state, rules);
      if (skillAlerts.length === 0) {
        clean++;
      } else {
        alerts.push(...skillAlerts);
      }
    }

    // Check for skills that disappeared
    for (const [name, skillState] of Object.entries(state.skills)) {
      const stillExists = skills.some(s => s.name === name);
      if (!stillExists) {
        alerts.push({
          type: 'removed',
          severity: 'info',
          skill: name,
          message: `Skill "${name}" was removed from disk.`,
        });
        delete state.skills[name];
      }
    }

    // Update state
    state.lastRunAt = new Date().toISOString();
    await this.saveState(state);

    return {
      alerts,
      scanned: skills.length,
      clean,
      timestamp: state.lastRunAt,
    };
  }

  /**
   * Check a single skill for changes
   */
  async _checkSkill(skill, state, rules) {
    const alerts = [];
    const scanner = new SkillScanner(rules);

    // Hash check first (fast)
    const { hash: currentHash, fileCount, totalSize } = await hashSkill(skill.path);
    const prevState = state.skills[skill.name];

    // New skill — not seen before
    if (!prevState) {
      // Check if it's in the ledger
      const { approved } = await this.ledger.isApproved(skill.name);
      
      if (!approved) {
        alerts.push({
          type: 'unapproved',
          severity: 'high',
          skill: skill.name,
          message: `Skill "${skill.name}" is installed but NOT in the approved ledger.`,
          details: { hash: currentHash, fileCount },
        });
      }

      // Scan it
      const report = await scanner.scanDirectory(skill.path);
      
      state.skills[skill.name] = {
        hash: currentHash,
        score: report.score,
        findingsCount: report.findings.length,
        lastScannedAt: new Date().toISOString(),
      };

      if (report.score < 50) {
        alerts.push({
          type: 'new_findings',
          severity: 'critical',
          skill: skill.name,
          message: `New skill "${skill.name}" has dangerous score: ${report.score}/100 (${report.findings.length} findings).`,
          details: { score: report.score, risk: report.risk, findings: report.findings.length },
        });
      }

      return alerts;
    }

    // Hash unchanged — skill hasn't been modified
    if (currentHash === prevState.hash) {
      return alerts;
    }

    // Hash changed — skill was modified!
    alerts.push({
      type: 'modified',
      severity: 'high',
      skill: skill.name,
      message: `Skill "${skill.name}" was modified since last scan. Hash changed.`,
      details: {
        previousHash: prevState.hash.slice(0, 16),
        currentHash: currentHash.slice(0, 16),
      },
    });

    // Re-scan to check for new issues
    const report = await scanner.scanDirectory(skill.path);
    const scoreDelta = prevState.score - report.score;

    if (scoreDelta > 10) {
      alerts.push({
        type: 'score_drop',
        severity: scoreDelta > 30 ? 'critical' : 'high',
        skill: skill.name,
        message: `Skill "${skill.name}" score dropped: ${prevState.score} → ${report.score} (Δ${scoreDelta}).`,
        details: {
          previousScore: prevState.score,
          currentScore: report.score,
          delta: scoreDelta,
          newFindings: report.findings.length - prevState.findingsCount,
        },
      });
    }

    // Run flow analysis on modified skills
    const flowAnalyzer = new FlowAnalyzer();
    const flowResult = await flowAnalyzer.analyze(skill.path);
    if (flowResult.chains.length > 0) {
      alerts.push({
        type: 'new_findings',
        severity: 'critical',
        skill: skill.name,
        message: `Skill "${skill.name}" has ${flowResult.chains.length} cross-file data flow chain(s) after modification.`,
        details: { chains: flowResult.chains.map(c => c.description) },
      });
    }

    // Update state
    state.skills[skill.name] = {
      hash: currentHash,
      score: report.score,
      findingsCount: report.findings.length,
      lastScannedAt: new Date().toISOString(),
    };

    // Check ledger — was this version approved?
    const { approved, hashMatch } = await this.ledger.isApproved(skill.name, currentHash);
    if (!hashMatch && prevState) {
      alerts.push({
        type: 'unapproved',
        severity: 'high',
        skill: skill.name,
        message: `Modified version of "${skill.name}" is NOT in the approved ledger. Re-approval needed.`,
      });
    }

    return alerts;
  }

  /**
   * Format alerts for human consumption
   */
  static formatAlerts(result) {
    const lines = [];
    lines.push(`🛡️ SkillGuard Watch Report — ${result.timestamp.split('T')[0]}`);
    lines.push(`   Scanned: ${result.scanned} skills | Clean: ${result.clean} | Alerts: ${result.alerts.length}`);

    if (result.alerts.length === 0) {
      lines.push('   ✅ All skills verified clean.');
      return lines.join('\n');
    }

    lines.push('');

    // Group by severity
    const critical = result.alerts.filter(a => a.severity === 'critical');
    const high = result.alerts.filter(a => a.severity === 'high');
    const medium = result.alerts.filter(a => a.severity === 'medium');
    const info = result.alerts.filter(a => a.severity === 'info');

    if (critical.length > 0) {
      lines.push('   🔴 CRITICAL:');
      for (const a of critical) lines.push(`      ${a.message}`);
    }
    if (high.length > 0) {
      lines.push('   🟠 HIGH:');
      for (const a of high) lines.push(`      ${a.message}`);
    }
    if (medium.length > 0) {
      lines.push('   ⚠️ MEDIUM:');
      for (const a of medium) lines.push(`      ${a.message}`);
    }
    if (info.length > 0) {
      lines.push('   ℹ️ INFO:');
      for (const a of info) lines.push(`      ${a.message}`);
    }

    return lines.join('\n');
  }
}
