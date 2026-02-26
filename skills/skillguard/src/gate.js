/**
 * SkillGuard Gate — Pre-install enforcement
 * 
 * Intercepts skill installations, scans, and makes allow/block/review decisions.
 * Integrates with the ledger for approval tracking and hash verification.
 */

import { readFile } from 'fs/promises';
import { join, dirname, resolve } from 'path';
import { fileURLToPath } from 'url';
import { SkillScanner } from './scanner.js';
import { FlowAnalyzer } from './flow-analyzer.js';
import { Ledger } from './ledger.js';
import { hashSkill, verifySkill } from './hasher.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

/**
 * @typedef {Object} GateConfig
 * @property {number} autoAllowThreshold — Score >= this: auto-allow (if requireApprovalForAll is false)
 * @property {number} reviewThreshold — Score >= this but < autoAllow: needs review
 * @property {number} blockThreshold — Score < reviewThreshold: hard block
 * @property {boolean} requireApprovalForAll — If true, ALL installs require human approval
 */

/**
 * @typedef {Object} GateResult
 * @property {'ALLOW'|'REVIEW'|'BLOCK'} decision
 * @property {number} score
 * @property {string} risk
 * @property {Object[]} findings
 * @property {Object[]} flowFindings — Cross-file flow findings
 * @property {boolean} requiresApproval
 * @property {string} hash — SHA-256 of skill contents
 * @property {boolean} previouslyApproved — Was this exact version approved before?
 * @property {string} reason — Human-readable decision reason
 * @property {Object} [diffResult] — If comparing to installed version
 */

export class Gate {
  /**
   * @param {Object} [options]
   * @param {GateConfig} [options.config]
   * @param {Ledger} [options.ledger]
   */
  constructor(options = {}) {
    this.config = options.config || {
      autoAllowThreshold: 80,
      reviewThreshold: 50,
      blockThreshold: 0,
      requireApprovalForAll: true,
    };
    this.ledger = options.ledger || new Ledger();
    this.rules = null;
  }

  /**
   * Load scanning rules
   */
  async _loadRules() {
    if (this.rules) return this.rules;
    const rulesPath = join(__dirname, '..', 'rules', 'dangerous-patterns.json');
    const data = JSON.parse(await readFile(rulesPath, 'utf-8'));
    this.rules = data.rules;
    return this.rules;
  }

  /**
   * Check a skill before installation
   * @param {string} skillPath — Path to skill directory to check
   * @param {Object} [options]
   * @param {string} [options.name] — Skill name override
   * @param {string} [options.source] — Source identifier (local, clawhub slug)
   * @param {string} [options.installedPath] — Path to currently installed version (for diff)
   * @returns {Promise<GateResult>}
   */
  async checkInstall(skillPath, options = {}) {
    const rules = await this._loadRules();
    const scanner = new SkillScanner(rules);
    const flowAnalyzer = new FlowAnalyzer();

    // Get skill hash
    const { hash, fileCount, totalSize } = await hashSkill(skillPath);

    // Determine skill name
    let skillName = options.name;
    if (!skillName) {
      try {
        const skillMd = await readFile(join(skillPath, 'SKILL.md'), 'utf-8');
        const nameMatch = skillMd.match(/^name:\s*(.+)/m);
        skillName = nameMatch ? nameMatch[1].trim() : basename(skillPath);
      } catch {
        const { basename } = await import('path');
        skillName = basename(skillPath);
      }
    }

    // Check if this exact version is already approved
    const { approved: previouslyApproved, entry: existingEntry, hashMatch } = 
      await this.ledger.isApproved(skillName, hash);

    if (previouslyApproved && hashMatch) {
      return {
        decision: 'ALLOW',
        score: existingEntry.score,
        risk: existingEntry.risk || 'LOW',
        findings: [],
        flowFindings: [],
        requiresApproval: false,
        hash,
        previouslyApproved: true,
        reason: `Previously approved (${existingEntry.date.split('T')[0]}). Hash matches.`,
      };
    }

    // Run full scan
    const report = await scanner.scanDirectory(skillPath);

    // Run cross-file flow analysis
    const flowResult = await flowAnalyzer.analyze(skillPath);
    const flowFindings = flowResult.findings;

    // Merge flow findings into score
    let adjustedScore = report.score;
    for (const f of flowFindings) {
      adjustedScore = Math.max(0, adjustedScore - f.weight);
    }

    // Run diff scan if installed version exists
    let diffResult = null;
    if (options.installedPath) {
      try {
        const { DiffScanner } = await import('./diff-scanner.js');
        const diffScanner = new DiffScanner(rules);
        diffResult = await diffScanner.diff(options.installedPath, skillPath);
      } catch { /* diff scan optional */ }
    }

    // If hash changed from approved version, note it
    const hashChanged = existingEntry && !hashMatch;

    // Make decision
    const { decision, reason, requiresApproval } = this._decide(
      adjustedScore, hashChanged, previouslyApproved
    );

    const result = {
      decision,
      score: adjustedScore,
      risk: report.risk,
      findings: report.findings,
      flowFindings,
      requiresApproval,
      hash,
      previouslyApproved: false,
      reason,
      diffResult,
      skillName,
      fileCount,
      totalSize,
    };

    // Auto-log to ledger based on decision
    if (decision === 'BLOCK') {
      await this.ledger.add({
        name: skillName,
        version: 'unknown',
        source: options.source || 'unknown',
        score: adjustedScore,
        risk: report.risk,
        hash,
        status: 'blocked',
        approver: 'auto',
        findingsCount: report.findings.length + flowFindings.length,
      });
    }

    return result;
  }

  /**
   * Approve a skill after review
   * @param {string} skillPath — Path to skill
   * @param {string} skillName — Name of skill
   * @param {GateResult} scanResult — Previous scan result
   * @param {Object} [options]
   * @param {string} [options.purpose] — Why this skill is needed
   */
  async approve(skillPath, skillName, scanResult, options = {}) {
    await this.ledger.add({
      name: skillName,
      version: 'unknown',
      source: options.source || 'unknown',
      score: scanResult.score,
      risk: scanResult.risk,
      hash: scanResult.hash,
      status: 'approved',
      approver: 'human',
      purpose: options.purpose || '',
      findingsCount: (scanResult.findings?.length || 0) + (scanResult.flowFindings?.length || 0),
    });
    return true;
  }

  /**
   * Make gate decision based on score and config
   */
  _decide(score, hashChanged, wasApproved) {
    const { autoAllowThreshold, reviewThreshold, requireApprovalForAll } = this.config;

    // Hash changed on a previously approved skill = always review
    if (hashChanged) {
      return {
        decision: 'REVIEW',
        reason: `Previously approved version modified (hash changed). Re-review required.`,
        requiresApproval: true,
      };
    }

    // Hard block for dangerous scores
    if (score < reviewThreshold) {
      return {
        decision: 'BLOCK',
        reason: `Score ${score}/100 is below review threshold (${reviewThreshold}). Too risky to install.`,
        requiresApproval: false, // blocked, not reviewable
      };
    }

    // Require approval for all (default)
    if (requireApprovalForAll) {
      return {
        decision: 'REVIEW',
        reason: `Policy: all installs require human approval. Score: ${score}/100.`,
        requiresApproval: true,
      };
    }

    // Auto-allow for high scores
    if (score >= autoAllowThreshold) {
      return {
        decision: 'ALLOW',
        reason: `Score ${score}/100 meets auto-allow threshold (${autoAllowThreshold}).`,
        requiresApproval: false,
      };
    }

    // Review zone
    return {
      decision: 'REVIEW',
      reason: `Score ${score}/100 requires review (between ${reviewThreshold}-${autoAllowThreshold}).`,
      requiresApproval: true,
    };
  }
}
