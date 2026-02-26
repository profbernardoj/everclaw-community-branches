#!/usr/bin/env node

/**
 * SkillGuard CLI v2.0
 * 
 * V1 Commands:
 *   skillguard scan <path>          Scan a local skill directory
 *   skillguard scan-hub <slug>      Download and scan a ClawHub skill
 *   skillguard check <text>         Check text for prompt injection
 *   skillguard batch <dir>          Scan all subdirectories as skills
 * 
 * V2 Commands (Gate):
 *   skillguard install <path|slug>  Gate-enforced install (scan → decide → log)
 *   skillguard approve <name>       Approve a reviewed skill by name
 *   skillguard revoke <name>        Revoke a skill's approval
 *   skillguard ledger               Show approved/blocked skills history
 *   skillguard verify <path>        Verify installed skill hasn't been modified
 *   skillguard diff <old> <new>     Compare two skill versions
 *   skillguard policy               Show current gate policy
 * 
 * V2 Commands (Watch):
 *   skillguard watch                Run a watch cycle on all installed skills
 *   skillguard runtime <path>       Runtime behavior analysis on a skill
 *   skillguard status               Show overall security status
 */

import { readFile } from 'fs/promises';
import { join, dirname, resolve, basename } from 'path';
import { fileURLToPath } from 'url';
import { SkillScanner } from './scanner.js';
import { formatTextReport, formatCompactReport } from './reporter.js';
import { downloadSkillForScan } from './clawhub.js';
import { Gate } from './gate.js';
import { Ledger } from './ledger.js';
import { hashSkill, verifySkill } from './hasher.js';
import { DiffScanner } from './diff-scanner.js';
import { FlowAnalyzer } from './flow-analyzer.js';
import { Watcher } from './watcher.js';
import { RuntimeMonitor } from './runtime-monitor.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

async function loadRules() {
  const rulesPath = join(__dirname, '..', 'rules', 'dangerous-patterns.json');
  const data = JSON.parse(await readFile(rulesPath, 'utf-8'));
  return data.rules;
}

async function loadConfig() {
  const configPath = join(__dirname, '..', 'skillguard.config.json');
  try {
    return JSON.parse(await readFile(configPath, 'utf-8'));
  } catch {
    return {
      gate: { autoAllowThreshold: 80, reviewThreshold: 50, blockThreshold: 0, requireApprovalForAll: true },
      ledger: {},
      scan: { enableFlowAnalysis: true, enableDiffScan: true, maxFileSize: 1048576 },
    };
  }
}

function resolveHomePath(p) {
  if (p && p.startsWith('~/')) return join(process.env.HOME, p.slice(2));
  return p;
}

async function main() {
  const args = process.argv.slice(2);
  const command = args[0];

  if (!command || command === '--help' || command === '-h') {
    console.log(`
SkillGuard v2.0 — Agent Security Scanner + Install Gate

Scan Commands:
  skillguard scan <path>            Scan a local skill directory
  skillguard scan-hub <slug>        Download and scan a ClawHub skill
  skillguard check "<text>"         Check text for prompt injection/threats
  skillguard batch <dir>            Scan all subdirectories as skills

Gate Commands (V2):
  skillguard install <path|slug>    Gate-enforced install check (scan → decide)
  skillguard approve <skill-name>   Approve a reviewed skill
  skillguard revoke <skill-name>    Revoke a skill's approval
  skillguard ledger                 Show approved/blocked skills history
  skillguard verify <path>          Verify skill hasn't changed since approval
  skillguard diff <old-path> <new>  Compare two skill versions
  skillguard policy                 Show current gate policy

Watch Commands (V2):
  skillguard watch                  Run watch cycle on all installed skills
  skillguard runtime <path>         Runtime behavior analysis on a skill
  skillguard status                 Overall security status dashboard

Options:
  --json        Output raw JSON report
  --compact     Output compact format (for chat)
  --quiet       Only output score and verdict
  --flow        Include cross-file flow analysis (default: on)
  --no-flow     Disable cross-file flow analysis
    `);
    process.exit(0);
  }

  const flags = {
    json: args.includes('--json'),
    compact: args.includes('--compact'),
    quiet: args.includes('--quiet'),
    flow: !args.includes('--no-flow'),
  };

  const config = await loadConfig();

  switch (command) {
    // ─── V1 Commands (preserved) ──────────────────────────────────
    case 'scan': {
      const rules = await loadRules();
      const targetPath = resolve(args[1] || '.');
      const scanner = new SkillScanner(rules);
      const report = await scanner.scanDirectory(targetPath);

      // Add flow analysis if enabled
      if (flags.flow) {
        const flowAnalyzer = new FlowAnalyzer();
        const flowResult = await flowAnalyzer.analyze(targetPath);
        if (flowResult.findings.length > 0) {
          report.findings.push(...flowResult.findings);
          // Recalculate score
          let deductions = 0;
          for (const f of report.findings) deductions += f.weight;
          report.score = Math.max(0, 100 - deductions);
          report.risk = report.score >= 80 ? 'LOW' : report.score >= 50 ? 'MEDIUM' : report.score >= 20 ? 'HIGH' : 'CRITICAL';
          report.flowChains = flowResult.chains;
        }
      }

      if (flags.json) {
        console.log(JSON.stringify(report, null, 2));
      } else if (flags.compact) {
        console.log(formatCompactReport(report));
      } else if (flags.quiet) {
        console.log(`${report.score}/100 ${report.risk} — ${report.findings.length} finding(s)`);
      } else {
        console.log(formatTextReport(report));
        if (report.flowChains?.length > 0) {
          console.log('\n🔗 Cross-File Flow Chains:');
          for (const chain of report.flowChains) {
            console.log(`  ${chain.severity.toUpperCase()}: ${chain.description}`);
            for (const step of chain.steps) {
              console.log(`    → ${step}`);
            }
          }
        }
      }

      process.exit(report.score < 50 ? 1 : 0);
    }

    case 'scan-hub': {
      const rules = await loadRules();
      const slug = args[1];
      if (!slug) {
        console.error('Error: provide a skill slug. Usage: skillguard scan-hub <slug>');
        process.exit(1);
      }

      console.error(`Downloading ${slug} from ClawHub...`);
      let download;
      try {
        download = await downloadSkillForScan(slug);
      } catch (err) {
        console.error(`Failed: ${err.message}`);
        process.exit(1);
      }

      try {
        const scanner = new SkillScanner(rules);
        const report = await scanner.scanDirectory(download.path);
        if (flags.json) {
          console.log(JSON.stringify(report, null, 2));
        } else if (flags.compact) {
          console.log(formatCompactReport(report, slug));
        } else {
          console.log(formatTextReport(report));
        }
        process.exit(report.score < 50 ? 1 : 0);
      } finally {
        await download.cleanup();
      }
    }

    case 'check': {
      const rules = await loadRules();
      const text = args.slice(1).filter(a => !a.startsWith('--')).join(' ');
      if (!text) {
        console.error('Error: provide text to check. Usage: skillguard check "text here"');
        process.exit(1);
      }

      const scanner = new SkillScanner(rules);
      const findings = scanner.scanContent(text, 'input');
      if (findings.length === 0) {
        console.log('✅ No threats detected.');
        process.exit(0);
      }

      console.log(`⚠️ ${findings.length} finding(s):\n`);
      for (const f of findings) {
        console.log(`  ${f.severity.toUpperCase()} [${f.ruleId}] ${f.title}`);
        console.log(`    Match: ${f.match}`);
        console.log('');
      }
      process.exit(1);
    }

    case 'batch': {
      const rules = await loadRules();
      const batchDir = resolve(args[1] || '.');
      const { readdir } = await import('fs/promises');
      const entries = await readdir(batchDir, { withFileTypes: true });
      const dirs = entries.filter(e => e.isDirectory()).map(e => e.name);

      console.log(`Scanning ${dirs.length} skills in ${batchDir}...\n`);

      const results = [];
      for (const dir of dirs) {
        const fullPath = join(batchDir, dir);
        const scanner = new SkillScanner(rules);
        const report = await scanner.scanDirectory(fullPath);
        results.push({ name: dir, score: report.score, risk: report.risk, findings: report.findings.length });
        const icon = report.score >= 80 ? '✅' : report.score >= 50 ? '⚠️' : '🔴';
        console.log(`  ${icon} ${dir.padEnd(30)} ${report.score}/100  ${report.risk.padEnd(8)} ${report.findings.length} finding(s)`);
      }

      console.log(`\n${results.length} skills scanned.`);
      const dangerous = results.filter(r => r.score < 50);
      if (dangerous.length > 0) {
        console.log(`🔴 ${dangerous.length} skill(s) flagged as HIGH/CRITICAL risk.`);
      }
      process.exit(dangerous.length > 0 ? 1 : 0);
    }

    // ─── V2 Commands (Gate) ───────────────────────────────────────

    case 'install': {
      const target = args[1];
      if (!target) {
        console.error('Error: provide a skill path or ClawHub slug.');
        console.error('Usage: skillguard install <path|slug>');
        process.exit(2);
      }

      const ledger = new Ledger({
        jsonPath: resolveHomePath(config.ledger.jsonPath),
        mdPath: resolveHomePath(config.ledger.mdPath),
      });
      const gate = new Gate({ config: config.gate, ledger });

      let skillPath;
      let source;
      let cleanup = null;

      // Determine if path or slug
      try {
        const { stat } = await import('fs/promises');
        await stat(resolve(target));
        skillPath = resolve(target);
        source = 'local';
      } catch {
        // Not a local path — try ClawHub
        console.error(`📦 Downloading ${target} from ClawHub...`);
        try {
          const download = await downloadSkillForScan(target);
          skillPath = download.path;
          source = `clawhub:${target}`;
          cleanup = download.cleanup;
        } catch (err) {
          console.error(`❌ Failed to download: ${err.message}`);
          process.exit(2);
        }
      }

      try {
        console.error('🔍 Scanning...');
        const result = await gate.checkInstall(skillPath, { source });

        const icon = result.decision === 'ALLOW' ? '✅' :
                     result.decision === 'REVIEW' ? '⚠️' : '🔴';

        if (flags.json) {
          console.log(JSON.stringify(result, null, 2));
        } else if (flags.compact) {
          console.log(`${icon} ${result.decision} ${result.score}/100 — ${result.reason}`);
        } else {
          console.log(`\n${icon} GATE DECISION: ${result.decision}`);
          console.log(`   Score: ${result.score}/100 (${result.risk})`);
          console.log(`   Hash: ${result.hash.slice(0, 16)}...`);
          console.log(`   Files: ${result.fileCount} (${(result.totalSize / 1024).toFixed(0)}KB)`);
          console.log(`   Reason: ${result.reason}`);
          
          if (result.previouslyApproved) {
            console.log(`   ✅ Previously approved — hash matches.`);
          }

          const critical = result.findings.filter(f => f.severity === 'critical' && f.weight > 0);
          const high = result.findings.filter(f => f.severity === 'high' && f.weight > 0);
          const flowCount = result.flowFindings?.length || 0;

          if (critical.length > 0) {
            console.log(`\n   🔴 Critical findings: ${critical.length}`);
            for (const f of critical.slice(0, 5)) {
              console.log(`      [${f.ruleId}] ${f.title} — ${f.file}:${f.line}`);
            }
          }
          if (high.length > 0) {
            console.log(`\n   🟠 High findings: ${high.length}`);
            for (const f of high.slice(0, 5)) {
              console.log(`      [${f.ruleId}] ${f.title} — ${f.file}:${f.line}`);
            }
          }
          if (flowCount > 0) {
            console.log(`\n   🔗 Cross-file flow findings: ${flowCount}`);
            for (const f of result.flowFindings) {
              console.log(`      ${f.severity.toUpperCase()}: ${f.title}`);
            }
          }

          if (result.diffResult) {
            console.log(`\n   📊 Version Diff:\n   ${result.diffResult.summary.replace(/\n/g, '\n   ')}`);
          }

          if (result.requiresApproval) {
            console.log(`\n   ⏳ Awaiting human approval. Run: skillguard approve "${result.skillName}"`);
          }
        }

        process.exit(result.decision === 'BLOCK' ? 1 : 0);
      } finally {
        if (cleanup) await cleanup();
      }
    }

    case 'approve': {
      const name = args[1];
      if (!name) {
        console.error('Error: provide skill name. Usage: skillguard approve <skill-name>');
        process.exit(2);
      }

      const purpose = args.slice(2).filter(a => !a.startsWith('--')).join(' ');
      const ledger = new Ledger({
        jsonPath: resolveHomePath(config.ledger.jsonPath),
        mdPath: resolveHomePath(config.ledger.mdPath),
      });

      // Find the most recent blocked/review entry for this skill
      const entries = await ledger.list();
      const pending = entries.filter(e => e.name === name && e.status === 'blocked').pop();

      if (pending) {
        // Convert blocked to approved
        pending.status = 'approved';
        pending.approver = 'human';
        pending.approvedAt = new Date().toISOString();
        if (purpose) pending.purpose = purpose;
        await ledger.save();
        console.log(`✅ Approved: ${name} (score: ${pending.score}/100, hash: ${pending.hash?.slice(0, 8)})`);
      } else {
        // Add a manual approval entry
        await ledger.add({
          name,
          version: 'unknown',
          source: 'manual',
          score: null,
          risk: 'UNKNOWN',
          hash: 'manual-approval',
          status: 'approved',
          approver: 'human',
          purpose: purpose || 'Manual approval',
        });
        console.log(`✅ Manually approved: ${name}`);
      }
      process.exit(0);
    }

    case 'revoke': {
      const name = args[1];
      if (!name) {
        console.error('Error: provide skill name. Usage: skillguard revoke <skill-name>');
        process.exit(2);
      }

      const ledger = new Ledger({
        jsonPath: resolveHomePath(config.ledger.jsonPath),
        mdPath: resolveHomePath(config.ledger.mdPath),
      });

      const revoked = await ledger.revoke(name);
      if (revoked) {
        console.log(`⚪ Revoked approval for: ${name}`);
      } else {
        console.log(`No approved entry found for: ${name}`);
      }
      process.exit(revoked ? 0 : 1);
    }

    case 'ledger': {
      const ledger = new Ledger({
        jsonPath: resolveHomePath(config.ledger.jsonPath),
        mdPath: resolveHomePath(config.ledger.mdPath),
      });

      const entries = await ledger.list();
      const stats = await ledger.stats();

      if (flags.json) {
        console.log(JSON.stringify({ entries, stats }, null, 2));
        process.exit(0);
      }

      console.log(`📋 SkillGuard Ledger — ${stats.total} entries`);
      console.log(`   ✅ Approved: ${stats.approved}  🔴 Blocked: ${stats.blocked}  ⚪ Revoked: ${stats.revoked}\n`);

      if (entries.length === 0) {
        console.log('   (empty — no skills scanned yet)');
      } else {
        for (const e of entries) {
          const icon = e.status === 'approved' ? '✅' :
                       e.status === 'blocked' ? '🔴' : '⚪';
          const date = e.date ? e.date.split('T')[0] : 'unknown';
          const shortHash = e.hash ? e.hash.slice(0, 8) : 'n/a';
          console.log(`   ${icon} ${e.name.padEnd(25)} ${String(e.score ?? '?').padStart(3)}/100  ${(e.approver || '').padEnd(5)}  ${date}  ${shortHash}`);
        }
      }
      process.exit(0);
    }

    case 'verify': {
      const targetPath = resolve(args[1] || '.');
      const ledger = new Ledger({
        jsonPath: resolveHomePath(config.ledger.jsonPath),
        mdPath: resolveHomePath(config.ledger.mdPath),
      });

      // Get skill name from SKILL.md
      let skillName;
      try {
        const skillMd = await readFile(join(targetPath, 'SKILL.md'), 'utf-8');
        const nameMatch = skillMd.match(/^name:\s*(.+)/m);
        skillName = nameMatch ? nameMatch[1].trim() : basename(targetPath);
      } catch {
        skillName = basename(targetPath);
      }

      const { approved, entry } = await ledger.isApproved(skillName);
      if (!approved || !entry?.hash) {
        console.log(`❓ ${skillName}: not found in ledger or no hash recorded.`);
        process.exit(1);
      }

      const { hash: currentHash } = await hashSkill(targetPath);
      if (currentHash === entry.hash) {
        console.log(`✅ ${skillName}: verified — matches approved hash (${entry.hash.slice(0, 8)})`);
        process.exit(0);
      } else {
        console.log(`❌ ${skillName}: MODIFIED since approval!`);
        console.log(`   Approved hash: ${entry.hash.slice(0, 16)}...`);
        console.log(`   Current hash:  ${currentHash.slice(0, 16)}...`);
        console.log(`   Re-scan required: skillguard install ${targetPath}`);
        process.exit(1);
      }
    }

    case 'diff': {
      const oldPath = resolve(args[1] || '.');
      const newPath = args[2] ? resolve(args[2]) : null;
      if (!newPath) {
        console.error('Error: provide two paths. Usage: skillguard diff <old-path> <new-path>');
        process.exit(2);
      }

      const rules = await loadRules();
      const diffScanner = new DiffScanner(rules);
      const result = await diffScanner.diff(oldPath, newPath);

      if (flags.json) {
        console.log(JSON.stringify(result, null, 2));
      } else {
        console.log('📊 Skill Version Diff\n');
        console.log(result.summary);

        if (result.added.length > 0) {
          console.log(`\n  ➕ Added files:`);
          for (const f of result.added) console.log(`     ${f}`);
        }
        if (result.removed.length > 0) {
          console.log(`\n  ➖ Removed files:`);
          for (const f of result.removed) console.log(`     ${f}`);
        }
        if (result.modified.length > 0) {
          console.log(`\n  ✏️  Modified files:`);
          for (const f of result.modified) console.log(`     ${f}`);
        }
        if (result.newFindings.length > 0) {
          console.log(`\n  ⚠️ New security findings:`);
          for (const f of result.newFindings.slice(0, 10)) {
            console.log(`     ${f.severity.toUpperCase()} [${f.ruleId}] ${f.title} — ${f.file}:${f.line}`);
          }
        }
      }

      process.exit(result.riskDelta > 10 ? 1 : 0);
    }

    case 'policy': {
      if (flags.json) {
        console.log(JSON.stringify(config, null, 2));
      } else {
        console.log('🛡️ SkillGuard Gate Policy\n');
        console.log(`   Auto-allow threshold:   ${config.gate.autoAllowThreshold}/100`);
        console.log(`   Review threshold:       ${config.gate.reviewThreshold}/100`);
        console.log(`   Block threshold:        < ${config.gate.reviewThreshold}/100`);
        console.log(`   Require approval for all: ${config.gate.requireApprovalForAll ? 'YES ✅' : 'no'}`);
        console.log(`\n   Flow analysis:          ${config.scan.enableFlowAnalysis ? 'enabled' : 'disabled'}`);
        console.log(`   Diff scanning:          ${config.scan.enableDiffScan ? 'enabled' : 'disabled'}`);
        console.log(`   Max file size:          ${(config.scan.maxFileSize / 1024).toFixed(0)}KB`);
        console.log(`\n   Config: ${join(__dirname, '..', 'skillguard.config.json')}`);
      }
      process.exit(0);
    }

    // ─── V2 Commands (Watch) ─────────────────────────────────────

    case 'watch': {
      const ledger = new Ledger({
        jsonPath: resolveHomePath(config.ledger.jsonPath),
        mdPath: resolveHomePath(config.ledger.mdPath),
      });

      const skillsDir = args[1] ? resolve(args[1]) : resolveHomePath('~/.openclaw/workspace/skills');
      const watcher = new Watcher({ skillsDir, ledger });

      console.error('🔍 Running watch cycle...');
      const result = await watcher.run();

      if (flags.json) {
        console.log(JSON.stringify(result, null, 2));
      } else {
        console.log(Watcher.formatAlerts(result));
      }

      process.exit(result.alerts.some(a => a.severity === 'critical') ? 1 : 0);
    }

    case 'runtime': {
      const targetPath = resolve(args[1] || '.');
      const monitor = new RuntimeMonitor();

      console.error(`🔍 Analyzing runtime behavior: ${targetPath}`);
      const result = await monitor.analyze(targetPath);

      if (flags.json) {
        console.log(JSON.stringify(result, null, 2));
      } else if (flags.compact) {
        if (result.findings.length === 0) {
          console.log('✅ No runtime risks detected.');
        } else {
          console.log(`⚠️ Runtime risk score: ${result.riskScore}/100 — ${result.findings.length} finding(s)`);
        }
      } else {
        console.log(`\n🔍 Runtime Behavior Analysis`);
        console.log(`   Risk score: ${result.riskScore}/100`);
        console.log(`   Findings: ${result.findings.length}\n`);

        if (result.findings.length === 0) {
          console.log('   ✅ No runtime-dangerous patterns detected.');
        } else {
          const grouped = {};
          for (const f of result.findings) {
            if (!grouped[f.type]) grouped[f.type] = [];
            grouped[f.type].push(f);
          }

          for (const [type, findings] of Object.entries(grouped)) {
            const label = type.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
            console.log(`   📌 ${label}:`);
            for (const f of findings) {
              const icon = f.severity === 'critical' ? '🔴' : f.severity === 'high' ? '🟠' : '⚠️';
              console.log(`      ${icon} ${f.description}`);
              console.log(`         ${f.file}:${f.line} — ${f.pattern}`);
            }
            console.log('');
          }
        }
      }

      process.exit(result.riskScore > 50 ? 1 : 0);
    }

    case 'status': {
      const ledger = new Ledger({
        jsonPath: resolveHomePath(config.ledger.jsonPath),
        mdPath: resolveHomePath(config.ledger.mdPath),
      });

      const skillsDir = args[1] ? resolve(args[1]) : resolveHomePath('~/.openclaw/workspace/skills');
      const watcher = new Watcher({ skillsDir, ledger });

      // Load state
      const watchState = await watcher.loadState();
      const ledgerStats = await ledger.stats();
      const skills = await watcher.discoverSkills();

      if (flags.json) {
        console.log(JSON.stringify({ ledgerStats, watchState, skills: skills.length }, null, 2));
        process.exit(0);
      }

      console.log('🛡️ SkillGuard Security Status\n');

      // Ledger summary
      console.log(`📋 Ledger:`);
      console.log(`   ✅ Approved: ${ledgerStats.approved}  🔴 Blocked: ${ledgerStats.blocked}  ⚪ Revoked: ${ledgerStats.revoked}`);

      // Watch summary
      console.log(`\n👁️ Watch:`);
      console.log(`   Installed skills: ${skills.length}`);
      console.log(`   Last scan: ${watchState.lastRunAt || 'never'}`);

      const trackedCount = Object.keys(watchState.skills || {}).length;
      const untrackedCount = skills.length - trackedCount;
      if (untrackedCount > 0) {
        console.log(`   ⚠️ ${untrackedCount} skill(s) not yet scanned by watcher`);
      }

      // Per-skill status
      if (skills.length > 0) {
        console.log(`\n📦 Skills:`);
        for (const skill of skills) {
          const state = watchState.skills?.[skill.name];
          const { approved } = await ledger.isApproved(skill.name);
          
          const icon = approved ? '✅' : '❓';
          const score = state?.score != null ? `${state.score}/100` : 'unscanned';
          const lastScan = state?.lastScannedAt ? state.lastScannedAt.split('T')[0] : 'never';
          
          console.log(`   ${icon} ${skill.name.padEnd(30)} ${score.padStart(7)}  scanned: ${lastScan}`);
        }
      }

      // Policy
      console.log(`\n🔧 Policy:`);
      console.log(`   Require approval: ${config.gate.requireApprovalForAll ? 'ALL skills' : `score < ${config.gate.autoAllowThreshold}`}`);
      console.log(`   Auto-block below: ${config.gate.reviewThreshold}/100`);

      process.exit(0);
    }

    default:
      console.error(`Unknown command: ${command}. Run skillguard --help for usage.`);
      process.exit(1);
  }
}

main().catch(err => {
  console.error(`Fatal error: ${err.message}`);
  process.exit(1);
});
