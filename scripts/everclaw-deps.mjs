#!/usr/bin/env node
/**
 * everclaw-deps.mjs — Dependency resolver for EverClaw flavors
 *
 * Reads `dependencies.clawhub` from a flavor's SKILL.md frontmatter (YAML),
 * checks what's already installed via .clawhub/lock.json, and installs missing deps.
 *
 * Usage:
 *   node everclaw-deps.mjs                     # resolve deps for current workspace skill
 *   node everclaw-deps.mjs --skill-path ./foo   # resolve deps for a specific skill
 *   node everclaw-deps.mjs --dry-run            # show what would be installed
 *   node everclaw-deps.mjs --list               # just list declared dependencies
 *   node everclaw-deps.mjs --check              # exit 1 if deps are missing
 */

import { readFileSync, existsSync } from 'fs';
import { join, resolve, dirname } from 'path';
import { execSync } from 'child_process';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ── Defaults ──
const DEFAULT_WORKSPACE = process.env.OPENCLAW_WORKSPACE
  || join(process.env.HOME, '.openclaw', 'workspace');

// ── Parse args ──
const args = process.argv.slice(2);
const flags = {
  skillPath: null,
  dryRun: args.includes('--dry-run'),
  list: args.includes('--list'),
  check: args.includes('--check'),
  force: args.includes('--force'),
  quiet: args.includes('--quiet'),
  help: args.includes('--help') || args.includes('-h'),
};

const pathIdx = args.indexOf('--skill-path');
if (pathIdx !== -1 && args[pathIdx + 1]) {
  flags.skillPath = resolve(args[pathIdx + 1]);
}

if (flags.help) {
  console.log(`everclaw-deps — Dependency resolver for EverClaw flavors

Usage:
  node everclaw-deps.mjs [options]

Options:
  --skill-path <path>   Path to the skill directory (default: cwd or workspace)
  --dry-run             Show what would be installed, don't install
  --list                List declared dependencies and exit
  --check               Exit 1 if any dependencies are missing
  --force               Reinstall even if already present
  --quiet               Suppress non-error output
  -h, --help            Show this help

Dependencies are declared in SKILL.md frontmatter:

  ---
  name: my-flavor
  dependencies:
    clawhub:
      - slug: everclaw-inference
        version: ">=0.9.0"
        required: true
      - slug: three-shifts
        required: false
        description: "Cyclic task execution"
    github:
      - repo: profbernardoj/everclaw
        path: skills/pii-guard
        description: "PII leak prevention"
  ---
`);
  process.exit(0);
}

// ── Helpers ──
function log(msg) { if (!flags.quiet) console.log(msg); }
function warn(msg) { console.error(`⚠️  ${msg}`); }
function error(msg) { console.error(`❌ ${msg}`); }

/**
 * Parse YAML frontmatter from SKILL.md
 * Minimal parser — handles the dependency block without a full YAML lib
 */
function parseFrontmatter(content) {
  const match = content.match(/^---\n([\s\S]*?)\n---/);
  if (!match) return {};

  const yaml = match[1];
  const result = { name: '', dependencies: { clawhub: [], github: [] } };

  // Extract name
  const nameMatch = yaml.match(/^name:\s*(.+)$/m);
  if (nameMatch) result.name = nameMatch[1].trim().replace(/^["']|["']$/g, '');

  // Find the dependencies block — it's a top-level key in the frontmatter
  const depsIdx = yaml.indexOf('\ndependencies:');
  if (depsIdx === -1) {
    // Also check if it starts at position 0
    if (!yaml.startsWith('dependencies:')) return result;
  }

  // Extract everything from dependencies: to the next top-level key or end
  const depsStart = depsIdx === -1 ? 0 : depsIdx + 1;
  const afterDeps = yaml.substring(depsStart);
  // Find the next top-level key (no leading whitespace, has a colon)
  const nextKeyMatch = afterDeps.match(/\n[a-z][a-z_-]*:\s/);
  const depsBlock = nextKeyMatch
    ? afterDeps.substring(0, nextKeyMatch.index)
    : afterDeps;

  // Parse list items by splitting on "- slug:" or "- repo:" patterns
  function parseItems(block) {
    const items = [];
    // Split on list item markers (    - ) — handles first item too
    const parts = block.split(/(?:^|\n)\s{4}-\s/).filter(s => s.trim());
    for (const part of parts) {
      const item = {};
      for (const line of part.split('\n')) {
        const kv = line.match(/^\s*(\w+):\s*(.+?)\s*$/);
        if (kv) {
          let val = kv[2];
          // Strip surrounding quotes
          val = val.replace(/^["']|["']$/g, '');
          item[kv[1]] = val;
        }
      }
      if (Object.keys(item).length) items.push(item);
    }
    return items;
  }

  // Extract clawhub section
  const clawhubIdx = depsBlock.indexOf('clawhub:');
  const githubIdx = depsBlock.indexOf('github:');

  if (clawhubIdx !== -1) {
    const start = depsBlock.indexOf('\n', clawhubIdx) + 1;
    const end = githubIdx !== -1 && githubIdx > clawhubIdx
      ? githubIdx : depsBlock.length;
    const clawhubBlock = depsBlock.substring(start, end);
    for (const item of parseItems(clawhubBlock)) {
      if (item.slug) {
        const aliases = item.aliases
          ? item.aliases.replace(/[\[\]"' ]/g, '').split(',').filter(Boolean)
          : [];
        result.dependencies.clawhub.push({
          slug: item.slug,
          aliases,
          version: item.version || null,
          required: item.required === 'false' ? false : true,
          description: item.description || '',
        });
      }
    }
  }

  if (githubIdx !== -1) {
    const start = depsBlock.indexOf('\n', githubIdx) + 1;
    const end = clawhubIdx !== -1 && clawhubIdx > githubIdx
      ? clawhubIdx : depsBlock.length;
    const githubBlock = depsBlock.substring(start, end);
    for (const item of parseItems(githubBlock)) {
      if (item.repo) {
        result.dependencies.github.push({
          repo: item.repo,
          path: item.path || '',
          required: item.required === 'false' ? false : true,
          description: item.description || '',
        });
      }
    }
  }

  return result;
}

/**
 * Read the ClawHub lock file to see what's already installed
 */
function readLockfile(workspace) {
  const lockPath = join(workspace, '.clawhub', 'lock.json');
  if (!existsSync(lockPath)) return {};
  try {
    const lock = JSON.parse(readFileSync(lockPath, 'utf-8'));
    return lock.skills || {};
  } catch {
    return {};
  }
}

/**
 * Check if a skill directory exists in the workspace
 */
function isSkillInstalled(workspace, slug) {
  return existsSync(join(workspace, 'skills', slug, 'SKILL.md'));
}

/**
 * Install a ClawHub dependency
 */
function installClawHub(slug, version, force) {
  const versionFlag = version ? ` --version ${version}` : '';
  const forceFlag = force ? ' --force' : '';
  const cmd = `clawhub install ${slug}${versionFlag}${forceFlag}`;
  log(`  📦 ${cmd}`);
  try {
    execSync(cmd, { stdio: 'inherit', timeout: 60000 });
    return true;
  } catch (e) {
    error(`Failed to install ${slug}: ${e.message}`);
    return false;
  }
}

/**
 * Install a GitHub dependency (sparse checkout of a subdirectory)
 */
function installGitHub(repo, repoPath, workspace) {
  const slug = repoPath.split('/').pop();
  const targetDir = join(workspace, 'skills', slug);

  if (existsSync(targetDir) && !flags.force) {
    log(`  ✓ ${slug} (already exists at skills/${slug})`);
    return true;
  }

  log(`  📥 Cloning ${repo}:${repoPath} → skills/${slug}`);
  try {
    // Use git sparse checkout for just the subdirectory
    const tmpDir = join(workspace, '.tmp-dep-' + slug);
    execSync(`rm -rf "${tmpDir}"`, { stdio: 'pipe' });
    execSync(
      `git clone --depth 1 --filter=blob:none --sparse https://github.com/${repo}.git "${tmpDir}"`,
      { stdio: 'pipe', timeout: 30000 }
    );
    execSync(`git -C "${tmpDir}" sparse-checkout set "${repoPath}"`, { stdio: 'pipe' });

    // Copy the skill to workspace
    const srcDir = join(tmpDir, repoPath);
    if (existsSync(srcDir)) {
      execSync(`cp -r "${srcDir}" "${targetDir}"`, { stdio: 'pipe' });
      log(`  ✓ Installed ${slug} from ${repo}`);
    } else {
      error(`Path ${repoPath} not found in ${repo}`);
      return false;
    }

    // Cleanup
    execSync(`rm -rf "${tmpDir}"`, { stdio: 'pipe' });
    return true;
  } catch (e) {
    error(`Failed to install ${slug} from GitHub: ${e.message}`);
    return false;
  }
}

// ── Main ──
function main() {
  // Find SKILL.md
  const searchPaths = [
    flags.skillPath,
    process.cwd(),
    DEFAULT_WORKSPACE,
  ].filter(Boolean);

  let skillMdPath = null;
  for (const p of searchPaths) {
    const candidate = join(p, 'SKILL.md');
    if (existsSync(candidate)) {
      skillMdPath = candidate;
      break;
    }
  }

  if (!skillMdPath) {
    error('No SKILL.md found. Use --skill-path to specify location.');
    process.exit(1);
  }

  const content = readFileSync(skillMdPath, 'utf-8');
  const meta = parseFrontmatter(content);

  const clawhubDeps = meta.dependencies.clawhub || [];
  const githubDeps = meta.dependencies.github || [];
  const totalDeps = clawhubDeps.length + githubDeps.length;

  if (totalDeps === 0) {
    log('No dependencies declared in SKILL.md frontmatter.');
    process.exit(0);
  }

  log(`\n🔗 ${meta.name || 'Skill'} — ${totalDeps} dependencies\n`);

  // ── List mode ──
  if (flags.list) {
    if (clawhubDeps.length) {
      log('ClawHub:');
      for (const d of clawhubDeps) {
        const req = d.required ? '(required)' : '(optional)';
        const ver = d.version ? ` ${d.version}` : '';
        log(`  - ${d.slug}${ver} ${req}${d.description ? ' — ' + d.description : ''}`);
      }
    }
    if (githubDeps.length) {
      log('GitHub:');
      for (const d of githubDeps) {
        const req = d.required ? '(required)' : '(optional)';
        log(`  - ${d.repo}:${d.path} ${req}${d.description ? ' — ' + d.description : ''}`);
      }
    }
    process.exit(0);
  }

  // ── Check what's installed ──
  // Use the OpenClaw workspace, not the skill's parent directory
  const workspace = DEFAULT_WORKSPACE;
  const installed = readLockfile(workspace);
  const missing = [];
  const present = [];

  for (const dep of clawhubDeps) {
    const slugsToCheck = [dep.slug, ...(dep.aliases || [])];
    const found = slugsToCheck.some(s => installed[s] || isSkillInstalled(workspace, s));
    if (found) {
      present.push({ ...dep, source: 'clawhub' });
    } else {
      missing.push({ ...dep, source: 'clawhub' });
    }
  }

  for (const dep of githubDeps) {
    const slug = dep.path.split('/').pop();
    if (isSkillInstalled(workspace, slug)) {
      present.push({ ...dep, source: 'github', slug });
    } else {
      missing.push({ ...dep, source: 'github', slug });
    }
  }

  // ── Report ──
  if (present.length) {
    log('✅ Already installed:');
    for (const d of present) log(`  ✓ ${d.slug}`);
  }

  if (missing.length) {
    log(`\n📋 Missing (${missing.length}):`);
    for (const d of missing) {
      const req = d.required ? '🔴 required' : '🟡 optional';
      log(`  ✗ ${d.slug} (${req})`);
    }
  } else {
    log('\n✅ All dependencies satisfied.');
    process.exit(0);
  }

  // ── Check mode ──
  if (flags.check) {
    const requiredMissing = missing.filter(d => d.required);
    if (requiredMissing.length) {
      error(`${requiredMissing.length} required dependencies missing.`);
      process.exit(1);
    }
    log('All required dependencies satisfied (some optional deps missing).');
    process.exit(0);
  }

  // ── Dry run ──
  if (flags.dryRun) {
    log('\n🏃 Dry run — would install:');
    for (const d of missing) {
      if (d.source === 'clawhub') {
        log(`  clawhub install ${d.slug}${d.version ? ' --version ' + d.version : ''}`);
      } else {
        log(`  git sparse-checkout ${d.repo}:${d.path} → skills/${d.slug}`);
      }
    }
    process.exit(0);
  }

  // ── Install ──
  log('\n📦 Installing dependencies...\n');
  let installed_count = 0;
  let failed_count = 0;

  for (const dep of missing) {
    if (dep.source === 'clawhub') {
      if (installClawHub(dep.slug, dep.version, flags.force)) {
        installed_count++;
      } else {
        failed_count++;
        if (dep.required) {
          error(`Required dependency ${dep.slug} failed to install.`);
          process.exit(1);
        }
      }
    } else if (dep.source === 'github') {
      if (installGitHub(dep.repo, dep.path, workspace)) {
        installed_count++;
      } else {
        failed_count++;
        if (dep.required) {
          error(`Required dependency ${dep.slug} failed to install.`);
          process.exit(1);
        }
      }
    }
  }

  log(`\n✅ Done: ${installed_count} installed, ${failed_count} failed, ${present.length} already present.`);
}

main();
