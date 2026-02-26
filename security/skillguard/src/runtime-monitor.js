/**
 * SkillGuard Runtime Monitor — Detect dangerous runtime behavior
 * 
 * Analyzes skills for patterns that indicate runtime code download,
 * dynamic execution, or behavior that only activates after install.
 * 
 * This is a static analysis of runtime-dangerous patterns, NOT a sandbox.
 * It catches skills that are designed to change behavior after installation.
 */

import { readFile, readdir, stat } from 'fs/promises';
import { join, relative, extname } from 'path';

const CODE_EXTS = new Set(['.js', '.mjs', '.cjs', '.ts', '.jsx', '.tsx', '.py', '.sh']);

/**
 * @typedef {Object} RuntimeFinding
 * @property {string} type — Category of runtime risk
 * @property {string} severity — critical | high | medium
 * @property {string} file — File path
 * @property {number} line — Line number
 * @property {string} pattern — What was detected
 * @property {string} description — Human-readable description
 */

export class RuntimeMonitor {
  /**
   * Analyze a skill for runtime-dangerous patterns
   * @param {string} skillPath
   * @returns {Promise<{ findings: RuntimeFinding[], riskScore: number }>}
   */
  async analyze(skillPath) {
    const findings = [];
    const files = await this._collectCodeFiles(skillPath);

    for (const { relPath, fullPath } of files) {
      let content;
      try { content = await readFile(fullPath, 'utf-8'); }
      catch { continue; }

      const ext = extname(relPath).toLowerCase();

      // Check for runtime code download
      this._checkCodeDownload(content, relPath, findings);

      // Check for dynamic evaluation
      this._checkDynamicEval(content, relPath, findings);

      // Check for time-delayed activation
      this._checkTimeBombs(content, relPath, findings);

      // Check for environment-dependent behavior
      this._checkEnvironmentSwitch(content, relPath, findings);

      // Check for self-modification
      this._checkSelfModification(content, relPath, findings);

      // Check for network callbacks / C2 patterns
      this._checkC2Patterns(content, relPath, findings);

      // Python-specific runtime risks
      if (ext === '.py') {
        this._checkPythonRuntime(content, relPath, findings);
      }

      // Shell-specific runtime risks
      if (ext === '.sh' || ext === '.bash') {
        this._checkShellRuntime(content, relPath, findings);
      }
    }

    // Calculate risk score (0-100, higher = riskier)
    let riskScore = 0;
    for (const f of findings) {
      riskScore += f.severity === 'critical' ? 30 : f.severity === 'high' ? 15 : 5;
    }
    riskScore = Math.min(100, riskScore);

    return { findings, riskScore };
  }

  /**
   * Detect patterns that download and execute code at runtime
   */
  _checkCodeDownload(content, filePath, findings) {
    const patterns = [
      {
        regex: /fetch\s*\([^)]*\)\s*\.then\s*\([^)]*\)\s*\.then\s*\(\s*(?:text|data|code|script)\s*=>\s*(?:eval|Function|new\s+Function)/g,
        desc: 'Fetch → eval chain — downloads and executes remote code',
        severity: 'critical',
      },
      {
        regex: /(?:axios|fetch|http\.get|request)\s*\([^)]*\)[\s\S]{0,200}(?:eval|exec|spawn|Function)\s*\(/g,
        desc: 'Network fetch near code execution — potential remote code download',
        severity: 'critical',
      },
      {
        regex: /(?:writeFile|fs\.write)\s*\([^)]*\.(?:js|sh|py|mjs)['"]\s*,[\s\S]{0,100}(?:require|import|exec|spawn)/g,
        desc: 'Writes code file then executes it — dynamic code deployment',
        severity: 'critical',
      },
      {
        regex: /import\s*\(\s*(?:url|endpoint|remote|fetched|downloaded)/gi,
        desc: 'Dynamic import from variable — may load remote modules',
        severity: 'high',
      },
      {
        regex: /require\s*\(\s*(?:path\.join|`\$\{|downloadedPath|remotePath|tempFile)/g,
        desc: 'Dynamic require from constructed path — may load downloaded code',
        severity: 'high',
      },
      {
        regex: /npm\s+install|pip\s+install|gem\s+install/g,
        desc: 'Package manager install at runtime — installs new dependencies',
        severity: 'high',
      },
    ];

    this._matchPatterns(content, filePath, patterns, 'code_download', findings);
  }

  /**
   * Detect dynamic code evaluation patterns
   */
  _checkDynamicEval(content, filePath, findings) {
    const patterns = [
      {
        regex: /new\s+Function\s*\(\s*(?:response|data|body|text|payload|config)\b/g,
        desc: 'new Function() from external data — compiles runtime code',
        severity: 'critical',
      },
      {
        regex: /eval\s*\(\s*(?:response|data|body|text|payload|config|JSON\.parse)\b/g,
        desc: 'eval() on external data — executes arbitrary code',
        severity: 'critical',
      },
      {
        regex: /vm\s*\.\s*(?:runInContext|runInNewContext|createScript|compileFunction)\s*\(/g,
        desc: 'Node.js vm module — sandboxed code execution (sandbox escapes exist)',
        severity: 'high',
      },
      {
        regex: /WebAssembly\s*\.\s*(?:instantiate|compile)\s*\(/g,
        desc: 'WebAssembly compilation — can execute binary code',
        severity: 'medium',
      },
    ];

    this._matchPatterns(content, filePath, patterns, 'dynamic_eval', findings);
  }

  /**
   * Detect time-delayed activation (time bombs)
   */
  _checkTimeBombs(content, filePath, findings) {
    const patterns = [
      {
        regex: /Date\.now\s*\(\s*\)\s*[><=]+\s*\d{12,}/g,
        desc: 'Timestamp comparison — activates after specific date',
        severity: 'critical',
      },
      {
        regex: /new\s+Date\s*\(\s*['"][^'"]+['"]\s*\)\s*[<>]/g,
        desc: 'Date comparison — behavior changes after specific date',
        severity: 'high',
      },
      {
        regex: /setTimeout\s*\([^,]+,\s*\d{6,}\s*\)/g,
        desc: 'Long setTimeout (>16 min) — delayed execution',
        severity: 'medium',
      },
      {
        regex: /(?:count|run|call|invoke|attempt)\s*[><=]+\s*\d{2,}\s*(?:\)|&&|\|\|)/g,
        desc: 'Counter-based activation — triggers after N executions',
        severity: 'high',
      },
    ];

    this._matchPatterns(content, filePath, patterns, 'time_bomb', findings);
  }

  /**
   * Detect environment-dependent behavior switches
   */
  _checkEnvironmentSwitch(content, filePath, findings) {
    const patterns = [
      {
        regex: /process\.env\.NODE_ENV\s*[!=]==?\s*['"](?:production|prod)['"]/g,
        desc: 'Behavior change in production mode',
        severity: 'medium',
      },
      {
        regex: /(?:isDocker|isContainer|isCI|isSandbox|isTest)\s*\(\s*\)/g,
        desc: 'Environment detection function — may evade sandboxed scanning',
        severity: 'high',
      },
      {
        regex: /\/proc\/1\/cgroup|\.dockerenv|KUBERNETES_SERVICE|CI=true/g,
        desc: 'Container/CI environment detection — sandbox evasion',
        severity: 'critical',
      },
      {
        regex: /os\.path\.exists\s*\(\s*['"]\/(proc\/1\/cgroup|\.dockerenv|run\/secrets)/g,
        desc: 'Python container detection — sandbox evasion',
        severity: 'critical',
      },
    ];

    this._matchPatterns(content, filePath, patterns, 'env_switch', findings);
  }

  /**
   * Detect self-modification patterns
   */
  _checkSelfModification(content, filePath, findings) {
    const patterns = [
      {
        regex: /(?:writeFile|fs\.write)\s*\(\s*__filename/g,
        desc: 'Writes to own file — self-modifying code',
        severity: 'critical',
      },
      {
        regex: /(?:writeFile|fs\.write)\s*\(\s*__dirname/g,
        desc: 'Writes to own directory — may modify skill files',
        severity: 'high',
      },
      {
        regex: /(?:writeFile|fs\.write)[\s\S]{0,100}SKILL\.md/g,
        desc: 'Modifies SKILL.md — may alter skill instructions post-install',
        severity: 'critical',
      },
      {
        regex: /(?:writeFile|fs\.write)[\s\S]{0,100}\.openclaw/g,
        desc: 'Writes to .openclaw directory — may modify agent configuration',
        severity: 'critical',
      },
      {
        regex: /(?:git\s+clone|git\s+pull|git\s+fetch)/g,
        desc: 'Git operations — may download new code at runtime',
        severity: 'high',
      },
    ];

    this._matchPatterns(content, filePath, patterns, 'self_modify', findings);
  }

  /**
   * Detect C2 (command & control) patterns
   */
  _checkC2Patterns(content, filePath, findings) {
    const patterns = [
      {
        regex: /setInterval\s*\(\s*(?:async\s+)?(?:function|\(\s*\)\s*=>)\s*{[\s\S]{0,500}fetch\s*\(/g,
        desc: 'Periodic network polling — command & control beacon pattern',
        severity: 'critical',
      },
      {
        regex: /WebSocket|new\s+WebSocket|ws:\/\/|wss:\/\//g,
        desc: 'WebSocket connection — persistent bidirectional channel',
        severity: 'high',
      },
      {
        regex: /(?:dns|dgram)\s*\.\s*(?:resolve|lookup|createSocket)/g,
        desc: 'DNS/UDP operations — potential covert channel',
        severity: 'high',
      },
      {
        regex: /setInterval[\s\S]{0,200}(?:exec|spawn|eval)/g,
        desc: 'Periodic code execution — may execute remote commands on schedule',
        severity: 'critical',
      },
    ];

    this._matchPatterns(content, filePath, patterns, 'c2_pattern', findings);
  }

  /**
   * Python-specific runtime risks
   */
  _checkPythonRuntime(content, filePath, findings) {
    const patterns = [
      {
        regex: /importlib\s*\.\s*import_module\s*\(\s*(?!['"])/g,
        desc: 'Dynamic Python import from variable',
        severity: 'high',
      },
      {
        regex: /exec\s*\(\s*(?:requests|urllib|response|data)\b/g,
        desc: 'exec() on network data — remote code execution',
        severity: 'critical',
      },
      {
        regex: /subprocess\.(?:Popen|call|run|check_output)\s*\(\s*(?:response|data|command|payload)/g,
        desc: 'Subprocess with external data — command injection',
        severity: 'critical',
      },
      {
        regex: /(?:pickle|marshal|shelve)\s*\.loads?\s*\(\s*(?:response|data|request)/g,
        desc: 'Deserialize network data — arbitrary code execution',
        severity: 'critical',
      },
    ];

    this._matchPatterns(content, filePath, patterns, 'python_runtime', findings);
  }

  /**
   * Shell-specific runtime risks
   */
  _checkShellRuntime(content, filePath, findings) {
    const patterns = [
      {
        regex: /curl\s+[^\n]*\|\s*(?:bash|sh|eval)/g,
        desc: 'Pipe curl to shell — remote code execution',
        severity: 'critical',
      },
      {
        regex: /wget\s+[^\n]*-O\s*-\s*\|\s*(?:bash|sh)/g,
        desc: 'Pipe wget to shell — remote code execution',
        severity: 'critical',
      },
      {
        regex: /source\s+<\s*\(\s*curl/g,
        desc: 'Source from curl — executes remote script in current shell',
        severity: 'critical',
      },
      {
        regex: /crontab\s+-|\/etc\/cron/g,
        desc: 'Crontab modification — persistence mechanism',
        severity: 'high',
      },
    ];

    this._matchPatterns(content, filePath, patterns, 'shell_runtime', findings);
  }

  /**
   * Match patterns and add findings
   */
  _matchPatterns(content, filePath, patterns, type, findings) {
    const lines = content.split('\n');

    for (const { regex, desc, severity } of patterns) {
      regex.lastIndex = 0;
      let match;
      while ((match = regex.exec(content)) !== null) {
        const lineNum = (content.slice(0, match.index).match(/\n/g) || []).length + 1;
        const lineContent = lines[lineNum - 1]?.trim() || '';

        // Skip if in a comment
        if (lineContent.startsWith('//') || lineContent.startsWith('#') || lineContent.startsWith('*')) {
          continue;
        }

        findings.push({
          type,
          severity,
          file: filePath,
          line: lineNum,
          pattern: match[0].slice(0, 80),
          description: desc,
        });
      }
    }
  }

  /**
   * Collect code files from skill directory
   */
  async _collectCodeFiles(dirPath, base = dirPath) {
    const results = [];
    let entries;
    try { entries = await readdir(dirPath, { withFileTypes: true }); }
    catch { return results; }

    for (const entry of entries) {
      const fullPath = join(dirPath, entry.name);
      const relPath = relative(base, fullPath);

      if (entry.isDirectory()) {
        if (['node_modules', '.git', '__pycache__'].includes(entry.name)) continue;
        results.push(...await this._collectCodeFiles(fullPath, base));
      } else if (entry.isFile() && CODE_EXTS.has(extname(entry.name).toLowerCase())) {
        results.push({ relPath, fullPath });
      }
    }
    return results;
  }
}
