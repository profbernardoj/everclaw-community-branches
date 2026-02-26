/**
 * SkillGuard Flow Analyzer — Cross-file data flow tracking
 * 
 * Builds import graphs and traces data flows across file boundaries.
 * Detects exfiltration chains: credential read → transform → network send.
 */

import { readFile, readdir } from 'fs/promises';
import { join, extname, basename, relative } from 'path';

const CODE_EXTS = new Set(['.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx']);

/**
 * @typedef {Object} ImportEdge
 * @property {string} from — Importing file
 * @property {string} to — Imported file/module
 * @property {string[]} symbols — Imported symbols
 * @property {boolean} isRelative — true if relative import
 */

/**
 * @typedef {Object} ExportInfo
 * @property {string} file — File path
 * @property {string[]} symbols — Exported symbol names
 * @property {Map<string, string>} symbolTypes — symbol → type hint (function, const, class)
 */

/**
 * @typedef {Object} FlowChain
 * @property {string} description — Human-readable description
 * @property {string} severity — critical | high | medium
 * @property {string[]} files — Files involved
 * @property {string[]} steps — Step descriptions
 */

export class FlowAnalyzer {
  constructor() {
    this.imports = []; // ImportEdge[]
    this.exports = new Map(); // file → ExportInfo
    this.fileContents = new Map(); // file → content
  }

  /**
   * Analyze a skill directory for cross-file data flows
   * @param {string} skillPath
   * @returns {Promise<{ imports: ImportEdge[], exports: Map, chains: FlowChain[], findings: Object[] }>}
   */
  async analyze(skillPath) {
    this.imports = [];
    this.exports = new Map();
    this.fileContents = new Map();

    // Collect all code files
    const files = await this._collectCodeFiles(skillPath);

    // Parse imports and exports for each file
    for (const { relPath, fullPath } of files) {
      const content = await this._readSafe(fullPath);
      if (!content) continue;
      this.fileContents.set(relPath, content);
      this._parseImports(content, relPath);
      this._parseExports(content, relPath);
    }

    // Detect dangerous flow chains
    const chains = this._detectChains();
    const findings = chains.map(chain => ({
      ruleId: 'FLOW_' + chain.severity.toUpperCase(),
      severity: chain.severity,
      category: 'cross-file-flow',
      title: `Cross-file flow: ${chain.description}`,
      file: chain.files.join(' → '),
      line: 0,
      match: '',
      context: chain.steps.join(' → '),
      weight: chain.severity === 'critical' ? 30 : chain.severity === 'high' ? 20 : 10,
    }));

    return { imports: this.imports, exports: this.exports, chains, findings };
  }

  /**
   * Parse import/require statements
   */
  _parseImports(content, filePath) {
    // ES imports: import { foo } from './bar'
    const esImports = content.matchAll(/import\s+(?:{([^}]+)}|\*\s+as\s+(\w+)|(\w+))\s+from\s+['"]([^'"]+)['"]/g);
    for (const match of esImports) {
      const symbols = match[1] ? match[1].split(',').map(s => s.trim().split(/\s+as\s+/)[0].trim()) :
                      match[2] ? [match[2]] :
                      match[3] ? [match[3]] : [];
      this.imports.push({
        from: filePath,
        to: match[4],
        symbols,
        isRelative: match[4].startsWith('.'),
      });
    }

    // CommonJS: const { foo } = require('./bar')
    const cjsImports = content.matchAll(/(?:const|let|var)\s+(?:{([^}]+)}|(\w+))\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)/g);
    for (const match of cjsImports) {
      const symbols = match[1] ? match[1].split(',').map(s => s.trim().split(/\s*:\s*/)[0].trim()) :
                      match[2] ? [match[2]] : [];
      this.imports.push({
        from: filePath,
        to: match[3],
        symbols,
        isRelative: match[3].startsWith('.'),
      });
    }

    // Dynamic imports: import('./foo')
    const dynImports = content.matchAll(/import\s*\(\s*['"]([^'"]+)['"]\s*\)/g);
    for (const match of dynImports) {
      this.imports.push({
        from: filePath,
        to: match[1],
        symbols: ['*'],
        isRelative: match[1].startsWith('.'),
      });
    }
  }

  /**
   * Parse export statements
   */
  _parseExports(content, filePath) {
    const symbols = [];
    const symbolTypes = new Map();

    // Named exports: export { foo, bar }
    const namedExports = content.matchAll(/export\s+{([^}]+)}/g);
    for (const match of namedExports) {
      for (const sym of match[1].split(',')) {
        const name = sym.trim().split(/\s+as\s+/).pop().trim();
        symbols.push(name);
      }
    }

    // Direct exports: export function foo() / export const bar
    const directExports = content.matchAll(/export\s+(function|const|let|var|class|async\s+function)\s+(\w+)/g);
    for (const match of directExports) {
      symbols.push(match[2]);
      symbolTypes.set(match[2], match[1].replace('async ', ''));
    }

    // Default export
    if (/export\s+default/.test(content)) {
      symbols.push('default');
    }

    // module.exports
    const moduleExports = content.matchAll(/module\.exports\s*(?:\.\s*(\w+))?\s*=/g);
    for (const match of moduleExports) {
      symbols.push(match[1] || 'default');
    }

    this.exports.set(filePath, { file: filePath, symbols, symbolTypes });
  }

  /**
   * Detect dangerous cross-file data flow chains
   */
  _detectChains() {
    const chains = [];

    // Build maps of what each file does
    const fileCapabilities = new Map();
    for (const [filePath, content] of this.fileContents) {
      const caps = {
        readsCredentials: false,
        makesNetworkCalls: false,
        encodesData: false,
        executesCode: false,
        writesFiles: false,
      };

      // Credential reads
      if (/process\.env|\.env|api[_-]?key|secret|token|password|credential|auth/i.test(content)) {
        caps.readsCredentials = true;
      }

      // Network calls
      if (/\bfetch\s*\(|\baxios\b|\bhttpx?\b|\brequests\.\w+\(|\bcurl\b|\bhttp\.request/i.test(content)) {
        caps.makesNetworkCalls = true;
      }

      // Data encoding
      if (/\bbtoa\b|\batob\b|\bBuffer\.from\b|\bbase64\b|\bJSON\.stringify\b.*\bfetch/i.test(content)) {
        caps.encodesData = true;
      }

      // Code execution
      if (/\beval\b|\bexec\b|\bspawn\b|\bchild_process\b|\bFunction\s*\(/i.test(content)) {
        caps.executesCode = true;
      }

      // File writes
      if (/\bwriteFile\b|\bfs\.\w*write\b|\bcreateWriteStream\b/i.test(content)) {
        caps.writesFiles = true;
      }

      fileCapabilities.set(filePath, caps);
    }

    // Check for cross-file exfiltration chains
    for (const imp of this.imports) {
      if (!imp.isRelative) continue; // Only analyze internal imports

      const importerCaps = fileCapabilities.get(imp.from);
      const exporterFile = this._resolveRelative(imp.from, imp.to);
      const exporterCaps = fileCapabilities.get(exporterFile);

      if (!importerCaps || !exporterCaps) continue;

      // Chain: File A reads credentials → File B sends network
      if (exporterCaps.readsCredentials && importerCaps.makesNetworkCalls) {
        chains.push({
          description: 'Credential read in one file, network send in another',
          severity: 'critical',
          files: [exporterFile, imp.from],
          steps: [
            `${exporterFile}: reads credentials/secrets`,
            `${imp.from}: imports from ${exporterFile} and makes network calls`,
          ],
        });
      }

      // Chain: File A reads credentials → File B encodes → File C sends
      if (exporterCaps.readsCredentials && importerCaps.encodesData) {
        // Check if importer also sends or if another file imports from importer
        const downstream = this.imports.filter(i => 
          i.isRelative && this._resolveRelative(i.from, i.to) === imp.from
        );
        for (const ds of downstream) {
          const dsCaps = fileCapabilities.get(ds.from);
          if (dsCaps?.makesNetworkCalls) {
            chains.push({
              description: 'Three-stage exfiltration: read → encode → send',
              severity: 'critical',
              files: [exporterFile, imp.from, ds.from],
              steps: [
                `${exporterFile}: reads credentials`,
                `${imp.from}: encodes/transforms data`,
                `${ds.from}: sends over network`,
              ],
            });
          }
        }
      }

      // Chain: File A has exec capabilities → File B imports and also has network
      if (exporterCaps.executesCode && importerCaps.makesNetworkCalls) {
        chains.push({
          description: 'Code execution + network access across files',
          severity: 'high',
          files: [exporterFile, imp.from],
          steps: [
            `${exporterFile}: executes code`,
            `${imp.from}: imports and has network access`,
          ],
        });
      }
    }

    return chains;
  }

  /**
   * Resolve a relative import path
   */
  _resolveRelative(fromFile, toModule) {
    const fromDir = fromFile.includes('/') ? fromFile.split('/').slice(0, -1).join('/') : '';
    let resolved = toModule;

    // Remove leading ./
    if (resolved.startsWith('./')) resolved = resolved.slice(2);
    if (resolved.startsWith('../')) {
      // Simple parent resolution
      const parts = fromDir.split('/');
      parts.pop();
      resolved = resolved.slice(3);
      resolved = parts.length ? parts.join('/') + '/' + resolved : resolved;
    } else if (fromDir) {
      resolved = fromDir + '/' + resolved;
    }

    // Try common extensions
    for (const ext of ['.js', '.mjs', '.ts', '/index.js', '/index.ts', '']) {
      const candidate = resolved + ext;
      if (this.fileContents.has(candidate)) return candidate;
    }

    return resolved;
  }

  /**
   * Collect all code files in a directory
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

  async _readSafe(path) {
    try { return await readFile(path, 'utf-8'); }
    catch { return null; }
  }
}
