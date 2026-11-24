// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
// Mechanical layering guard modeled on Weftale's static dependency boundary tests.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import module from 'node:module';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { validateContractDecl } from '@loomward/shared';

const REPO_ROOT = path.resolve(import.meta.dirname, '../../..');
const NODE_BUILTINS = new Set(
  module.builtinModules.flatMap(name => [name, name.replace(/^node:/, ''), `node:${name.replace(/^node:/, '')}`]),
);

function walkSourceFiles(dir) {
  if (!fs.existsSync(dir)) return [];
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name === 'test' || entry.name === 'dist') continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walkSourceFiles(full));
    else if (/\.(?:mjs|cjs|js|ts|mts|cts)$/.test(entry.name)) out.push(full);
  }
  return out;
}

const REGEX_PRECEDING_KEYWORDS = new Set([
  'return', 'throw', 'case', 'delete', 'void', 'typeof', 'yield',
  'await', 'in', 'instanceof', 'new', 'else', 'do', 'of',
]);

/**
 * Lex JavaScript/TypeScript source into code tokens (excluding comments, regexes,
 * and template/string internals so string-embedded comments cannot spoof stripping)
 * plus a comment-stripped mirror preserving quoted literals.
 */
function scanJsSource(source) {
  const tokens = [];
  const codeChunks = [];
  const len = source.length;
  let i = 0;
  let regexAllowed = true;
  const braceStack = []; // tracks template `${ ... }` interpolation nesting

  const readString = quote => {
    let val = '';
    const start = i++;
    while (i < len) {
      const ch = source[i++];
      if (ch === '\\') {
        if (i < len) val += source[i++];
        continue;
      }
      if (ch === quote) break;
      val += ch;
    }
    codeChunks.push(source.slice(start, i));
    tokens.push({ kind: 'string', value: val });
    regexAllowed = false;
  };

  const readRegex = () => {
    const start = i++;
    let inClass = false;
    while (i < len) {
      const ch = source[i++];
      if (ch === '\\') {
        if (i < len) i++;
        continue;
      }
      if (ch === '[') { inClass = true; continue; }
      if (ch === ']' && inClass) { inClass = false; continue; }
      if (ch === '/' && !inClass) break;
      if (ch === '\n' || ch === '\r') break;
    }
    while (i < len && /[a-z]/i.test(source[i])) i++;
    codeChunks.push(' /re/ ');
    tokens.push({ kind: 'regex', value: source.slice(start, i) });
    regexAllowed = false;
  };

  const readTemplateSegment = (isStart) => {
    let val = '';
    const start = i;
    if (isStart) i++; // skip opening `
    let closedCleanly = false;
    let interpolated = false;
    while (i < len) {
      const ch = source[i++];
      if (ch === '\\') {
        if (i < len) val += source[i++];
        continue;
      }
      if (ch === '`') {
        closedCleanly = true;
        break;
      }
      if (ch === '$' && source[i] === '{') {
        i++; // skip {
        interpolated = true;
        braceStack.push({ type: 'template', depth: 1 });
        regexAllowed = true;
        break;
      }
      val += ch;
    }
    codeChunks.push(source.slice(start, i));
    if (isStart && closedCleanly) {
      tokens.push({ kind: 'template', value: val });
      regexAllowed = false;
    } else if (interpolated) {
      tokens.push({ kind: 'template_part', value: val });
    } else {
      regexAllowed = false;
    }
  };

  while (i < len) {
    const ch = source[i];
    if (ch === '/' && source[i + 1] === '/') {
      i += 2;
      while (i < len && source[i] !== '\n' && source[i] !== '\r') i++;
      codeChunks.push(' ');
      continue;
    }
    if (ch === '/' && source[i + 1] === '*') {
      const start = i;
      i += 2;
      while (i < len && !(source[i] === '*' && source[i + 1] === '/')) {
        if (source[i] === '\n') codeChunks.push('\n');
        i++;
      }
      if (i < len) i += 2;
      codeChunks.push(' ');
      if (start >= 0) continue;
    }
    if (ch === '\'' || ch === '"') {
      readString(ch);
      continue;
    }
    if (ch === '`') {
      readTemplateSegment(true);
      continue;
    }
    if (ch === '/' && regexAllowed) {
      readRegex();
      continue;
    }
    if (/[a-zA-Z_$]/.test(ch)) {
      const start = i;
      i++;
      while (i < len && /[a-zA-Z0-9_$]/.test(source[i])) i++;
      const word = source.slice(start, i);
      codeChunks.push(word);
      tokens.push({ kind: 'ident', value: word });
      regexAllowed = REGEX_PRECEDING_KEYWORDS.has(word);
      continue;
    }
    if (/[0-9]/.test(ch)) {
      const start = i;
      while (i < len && /[0-9a-fA-FxXoObBn._]/.test(source[i])) i++;
      const num = source.slice(start, i);
      codeChunks.push(num);
      tokens.push({ kind: 'number', value: num });
      regexAllowed = false;
      continue;
    }
    if (/\s/.test(ch)) {
      codeChunks.push(ch);
      i++;
      continue;
    }
    if (ch === '{') {
      const top = braceStack[braceStack.length - 1];
      if (top) top.depth++;
      else braceStack.push({ type: 'block', depth: 1 });
    } else if (ch === '}') {
      const top = braceStack[braceStack.length - 1];
      if (top) {
        top.depth--;
        if (top.depth === 0) {
          braceStack.pop();
          if (top.type === 'template') {
            codeChunks.push('}');
            tokens.push({ kind: 'punct', value: '}' });
            i++;
            readTemplateSegment(false);
            continue;
          }
        }
      }
    }
    codeChunks.push(ch);
    if (ch === '=' && source[i + 1] === '>') {
      tokens.push({ kind: 'punct', value: '=>' });
      codeChunks.push('>');
      i += 2;
      regexAllowed = true;
      continue;
    }
    tokens.push({ kind: 'punct', value: ch });
    regexAllowed = '([{,;?:!~+-*%&|^<>=/'.includes(ch);
    i++;
  }
  return { code: codeChunks.join(''), tokens };
}

function stripJsComments(source) {
  return scanJsSource(source).code;
}

function parseImportSpecifiersFromSource(source) {
  const { tokens } = scanJsSource(source);
  const specs = [];
  for (let i = 0; i < tokens.length; i++) {
    const tok = tokens[i];
    const prev = i > 0 ? tokens[i - 1] : null;
    if (tok.kind !== 'ident') continue;

    if (tok.value === 'import' && !(prev?.kind === 'punct' && prev.value === '.')) {
      const next = tokens[i + 1];
      if (!next) continue;
      if (next.kind === 'string') {
        specs.push({ spec: next.value, typeOnly: false });
        continue;
      }
      if (next.kind === 'punct' && next.value === '(') {
        const arg = tokens[i + 2];
        const close = tokens[i + 3];
        if ((arg?.kind === 'string' || arg?.kind === 'template') && close?.kind === 'punct' && close.value === ')') {
          specs.push({ spec: arg.value, typeOnly: false });
        }
        continue;
      }
      if (next.kind === 'punct' && next.value === '.') continue; // import.meta
      const isTypeImport = next.kind === 'ident' && next.value === 'type'
        && !(tokens[i + 2]?.kind === 'ident' && tokens[i + 2].value === 'from')
        && !(tokens[i + 2]?.kind === 'punct' && (tokens[i + 2].value === ',' || tokens[i + 2].value === '.'));
      let j = i + 1;
      let braceDepth = 0;
      while (j < tokens.length) {
        const cur = tokens[j];
        if (cur.kind === 'punct' && cur.value === '{') braceDepth++;
        else if (cur.kind === 'punct' && cur.value === '}') {
          if (braceDepth === 0) break;
          braceDepth--;
        } else if (braceDepth === 0 && cur.kind === 'punct' && cur.value === ';') {
          break;
        } else if (braceDepth === 0 && cur.kind === 'ident' && cur.value === 'from' && tokens[j + 1]?.kind === 'string') {
          specs.push({ spec: tokens[j + 1].value, typeOnly: isTypeImport });
          i = j + 1;
          break;
        }
        j++;
      }
      continue;
    }

    if (tok.value === 'export' && !(prev?.kind === 'punct' && prev.value === '.')) {
      const next = tokens[i + 1];
      if (!next) continue;
      const isReexportHead =
        (next.kind === 'punct' && (next.value === '*' || next.value === '{')) ||
        (next.kind === 'ident' && next.value === 'type'
          && tokens[i + 2]?.kind === 'punct' && (tokens[i + 2].value === '*' || tokens[i + 2].value === '{'));
      if (!isReexportHead) continue;
      let j = i + 1;
      let braceDepth = 0;
      while (j < tokens.length) {
        const cur = tokens[j];
        if (cur.kind === 'punct' && cur.value === '{') braceDepth++;
        else if (cur.kind === 'punct' && cur.value === '}') {
          if (braceDepth === 0) break;
          braceDepth--;
        } else if (braceDepth === 0 && cur.kind === 'punct' && cur.value === ';') {
          break;
        } else if (braceDepth === 0 && cur.kind === 'ident' && cur.value === 'from' && tokens[j + 1]?.kind === 'string') {
          specs.push({ spec: tokens[j + 1].value, typeOnly: next.kind === 'ident' && next.value === 'type' });
          i = j + 1;
          break;
        }
        j++;
      }
      continue;
    }

    if ((tok.value === 'require' || tok.value === 'getBuiltinModule')
      && tokens[i + 1]?.kind === 'punct' && tokens[i + 1].value === '('
      && (tokens[i + 2]?.kind === 'string' || tokens[i + 2]?.kind === 'template')
      && tokens[i + 3]?.kind === 'punct' && tokens[i + 3].value === ')') {
      const rawSpec = tokens[i + 2].value;
      specs.push({
        spec: tok.value === 'getBuiltinModule' ? `node:${rawSpec.replace(/^node:/, '')}` : rawSpec,
        typeOnly: false,
      });
    }
  }
  return specs;
}

function parseImportSpecifiers(filePath) {
  return parseImportSpecifiersFromSource(fs.readFileSync(filePath, 'utf8'));
}

function rel(filePath) {
  return path.relative(REPO_ROOT, filePath).split(path.sep).join('/');
}

test('layering: @loomward/shared has zero Node/host/cordis/kernel/plugin imports', () => {
  const sharedSrcDir = path.join(REPO_ROOT, 'packages/shared/src');
  const sharedFiles = walkSourceFiles(sharedSrcDir);
  assert.ok(sharedFiles.length > 0);
  const violations = [];
  for (const file of sharedFiles) {
    const raw = stripJsComments(fs.readFileSync(file, 'utf8'));
    if (/\bprocess\.getBuiltinModule\b|\bcreateRequire\b/.test(raw)) {
      violations.push(`${rel(file)} -> uses dynamic Node builtin loader`);
    }
    for (const imp of parseImportSpecifiers(file)) {
      const spec = imp.spec;
      if (NODE_BUILTINS.has(spec) || spec.startsWith('node:')) {
        violations.push(`${rel(file)} -> ${spec} (Node builtin forbidden in @loomward/shared)`);
        continue;
      }
      if (spec.startsWith('.')) {
        const resolved = path.resolve(path.dirname(file), spec);
        const relToShared = path.relative(sharedSrcDir, resolved);
        if (relToShared.startsWith('..') || path.isAbsolute(relToShared)) {
          violations.push(`${rel(file)} -> ${spec} (exits packages/shared/src)`);
        }
        continue;
      }
      if (spec !== '@loomward/shared') {
        violations.push(`${rel(file)} -> ${spec} (external dependency forbidden in @loomward/shared)`);
      }
    }
  }
  assert.deepEqual(violations, []);
});

test('layering: non-kernel packages and plugins never import cordis at runtime or cross-import sibling packages', () => {
  const packagesDir = path.join(REPO_ROOT, 'packages');
  const pluginsDir = path.join(REPO_ROOT, 'plugins');
  const violations = [];

  for (const [groupName, groupDir] of [['packages', packagesDir], ['plugins', pluginsDir]]) {
    if (!fs.existsSync(groupDir)) continue;
    for (const entry of fs.readdirSync(groupDir, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue;
      const ownName = entry.name;
      const pkgJsonPath = path.join(groupDir, ownName, 'package.json');
      if (fs.existsSync(pkgJsonPath)) {
        const pkgJson = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
        const deps = { ...pkgJson.dependencies, ...pkgJson.optionalDependencies };
        if (!(groupName === 'packages' && ownName === 'kernel') && Object.hasOwn(deps, 'cordis')) {
          violations.push(`${rel(pkgJsonPath)} -> dependency on cordis is restricted to @loomward/kernel`);
        }
        if (groupName === 'plugins') {
          for (const depName of Object.keys(deps)) {
            if (depName.startsWith('@loomward/') && depName !== '@loomward/shared') {
              violations.push(`${rel(pkgJsonPath)} -> plugin cannot depend on ${depName}`);
            }
          }
        }
      }
      const srcDir = path.join(groupDir, ownName, 'src');
      for (const file of walkSourceFiles(srcDir)) {
        for (const imp of parseImportSpecifiers(file)) {
          if (imp.typeOnly) continue;
          if (!(groupName === 'packages' && ownName === 'kernel') && /^cordis(?:\/|$)/.test(imp.spec)) {
            violations.push(`${rel(file)} -> ${imp.spec} (only @loomward/kernel may import cordis)`);
          }
          if (imp.spec.startsWith('.')) {
            const target = rel(path.resolve(path.dirname(file), imp.spec));
            const parts = target.split('/');
            if ((parts[0] === 'packages' || parts[0] === 'plugins') && (parts[0] !== groupName || parts[1] !== ownName)) {
              violations.push(`${rel(file)} -> ${imp.spec} (cross-package relative import)`);
            }
            if (groupName === 'plugins' && ownName !== 'mcp-hub' && parts[0] !== 'plugins') {
              violations.push(`${rel(file)} -> ${imp.spec} (plugin relative import outside plugin boundary)`);
            }
            if (groupName === 'packages' && ['shared', 'kernel', 'cloud-relay'].includes(ownName) && parts[0] !== 'packages') {
              violations.push(`${rel(file)} -> ${imp.spec} (core package relative import outside packages/)`);
            }
          }
          if (groupName === 'plugins') {
            if (
              /^@loomward\//.test(imp.spec)
              && imp.spec !== '@loomward/shared'
              && imp.spec !== `@loomward/plugin-${ownName}`
            ) {
              violations.push(`${rel(file)} -> ${imp.spec} (plugins may only import @loomward/shared)`);
            }
          }
        }
      }
    }
  }
  assert.deepEqual(violations, []);
});

test('layering: every workspace root package and extension plugin declares a valid contract', async () => {
  const rootsDir = path.join(REPO_ROOT, 'packages');
  const pluginsDir = path.join(REPO_ROOT, 'plugins');
  const checked = [];

  for (const [groupName, groupDir] of [['packages', rootsDir], ['plugins', pluginsDir]]) {
    if (!fs.existsSync(groupDir)) continue;
    for (const entry of fs.readdirSync(groupDir, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue;
      if (groupName === 'packages' && (entry.name === 'shared' || entry.name === 'kernel')) continue;
      const contractPath = path.join(groupDir, entry.name, 'src/contract.mjs');
      assert.equal(fs.existsSync(contractPath), true, `Missing contract: ${rel(contractPath)}`);
      const mod = await import(pathToFileURL(contractPath).href);
      const decl = validateContractDecl(mod.contract);
      if (groupName === 'plugins') {
        assert.equal(decl.kind, 'extension-plugin');
        assert.equal(decl.executionBoundary, 'out-of-process', `Plugin ${decl.id} must declare out-of-process executionBoundary`);
      } else {
        assert.equal(decl.kind, 'root-plugin');
      }
      checked.push(decl.id);
    }
  }
  assert.ok(checked.length >= 8, `Expected at least 8 declared packages/plugins, got ${checked.length}`);
});

test('layering scanner: blocks string-comment, regex-slash, zero-space import, and dynamic loader bypasses without string false positives', () => {
  const bypassSource = [
    'const s = "/*";',
    'import{readFile}from\'node:fs/promises\';',
    'const e = "*/";',
    'const re = /https:\\/\\/example.test/; import\'node:path\';',
    'export*from"node:crypto";',
    'const loader = process.getBuiltinModule("os");',
  ].join('\n');
  const specs = parseImportSpecifiersFromSource(bypassSource).map(x => x.spec);
  assert.deepEqual(specs, ['node:fs/promises', 'node:path', 'node:crypto', 'node:os']);
  const stripped = stripJsComments(bypassSource);
  assert.match(stripped, /\bprocess\.getBuiltinModule\b/);

  const benignString = [
    'const doc = "import fs from \'node:fs\';";',
    'const tmpl = `/* ${1 + 2} */ export * from "node:child_process"`;',
    '// import secret from "node:net";',
    '/* export * from "node:http"; */',
  ].join('\n');
  assert.deepEqual(parseImportSpecifiersFromSource(benignString), []);
});
