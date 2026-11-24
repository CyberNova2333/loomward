// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
// Mechanical layering guard modeled on Weftale's static dependency boundary tests.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
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
  'await', 'in', 'instanceof', 'new', 'else', 'do',
]);
const EXPR_PREFIX_PUNCT = new Set([
  '(', '[', '=', ',', '?', ':', '!', '~', '+', '-', '*', '%', '&', '|', '^', '<', '>', '/', '=>', '??', '??=',
]);
const EXPR_PREFIX_KEYWORDS = new Set([
  'return', 'throw', 'case', 'delete', 'void', 'typeof', 'yield',
  'await', 'in', 'instanceof', 'new',
]);
const NO_LT_EXPR_PREFIX_KEYWORDS = new Set(['return', 'throw', 'yield']);
const NON_FOR_OF_PREV_KEYWORDS = new Set([
  'var', 'let', 'const', 'typeof', 'void', 'delete', 'await',
  'yield', 'new', 'in', 'instanceof', 'return', 'throw', 'case', 'else',
  'do', 'class', 'function', 'async',
]);
const STATEMENT_PAREN_KEYWORDS = new Set(['if', 'while', 'for', 'with']);
const BLOCK_PAREN_KEYWORDS = new Set(['if', 'while', 'for', 'with', 'switch', 'catch']);
const BLOCK_BEFORE_BRACE_KEYWORDS = new Set(['else', 'do', 'try', 'finally', 'catch']);
const DYNAMIC_BUILTIN_LOADER_RE = /\bprocess\s*(?:\?\.|\.)\s*getBuiltinModule\b|\bcreateRequire\b/;
const IDENT_START_RE = /^[\p{ID_Start}$_]$/u;
const IDENT_CONTINUE_RE = /^[\p{ID_Continue}$\u200c\u200d]$/u;

function isLineTerminator(ch) {
  return ch === '\n' || ch === '\r' || ch === '\u2028' || ch === '\u2029';
}

const SINGLE_CHAR_ESCAPES = new Map([
  ['n', '\n'],
  ['r', '\r'],
  ['t', '\t'],
  ['b', '\b'],
  ['f', '\f'],
  ['v', '\v'],
  ['\'', '\''],
  ['"', '"'],
  ['`', '`'],
  ['\\', '\\'],
]);

function decodeJsEscapeAt(source, pos) {
  const len = source.length;
  if (pos >= len) return { value: '', nextIndex: pos };
  const esc = source[pos];
  const next = pos + 1;

  if (esc === '\n' || esc === '\u2028' || esc === '\u2029') {
    return { value: '', nextIndex: next };
  }
  if (esc === '\r') {
    return { value: '', nextIndex: source[next] === '\n' ? next + 1 : next };
  }
  if (SINGLE_CHAR_ESCAPES.has(esc)) {
    return { value: SINGLE_CHAR_ESCAPES.get(esc), nextIndex: next };
  }
  if (esc === '0') {
    if (next >= len || !/[0-9]/.test(source[next])) {
      return { value: '\0', nextIndex: next };
    }
    return { value: '0', nextIndex: next };
  }
  if (esc === 'x') {
    if (next + 2 <= len && /^[0-9a-fA-F]{2}$/.test(source.slice(next, next + 2))) {
      return {
        value: String.fromCharCode(parseInt(source.slice(next, next + 2), 16)),
        nextIndex: next + 2,
      };
    }
    return { value: 'x', nextIndex: next };
  }
  if (esc === 'u') {
    if (source[next] === '{') {
      let k = next + 1;
      while (k < len && /[0-9a-fA-F]/.test(source[k])) k++;
      if (k > next + 1 && k < len && source[k] === '}') {
        const cp = parseInt(source.slice(next + 1, k), 16);
        if (cp <= 0x10ffff) {
          return { value: String.fromCodePoint(cp), nextIndex: k + 1 };
        }
      }
      return { value: 'u', nextIndex: next };
    }
    if (next + 4 <= len && /^[0-9a-fA-F]{4}$/.test(source.slice(next, next + 4))) {
      return {
        value: String.fromCharCode(parseInt(source.slice(next, next + 4), 16)),
        nextIndex: next + 4,
      };
    }
    return { value: 'u', nextIndex: next };
  }
  return { value: esc, nextIndex: next };
}

function isIdentStartChar(ch) {
  const code = ch.charCodeAt(0);
  if (ch.length === 1 && code < 128) {
    return (code >= 65 && code <= 90) || (code >= 97 && code <= 122) || code === 95 || code === 36;
  }
  return IDENT_START_RE.test(ch);
}

function isIdentContinueChar(ch) {
  const code = ch.charCodeAt(0);
  if (ch.length === 1 && code < 128) {
    return (code >= 65 && code <= 90) || (code >= 97 && code <= 122) || (code >= 48 && code <= 57) || code === 95 || code === 36;
  }
  return IDENT_CONTINUE_RE.test(ch);
}

function readIdentCharAt(source, pos, isStart) {
  const len = source.length;
  if (pos >= len) return null;
  if (source[pos] === '\\' && source[pos + 1] === 'u') {
    const next = pos + 2;
    let cp = -1;
    let nextIndex = -1;
    if (source[next] === '{') {
      let k = next + 1;
      while (k < len && /[0-9a-fA-F]/.test(source[k])) k++;
      if (k > next + 1 && k < len && source[k] === '}') {
        const parsed = parseInt(source.slice(next + 1, k), 16);
        if (parsed <= 0x10ffff) {
          cp = parsed;
          nextIndex = k + 1;
        }
      }
    } else if (next + 4 <= len && /^[0-9a-fA-F]{4}$/.test(source.slice(next, next + 4))) {
      cp = parseInt(source.slice(next, next + 4), 16);
      nextIndex = next + 4;
    }
    if (cp >= 0) {
      const ch = String.fromCodePoint(cp);
      if (isStart ? isIdentStartChar(ch) : isIdentContinueChar(ch)) {
        return { ch, nextIndex, escaped: true };
      }
    }
    return null;
  }
  const cp = source.codePointAt(pos);
  const ch = String.fromCodePoint(cp);
  if (isStart ? isIdentStartChar(ch) : isIdentContinueChar(ch)) {
    return { ch, nextIndex: pos + ch.length, escaped: false };
  }
  return null;
}

function readIdentifierAt(source, startPos) {
  const first = readIdentCharAt(source, startPos, true);
  if (!first) return null;
  let value = first.ch;
  let escaped = first.escaped;
  let pos = first.nextIndex;
  while (pos < source.length) {
    const next = readIdentCharAt(source, pos, false);
    if (!next) break;
    value += next.ch;
    if (next.escaped) escaped = true;
    pos = next.nextIndex;
  }
  return { value, nextIndex: pos, escaped };
}

function isMemberPunct(tok) {
  return tok?.kind === 'punct' && (tok.value === '.' || tok.value === '?.');
}

function isExprContextAt(tokens, len, lastExprColonIdx, { allowExportDefaultExpr = false, allowExtendsExpr = false } = {}) {
  if (len <= 0) return false;
  const t1 = tokens[len - 1];
  const t2 = len >= 2 ? tokens[len - 2] : null;
  if (t1.kind === 'template_part') return true;
  if (t1.kind === 'punct') {
    if (t1.value === ':') return lastExprColonIdx === len - 1;
    return EXPR_PREFIX_PUNCT.has(t1.value);
  }
  if (t1.kind === 'ident') {
    if (isMemberPunct(t2) || t1.escaped) return false;
    if (t1.ltAfter && NO_LT_EXPR_PREFIX_KEYWORDS.has(t1.value)) return false;
    if (EXPR_PREFIX_KEYWORDS.has(t1.value)) return true;
    if (t1.value === 'of' && t1.isForOf) return true;
    if (allowExportDefaultExpr && t1.value === 'default' && t2?.kind === 'ident' && !t2.escaped && t2.value === 'export') {
      return true;
    }
    if (allowExtendsExpr && t1.value === 'extends') {
      return true;
    }
  }
  return false;
}

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
  const braceStack = []; // tracks `{ ... }` (template interpolations, blocks, and object/expr literals)
  const parenStack = []; // tracks `( ... )` statement condition headers vs expressions
  const ternaryStack = []; // tracks active ternary `?` nesting depth
  const classStack = []; // tracks pending `class` headers (supports nested `class` inside `extends`)
  let bracketDepth = 0;
  let pendingFn = null;
  let lastParen = null;
  let lastExprColonIdx = -1;
  let pendingJumpLabel = false;
  let pendingModuleDecl = null;
  let sawLineTerminatorSincePrevToken = false;

  const isTopLevel = () => braceStack.length === 0 && parenStack.length === 0 && bracketDepth === 0;
  const markLineTerminator = () => {
    pendingJumpLabel = false;
    sawLineTerminatorSincePrevToken = true;
    if (tokens.length > 0) tokens[tokens.length - 1].ltAfter = true;
  };
  const pushToken = token => {
    tokens.push(token);
    sawLineTerminatorSincePrevToken = false;
  };

  const clearStackAtCurrentDepth = stack => {
    const b = braceStack.length;
    const p = parenStack.length;
    const k = bracketDepth;
    while (stack.length > 0) {
      const top = stack[stack.length - 1];
      if (top.b === b && top.p === p && top.k === k) stack.pop();
      else break;
    }
  };

  const pruneStacksToCurrentDepth = () => {
    const b = braceStack.length;
    const p = parenStack.length;
    const k = bracketDepth;
    for (const stack of [ternaryStack, classStack]) {
      while (stack.length > 0) {
        const top = stack[stack.length - 1];
        if (top.b > b || top.p > p || top.k > k) stack.pop();
        else break;
      }
    }
    if (pendingFn && (pendingFn.b > b || pendingFn.p > p || pendingFn.k > k)) {
      pendingFn = null;
    }
  };

  const readString = quote => {
    let val = '';
    const start = i++;
    while (i < len) {
      const ch = source[i++];
      if (ch === '\\') {
        const decoded = decodeJsEscapeAt(source, i);
        val += decoded.value;
        i = decoded.nextIndex;
        continue;
      }
      if (ch === quote) break;
      val += ch;
    }
    const prev = tokens.length > 0 ? tokens[tokens.length - 1] : null;
    const prev2 = tokens.length > 1 ? tokens[tokens.length - 2] : null;
    codeChunks.push(source.slice(start, i));
    pushToken({ kind: 'string', value: val });
    pendingFn = null;
    pendingJumpLabel = false;
    const completesModuleDecl =
      isTopLevel() && (pendingModuleDecl === 'import-head' || pendingModuleDecl === 'module-from');
    // Retain `export * as "alias"` clause state until `from "<specifier>"` completes.
    const keepsExportAlias =
      isTopLevel()
      && pendingModuleDecl === 'export-clause'
      && prev?.kind === 'ident'
      && !prev.escaped
      && prev.value === 'as'
      && prev2?.kind === 'punct'
      && prev2.value === '*';
    if (isTopLevel() && !keepsExportAlias) pendingModuleDecl = null;
    regexAllowed = completesModuleDecl;
  };

  const readRegex = () => {
    const start = i++;
    let inClass = false;
    let closed = false;
    while (i < len) {
      const ch = source[i++];
      if (ch === '\\') {
        if (i < len && !isLineTerminator(source[i])) i++;
        continue;
      }
      if (ch === '[') { inClass = true; continue; }
      if (ch === ']' && inClass) { inClass = false; continue; }
      if (ch === '/' && !inClass) { closed = true; break; }
      if (isLineTerminator(ch)) break;
    }
    if (closed) {
      while (i < len && /[a-z]/i.test(source[i])) i++;
    }
    codeChunks.push(' /re/ ');
    pushToken({ kind: 'regex', value: source.slice(start, i) });
    pendingFn = null;
    pendingJumpLabel = false;
    if (isTopLevel()) pendingModuleDecl = null;
    regexAllowed = false;
  };

  const readTemplateSegment = (isStart) => {
    let val = '';
    const start = i;
    const atTopLevel = isTopLevel();
    if (isStart) i++; // skip opening `
    let closedCleanly = false;
    let interpolated = false;
    while (i < len) {
      const ch = source[i++];
      if (ch === '\\') {
        const decoded = decodeJsEscapeAt(source, i);
        val += decoded.value;
        i = decoded.nextIndex;
        continue;
      }
      if (ch === '`') {
        closedCleanly = true;
        break;
      }
      if (ch === '$' && source[i] === '{') {
        i++; // skip {
        interpolated = true;
        braceStack.push({ type: 'template', regexAfter: false });
        regexAllowed = true;
        break;
      }
      if (ch === '\r') {
        if (i < len && source[i] === '\n') i++;
        val += '\n';
        continue;
      }
      val += ch;
    }
    codeChunks.push(source.slice(start, i));
    pendingFn = null;
    pendingJumpLabel = false;
    if (atTopLevel) pendingModuleDecl = null;
    if (isStart && closedCleanly) {
      pushToken({ kind: 'template', value: val });
      regexAllowed = false;
    } else if (interpolated) {
      pushToken({ kind: 'template_part', value: val });
    } else {
      sawLineTerminatorSincePrevToken = false;
      regexAllowed = false;
    }
  };

  if (source.startsWith('#!')) {
    i = 2;
    while (i < len && !isLineTerminator(source[i])) i++;
    codeChunks.push(' ');
  }

  while (i < len) {
    const ch = source[i];
    if (ch === '/' && source[i + 1] === '/') {
      i += 2;
      while (i < len && !isLineTerminator(source[i])) i++;
      markLineTerminator();
      codeChunks.push(' ');
      continue;
    }
    if (ch === '/' && source[i + 1] === '*') {
      i += 2;
      while (i < len && !(source[i] === '*' && source[i + 1] === '/')) {
        if (isLineTerminator(source[i])) {
          markLineTerminator();
          if (source[i] !== '\r' || source[i + 1] !== '\n') codeChunks.push('\n');
        }
        i++;
      }
      if (i < len) i += 2;
      codeChunks.push(' ');
      continue;
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
    if (ch === '#') {
      const priv = readIdentifierAt(source, i + 1);
      if (priv) {
        const word = `#${priv.value}`;
        codeChunks.push(word);
        pushToken({ kind: 'private_ident', value: word });
        i = priv.nextIndex;
        pendingFn = null;
        pendingJumpLabel = false;
        if (isTopLevel()) pendingModuleDecl = null;
        regexAllowed = false;
        continue;
      }
    }
    const ident = readIdentifierAt(source, i);
    if (ident) {
      const word = ident.value;
      i = ident.nextIndex;
      const prev = tokens.length > 0 ? tokens[tokens.length - 1] : null;
      const prev2 = tokens.length > 1 ? tokens[tokens.length - 2] : null;
      const isPropName = isMemberPunct(prev);
      const isKeywordCandidate = !isPropName && !ident.escaped;
      const isJumpLabel = pendingJumpLabel && !isPropName;
      pendingJumpLabel = false;

      if (isJumpLabel && (ident.escaped || (word !== 'break' && word !== 'continue' && word !== 'debugger' && word !== 'import' && word !== 'export'))) {
        codeChunks.push(word);
        const token = { kind: 'ident', value: word };
        if (ident.escaped) token.escaped = true;
        pushToken(token);
        pendingFn = null;
        pendingModuleDecl = null;
        regexAllowed = true;
        continue;
      }

      if (isKeywordCandidate && word === 'function') {
        const prefixLen = !sawLineTerminatorSincePrevToken
          && prev?.kind === 'ident'
          && !prev.escaped
          && prev.value === 'async'
          && !isMemberPunct(prev2)
          ? tokens.length - 1
          : tokens.length;
        pendingFn = {
          isExpr: isExprContextAt(tokens, prefixLen, lastExprColonIdx, { allowExtendsExpr: true }),
          b: braceStack.length,
          p: parenStack.length,
          k: bracketDepth,
          sawStar: false,
          sawName: false,
        };
      } else if (isKeywordCandidate && word === 'class') {
        classStack.push({
          isExpr: isExprContextAt(tokens, tokens.length, lastExprColonIdx, { allowExtendsExpr: true }),
          b: braceStack.length,
          p: parenStack.length,
          k: bracketDepth,
        });
        pendingFn = null;
      } else if (pendingFn) {
        if (!pendingFn.sawName && pendingFn.b === braceStack.length && pendingFn.p === parenStack.length) {
          pendingFn.sawName = true;
        } else {
          pendingFn = null;
        }
      }

      if (isTopLevel()) {
        if (pendingModuleDecl === null) {
          if (isKeywordCandidate && word === 'import') pendingModuleDecl = 'import-head';
          else if (isKeywordCandidate && word === 'export') pendingModuleDecl = 'export-head';
        } else if (pendingModuleDecl === 'import-head') {
          pendingModuleDecl = isPropName ? null : 'import-clause';
        } else if (pendingModuleDecl === 'import-clause') {
          if (isKeywordCandidate && word === 'from' && !(prev?.kind === 'ident' && !prev.escaped && prev.value === 'as')) {
            pendingModuleDecl = 'module-from';
          } else if (
            isPropName
            || !(
              (!ident.escaped && word === 'as')
              || (prev?.kind === 'ident' && !prev.escaped && (prev.value === 'as' || prev.value === 'type' || prev.value === 'import'))
              || (prev?.kind === 'punct' && prev.value === ',')
            )
          ) {
            pendingModuleDecl = isKeywordCandidate && word === 'import'
              ? 'import-head'
              : (isKeywordCandidate && word === 'export' ? 'export-head' : null);
          }
        } else if (pendingModuleDecl === 'export-head') {
          if (isKeywordCandidate && word === 'type') {
            pendingModuleDecl = 'export-type-head';
          } else {
            pendingModuleDecl = isKeywordCandidate && word === 'import'
              ? 'import-head'
              : (isKeywordCandidate && word === 'export' ? 'export-head' : null);
          }
        } else if (pendingModuleDecl === 'export-type-head') {
          pendingModuleDecl = isKeywordCandidate && word === 'import'
            ? 'import-head'
            : (isKeywordCandidate && word === 'export' ? 'export-head' : null);
        } else if (pendingModuleDecl === 'export-clause') {
          if (isKeywordCandidate && word === 'from' && !(prev?.kind === 'ident' && !prev.escaped && prev.value === 'as')) {
            pendingModuleDecl = 'module-from';
          } else if (
            isPropName
            || !((!ident.escaped && word === 'as') || (prev?.kind === 'ident' && !prev.escaped && prev.value === 'as'))
          ) {
            pendingModuleDecl = isKeywordCandidate && word === 'import'
              ? 'import-head'
              : (isKeywordCandidate && word === 'export' ? 'export-head' : null);
          }
        } else if (pendingModuleDecl === 'module-from') {
          pendingModuleDecl = isKeywordCandidate && word === 'import'
            ? 'import-head'
            : (isKeywordCandidate && word === 'export' ? 'export-head' : null);
        }
      }

      const topParen = parenStack[parenStack.length - 1];
      const inForHeaderTop = Boolean(
        topParen?.isForHeader
        && braceStack.length === topParen.forBraceDepth
        && bracketDepth === topParen.forBracketDepth
        && !topParen.forSawSemi
        && !topParen.forSawInOrOf,
      );
      let isForOf = false;
      if (isKeywordCandidate && inForHeaderTop) {
        if (word === 'in') {
          topParen.forSawInOrOf = true;
        } else if (word === 'of') {
          isForOf = Boolean(
            prev && (
              (prev.kind === 'punct' && (prev.value === ')' || prev.value === ']' || prev.value === '}'))
              || prev.kind === 'private_ident'
              || (prev.kind === 'ident' && (isMemberPunct(prev2) || prev.escaped || !NON_FOR_OF_PREV_KEYWORDS.has(prev.value)))
            ),
          );
          if (isForOf) topParen.forSawInOrOf = true;
        }
      }

      codeChunks.push(word);
      const token = { kind: 'ident', value: word };
      if (ident.escaped) token.escaped = true;
      if (isForOf) token.isForOf = true;
      pushToken(token);
      const isExportDefault = isKeywordCandidate && word === 'default' && prev?.kind === 'ident' && !prev.escaped && prev.value === 'export';
      const isJumpStmt = isKeywordCandidate && (word === 'break' || word === 'continue');
      if (isJumpStmt) pendingJumpLabel = true;
      const isDebuggerStmt = isKeywordCandidate && word === 'debugger';
      regexAllowed = isForOf || (isKeywordCandidate && (
        REGEX_PRECEDING_KEYWORDS.has(word) || isExportDefault || isJumpStmt || isDebuggerStmt
      ));
      continue;
    }
    if (/[0-9]/.test(ch)) {
      const start = i;
      while (i < len && /[0-9a-fA-FxXoObBn._]/.test(source[i])) i++;
      const num = source.slice(start, i);
      codeChunks.push(num);
      pushToken({ kind: 'number', value: num });
      pendingFn = null;
      pendingJumpLabel = false;
      if (isTopLevel()) pendingModuleDecl = null;
      regexAllowed = false;
      continue;
    }
    if (/\s/.test(ch)) {
      if (isLineTerminator(ch)) markLineTerminator();
      codeChunks.push(ch);
      i++;
      continue;
    }
    if ((ch === '+' && source[i + 1] === '+') || (ch === '-' && source[i + 1] === '-')) {
      const op = ch + ch;
      codeChunks.push(op);
      pushToken({ kind: 'punct', value: op });
      i += 2;
      pendingFn = null;
      pendingJumpLabel = false;
      if (isTopLevel()) pendingModuleDecl = null;
      regexAllowed = false;
      continue;
    }
    if (ch === '=' && source[i + 1] === '>') {
      codeChunks.push('=>');
      pushToken({ kind: 'punct', value: '=>' });
      i += 2;
      pendingFn = null;
      pendingJumpLabel = false;
      if (isTopLevel()) pendingModuleDecl = null;
      regexAllowed = true;
      continue;
    }
    if (ch === '?' && source[i + 1] === '.' && !/[0-9]/.test(source[i + 2] ?? '')) {
      codeChunks.push('?.');
      pushToken({ kind: 'punct', value: '?.' });
      i += 2;
      pendingFn = null;
      pendingJumpLabel = false;
      if (isTopLevel()) pendingModuleDecl = null;
      regexAllowed = false;
      continue;
    }
    if (ch === '?' && source[i + 1] === '?') {
      const op = source[i + 2] === '=' ? '??=' : '??';
      codeChunks.push(op);
      pushToken({ kind: 'punct', value: op });
      i += op.length;
      pendingFn = null;
      pendingJumpLabel = false;
      if (isTopLevel()) pendingModuleDecl = null;
      regexAllowed = true;
      continue;
    }
    if (ch === '(') {
      pendingJumpLabel = false;
      pendingModuleDecl = null;
      let entry;
      if (pendingFn && pendingFn.b === braceStack.length && pendingFn.p === parenStack.length && pendingFn.k === bracketDepth) {
        entry = { regexAfter: false, isBlockHeader: !pendingFn.isExpr, funcBodyIsExpr: pendingFn.isExpr, isFnParams: true };
        pendingFn = null;
      } else {
        const t1 = tokens.length > 0 ? tokens[tokens.length - 1] : null;
        const t2 = tokens.length > 1 ? tokens[tokens.length - 2] : null;
        const t3 = tokens.length > 2 ? tokens[tokens.length - 3] : null;
        const isForHeader =
          (t1?.kind === 'ident' && !t1.escaped && t1.value === 'for' && !isMemberPunct(t2))
          || (t1?.kind === 'ident' && !t1.escaped && t1.value === 'await'
            && t2?.kind === 'ident' && !t2.escaped && t2.value === 'for' && !isMemberPunct(t3));
        const isStmtCond =
          isForHeader
          || (t1?.kind === 'ident' && !t1.escaped && STATEMENT_PAREN_KEYWORDS.has(t1.value) && !isMemberPunct(t2));
        const isBlockHeader = isStmtCond
          || (t1?.kind === 'ident' && !t1.escaped && BLOCK_PAREN_KEYWORDS.has(t1.value) && !isMemberPunct(t2));
        entry = {
          regexAfter: isStmtCond,
          isBlockHeader,
          funcBodyIsExpr: false,
          isFnParams: false,
          isForHeader,
          forBraceDepth: braceStack.length,
          forBracketDepth: bracketDepth,
          forSawSemi: false,
          forSawInOrOf: false,
        };
      }
      parenStack.push(entry);
      codeChunks.push('(');
      pushToken({ kind: 'punct', value: '(' });
      i++;
      regexAllowed = true;
      continue;
    }
    if (ch === ')') {
      const popped = parenStack.pop();
      pruneStacksToCurrentDepth();
      pendingFn = null;
      pendingJumpLabel = false;
      if (isTopLevel()) pendingModuleDecl = null;
      const tokIdx = tokens.length;
      codeChunks.push(')');
      pushToken({ kind: 'punct', value: ')' });
      i++;
      lastParen = popped
        ? { tokIdx, isBlockHeader: popped.isBlockHeader, funcBodyIsExpr: popped.funcBodyIsExpr, isFnParams: popped.isFnParams }
        : null;
      regexAllowed = popped ? popped.regexAfter : false;
      continue;
    }
    if (ch === '{') {
      pendingFn = null;
      pendingJumpLabel = false;
      if (isTopLevel()) {
        if (pendingModuleDecl === 'import-head') pendingModuleDecl = 'import-clause';
        else if (pendingModuleDecl === 'export-head' || pendingModuleDecl === 'export-type-head') pendingModuleDecl = 'export-clause';
        else if (pendingModuleDecl === 'module-from') pendingModuleDecl = null;
      }
      let braceEntry;
      const t1 = tokens.length > 0 ? tokens[tokens.length - 1] : null;
      const t2 = tokens.length > 1 ? tokens[tokens.length - 2] : null;
      const topClass = classStack[classStack.length - 1];
      const isExtendsObjectStart = t1?.kind === 'ident' && !t1.escaped && t1.value === 'extends' && !isMemberPunct(t2);
      if (lastParen && lastParen.tokIdx === tokens.length - 1 && lastParen.isFnParams) {
        braceEntry = lastParen.funcBodyIsExpr
          ? { type: 'expr', regexAfter: false }
          : { type: 'block', regexAfter: true };
      } else if (
        !isExtendsObjectStart
        && topClass
        && topClass.b === braceStack.length
        && topClass.p === parenStack.length
        && topClass.k === bracketDepth
      ) {
        classStack.pop();
        braceEntry = { type: topClass.isExpr ? 'expr' : 'block', regexAfter: !topClass.isExpr };
      } else if (lastParen && lastParen.tokIdx === tokens.length - 1) {
        braceEntry = lastParen.funcBodyIsExpr
          ? { type: 'expr', regexAfter: false }
          : { type: 'block', regexAfter: true };
      } else if (t1?.kind === 'ident' && !t1.escaped && BLOCK_BEFORE_BRACE_KEYWORDS.has(t1.value) && !isMemberPunct(t2)) {
        braceEntry = { type: 'block', regexAfter: true };
      } else if (t1?.kind === 'punct' && t1.value === '=>') {
        braceEntry = { type: 'block', regexAfter: true };
      } else if (isExprContextAt(tokens, tokens.length, lastExprColonIdx, { allowExportDefaultExpr: true, allowExtendsExpr: true })) {
        braceEntry = { type: 'expr', regexAfter: false };
      } else {
        braceEntry = { type: 'block', regexAfter: true };
      }
      braceStack.push(braceEntry);
      codeChunks.push('{');
      pushToken({ kind: 'punct', value: '{' });
      i++;
      regexAllowed = true;
      continue;
    }
    if (ch === '}') {
      const popped = braceStack.pop();
      pruneStacksToCurrentDepth();
      pendingFn = null;
      pendingJumpLabel = false;
      if (!popped && isTopLevel()) pendingModuleDecl = null;
      codeChunks.push('}');
      pushToken({ kind: 'punct', value: '}' });
      i++;
      if (popped?.type === 'template') {
        readTemplateSegment(false);
        continue;
      }
      regexAllowed = popped ? popped.regexAfter : false;
      continue;
    }

    pendingJumpLabel = false;
    if (ch === '[') {
      bracketDepth++;
      pendingFn = null;
      pendingModuleDecl = null;
    } else if (ch === ']') {
      if (bracketDepth > 0) bracketDepth--;
      pruneStacksToCurrentDepth();
      pendingFn = null;
      if (isTopLevel()) pendingModuleDecl = null;
    } else if (ch === '?') {
      ternaryStack.push({ b: braceStack.length, p: parenStack.length, k: bracketDepth });
      pendingFn = null;
      if (isTopLevel()) pendingModuleDecl = null;
    } else if (ch === ':') {
      pendingFn = null;
      const top = ternaryStack[ternaryStack.length - 1];
      const matchesTernary = Boolean(top && top.b === braceStack.length && top.p === parenStack.length && top.k === bracketDepth);
      if (matchesTernary) ternaryStack.pop();
      if (matchesTernary || braceStack[braceStack.length - 1]?.type === 'expr') {
        lastExprColonIdx = tokens.length;
      }
      clearStackAtCurrentDepth(classStack);
      if (isTopLevel()) pendingModuleDecl = null;
    } else if (ch === '*') {
      if (pendingFn && !pendingFn.sawStar && !pendingFn.sawName && pendingFn.b === braceStack.length && pendingFn.p === parenStack.length) {
        pendingFn.sawStar = true;
      } else {
        pendingFn = null;
      }
      if (isTopLevel()) {
        if (pendingModuleDecl === 'import-head') pendingModuleDecl = 'import-clause';
        else if (pendingModuleDecl === 'export-head' || pendingModuleDecl === 'export-type-head') pendingModuleDecl = 'export-clause';
        else if (pendingModuleDecl !== 'import-clause' && pendingModuleDecl !== 'export-clause') pendingModuleDecl = null;
      }
    } else {
      pendingFn = null;
      if (ch === ';') {
        clearStackAtCurrentDepth(classStack);
        clearStackAtCurrentDepth(ternaryStack);
        const topParen = parenStack[parenStack.length - 1];
        if (
          topParen?.isForHeader
          && braceStack.length === topParen.forBraceDepth
          && bracketDepth === topParen.forBracketDepth
        ) {
          topParen.forSawSemi = true;
        }
      }
      if (isTopLevel() && !(ch === ',' && pendingModuleDecl === 'import-clause')) {
        pendingModuleDecl = null;
      }
    }

    codeChunks.push(ch);
    pushToken({ kind: 'punct', value: ch });
    regexAllowed = '([{,;?:!~+-*%&|^<>=/'.includes(ch);
    i++;
  }
  return { code: codeChunks.join(''), tokens };
}

function stripJsComments(source) {
  return scanJsSource(source).code;
}

function extractParenthesizedCallLiteralArg(tokens, openIdx) {
  if (tokens[openIdx]?.kind !== 'punct' || tokens[openIdx].value !== '(') return null;
  let depth = 0;
  let k = openIdx + 1;
  while (k < tokens.length && tokens[k].kind === 'punct' && tokens[k].value === '(') {
    depth++;
    k++;
  }
  const arg = tokens[k];
  if (!arg || (arg.kind !== 'string' && arg.kind !== 'template')) return null;
  k++;
  while (depth > 0) {
    if (k >= tokens.length || tokens[k].kind !== 'punct' || tokens[k].value !== ')') return null;
    depth--;
    k++;
  }
  const after = tokens[k];
  if (!after || after.kind !== 'punct' || (after.value !== ')' && after.value !== ',')) return null;
  return arg.value;
}

function parseImportSpecifiersFromSource(source) {
  const { tokens } = scanJsSource(source);
  const specs = [];
  for (let i = 0; i < tokens.length; i++) {
    const tok = tokens[i];
    const prev = i > 0 ? tokens[i - 1] : null;
    if (tok.kind !== 'ident') continue;

    if (tok.value === 'import' && !tok.escaped && !isMemberPunct(prev)) {
      const next = tokens[i + 1];
      if (!next) continue;
      if (next.kind === 'string') {
        specs.push({ spec: next.value, typeOnly: false });
        continue;
      }
      if (next.kind === 'punct' && next.value === '(') {
        const argSpec = extractParenthesizedCallLiteralArg(tokens, i + 1);
        if (argSpec !== null) {
          specs.push({ spec: argSpec, typeOnly: false });
        }
        continue;
      }
      if (isMemberPunct(next)) continue; // import.meta
      const isTypeImport = next.kind === 'ident' && !next.escaped && next.value === 'type'
        && !(tokens[i + 2]?.kind === 'ident' && !tokens[i + 2].escaped && tokens[i + 2].value === 'from')
        && !(tokens[i + 2]?.kind === 'punct' && (tokens[i + 2].value === ',' || isMemberPunct(tokens[i + 2])));
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
        } else if (braceDepth === 0 && cur.kind === 'ident' && !cur.escaped && cur.value === 'from' && tokens[j + 1]?.kind === 'string') {
          specs.push({ spec: tokens[j + 1].value, typeOnly: isTypeImport });
          i = j + 1;
          break;
        }
        j++;
      }
      continue;
    }

    if (tok.value === 'export' && !tok.escaped && !isMemberPunct(prev)) {
      const next = tokens[i + 1];
      if (!next) continue;
      const isReexportHead =
        (next.kind === 'punct' && (next.value === '*' || next.value === '{')) ||
        (next.kind === 'ident' && !next.escaped && next.value === 'type'
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
        } else if (braceDepth === 0 && cur.kind === 'ident' && !cur.escaped && cur.value === 'from' && tokens[j + 1]?.kind === 'string') {
          specs.push({ spec: tokens[j + 1].value, typeOnly: next.kind === 'ident' && !next.escaped && next.value === 'type' });
          i = j + 1;
          break;
        }
        j++;
      }
      continue;
    }

    if (tok.value === 'require' || tok.value === 'getBuiltinModule') {
      let openIdx = i + 1;
      if (tokens[openIdx]?.kind === 'punct' && tokens[openIdx].value === '?.') {
        openIdx++;
      }
      if (tokens[openIdx]?.kind === 'punct' && tokens[openIdx].value === '(') {
        const rawSpec = extractParenthesizedCallLiteralArg(tokens, openIdx);
        if (rawSpec !== null) {
          specs.push({
            spec: tok.value === 'getBuiltinModule' ? `node:${rawSpec.replace(/^node:/, '')}` : rawSpec,
            typeOnly: false,
          });
        }
      }
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

function assertValidEsm(src) {
  const res = spawnSync(process.execPath, ['--input-type=module', '--check'], { input: src, encoding: 'utf8' });
  assert.equal(res.status, 0, `Expected valid ESM for ${JSON.stringify(src)}: ${res.stderr}`);
}

test('layering: @loomward/shared has zero Node/host/cordis/kernel/plugin imports', () => {
  const sharedSrcDir = path.join(REPO_ROOT, 'packages/shared/src');
  const sharedFiles = walkSourceFiles(sharedSrcDir);
  assert.ok(sharedFiles.length > 0);
  const violations = [];
  for (const file of sharedFiles) {
    const raw = stripJsComments(fs.readFileSync(file, 'utf8'));
    if (DYNAMIC_BUILTIN_LOADER_RE.test(raw)) {
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

test('layering scanner: handles U+2028/U+2029 terminators, postfix ++/--, statement )/} regexes, and multi-arg loaders', () => {
  const specsOf = src => parseImportSpecifiersFromSource(src).map(x => x.spec);

  // 1. U+2028 / U+2029 line terminators in // comments and regex literals
  assert.deepEqual(specsOf('// comment\u2028import "node:fs";'), ['node:fs']);
  assert.deepEqual(specsOf('// comment\u2029export * from "node:path";'), ['node:path']);
  assert.deepEqual(specsOf('const r1 = /abc/\u2028import "node:crypto";'), ['node:crypto']);
  assert.deepEqual(specsOf('const r2 = /abc/\u2029process.getBuiltinModule("os");'), ['node:os']);
  assert.deepEqual(specsOf('const bad = /unclosed\u2028import "node:url";'), ['node:url']);

  // 2. Postfix ++ / -- leaves regexAllowed = false so division does not swallow dynamic loaders
  const postfixDiv = 'const x = a++ / 1; process.getBuiltinModule("fs"); const y = 2 / 1;';
  assert.deepEqual(specsOf(postfixDiv), ['node:fs']);
  assert.match(stripJsComments(postfixDiv), /\bprocess\.getBuiltinModule\b/);
  assert.deepEqual(specsOf('const x = a-- / 1; import "node:path"; const y = 2 / 1;'), ['node:path']);
  assert.deepEqual(specsOf('const x = a++ + /"/.test(s); import "node:crypto";'), ['node:crypto']);
  assert.deepEqual(specsOf('const x = a---/"/.test(s); import "node:url";'), ['node:url']);

  // 3. Statement ) / } contexts allow regex literals (/"/ must not open an unclosed string)
  const stmtRegexCases = [
    ['if (cond) /"/.test(s); import "node:fs";', ['node:fs']],
    ['while (cond) /"/.test(s); import "node:path";', ['node:path']],
    ['for (let i = 0; i < 1; i++) /"/.test(s); import "node:crypto";', ['node:crypto']],
    ['for await (const x of xs) /"/.test(s); import "node:stream";', ['node:stream']],
    ['do {} while (cond) /"/.test(s); import "node:timers";', ['node:timers']],
    ['if (cond) {} else /"/.test(s); import "node:events";', ['node:events']],
    ['if (cond) { ok(); } /"/.test(s); import "node:url";', ['node:url']],
    ['if (cond) {} else { ok(); } /"/.test(s); import "node:os";', ['node:os']],
    ['function f() {}\n/"/.test(s); import "node:util";', ['node:util']],
    ['class C {}\n/"/.test(s); import "node:zlib";', ['node:zlib']],
    ['const arrow = () => {}\n/"/.test(s); import "node:buffer";', ['node:buffer']],
    ['try {} catch { ok(); } /"/.test(s); import "node:http";', ['node:http']],
  ];
  for (const [src, expected] of stmtRegexCases) {
    assert.deepEqual(specsOf(src), expected, `Expected ${expected} for: ${src}`);
  }

  // Expression ) / } / property-keyword controls keep regexAllowed = false for division
  const exprDivCases = [
    ['const x = (a + b) / 2; import "node:fs"; const y = 4 / 2;', ['node:fs']],
    ['const o = { a: 1 } / 2; import "node:path"; const y = 4 / 2;', ['node:path']],
    ['const f = function() {} / 2; import "node:crypto"; const y = 4 / 2;', ['node:crypto']],
    ['const C = class {} / 2; import "node:url"; const y = 4 / 2;', ['node:url']],
    ['const m = obj.if(x) / 2; import "node:os"; const y = 4 / 2;', ['node:os']],
    ['const k = obj.return / 2; import "node:util"; const y = 4 / 2;', ['node:util']],
    ['const t = cond ? a : { b: 1 } / 2; import "node:zlib"; const y = 4 / 2;', ['node:zlib']],
  ];
  for (const [src, expected] of exprDivCases) {
    assert.deepEqual(specsOf(src), expected, `Expected ${expected} for: ${src}`);
  }

  // 4. import(...), require(...), getBuiltinModule(...) accept ',' as well as ')'
  assert.deepEqual(
    specsOf([
      'await import("node:fs", { with: { type: "json" } });',
      'await import("node:path",);',
      'await import(`node:url`, { with: { type: "json" } });',
      'require("node:crypto", 1);',
      'process.getBuiltinModule("os", 1);',
    ].join('\n')),
    ['node:fs', 'node:path', 'node:url', 'node:crypto', 'node:os'],
  );

  // Benign controls: string/template/comment/regex/dynamic concatenation must not false-positive
  assert.deepEqual(
    specsOf([
      'const s = "import(\\"node:fs\\", { with: { type: \\"json\\" } })";',
      'const t = `if (c) /re/; require("node:path", 1)`;',
      '// import "node:crypto";\n/* process.getBuiltinModule("os", 1); */',
      'const re = /import "node:url"/;',
      'const dyn = import("node:fs" + suffix);',
    ].join('\n')),
    [],
  );
});

test('layering scanner: decodes string/template escapes, ASI statement-end regexes, and parenthesized loaders', () => {
  const specsOf = src => parseImportSpecifiersFromSource(src).map(x => x.spec);

  // 1. JS escape decoding in string literals and untagged templates
  assert.deepEqual(
    specsOf([
      String.raw`import "\u006eode:fs";`,
      String.raw`import "cord\x69s";`,
      String.raw`import "\u{6e}ode:path";`,
      String.raw`import { readFile } from "\u006eode:fs/promises";`,
      String.raw`export * from "\x6eode:crypto";`,
      'await import(`cord\\u0069s`);',
      'await import(`node:\\x66s`);',
      'await import(`node:\\u{70}ath`);',
      String.raw`require("\u0063ordis");`,
      String.raw`process.getBuiltinModule("\u{6f}s");`,
    ].join('\n')),
    [
      'node:fs',
      'cordis',
      'node:path',
      'node:fs/promises',
      'node:crypto',
      'cordis',
      'node:fs',
      'node:path',
      'cordis',
      'node:os',
    ],
  );

  // Standard char escapes, line continuations, \0 without octal ambiguity, and identity fallback
  assert.deepEqual(
    specsOf([
      'import "node:\\\nfs";',
      'import "node:\\\r\npath";',
      'import "node:\\\rurl";',
      'import "node:\\\u2028crypto";',
      'import "node:\\\u2029os";',
      'await import(`node:\\\nzlib`);',
      String.raw`import "no\de:events";`,
      String.raw`import "a\nb\rc\td\be\ff\vg\'\"\\";`,
      'import "\\`\\0";',
      String.raw`import "\01";`,
      String.raw`const s = "trailing\\"; import "node:http";`,
      'const t = `trailing\\\\`; import "node:net";',
      'const tagged = tag`\\xZZ\\uZZZZ\\u{}\\u{110000}`; import "node:dns";',
    ].join('\n')),
    [
      'node:fs',
      'node:path',
      'node:url',
      'node:crypto',
      'node:os',
      'node:zlib',
      'node:events',
      'a\nb\rc\td\be\ff\vg\'"\\',
      '`\0',
      '01',
      'node:http',
      'node:net',
      'node:dns',
    ],
  );

  // 2. ASI / statement-end regexes after debugger, break/continue (+ same-line label), and module decls
  const asiRegexCases = [
    ['debugger\n/"/.test("x"); import "node:fs";', ['node:fs']],
    ['while (false) {\n break\n /"/.test("x"); await import("node:fs");\n}', ['node:fs']],
    ['outer: while (false) {\n break outer\n /"/.test("x"); await import("node:fs");\n}', ['node:fs']],
    ['outer: while (false) {\n break /* same-line */ outer\n /"/.test("x"); await import("node:fs");\n}', ['node:fs']],
    ['while (false) {\n continue\n /"/.test("x"); await import("node:fs");\n}', ['node:fs']],
    ['outer: while (false) {\n continue outer\n /"/.test("x"); await import("node:fs");\n}', ['node:fs']],
    ['import "node:events"\n/"/.test("x"); import "node:fs";', ['node:events', 'node:fs']],
    ['import x from "node:events"\n/"/.test("x"); import "node:fs";', ['node:events', 'node:fs']],
    ['import * as ns from "node:events"\n/"/.test("x"); import "node:fs";', ['node:events', 'node:fs']],
    ['import { EventEmitter } from "node:events"\n/"/.test("x"); import "node:fs";', ['node:events', 'node:fs']],
    ['import from from "node:events"\n/"/.test("x"); import "node:fs";', ['node:events', 'node:fs']],
    ['import * as from from "node:events"\n/"/.test("x"); import "node:fs";', ['node:events', 'node:fs']],
    ['import { "default" as def } from "node:events"\n/"/.test("x"); import "node:fs";', ['node:events', 'node:fs']],
    ['export * from "node:events"\n/"/.test("x"); import "node:fs";', ['node:events', 'node:fs']],
    ['export * as ns from "node:events"\n/"/.test("x"); import "node:fs";', ['node:events', 'node:fs']],
    ['export { EventEmitter } from "node:events"\n/"/.test("x"); import "node:fs";', ['node:events', 'node:fs']],
    ['export type * from "node:events"\n/"/.test("x"); import "node:fs";', ['node:events', 'node:fs']],
    ['import data from "./data.json" with { type: "json" }\n/"/.test("x"); import "node:fs";', ['./data.json', 'node:fs']],
  ];
  for (const [src, expected] of asiRegexCases) {
    assert.deepEqual(specsOf(src), expected, `Expected ${expected} for: ${src}`);
    assert.match(stripJsComments(src), /\/re\//, `Expected regex token for: ${src}`);
  }

  // Division / non-statement controls keep regexAllowed = false
  const asiDivisionControls = [
    ['const a = b\n/ 2 / 1; import "node:fs";', ['node:fs']],
    ['const a = b\n/ 2; import "node:fs"; const c = 4 / 2;', ['node:fs']],
    ['outer: while (false) {\n break\nouter / 2; await import("node:fs"); const c = 4 / 2;\n}', ['node:fs']],
    ['outer: while (false) {\n break /* line1\nline2 */ outer / 2; await import("node:fs"); const c = 4 / 2;\n}', ['node:fs']],
    ['const obj = { debugger: 1, break: 2, continue: 3 }; const x = obj.debugger / 2; import "node:fs"; const y = obj.break / 2; import "node:path"; const z = obj.continue / 2;', ['node:fs', 'node:path']],
    ['export default "foo" / 2; import "node:fs"; const y = 4 / 2;', ['node:fs']],
    ['export const s = "foo"\n/ 2; import "node:fs"; const y = 4 / 2;', ['node:fs']],
    ['const p = import("node:events")\n/ 2; import "node:fs"; const y = 4 / 2;', ['node:events', 'node:fs']],
    ['const r = from("node:events")\n/ 2; import "node:fs"; const y = 4 / 2;', ['node:fs']],
  ];
  for (const [src, expected] of asiDivisionControls) {
    assert.deepEqual(specsOf(src), expected, `Expected ${expected} for: ${src}`);
    assert.doesNotMatch(stripJsComments(src), /\/re\//, `Expected division, not regex, for: ${src}`);
  }

  // 3. Arbitrarily parenthesized literal specifiers in import(), require(), getBuiltinModule()
  assert.deepEqual(
    specsOf([
      'await import(("node:fs"));',
      'await import((("node:path")), { with: { type: "json" } });',
      'await import(("cordis"));',
      'await import(((`cord\\u0069s`)));',
      'require(("cordis"));',
      'require((("node:crypto")), 1);',
      'process.getBuiltinModule(("fs"));',
      'process.getBuiltinModule((("os")), 1);',
    ].join('\n')),
    ['node:fs', 'node:path', 'cordis', 'cordis', 'cordis', 'node:crypto', 'node:fs', 'node:os'],
  );

  assert.deepEqual(
    specsOf([
      'await import(("node:fs") + suffix);',
      'await import(("node:fs" + suffix));',
      'require(("cor" + "dis"));',
      'process.getBuiltinModule(("f" + "s"));',
    ].join('\n')),
    [],
  );
});

test('layering scanner: blocks optional-chained loaders, string export aliases before /re/, and nested class extends', () => {
  const specsOf = src => parseImportSpecifiersFromSource(src).map(x => x.spec);

  // 1. Optional chaining `?.` on dynamic loaders and member/ternary regex tracking
  const optChainCalls = [
    ['const loader = process?.getBuiltinModule?.("fs");', ['node:fs'], true],
    ['const loader = process?.getBuiltinModule("os");', ['node:os'], true],
    ['const loader = process.getBuiltinModule?.("path");', ['node:path'], true],
    ['const loader = process?.getBuiltinModule?.(("crypto"), 1);', ['node:crypto'], true],
    ['const loader = process /* c */ ?. /* c */ getBuiltinModule?.(`node:\\u0075rl`);', ['node:url'], true],
    ['const r = require?.("cordis");', ['cordis'], false],
    ['const r = require?.(("node:fs"), 1);', ['node:fs'], false],
    ['const r = require?.(`cord\\u0069s`);', ['cordis'], false],
  ];
  for (const [src, expected, expectSharedRegex] of optChainCalls) {
    assert.deepEqual(specsOf(src), expected, `Expected ${expected} for: ${src}`);
    assert.equal(DYNAMIC_BUILTIN_LOADER_RE.test(stripJsComments(src)), expectSharedRegex, `Shared regex mismatch for: ${src}`);
  }

  // Optional-chaining member access, ternary leading-dot float `.5`, and `? .` regex boundaries
  const optChainRegexControls = [
    ['const x = a?.b / 2; import "node:fs"; const y = 4 / 2;', ['node:fs'], false],
    ['const x = a?.() / 2; import "node:path"; const y = 4 / 2;', ['node:path'], false],
    ['const m = obj?.return / 2; import "node:crypto"; const y = 4 / 2;', ['node:crypto'], false],
    ['const m = obj?.if(cond) / 2; import "node:os"; const y = 4 / 2;', ['node:os'], false],
    ['obj?.import("node:fs");', [], false],
    ['const x = cond?.5 : /"/.test(s); import "node:fs";', ['node:fs'], true],
    ['const x = cond?.5 : { a: 1 } / 2; import "node:path"; const y = 4 / 2;', ['node:path'], false],
    ['const x = cond ? .5 : /"/.test(s); import "node:crypto";', ['node:crypto'], true],
  ];
  for (const [src, expected, expectRegex] of optChainRegexControls) {
    assert.deepEqual(specsOf(src), expected, `Expected ${expected} for: ${src}`);
    if (expectRegex) {
      assert.match(stripJsComments(src), /\/re\//, `Expected regex token for: ${src}`);
    } else {
      assert.doesNotMatch(stripJsComments(src), /\/re\//, `Expected division/call, not regex, for: ${src}`);
    }
  }

  assert.deepEqual(
    specsOf([
      'require?.("cor" + "dis");',
      'process?.getBuiltinModule?.("f" + "s");',
      'const s = "require?.(\'cordis\')";',
    ].join('\n')),
    [],
  );

  // 2. ES2022 `export * as "str" from ...` ASI before regex literal
  const stringAliasExports = [
    ['export * as "ns-name" from "node:events"\n/"/.test("x"); import "node:fs";', ['node:events', 'node:fs']],
    ['export * as "from" from "node:events"\n/"/.test("x"); import "node:fs";', ['node:events', 'node:fs']],
    [String.raw`export * as "\u006es" from "node:events"` + '\n/"/.test("x"); import "node:fs";', ['node:events', 'node:fs']],
    ['export type * as "ns-name" from "node:events"\n/"/.test("x"); import "node:fs";', ['node:events', 'node:fs']],
    ['export { "default" as "ns-name" } from "node:events"\n/"/.test("x"); import "node:fs";', ['node:events', 'node:fs']],
  ];
  for (const [src, expected] of stringAliasExports) {
    assert.deepEqual(specsOf(src), expected, `Expected ${expected} for: ${src}`);
    assert.match(stripJsComments(src), /\/re\//, `Expected regex token for: ${src}`);
  }

  const stringAliasControls = [
    ['let as = 1; export { as }\nas\n"foo" / 2; import "node:fs"; const y = 4 / 2;', ['node:fs']],
    ['let a = 1; export { a }\n"foo" / 2; import "node:fs"; const y = 4 / 2;', ['node:fs']],
    ['let from = 4; export { from };\nfrom / 2; import "node:fs"; const y = 4 / 2;', ['node:fs']],
  ];
  for (const [src, expected] of stringAliasControls) {
    assert.deepEqual(specsOf(src), expected, `Expected ${expected} for: ${src}`);
    assert.doesNotMatch(stripJsComments(src), /\/re\//, `Expected division, not regex, for: ${src}`);
  }

  // 3. Nested `class`, object literals, and function expressions inside `extends`
  const nestedClassExprDivCases = [
    'const C = class extends mix(class {}) {} / 2; import "node:fs"; const y = 4 / 2;',
    'const C = class extends (class {}) {} / 2; import "node:fs"; const y = 4 / 2;',
    'const C = class extends class {} {} / 2; import "node:fs"; const y = 4 / 2;',
    'const C = class extends mix(class extends (class {}) {}) {} / 2; import "node:fs"; const y = 4 / 2;',
    'const C = class extends { constructor: Object }.constructor {} / 2; import "node:fs"; const y = 4 / 2;',
    'const C = class extends function() {} {} / 2; import "node:fs"; const y = 4 / 2;',
    'const C = class extends obj.extends {} / 2; import "node:fs"; const y = 4 / 2;',
    'const C = class extends Base<A, B> {} / 2; import "node:fs"; const y = 4 / 2;',
  ];
  for (const src of nestedClassExprDivCases) {
    assert.deepEqual(specsOf(src), ['node:fs'], `Expected ['node:fs'] for: ${src}`);
    assert.doesNotMatch(stripJsComments(src), /\/re\//, `Expected division, not regex, for: ${src}`);
  }

  const nestedClassDeclRegexCases = [
    'class A extends class B {} {}\n/"/.test("x"); import "node:fs";',
    'class A extends mix(class {}) {}\n/"/.test("x"); import "node:fs";',
    'export default class extends class {} {}\n/"/.test("x"); import "node:fs";',
  ];
  for (const src of nestedClassDeclRegexCases) {
    assert.deepEqual(specsOf(src), ['node:fs'], `Expected ['node:fs'] for: ${src}`);
    assert.match(stripJsComments(src), /\/re\//, `Expected regex token for: ${src}`);
  }
});

test('layering scanner: handles template interpolation exprs, contextual of, private #ident, and hashbangs', () => {
  const specsOf = src => parseImportSpecifiersFromSource(src).map(x => x.spec);

  // 1. Template interpolation `${...}` is expression context (avoid closing-brace regex inversion)
  const templateExprDivCases = [
    'const t1 = `${{ a: 1 } / 2}`; import "node:fs"; const y1 = 4 / 2;',
    'const t2 = `${class {} / 2}`; import "node:fs"; const y2 = 4 / 2;',
    'const t3 = `${function () {} / 2}`; import "node:fs"; const y3 = 4 / 2;',
    'const t4 = `${async function () {} / 2}`; import "node:fs"; const y4 = 4 / 2;',
    'const t5 = `${function* () {} / 2}`; import "node:fs"; const y5 = 4 / 2;',
    'const t6 = `${class extends Base {} / 2}`; import "node:fs"; const y6 = 4 / 2;',
    'const t7 = `${class extends { a: 1 } {} / 2}`; import "node:fs"; const y7 = 4 / 2;',
    'const t8 = `${/* c */ { a: 1 } / 2} mid ${{ b: 2 } / 2}`; import "node:fs"; const y8 = 4 / 2;',
    'const t9 = `${`${{ a: 1 } / 2}` / 2}`; import "node:fs"; const y9 = 4 / 2;',
    'const t10 = tag`${{ a: 1 } / 2}`; import "node:fs"; const y10 = 4 / 2;',
  ];
  for (const src of templateExprDivCases) {
    assert.deepEqual(specsOf(src), ['node:fs'], `Expected ['node:fs'] for: ${src}`);
    assert.doesNotMatch(stripJsComments(src), /\/re\//, `Expected division, not regex, for: ${src}`);
  }

  const templateInnerRegexSrc = 'const tr = `${/a/.test(s) ? { a: 1 } / 2 : { b: 2 } / 2}`; import "node:fs"; const yr = 4 / 2;';
  assert.deepEqual(specsOf(templateInnerRegexSrc), ['node:fs']);
  assert.match(stripJsComments(templateInnerRegexSrc), /\/re\//);

  // 2. Contextual `of`: division outside `for (... of ...)`, regex only directly inside `for` header after `of` keyword
  const contextualOfDivCases = [
    'const of = 4; const x = of / 2; import "node:fs"; const y = 4 / 2;',
    'function f(of) { return of / 2; } import "node:fs"; const y = 4 / 2;',
    'let of = 4; for (of / 2; ; ) break; import "node:fs"; const y = 4 / 2;',
    'let of = 4; for (let x = of / 2; ; ) break; import "node:fs"; const y = 4 / 2;',
    'let of = 4; for (let x = (of / 2); ; ) break; import "node:fs"; const y = 4 / 2;',
    'let of = 4; for (let x = 1; x < of / 2; x++) break; import "node:fs"; const y = 4 / 2;',
    'let of = 4; for (let x = 1; x < 2; of / 2) break; import "node:fs"; const y = 4 / 2;',
    'let of = 4; for (typeof of / 2; ; ) break; import "node:fs"; const y = 4 / 2;',
    'for (let of = 4; of / 2 < 5; ) break; import "node:fs"; const y = 4 / 2;',
    'const of = 4; for (const x of of / 2 ? [] : []) {} import "node:fs"; const y = 4 / 2;',
    'let of = 4; for (const x in of / 2 ? {} : {}) {} import "node:fs"; const y = 4 / 2;',
    'const obj = { of: 4 }; const x = obj.of / 2; import "node:fs"; const y = 4 / 2;',
    'class C { for(of) { return of / 2; } } import "node:fs"; const y = 4 / 2;',
    String.raw`const \u006f\u0066 = 4; const x = \u006f\u0066 / 2; import "node:fs"; const y = 4 / 2;`,
    'for (const x of { a: 1 } / 2 ? [] : []) {} import "node:fs"; const y = 4 / 2;',
    'for (const x of class {} / 2 ? [] : []) {} import "node:fs"; const y = 4 / 2;',
    'for (const x of function () {} / 2 ? [] : []) {} import "node:fs"; const y = 4 / 2;',
  ];
  for (const src of contextualOfDivCases) {
    assert.deepEqual(specsOf(src), ['node:fs'], `Expected ['node:fs'] for: ${src}`);
    assert.doesNotMatch(stripJsComments(src), /\/re\//, `Expected division, not regex, for: ${src}`);
  }

  const contextualOfRegexCases = [
    'for (const x of [/a/]) {} import "node:fs";',
    'for (const x of /"/.source) {} import "node:fs";',
    'for await (const x of /"/.source) {} import "node:fs";',
    'for (const [a = () => { const z = 1; }] of /"/.source) {} import "node:fs";',
    'for (const { a } of /"/.source) {} import "node:fs";',
    'let x; for ((x) of /"/.source) {} import "node:fs";',
    'for (const of of /"/.source) {} import "node:fs";',
    'for (let of of /"/.source) {} import "node:fs";',
    'let of; for (of of /"/.source) {} import "node:fs";',
    'const o = {}; for (o.of of /"/.source) {} import "node:fs";',
    'const o = {}; for (o.typeof of /"/.source) {} import "node:fs";',
    String.raw`for (const \u006f\u0066 of /"/.source) {} import "node:fs";`,
    'const of = 1;\nof\nfunction f() {}\n/"/.test("x"); import "node:fs";',
    'const of = 1;\nof\nclass C {}\n/"/.test("x"); import "node:fs";',
  ];
  for (const src of contextualOfRegexCases) {
    assert.deepEqual(specsOf(src), ['node:fs'], `Expected ['node:fs'] for: ${src}`);
    assert.match(stripJsComments(src), /\/re\//, `Expected regex token for: ${src}`);
  }

  // 3. Private `#ident` tokens, Unicode/escaped identifiers, and `#!` hashbangs
  const privateDivCases = [
    'class C { #return = 4; m() { const x = this.#return / 2; process.getBuiltinModule("fs"); const y = 4 / 2; } }',
    'class C { #break = 4; #continue = 4; #debugger = 4; #of = 4; m() { const a = this.#break / 2; const b = this.#continue / 2; const c = this.#debugger / 2; const d = this.#of / 2; process.getBuiltinModule("fs"); const y = 4 / 2; } }',
    'class C { #class = 4; #function = 4; #extends = 4; #export = 4; #import = 4; m() { const a = this.#class / 2; const b = this.#function / 2; const c = this.#extends / 2; const d = this.#export / 2; const e = this.#import / 2; process.getBuiltinModule("fs"); const y = 4 / 2; } }',
    String.raw`class C { #\u0072eturn = 4; m() { const x = this.#\u0072eturn / 2; process.getBuiltinModule("fs"); const y = 4 / 2; } }`,
    'class C { #πreturn = 4; m() { const x = this.#πreturn / 2; process.getBuiltinModule("fs"); const y = 4 / 2; } }',
    'const πreturn = 4; const x = πreturn / 2; process.getBuiltinModule("fs"); const y = 4 / 2;',
    'class C { #if() {} m() { const x = this.#if(1) / 2; process.getBuiltinModule("fs"); const y = 4 / 2; } }',
    'class C { #for() {} m() { const x = this.#for(1) / 2; process.getBuiltinModule("fs"); const y = 4 / 2; } }',
  ];
  for (const src of privateDivCases) {
    assert.deepEqual(specsOf(src), ['node:fs'], `Expected ['node:fs'] for: ${src}`);
    assert.doesNotMatch(stripJsComments(src), /\/re\//, `Expected division, not regex, for: ${src}`);
  }

  const privateRegexCases = [
    'class C { #x; m() { for (this.#x of /"/.source) {} process.getBuiltinModule("fs"); } }',
    'class C { #return = 4; m(o) { if (#return in o) /"/.test("x"); process.getBuiltinModule("fs"); } }',
  ];
  for (const src of privateRegexCases) {
    assert.deepEqual(specsOf(src), ['node:fs'], `Expected ['node:fs'] for: ${src}`);
    assert.match(stripJsComments(src), /\/re\//, `Expected regex token for: ${src}`);
  }

  // Hashbang preservation and escaped dynamic loaders
  assert.deepEqual(specsOf('#!/usr/bin/env -S node --title="foo"\nimport "node:fs";'), ['node:fs']);
  assert.doesNotMatch(stripJsComments('#!/usr/bin/env -S node --title="foo"\nimport "node:fs";'), /\/re\//);
  assert.deepEqual(specsOf('#!/usr/bin/env node\n/"/.test("x"); import "node:fs";'), ['node:fs']);
  assert.match(stripJsComments('#!/usr/bin/env node\n/"/.test("x"); import "node:fs";'), /\/re\//);

  const escapedDynamicLoader = String.raw`process.get\u0042uiltinModule("fs");`;
  assert.deepEqual(specsOf(escapedDynamicLoader), ['node:fs']);
  assert.equal(DYNAMIC_BUILTIN_LOADER_RE.test(stripJsComments(escapedDynamicLoader)), true);
  assert.deepEqual(specsOf(String.raw`req\u0075ire("cordis");`), ['cordis']);

  // False-positive controls: private #import/#export/#require/#getBuiltinModule must never trigger
  const privateFalsePositiveControl = [
    'class C {',
    '  #import() {}',
    '  #export() {}',
    '  #require() {}',
    '  #getBuiltinModule() {}',
    '  m() {',
    '    this.#import("node:fs");',
    '    this.#import?.("node:fs");',
    '    this.#export("node:fs");',
    '    this.#require("cordis");',
    '    this.#getBuiltinModule("fs");',
    '  }',
    '}',
  ].join('\n');
  assert.deepEqual(specsOf(privateFalsePositiveControl), []);
  assert.equal(
    DYNAMIC_BUILTIN_LOADER_RE.test(stripJsComments('class C { #getBuiltinModule() {} m() { this.#getBuiltinModule("fs"); } }')),
    false,
  );
});

test('layering scanner: enforces [no LineTerminator here] ASI for async function, return/yield, and for-of using', () => {
  const specsOf = src => parseImportSpecifiersFromSource(src).map(x => x.spec);

  // 1. `async [no LineTerminator here] function` ASI cases -> FunctionDeclaration (`regexAfter: true`)
  const asyncFunctionAsiRegexCases = [
    'let async = 1;\nlet x = async\nfunction g() {}\n/"/.test("x"); import "node:fs";',
    'let async = 1;\nlet x = async\rfunction g() {}\n/"/.test("x"); import "node:fs";',
    'let async = 1;\nlet x = async\u2028function g() {}\n/"/.test("x"); import "node:fs";',
    'let async = 1;\nlet x = async\u2029function g() {}\n/"/.test("x"); import "node:fs";',
    'let async = 1;\nlet x = async // line comment\nfunction g() {}\n/"/.test("x"); import "node:fs";',
    'let async = 1;\nlet x = async /* \n */ function g() {}\n/"/.test("x"); import "node:fs";',
    'let async = 1;\nlet x = async /* \u2028 */ function g() {}\n/"/.test("x"); import "node:fs";',
    'let async = 1;\nlet x = async\n/* inline */ function g() {}\n/"/.test("x"); import "node:fs";',
    'let async = 1;\nlet x = async\nfunction* g() {}\n/"/.test("x"); import "node:fs";',
    'let async = 1;\nexport default async\nfunction g() {}\n/"/.test("x"); import "node:fs";',
    'export default async /* inline */ function () {}\n/"/.test("x"); import "node:fs";',
    'export default\nasync function g() {}\n/"/.test("x"); import "node:fs";',
  ];
  for (const src of asyncFunctionAsiRegexCases) {
    assertValidEsm(src);
    assert.deepEqual(specsOf(src), ['node:fs'], `Expected ['node:fs'] for: ${src}`);
    assert.match(stripJsComments(src), /\/re\//, `Expected regex token for: ${src}`);
  }

  // Same-line `async /* inline */ function` controls remain AsyncFunctionExpression (`regexAfter: false`)
  const asyncFunctionExprDivCases = [
    'let x = async /* inline */ function () {} / 2; import "node:fs"; const y = 4 / 2;',
    'let x = async function () {} / 2; import "node:fs"; const y = 4 / 2;',
    'let x = async /* inline */ function* () {} / 2; import "node:fs"; const y = 4 / 2;',
    'const C = class extends async /* inline */ function () {} {} / 2; import "node:fs"; const y = 4 / 2;',
  ];
  for (const src of asyncFunctionExprDivCases) {
    assertValidEsm(src);
    assert.deepEqual(specsOf(src), ['node:fs'], `Expected ['node:fs'] for: ${src}`);
    assert.doesNotMatch(stripJsComments(src), /\/re\//, `Expected division, not regex, for: ${src}`);
  }

  // 2. `return` / `yield` `[no LineTerminator here]` ASI vs same-line expression controls
  const returnYieldAsiRegexCases = [
    'function f() { return\nfunction g() {}\n/"/.test("x"); } import "node:fs";',
    'function f() { return\nasync function g() {}\n/"/.test("x"); } import "node:fs";',
    'function f() { return /* \n */ async /* inline */ function g() {}\n/"/.test("x"); } import "node:fs";',
    'function f() { return // comment\nclass C {}\n/"/.test("x"); } import "node:fs";',
    'function f() { return\n{ a: 1 }\n/"/.test("x"); } import "node:fs";',
    'function* f() { yield\nfunction g() {}\n/"/.test("x"); } import "node:fs";',
    'function* f() { yield\nasync function g() {}\n/"/.test("x"); } import "node:fs";',
    'function* f() { yield /* \n */ class C {}\n/"/.test("x"); } import "node:fs";',
    'function* f() { yield\n{ a: 1 }\n/"/.test("x"); } import "node:fs";',
  ];
  for (const src of returnYieldAsiRegexCases) {
    assertValidEsm(src);
    assert.deepEqual(specsOf(src), ['node:fs'], `Expected ['node:fs'] for: ${src}`);
    assert.match(stripJsComments(src), /\/re\//, `Expected regex token for: ${src}`);
  }

  const returnYieldSameLineDivCases = [
    'function f() { return /* inline */ function () {} / 2; } import "node:fs"; const y = 4 / 2;',
    'function f() { return /* inline */ async /* inline */ function () {} / 2; } import "node:fs"; const y = 4 / 2;',
    'function f() { return /* inline */ class {} / 2; } import "node:fs"; const y = 4 / 2;',
    'function f() { return /* inline */ { a: 1 } / 2; } import "node:fs"; const y = 4 / 2;',
    'function* f() { yield /* inline */ function () {} / 2; } import "node:fs"; const y = 4 / 2;',
    'function* f() { yield /* inline */ { a: 1 } / 2; } import "node:fs"; const y = 4 / 2;',
    'async function f() { await\nfunction () {} / 2; } import "node:fs"; const y = 4 / 2;',
    'export default\n{ a: 1 } / 2; import "node:fs";',
  ];
  for (const src of returnYieldSameLineDivCases) {
    assertValidEsm(src);
    assert.deepEqual(specsOf(src), ['node:fs'], `Expected ['node:fs'] for: ${src}`);
    assert.doesNotMatch(stripJsComments(src), /\/re\//, `Expected division, not regex, for: ${src}`);
  }

  // 3. `for (using [of] ...)` contextual `of` parity
  for (const src of [
    'let using = 1; for (using of /"/.source) {} import "node:fs";',
    'let using = 1; for (using\nof /"/.source) {} import "node:fs";',
  ]) {
    assertValidEsm(src);
    assert.deepEqual(specsOf(src), ['node:fs'], `Expected ['node:fs'] for: ${src}`);
    assert.match(stripJsComments(src), /\/re\//, `Expected regex token for: ${src}`);
  }
  for (const src of [
    'let using = 1, of = 4; for (using of of / 2 ? [1] : [2]) {} import "node:fs"; const y = 4 / 2;',
    'for (using of = 1; of / 2 < 5; ) break; import "node:fs"; const y = 4 / 2;',
  ]) {
    assertValidEsm(src);
    assert.deepEqual(specsOf(src), ['node:fs'], `Expected ['node:fs'] for: ${src}`);
    assert.doesNotMatch(stripJsComments(src), /\/re\//, `Expected division, not regex, for: ${src}`);
  }
});

test('layering scanner: handles ?? / ??= without poisoning ternaryStack, switch/label regexes, or ; pruning', () => {
  const specsOf = src => parseImportSpecifiersFromSource(src).map(x => x.spec);

  const nullishRegexCases = [
    'const x = a ?? b;\nlbl: { ok(); }\n/"/.test("x"); import "node:fs";',
    'const x = a ?? b\nlbl: { ok(); }\n/"/.test("x"); import "node:fs";',
    'function f(a, b) {\n  switch (a) {\n    case 1: const y = a ?? b;\n    case 2: { ok(); } /"/.test("x"); process.getBuiltinModule("fs");\n  }\n}',
    'function f(a, b) {\n  switch (a) {\n    case 1: a ??= b;\n    default: { ok(); } /"/.test("x"); process.getBuiltinModule("fs");\n  }\n}',
    'function f(a, b) {\n  switch (a) {\n    case a ?? b: { ok(); } /"/.test("x"); process.getBuiltinModule("fs");\n  }\n}',
    'let x = null;\nx ??= b;\nlbl: { ok(); }\n/"/.test("x"); import "node:fs";',
    'const x = a ?? /"/.test("x"); import "node:fs";',
    'let x = null; x ??= /"/.test("x"); import "node:fs";',
    'const x = cond ? a : b;\nlbl: { ok(); }\n/"/.test("x"); import "node:fs";',
  ];
  for (const src of nullishRegexCases) {
    assertValidEsm(src);
    assert.deepEqual(specsOf(src), ['node:fs'], `Expected ['node:fs'] for: ${src}`);
    assert.match(stripJsComments(src), /\/re\//, `Expected regex token for: ${src}`);
  }

  const nullishDivisionCases = [
    'const x = a ?? { k: 1 } / 2; import "node:fs";',
    'const x = cond?.x ?? { a: 1 } / 2; import "node:fs";',
    'let x; x ??= { a: 1 } / 2; import "node:fs";',
    'const x = cond ? { a: 1 } / 2 : { b: 1 } / 2; import "node:fs";',
    'const x = cond ? .5 ?? { a: 1 } / 2 : { b: 1 } / 2; import "node:fs";',
    'const x = a ?? function () {} / 2; import "node:fs";',
    'const x = a ?? async function () {} / 2; import "node:fs";',
    'const x = a ?? class {} / 2; import "node:fs";',
    'const x = { a: b ?? { c: 1 } / 2 }; import "node:fs";',
  ];
  for (const src of nullishDivisionCases) {
    assertValidEsm(src);
    assert.deepEqual(specsOf(src), ['node:fs'], `Expected ['node:fs'] for: ${src}`);
    assert.doesNotMatch(stripJsComments(src), /\/re\//, `Expected division, not regex, for: ${src}`);
  }

  // Semicolon statement termination prunes stale ternaryStack entries at the current (b, p, k)
  // (e.g. TS optional members `x?;` or malformed `?` before `;`) without breaking valid TS `x?: T`.
  const semiPruneAndTsOptionalCases = [
    'const x = 1 ? 2; lbl: { ok(); } /"/.test("x"); import "node:fs";',
    'class C { static { const x = 1 ? 2; lbl: { ok(); } /"/.test("x"); process.getBuiltinModule("fs"); } }',
    'interface I { x?; }\nfunction f(a?: { k: number }) { return 1; } /"/.test("x"); import "node:fs";',
    'class C { x?; m(a?: number) { lbl: { ok(); } /"/.test("x"); } } import "node:fs";',
  ];
  for (const src of semiPruneAndTsOptionalCases) {
    assert.deepEqual(specsOf(src), ['node:fs'], `Expected ['node:fs'] for: ${src}`);
    assert.match(stripJsComments(src), /\/re\//, `Expected regex token for: ${src}`);
  }
});
