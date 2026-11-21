// Extracts prefix_rule(...) calls from Codex Starlark *.rules files without a
// Starlark interpreter. Only literal strings and lists are understood; anything
// else inside a prefix_rule call makes that call "unparsed" (reported by line).
//
// Pattern elements: a string, or a list of strings (alternatives at that position),
// so `pattern=["git", ["push", "pull"]]` -> ['git', ['push', 'pull']].
// `match` / `not_match` are parsed for validity and then ignored.
// parseRules never throws.

const DECISIONS = new Set(['allow', 'prompt', 'forbidden']);
const ID_START = /[A-Za-z_]/;
const ID_CHAR = /[A-Za-z0-9_]/;
const SIMPLE_ESC = { n: '\n', t: '\t', r: '\r', '\\': '\\', '"': '"', "'": "'", 0: '\0' };

class RuleError extends Error {}

// Reads a string literal starting at s[i] (a quote). Returns { value, end }.
function readString(s, i) {
  const q = s[i];
  const triple = s.startsWith(q.repeat(3), i);
  let j = i + (triple ? 3 : 1);
  let out = '';
  for (;;) {
    if (j >= s.length) throw new RuleError('unterminated string');
    const c = s[j];
    if (triple ? s.startsWith(q.repeat(3), j) : c === q) return { value: out, end: j + (triple ? 3 : 1) };
    if (!triple && c === '\n') throw new RuleError('newline in string');
    if (c === '\\') {
      const e = s[j + 1];
      if (e === undefined) throw new RuleError('unterminated string');
      if (e === 'x' && /^[0-9a-fA-F]{2}$/.test(s.slice(j + 2, j + 4))) {
        out += String.fromCharCode(parseInt(s.slice(j + 2, j + 4), 16));
        j += 4;
      } else if (e === 'u' && /^[0-9a-fA-F]{4}$/.test(s.slice(j + 2, j + 6))) {
        out += String.fromCharCode(parseInt(s.slice(j + 2, j + 6), 16));
        j += 6;
      } else if (e === '\n') {
        j += 2; // line continuation
      } else {
        out += Object.hasOwn(SIMPLE_ESC, e) ? SIMPLE_ESC[e] : '\\' + e;
        j += 2;
      }
    } else {
      out += c;
      j++;
    }
  }
}

// Parses the argument list after `prefix_rule(`; returns { kwargs, end }.
function parseCall(s, start) {
  let i = start;
  const skip = () => {
    for (;;) {
      if (/\s/.test(s[i] ?? 'x') && i < s.length) i++;
      else if (s[i] === '#') while (i < s.length && s[i] !== '\n') i++;
      else return;
    }
  };
  const value = (depth) => {
    if (depth > 8) throw new RuleError('nesting too deep');
    skip();
    const c = s[i];
    if (c === '"' || c === "'") {
      const r = readString(s, i);
      i = r.end;
      return r.value;
    }
    if (c === '[') {
      i++;
      const arr = [];
      for (;;) {
        skip();
        if (i >= s.length) throw new RuleError('unterminated list');
        if (s[i] === ']') {
          i++;
          return arr;
        }
        arr.push(value(depth + 1));
        skip();
        if (s[i] === ',') i++;
        else if (s[i] !== ']') throw new RuleError('expected , or ]');
      }
    }
    throw new RuleError('unsupported expression');
  };

  const kwargs = {};
  for (;;) {
    skip();
    if (i >= s.length) throw new RuleError('unterminated call');
    if (s[i] === ')') return { kwargs, end: i + 1 };
    if (!ID_START.test(s[i])) throw new RuleError('expected keyword argument');
    const st = i;
    while (i < s.length && ID_CHAR.test(s[i])) i++;
    const name = s.slice(st, i);
    skip();
    if (s[i] !== '=') throw new RuleError('expected =');
    i++;
    const v = value(0);
    if (Object.hasOwn(kwargs, name)) throw new RuleError('duplicate argument');
    kwargs[name] = v;
    skip();
    if (s[i] === ',') i++;
    else if (s[i] !== ')') throw new RuleError('expected , or )');
  }
}

function toRule(kwargs, line) {
  const p = kwargs.pattern;
  if (!Array.isArray(p) || p.length === 0) throw new RuleError('missing pattern');
  const pattern = p.map((el) => {
    if (typeof el === 'string') return el;
    if (Array.isArray(el) && el.length > 0 && el.every((x) => typeof x === 'string')) return el;
    throw new RuleError('bad pattern element');
  });
  const decision = kwargs.decision === undefined ? 'allow' : kwargs.decision;
  if (typeof decision !== 'string' || !DECISIONS.has(decision)) throw new RuleError('bad decision');
  const rule = { pattern, decision, line };
  if (kwargs.justification !== undefined) {
    if (typeof kwargs.justification !== 'string') throw new RuleError('bad justification');
    rule.justification = kwargs.justification;
  }
  return rule;
}

export function parseRules(text) {
  const rules = [];
  const unparsed = [];
  if (typeof text !== 'string') return { rules, unparsed };
  try {
    const s = text.replace(/^﻿/, '').replace(/\r\n?/g, '\n');
    let i = 0;
    let line = 1;
    while (i < s.length) {
      const c = s[i];
      if (c === '\n') {
        line++;
        i++;
      } else if (c === '#') {
        while (i < s.length && s[i] !== '\n') i++;
      } else if (c === '"' || c === "'") {
        // Skip string literals so prefix_rule( inside them is not treated as a call.
        let end;
        try {
          end = readString(s, i).end;
        } catch {
          end = i + 1;
        }
        for (let k = i; k < end; k++) if (s[k] === '\n') line++;
        i = end;
      } else if (ID_START.test(c)) {
        const st = i;
        while (i < s.length && ID_CHAR.test(s[i])) i++;
        if (s.slice(st, i) !== 'prefix_rule' || (st > 0 && s[st - 1] === '.')) continue;
        let j = i;
        while (s[j] === ' ' || s[j] === '\t') j++;
        if (s[j] !== '(') continue;
        const callLine = line;
        try {
          const { kwargs, end } = parseCall(s, j + 1);
          rules.push(toRule(kwargs, callLine));
          for (let k = i; k < end; k++) if (s[k] === '\n') line++;
          i = end;
        } catch {
          unparsed.push(callLine);
          i = j + 1; // resume right after the opening paren
        }
      } else {
        i++;
      }
    }
  } catch {
    // never throw; return what was gathered so far
  }
  return { rules, unparsed };
}
