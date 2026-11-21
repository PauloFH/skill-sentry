// Minimal zero-dependency TOML parser covering what Codex config files use:
// tables, arrays of tables, dotted/quoted keys, basic/literal/multiline strings,
// numbers, booleans, dates (kept as strings), arrays and inline tables.
// parseToml never throws: it returns { ok: true, value } or { ok: false, error, line }.

class TomlError extends Error {
  constructor(message, pos) {
    super(message);
    this.pos = pos;
  }
}

const hasOwn = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
const isPlainObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

function setOwn(obj, key, value) {
  // defineProperty keeps "__proto__" and friends as inert own keys.
  Object.defineProperty(obj, key, { value, enumerable: true, writable: true, configurable: true });
}

const BARE = /[A-Za-z0-9_-]/;
const DATETIME = /\d{4}-\d{2}-\d{2}(?:[Tt ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:[Zz]|[+-]\d{2}:\d{2})?)?(?![\w:])/y;
const TIME = /\d{2}:\d{2}:\d{2}(?:\.\d+)?(?![\w:])/y;
const ESCAPES = { b: '\b', t: '\t', n: '\n', f: '\f', r: '\r', '"': '"', '\\': '\\' };
const MAX_DEPTH = 64;

function parseDocument(src) {
  const s = src;
  let i = 0;
  const root = {};
  const explicit = new WeakSet(); // tables defined by a [header]
  const sealed = new WeakSet(); // inline tables / tables built by dotted keys
  const aot = new WeakSet(); // arrays created by [[header]]
  let cur = root;

  const fail = (msg, pos = i) => {
    throw new TomlError(msg, pos);
  };
  const skipWs = () => {
    while (s[i] === ' ' || s[i] === '\t') i++;
  };
  const skipComment = () => {
    if (s[i] === '#') while (i < s.length && s[i] !== '\n') i++;
  };
  const skipWsNlComments = () => {
    for (;;) {
      skipWs();
      if (s[i] === '#') skipComment();
      else if (s[i] === '\n') i++;
      else return;
    }
  };
  const endOfLine = () => {
    skipWs();
    skipComment();
    if (i < s.length && s[i] !== '\n') fail('unexpected characters after value');
    i++;
  };

  function parseBasicBody(multi) {
    let out = '';
    const start = i;
    for (;;) {
      if (i >= s.length) fail('unterminated string', start);
      const c = s[i];
      if (multi) {
        if (c === '"' && s.startsWith('"""', i)) {
          let q = 0;
          while (s[i + q] === '"') q++;
          if (q > 5) fail('too many quotes', i);
          out += '"'.repeat(q - 3);
          i += q;
          return out;
        }
      } else if (c === '"') {
        i++;
        return out;
      } else if (c === '\n') fail('newline in string', start);
      if (c === '\\') {
        i++;
        const e = s[i];
        if (hasOwn(ESCAPES, e)) {
          out += ESCAPES[e];
          i++;
        } else if (e === 'u' || e === 'U') {
          const n = e === 'u' ? 4 : 8;
          const hex = s.slice(i + 1, i + 1 + n);
          if (hex.length !== n || !/^[0-9a-fA-F]+$/.test(hex)) fail('bad unicode escape');
          const cp = parseInt(hex, 16);
          if (cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) fail('bad unicode code point');
          out += String.fromCodePoint(cp);
          i += 1 + n;
        } else if (multi && /[ \t\n]/.test(e ?? '')) {
          let j = i;
          while (s[j] === ' ' || s[j] === '\t') j++;
          if (s[j] !== '\n') fail('invalid escape');
          while (s[j] === ' ' || s[j] === '\t' || s[j] === '\n') j++;
          i = j;
        } else fail('invalid escape');
      } else {
        out += c;
        i++;
      }
    }
  }

  function parseLiteralBody(multi) {
    const start = i;
    if (!multi) {
      const end = s.indexOf("'", i);
      const nl = s.indexOf('\n', i);
      if (end < 0 || (nl >= 0 && nl < end)) fail('unterminated literal string', start);
      const out = s.slice(i, end);
      i = end + 1;
      return out;
    }
    for (let j = i; j < s.length; j++) {
      if (s.startsWith("'''", j)) {
        let q = 0;
        while (s[j + q] === "'") q++;
        if (q > 5) fail('too many quotes', j);
        const out = s.slice(i, j) + "'".repeat(q - 3);
        i = j + q;
        return out;
      }
    }
    return fail('unterminated literal string', start);
  }

  function parseString() {
    const q = s[i];
    const multi = s.startsWith(q.repeat(3), i);
    i += multi ? 3 : 1;
    if (multi && s[i] === '\n') i++;
    return q === '"' ? parseBasicBody(multi) : parseLiteralBody(multi);
  }

  function parseKeyPart() {
    if (s[i] === '"') {
      if (s.startsWith('"""', i)) fail('multiline string as key');
      i++;
      return parseBasicBody(false);
    }
    if (s[i] === "'") {
      if (s.startsWith("'''", i)) fail('multiline string as key');
      i++;
      return parseLiteralBody(false);
    }
    const start = i;
    while (i < s.length && BARE.test(s[i])) i++;
    if (i === start) fail('expected key');
    return s.slice(start, i);
  }

  function parseKey() {
    const parts = [];
    for (;;) {
      skipWs();
      parts.push(parseKeyPart());
      skipWs();
      if (s[i] === '.') i++;
      else return parts;
    }
  }

  function parseNumberOrBare() {
    const start = i;
    while (i < s.length && !/[\s,\]}#]/.test(s[i])) i++;
    const t = s.slice(start, i);
    if (t === 'true') return true;
    if (t === 'false') return false;
    if (/^[+-]?inf$/.test(t)) return t[0] === '-' ? -Infinity : Infinity;
    if (/^[+-]?nan$/.test(t)) return NaN;
    const clean = (x) => x.replace(/_/g, '');
    if (/^[+-]?(0|[1-9](_?\d)*)$/.test(t)) return Number(clean(t));
    if (/^0x[0-9a-fA-F](_?[0-9a-fA-F])*$/.test(t)) return parseInt(clean(t).slice(2), 16);
    if (/^0o[0-7](_?[0-7])*$/.test(t)) return parseInt(clean(t).slice(2), 8);
    if (/^0b[01](_?[01])*$/.test(t)) return parseInt(clean(t).slice(2), 2);
    if (/^[+-]?(0|[1-9](_?\d)*)(\.\d(_?\d)*)?([eE][+-]?\d(_?\d)*)?$/.test(t)) return Number(clean(t));
    return fail('invalid value', start);
  }

  function parseValue(depth) {
    if (depth > MAX_DEPTH) fail('nesting too deep');
    const c = s[i];
    if (c === undefined || c === '\n') fail('missing value');
    if (c === '"' || c === "'") return parseString();
    if (c === '[') return parseArray(depth);
    if (c === '{') return parseInline(depth);
    if (/\d/.test(c)) {
      for (const re of [DATETIME, TIME]) {
        re.lastIndex = i;
        const m = re.exec(s);
        if (m) {
          i += m[0].length;
          return m[0];
        }
      }
    }
    return parseNumberOrBare();
  }

  function parseArray(depth) {
    i++;
    const arr = [];
    for (;;) {
      skipWsNlComments();
      if (i >= s.length) fail('unterminated array');
      if (s[i] === ']') {
        i++;
        return arr;
      }
      arr.push(parseValue(depth + 1));
      skipWsNlComments();
      if (s[i] === ',') i++;
      else if (s[i] !== ']') fail('expected , or ] in array');
    }
  }

  function assignDotted(table, keys, value, pos) {
    let t = table;
    for (let k = 0; k < keys.length - 1; k++) {
      const key = keys[k];
      if (hasOwn(t, key)) {
        const next = t[key];
        if (!isPlainObj(next) || (sealed.has(next) && !keySealedByDots.has(next)) || explicit.has(next)) fail('key conflicts with existing value', pos);
        t = next;
      } else {
        const next = {};
        sealed.add(next);
        keySealedByDots.add(next);
        setOwn(t, key, next);
        t = next;
      }
    }
    const last = keys[keys.length - 1];
    if (hasOwn(t, last)) fail(`duplicate key "${last}"`, pos);
    setOwn(t, last, value);
  }
  const keySealedByDots = new WeakSet();

  function parseInline(depth) {
    i++;
    const obj = {};
    sealed.add(obj);
    for (;;) {
      skipWsNlComments();
      if (i >= s.length) fail('unterminated inline table');
      if (s[i] === '}') {
        i++;
        return obj;
      }
      const pos = i;
      const keys = parseKey();
      skipWs();
      if (s[i] !== '=') fail('expected = after key');
      i++;
      skipWs();
      assignDotted(obj, keys, parseValue(depth + 1), pos);
      skipWsNlComments();
      if (s[i] === ',') i++;
      else if (s[i] !== '}') fail('expected , or } in inline table');
    }
  }

  // Walk the key path of a [header]; arrays resolve to their last element.
  function walk(keys, pos) {
    let t = root;
    for (let k = 0; k < keys.length - 1; k++) {
      const key = keys[k];
      let next;
      if (hasOwn(t, key)) {
        next = t[key];
        if (Array.isArray(next)) next = next[next.length - 1];
        if (!isPlainObj(next) || sealed.has(next)) fail('table path conflicts with existing value', pos);
      } else {
        next = {};
        setOwn(t, key, next);
      }
      t = next;
    }
    return t;
  }

  function parseHeader() {
    const pos = i;
    const isArr = s.startsWith('[[', i);
    i += isArr ? 2 : 1;
    const keys = parseKey();
    skipWs();
    if (isArr) {
      if (!s.startsWith(']]', i)) fail('expected ]] to close array of tables');
      i += 2;
    } else {
      if (s[i] !== ']') fail('expected ] to close table header');
      i++;
    }
    const parent = walk(keys, pos);
    const last = keys[keys.length - 1];
    if (isArr) {
      let arr;
      if (hasOwn(parent, last)) {
        arr = parent[last];
        if (!Array.isArray(arr) || !aot.has(arr)) fail(`"${last}" is not an array of tables`, pos);
      } else {
        arr = [];
        aot.add(arr);
        setOwn(parent, last, arr);
      }
      const t = {};
      explicit.add(t);
      arr.push(t);
      cur = t;
    } else {
      let t;
      if (hasOwn(parent, last)) {
        t = parent[last];
        if (!isPlainObj(t) || explicit.has(t) || sealed.has(t)) fail(`table "${last}" redefined`, pos);
      } else {
        t = {};
        setOwn(parent, last, t);
      }
      explicit.add(t);
      cur = t;
    }
    endOfLine();
  }

  while (i < s.length) {
    skipWsNlComments();
    if (i >= s.length) break;
    if (s[i] === '[') {
      parseHeader();
      continue;
    }
    const pos = i;
    const keys = parseKey();
    skipWs();
    if (s[i] !== '=') fail('expected = after key');
    i++;
    skipWs();
    assignDotted(cur, keys, parseValue(0), pos);
    endOfLine();
  }
  return root;
}

function lineAt(src, pos) {
  let line = 1;
  const end = Math.min(Math.max(pos, 0), src.length);
  for (let k = 0; k < end; k++) if (src[k] === '\n') line++;
  return line;
}

export function parseToml(text) {
  if (typeof text !== 'string') return { ok: false, error: 'input is not a string', line: 1 };
  const src = text.replace(/^﻿/, '').replace(/\r\n?/g, '\n');
  try {
    return { ok: true, value: parseDocument(src) };
  } catch (e) {
    if (e instanceof TomlError) return { ok: false, error: e.message, line: lineAt(src, e.pos) };
    return { ok: false, error: 'unparseable TOML', line: 1 };
  }
}
