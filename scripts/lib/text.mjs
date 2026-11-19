import os from 'node:os';

/**
 * Single source of truth for invisible / bidi / tag characters (escapes only, no raw characters):
 * U+200B-U+200F zero-width and direction marks, U+2060 word joiner, U+FEFF BOM/ZWNBSP,
 * U+202A-U+202E and U+2066-U+2069 bidi controls, U+E0000-U+E007F tag characters.
 */
export const INVISIBLE_CLASS = '\\u200B-\\u200F\\u2060\\uFEFF\\u202A-\\u202E\\u2066-\\u2069\\u{E0000}-\\u{E007F}';

/** Fresh global regex (own lastIndex) matching one invisible character. */
export const invisibleRegex = () => new RegExp(`[${INVISIBLE_CLASS}]`, 'gu');

/** Expand `~`, convert backslashes to `/`, lowercase on win32. */
export function normalizePath(p) {
  let s = String(p ?? '');
  if (s === '~' || s.startsWith('~/') || s.startsWith('~\\')) s = os.homedir() + s.slice(1);
  s = s.replace(/\\/g, '/');
  return process.platform === 'win32' ? s.toLowerCase() : s;
}

/** Render invisible / bidi / tag characters as \uXXXX escapes. */
export function escapeInvisible(s) {
  return String(s).replace(invisibleRegex(), ch => {
    const cp = ch.codePointAt(0);
    return cp > 0xFFFF
      ? '\\u{' + cp.toString(16).toUpperCase() + '}'
      : '\\u' + cp.toString(16).toUpperCase().padStart(4, '0');
  });
}

export function truncate(s, n = 200) {
  s = String(s);
  return s.length > n ? s.slice(0, n) + '…' : s;
}

const CODE = new Set(['js', 'mjs', 'cjs', 'ts', 'py', 'sh', 'ps1', 'bat', 'cmd']);
const CONFIG = new Set(['json', 'yaml', 'yml', 'toml']);
const BINARY = new Set(['exe', 'dll', 'so', 'dylib', 'node', 'bin']);

/** @returns {'markdown'|'code'|'config'|'binary'|'other'} */
export function classifyFile(relPath) {
  const base = String(relPath).replace(/\\/g, '/').split('/').pop().toLowerCase();
  const parts = base.split('.');
  if (parts.length < 2) return 'other';
  let ext = parts[parts.length - 1];
  // Inert fixtures: `name.X.txt` is classified as X.
  if (ext === 'txt' && parts.length >= 3) ext = parts[parts.length - 2];
  if (ext === 'md') return 'markdown';
  if (CODE.has(ext)) return 'code';
  if (CONFIG.has(ext)) return 'config';
  if (BINARY.has(ext)) return 'binary';
  return 'other';
}
