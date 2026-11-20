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

/** Attacker-influenced text (ids, names, paths, snippets) as shown to Claude: escaped, then capped. */
export const untrusted = s => truncate(escapeInvisible(s ?? ''), 200);

const R = '<redacted>';
// Flags whose value is a credential: --token, --api-key, --apikey, --key, --secret, --password, --auth,
// --bearer, also with a prefix (--access-token, --client-secret).
const SECRET_FLAG_NAME = '--(?:[\\w-]*-)?(?:token|api-?key|key|secret|password|passwd|auth|bearer)';
const SECRET_FLAG = new RegExp(`(^|\\s)(${SECRET_FLAG_NAME})(=|\\s+)("[^"]*"|'[^']*'|\\S+)`, 'gi');
const SECRET_FLAG_EXACT = new RegExp(`^${SECRET_FLAG_NAME}$`, 'i');
// `-p <value>` is a password only for these commands; for npx/npm/pnpm/yarn/uvx/bunx it names a package
// (shown so a package swap stays visible), for docker a port.
// A package runner or container tool in the text wins: its `-p` is never treated as a password.
const PASSWORD_P_CMD = /(?:^|[\s/\\"'])(?:sshpass|mysql|mysqladmin|mysqldump|mariadb|mongo|mongosh)(?:\.exe)?(?=[\s"']|$)/i;
const P_RUNNER = /(?:^|[\s/\\"'])(?:npx|npm|pnpm|yarn|uvx|bunx|bun|docker|podman)(?:\.exe|\.cmd)?(?=[\s"']|$)/i;
const pIsPasswordIn = text => PASSWORD_P_CMD.test(text) && !P_RUNNER.test(text);
const P_FLAG = /(^|\s)(-p)(=|\s+)("[^"]*"|'[^']*'|\S+)/g;
const SECRET_ASSIGN = /(^|\s)([A-Za-z_][\w.-]*)=("[^"]*"|'[^']*'|\S+)/g;
const SECRET_NAME = /token|secret|key|pass|auth/i;
const URL_RE = /[a-z][\w+.-]*:\/\/[^\s"'<>]+/gi;
/** Well-known credential shapes (Anthropic/OpenAI, GitHub, Slack, AWS, Google, GitLab). */
export const TOKEN_SHAPES = /\b(?:sk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|xox[abprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|glpat-[A-Za-z0-9_-]{20,})/;
const TOKEN_SHAPES_G = new RegExp(TOKEN_SHAPES.source, 'g');
// `Name: value` where Name names a credential (X-Api-Key, Authorization, Cookie, ...); not `scheme://`.
const HEADER_FORM = /\b((?=[\w-]*(?:key|token|auth|secret|cookie|session|passw))[A-Za-z][\w-]*)(["']?)(\s*:\s*)(?!\/\/)((?:(?:Bearer|Basic|Token)\s+)?[^\s"',;]+)/gi;
// Bot API token in a URL path: /bot<digits>:<token>.
const BOT_TOKEN = /(\/bot)\d{5,}:[A-Za-z0-9_-]{20,}/g;

/**
 * Hide credentials in config text before it is stored or shown: URL `user:password@` and query values,
 * values after credential flags, `KEY=value` when KEY names a secret, `Bearer`/`Basic` tokens,
 * `Name: value` credential headers, bot tokens in URL paths and well-known token shapes.
 */
export function redactSecrets(str) {
  let s = String(str ?? '');
  s = s.replace(URL_RE, url => url
    .replace(/^([a-z][\w+.-]*:\/\/)[^/?#@\s]*@/i, `$1${R}@`)
    .replace(/\?([^#]*)/, (_, q) => '?' + q.split('&').map(kv => (kv.includes('=') ? kv.slice(0, kv.indexOf('=') + 1) + R : kv)).join('&')));
  s = s.replace(SECRET_FLAG, (_, pre, flag, sep) => `${pre}${flag}${sep}${R}`);
  if (pIsPasswordIn(s)) s = s.replace(P_FLAG, (_, pre, flag, sep) => `${pre}${flag}${sep}${R}`);
  s = s.replace(SECRET_ASSIGN, (m, pre, key) => (SECRET_NAME.test(key) ? `${pre}${key}=${R}` : m));
  s = s.replace(/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}/g, `$1 ${R}`);
  s = s.replace(BOT_TOKEN, `$1${R}`);
  s = s.replace(HEADER_FORM, (m, name, q, sep, val) => {
    const scheme = /^(?:Bearer|Basic|Token)\s+/i.exec(val)?.[0] ?? '';
    const rest = val.slice(scheme.length);
    if (rest === R || rest.startsWith(R) || /^(?:Bearer|Basic|Token)$/i.test(val)) return m;
    return `${name}${q}${sep}${scheme}${R}`;
  });
  s = s.replace(TOKEN_SHAPES_G, R);
  return s;
}

/**
 * redactSecrets over an argv array: also hides the element that follows a bare credential flag
 * (`-p` only when `command` itself is a password-taking command, decided by its basename).
 */
export function redactArgs(args, command = '') {
  const out = [];
  const base = String(command ?? '').trim().split(/\s+/)[0].replace(/^.*[\\/]/, '');
  const pIsPassword = pIsPasswordIn(base);
  for (let i = 0; i < args.length; i++) {
    const a = String(args[i]);
    const prev = i > 0 ? String(args[i - 1]) : '';
    const flagBefore = SECRET_FLAG_EXACT.test(prev) || (pIsPassword && prev === '-p');
    out.push(flagBefore ? R : redactSecrets(a));
  }
  return out;
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
