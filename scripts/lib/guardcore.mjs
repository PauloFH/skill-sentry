// Pure decision logic for the PreToolUse guard. Kept free of inventory/scanner imports so the
// common "no match" path stays fast.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { matchCommand, matchPath } from './rules.mjs';
import { escapeInvisible, truncate } from './text.mjs';
import { isCommandAllowed } from './allowlist.mjs';

// Path strings collected from MCP arguments; one more fails safe (PATH_UNRESOLVED).
const MAX_MCP_STRINGS = 128;
// Values visited in MCP arguments (iterative walk, any depth); one more fails safe.
const MAX_MCP_NODES = 50_000;
// MCP argument keys that carry content, never a path (content is never inspected, §6.2).
const MCP_CONTENT_KEYS = new Set(['content', 'contents', 'text', 'body', 'data', 'new_string', 'old_string', 'new_source', 'message', 'prompt']);
const MCP_WRITE_TOOL = /write|edit|create|move|copy|append|rename|delete|remove|upload|save|put/i;

const str = v => typeof v === 'string' && v.length > 0;
const pathLike = s => str(s) && s.length <= 4096 && !/[\r\n]/.test(s) && (s.includes('/') || s.includes('\\') || s.startsWith('~'));

// A scheme has 2+ characters: `C://Users/x` is a drive path (Node resolves it to `C:\Users\x`), not a URL.
const URL_LIKE = /^[a-z][\w+.-]+:\/\//i;
const MIME_TYPE = /^(?:application|audio|font|image|message|model|multipart|text|video)\/[a-z0-9][\w.+-]*$/i;
const SLASH_DATE = /^\d{1,4}\/\d{1,2}\/\d{1,4}$/;
/**
 * Strings that are not local paths: URLs, and MIME types / slash dates whose first segment does not
 * exist under cwd (`text/x` IS a path when `<cwd>/text` exists, e.g. a junction). One cached lstat
 * per distinct first segment; any error counts as "exists" (fail safe).
 */
function makeNonPath(cwd) {
  const exists = new Map();
  const segExists = seg => {
    if (!exists.has(seg)) {
      let e = true;
      try { e = fs.lstatSync(path.resolve(cwd || process.cwd(), seg), { throwIfNoEntry: false }) !== undefined; } catch { /* fail safe */ }
      exists.set(seg, e);
    }
    return exists.get(seg);
  };
  return s => URL_LIKE.test(s) || ((MIME_TYPE.test(s) || SLASH_DATE.test(s)) && !segExists(s.slice(0, s.indexOf('/'))));
}

/**
 * Collect path-like strings in encounter order, at any depth (iterative, so deep nesting cannot
 * overflow the stack). Non-path strings take no slot in the cap and are kept only if a path rule
 * matches them as written (`file:///…/.ssh/id_rsa`). `state.truncated` is set when the string cap
 * or node budget hid anything.
 */
function collectPathStrings(root, out, state, cwd) {
  const nonPath = makeNonPath(cwd);
  const stack = [[root, '']];
  const seen = new Set();
  let nodes = 1;
  while (stack.length) {
    const [value, key] = stack.pop();
    if (MCP_CONTENT_KEYS.has(key)) continue;
    if (typeof value === 'string') {
      if (seen.has(value) || !pathLike(value) || (nonPath(value) && !matchPath(value).length)) continue;
      if (out.length >= MAX_MCP_STRINGS) { state.truncated = true; return; }
      seen.add(value);
      out.push(value);
      continue;
    }
    if (!value || typeof value !== 'object') continue;
    const kids = Array.isArray(value) ? value.map(v => [v, '']) : Object.entries(value).map(([k, v]) => [v, k.toLowerCase()]);
    nodes += kids.length;
    if (nodes > MAX_MCP_NODES) { state.truncated = true; return; }
    for (let n = kids.length - 1; n >= 0; n--) stack.push(kids[n]);
  }
}

/**
 * Pull the inspectable targets out of a tool call. Write/Edit content is never returned.
 * @returns {{ commands: string[], readPaths: string[], writePaths: string[], urls: string[] }}
 */
export function extractTargets(toolName, toolInput) {
  return extractTargetsEx(toolName, toolInput).targets;
}

/** extractTargets plus `mcp` (targets came from MCP arguments) and `truncated` (some were not collected). */
function extractTargetsEx(toolName, toolInput, cwd) {
  const t = { commands: [], readPaths: [], writePaths: [], urls: [] };
  const state = { truncated: false, mcp: false };
  const i = toolInput && typeof toolInput === 'object' ? toolInput : {};
  switch (toolName) {
    case 'Bash':
    case 'PowerShell':
      if (str(i.command)) t.commands.push(i.command);
      break;
    case 'Read':
      if (str(i.file_path)) t.readPaths.push(i.file_path);
      break;
    case 'Grep':
      if (str(i.path)) t.readPaths.push(i.path);
      if (pathLike(i.glob)) t.readPaths.push(i.glob);
      break;
    case 'Glob':
      if (str(i.path)) t.readPaths.push(i.path);
      if (pathLike(i.pattern)) t.readPaths.push(i.pattern);
      break;
    case 'Write':
    case 'Edit':
    case 'MultiEdit':
      if (str(i.file_path)) t.writePaths.push(i.file_path);
      break;
    case 'NotebookEdit':
      if (str(i.notebook_path)) t.writePaths.push(i.notebook_path);
      break;
    case 'WebFetch':
      if (str(i.url)) t.urls.push(i.url);
      break;
    default:
      if (typeof toolName === 'string' && toolName.startsWith('mcp__')) {
        state.mcp = true;
        collectPathStrings(i, t.readPaths, state, cwd);
        if (MCP_WRITE_TOOL.test(toolName.slice(toolName.lastIndexOf('__') + 2))) t.writePaths.push(...t.readPaths);
      }
  }
  return { targets: t, ...state };
}

// ---- self-protection: canonical, case-insensitive (win32) comparison ----

function realpathish(abs) {
  const rest = [];
  let cur = abs;
  for (let n = 0; n < 64; n++) {
    try {
      return path.join(fs.realpathSync.native(cur), ...rest);
    } catch {
      const parent = path.dirname(cur);
      if (parent === cur) return abs;
      rest.unshift(path.basename(cur));
      cur = parent;
    }
  }
  return abs;
}

/** `~` expanded; nothing else (aliases are handled by the unusual-form classification). */
function plainPath(p) {
  let s = String(p);
  if (s === '~' || s.startsWith('~/') || s.startsWith('~\\')) s = os.homedir() + s.slice(1);
  return s;
}

// ---- Ruling K: unusual path forms (classified by string only, never touched on disk) ----

const DEVICE_OR_UNC = /^[\\/]{2}/;                                     // \\?\, \\.\, \\host\, //host/
const SHORT_NAME_SEGMENT = /(?:^|\/)[^/]{1,6}~\d+(?:\.[^/]{0,3})?(?:\/|$)/i; // 8.3 alias (CLAUDE~1, SETTIN~1.JSO)
const NTFS_STREAM = /::\$|:\$data/i;
// Path-shaped: absolute, home-relative or explicitly relative (MCP prose like "see a/b." is not).
const PATH_SHAPED = /^(?:[\\/]|~|\.{1,2}[\\/]|[a-z]:)/i;

/**
 * Device paths, UNC paths of any host, 8.3 short-name segments, NTFS stream suffixes, and components
 * ending in `.` or space (Win32 strips them) can alias protected files in ways string and realpath
 * comparison cannot follow without network or device I/O.
 */
export function isUnusualPath(p) {
  const s = String(p);
  if (URL_LIKE.test(s)) return false;
  const fwd = s.replace(/\\/g, '/');
  if (DEVICE_OR_UNC.test(s) || SHORT_NAME_SEGMENT.test(fwd) || NTFS_STREAM.test(s)) return true;
  return fwd.split('/').some(c => c !== '.' && c !== '..' && /[. ]$/.test(c));
}

// Distinct ordinary paths that get realpath + stat in one decision (covers MAX_MCP_STRINGS read+write).
const MAX_IO_PATHS = MAX_MCP_STRINGS * 2;

const normForCompare = s => {
  let out = String(s).replace(/\\/g, '/');
  if (out.length > 1 && out.endsWith('/')) out = out.replace(/\/+$/, '');
  return process.platform === 'win32' ? out.toLowerCase() : out;
};

/** Canonical form of a protected root (trusted configuration, resolved without the budget). */
function canonRoot(r) {
  return normForCompare(realpathish(path.resolve(r)));
}

const fileId = p => {
  try {
    const st = fs.statSync(p, { bigint: true, throwIfNoEntry: false });
    return st && st.ino !== 0n ? `${st.dev}:${st.ino}` : null;
  } catch { return null; }
};

/**
 * Per-decision path resolver. Spelling-dependent facts (unusual form, URL) are computed per call from
 * the raw string; only I/O results (`long`, parent id) are cached, keyed by the normalized absolute
 * path, so a skipped spelling never hides the resolution of another spelling of the same file. At most
 * one realpath (plus one parent stat for writes) per distinct ordinary path, within MAX_IO_PATHS.
 */
function makeResolver(cwd, mcp) {
  const io = new Map();
  const state = { left: MAX_IO_PATHS, unresolved: false };
  const get = p => {
    const raw = String(p);
    let abs = raw;
    try { abs = path.resolve(cwd || process.cwd(), plainPath(raw)); } catch { /* keep raw */ }
    const checkForm = !mcp || PATH_SHAPED.test(raw);
    const unusual = checkForm && (isUnusualPath(raw) || isUnusualPath(abs));
    if (unusual || (mcp && URL_LIKE.test(raw))) return { abs, long: null, unusual, io: null };
    const key = normForCompare(abs);
    let e = io.get(key);
    if (!e) {
      if (state.left <= 0) { state.unresolved = true; return { abs, long: null, unusual, io: null }; }
      state.left--;
      let long = null;
      try { long = realpathish(abs); } catch { long = null; }
      e = { long, parentId: undefined };
      io.set(key, e);
    }
    // A resolved form that is itself unusual (mapped drive -> UNC, volume without a letter) fails safe too.
    // Unchecked MCP strings keep their raw tail, so only the resolved prefix (device/UNC) counts for them.
    const longUnusual = e.long !== null && (checkForm ? isUnusualPath(e.long) : DEVICE_OR_UNC.test(e.long));
    return { abs, long: e.long, unusual: longUnusual, io: e };
  };
  const parentId = r => {
    if (!r.io) return null;
    if (r.io.parentId === undefined) r.io.parentId = r.long ? fileId(path.dirname(r.long)) : null;
    return r.io.parentId;
  };
  return { get, parentId, state };
}

const isUnder = (p, root) => p === root || p.startsWith(root.endsWith('/') ? root : root + '/');

const reEscape = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
// Hosts that make a UNC admin share (`\\host\C$\...`) point back at a local drive (shell text only).
const LOCAL_HOST = `(?:localhost|127\\.0\\.0\\.1|\\[?::1\\]?${os.hostname() ? '|' + reEscape(os.hostname()) : ''})`;
const ADMIN_SHARE_IN_TEXT = new RegExp(`//(?:[?.]/unc/)?${LOCAL_HOST}/([a-z])\\$(?=/|$|[\\s'"])`, 'gi');

const lowerOnWin = s => (process.platform === 'win32' ? s.toLowerCase() : s);
const slashes = s => String(s).replace(/\\/g, '/').replace(/\/+$/, '');

/**
 * Shell text with backslashes -> '/', local admin shares -> drive letters, home references expanded,
 * `//` and `/./` collapsed, lowercased on win32.
 */
function normCommandText(cmd) {
  const home = slashes(os.homedir());
  let s = String(cmd).replace(/\\/g, '/');
  s = s.replace(ADMIN_SHARE_IN_TEXT, '$1:');
  s = s.replace(/\$\{HOME\}|\$HOME\b|%USERPROFILE%|%HOMEDRIVE%%HOMEPATH%|\$\{env:USERPROFILE\}|\$env:USERPROFILE\b|\$env:HOME\b/gi, home);
  s = s.replace(/(^|[\s'"=(:;|&>])~(?=\/|$|[\s'";|&)])/g, (_, pre) => pre + home);
  for (let prev = ''; prev !== s;) { prev = s; s = s.replace(/\/\.(?=\/)/g, ''); }
  s = s.replace(/\/{2,}/g, '/');
  return lowerOnWin(s);
}

// `skill-sentry` path segment (any spelling: absolute, relative after `cd ~/.claude`, bare), not
// `some-skill-sentry-fork`. Boundary on both sides = start/end or any character outside [\w.-] (same
// notion as `mentions`). Trailing dots/spaces are accepted (Ruling K): Win32 strips them, so
// `skill-sentry.\x` is the same dir. Groups: 1 = left boundary, 2 = trailing dots/spaces.
const SELF_SEGMENT = /(^|[^\w.-])skill-sentry([. ]*)(?=$|[^\w.-])/gi;
const SEG_LEN = 'skill-sentry'.length;

// ---- Ruling R9: a `skill-sentry` segment asks only when it can name the data or install dir ----

// Rule 4: a data-dir file name right after the segment.
const DATA_FILE_AFTER = /^["']*\/["']*(?:allowlist\.json|baseline\.json|guard\.log|guard-sessions|reports)/i;
// Rule 1: parents that can hold the data dir (`.claude`) or the install dir (`plugins/cache/<mkt>/<name>`).
const PROTECTED_PARENTS = new Set(['.claude', 'cache', 'plugins', 'skill-sentry']);
// Rule 2: a path prefix is literal only if made of these characters (quotes removed first). Anything else
// (`$`, `%`, `*`, `?`, `[`, `{`, backtick, `(`, `~user`/`~-`/8.3 `~`, control or exotic spaces) asks.
const LITERAL_PREFIX = /^[\p{L}\p{N}_.:/-]*$/u;
// Rule 2: a glob, brace or expansion character touching the segment itself (`skill-sentry*`, `{a,skill-sentry}`).
const GLOB_NEIGHBOR = /[*?[\]{},$%`]/;
// Rule 3 contexts: the text names Claude's home, or computes paths (variables, substitutions, grouping).
const CLAUDE_TEXT = /\.claude|plugins/i;
const DYNAMIC_TEXT = /[$%`({@]/;
// Any segment asks when the same command can make a literal path point at Claude's home: it names a
// `.claude` path segment (not `.claude-plugin`) or links/moves something (`ln -s ~/.cl?ude /tmp/j &&
// rm -rf /tmp/j/skill-sentry`). Links made by an earlier command are caught by realpath instead.
const CLAUDE_SEGMENT = /(?:^|[^\w.-])\.claude[. ]*(?=$|[^\w.-])/i;
const LINK_OR_MOVE = /(?:^|[\s;&|({])(?:ln|mklink|subst|mount|mv|move|ren|rename|robocopy|new-item|ni|move-item|mi|rename-item|rni)(?=$|[\s;&|)])/i;
// Ruling K in shell text: a UNC/device path token (collapsed later by normCommandText).
const UNC_TOKEN = /(?:^|[\s'"=(<>|;&,])[\\/]{2}(?![\\/])/;
// Characters that end a path token when walking back from the segment.
const TOKEN_BOUNDARY = /[\s=<>|;&]/;
// Directory changes; group 1 = command, group 2 = its argument text up to the next statement end.
const CD_COMMAND = /(?:^|[\s;&|({])(cd|chdir|pushd|popd|sl|set-location|push-location|pop-location)(?=$|[\s;&|)])([^;&|\n)]*)/gi;
const CD_LITERAL = /^[\p{L}\p{N}_.:/ "'-]*$/u;

/**
 * Directory changes in normalized shell text: `nonLiteral` when any target is computed, globbed,
 * `-`, or a stack pop; otherwise the literal targets (quotes and parameter names removed).
 */
function cdTargets(text) {
  const out = { nonLiteral: false, literal: [] };
  for (const m of text.matchAll(CD_COMMAND)) {
    const cmd = m[1].toLowerCase();
    let arg = m[2].trim();
    if (cmd === 'popd' || cmd === 'pop-location' || arg === '-' || arg.startsWith('- ') || !CD_LITERAL.test(arg)) {
      out.nonLiteral = true;
      continue;
    }
    while (/^--?[a-z][\w-]*(?:\s+|$)|^--(?:\s+|$)/i.test(arg)) arg = arg.replace(/^--?[\w-]*\s*/, '');
    const q = /^["']/.test(arg) ? arg[0] : null;
    const close = q ? arg.indexOf(q, 1) : -1;
    const target = q ? arg.slice(1, close === -1 ? undefined : close) : arg.split(/\s+/)[0];
    if (target) out.literal.push(target);
  }
  return out;
}

/**
 * Whether a normalized shell text names the data or install dir through a `skill-sentry` segment
 * (Ruling R9). `ctx` supplies lazily computed facts shared by every text of one command.
 */
function segmentAsks(text, ctx) {
  for (const m of text.matchAll(SELF_SEGMENT)) {
    const start = m.index + m[1].length;
    const end = start + SEG_LEN + m[2].length;
    if (DATA_FILE_AFTER.test(text.slice(end))) return true; // rule 4
    if (ctx.unc || ctx.relinks()) return true; // Ruling K; same-command link, move or `.claude` path
    const prev = text[start - 1] ?? '';
    if (GLOB_NEIGHBOR.test(prev) || GLOB_NEIGHBOR.test(text[end] ?? '')) return true; // rule 2 (segment)
    let token = 'skill-sentry';
    let relative = true; // bare
    if (prev === '/') {
      let s = start - 1;
      while (s > 0 && !TOKEN_BOUNDARY.test(text[s - 1])) s--;
      const prefix = text.slice(s, start).replace(/["']/g, '');
      if (!LITERAL_PREFIX.test(prefix)) return true; // rule 2 (parent)
      const comps = prefix.split('/').slice(0, -1).map(c => (c === '.' || c === '..' ? c : c.replace(/[. ]+$/, '').toLowerCase()));
      if (PROTECTED_PARENTS.has(comps[comps.length - 1]) || comps.includes('.claude')) return true; // rule 1
      relative = comps.includes('.') || comps.includes('..');
      token = prefix + token;
    }
    if (relative && ctx.risky()) return true; // rule 3
    if (ctx.resolvesProtected(token)) return true; // literal spelling of a protected dir (junction, cwd)
  }
  return false;
}

/** Lazily computed context for segmentAsks over the texts of one command. */
function segmentContext(raw, texts, { roots, cwd }) {
  const base = str(cwd) ? cwd : process.cwd();
  let claude;
  const claudeForms = () => (claude ??= rootForms(path.join(os.homedir(), '.claude')));
  const hits = f => roots.some(r => isUnder(f, r) || isUnder(r, f)) || claudeForms().some(c => isUnder(f, c));
  let cds;
  const cdInfo = () => {
    if (!cds) {
      cds = { nonLiteral: false, literal: [] };
      for (const t of texts) {
        const c = cdTargets(t);
        cds.nonLiteral ||= c.nonLiteral;
        cds.literal.push(...c.literal);
      }
    }
    return cds;
  };
  let risky;
  let relinks;
  let bases;
  const seen = new Map();
  return {
    unc: UNC_TOKEN.test(raw),
    relinks: () => (relinks ??= texts.some(t => CLAUDE_SEGMENT.test(t) || LINK_OR_MOVE.test(t))),
    risky: () => (risky ??= rootForms(base).some(f => [...roots, ...claudeForms()].some(r => isUnder(f, r)))
      || texts.some(t => CLAUDE_TEXT.test(t) || DYNAMIC_TEXT.test(t))
      || cdInfo().nonLiteral),
    resolvesProtected: token => {
      bases ??= [base, ...cdInfo().literal.map(c => path.resolve(base, c))];
      for (const b of bases) {
        let abs;
        try { abs = path.resolve(b, token); } catch { return true; }
        if (!seen.has(abs)) seen.set(abs, [lowerOnWin(slashes(abs)), canonRoot(abs)].some(hits));
        if (seen.get(abs)) return true;
      }
      return false;
    },
  };
}

/**
 * De-obfuscated copy of a shell command, used only to ADD matches: drops cmd `^` escapes,
 * PowerShell backtick escapes, backslash-before-alphanumeric, empty quote pairs, and quotes
 * around a single word (`c''url`, `c^url`, `s\h`, `"sh"`).
 */
export function deobfuscate(cmd) {
  return String(cmd)
    .replace(/\^/g, '')
    .replace(/`(?=[A-Za-z])/g, '')
    .replace(/\\(?=[A-Za-z0-9])/g, '')
    .replace(/''|""/g, '')
    .replace(/(["'])([^\s"']+)\1/g, '$2');
}

/** `needle` occurs in `text` and is not just a prefix of a longer name (`skill-sentry-x`). */
function mentions(text, needle) {
  if (!needle) return false;
  for (let i = text.indexOf(needle); i !== -1; i = text.indexOf(needle, i + 1)) {
    const next = text[i + needle.length];
    if (next === undefined || !/[\w.-]/.test(next)) return true;
  }
  return false;
}

/** Normalized text forms of a protected root: as given (resolved) and canonical (realpath). */
function rootForms(r) {
  return [...new Set([lowerOnWin(slashes(path.resolve(r))), canonRoot(r)])].filter(f => f.length > 3);
}

// ---- Ruling M: read-only invocations of our own scripts ----

// Only fixed token lists are exempt from SELF_PROTECT; no shell argument is parsed beyond them
// (PowerShell's grammar - arrays from `,`, splatting, dropped empty strings - kept defeating that):
//   node <scanPath> [--json | --diff-only]...      node <hardenPath> check
// `<path>` is bare or wrapped in one pair of matching quotes, absolute (`X:\`, `X:/` or `/`), and made
// only of `[A-Za-z0-9 ._:/\~-]` (space only when quoted, `\` only under PowerShell). Anything else,
// including every value-taking flag, keeps the prompt.
const SELF_INVOCATION = /^node(?:\.exe)? +(?:"([^"]*)"|'([^']*)'|([^ "']+))((?: +[^ ]+)*) *$/i;
const SELF_PATH = /^[A-Za-z0-9 ._:/\\~-]+$/;

/** Exact read-only self invocation (Ruling M); mutating or parameterized forms return false. */
export function isReadOnlySelfInvocation(cmd, selfRoot, toolName = 'Bash') {
  if (!str(cmd) || !str(selfRoot)) return false;
  const m = SELF_INVOCATION.exec(cmd);
  if (!m) return false;
  const script = m[1] ?? m[2] ?? m[3];
  if (!SELF_PATH.test(script) || (m[3] !== undefined && script.includes(' '))) return false;
  if (script.includes('\\') && toolName !== 'PowerShell') return false;
  if (!/^(?:[A-Za-z]:[\\/]|\/(?![\\/]))/.test(script) || isUnusualPath(script)) return false;
  const target = lowerOnWin(slashes(path.resolve(script)));
  const is = name => rootForms(selfRoot).some(f => target === `${f}/scripts/${lowerOnWin(name)}`);
  const args = m[4].split(' ').filter(Boolean);
  if (is('harden.mjs')) return args.length === 1 && args[0] === 'check';
  return is('scan.mjs') && args.every(a => a === '--json' || a === '--diff-only');
}

// ---- decision ----

const resolveLazy = v => (typeof v === 'function' ? v() : v);
const snip = s => truncate(escapeInvisible(String(s ?? '')), 200);
const WRITE_PROTECTED = m => m.category === 'persistence' || m.ruleId === 'SECRET_PATH_SSH';

/**
 * Command/URL matches. A secret and an exfil match in the same statement (pipeline; split on
 * `;`, `&&`, `||`, newlines) escalate the exfil match to critical, as scoring does per file.
 * Separate statements (`export $(cat .env) && curl -d @body.json ...`) stay high.
 */
function textMatches(text, target) {
  const ms = matchCommand(text);
  const escalate = new Set();
  if (ms.some(m => m.category === 'secret') && ms.some(m => m.category === 'exfil')) {
    const statements = text.replace(/\\\r?\n[ \t]*/g, ' ').split(/&&|\|\||;|\r?\n/);
    for (const s of statements) {
      const sm = matchCommand(s);
      if (sm.some(m => m.category === 'secret')) for (const m of sm) if (m.category === 'exfil') escalate.add(m.ruleId);
    }
  }
  return ms.map(m => (escalate.has(m.ruleId) && m.severity !== 'critical'
    ? { ...m, severity: 'critical', escalated: true, target } : { ...m, target }));
}

const RANK = { critical: 3, high: 2, medium: 1, info: 0 };

/** Matches on the raw command plus its de-obfuscated copy (union per rule, higher severity wins). */
function commandMatches(target) {
  const out = textMatches(target, target);
  const clean = deobfuscate(target);
  if (clean === target) return out;
  for (const m of textMatches(clean, target)) {
    const i = out.findIndex(x => x.ruleId === m.ruleId);
    if (i === -1) out.push(m);
    else if (RANK[m.severity] > RANK[out[i].severity]) out[i] = m;
  }
  return out;
}

/** Path rule matches on the path as given plus its resolved long form (symlinks, junctions, subst). */
function pathMatches(p, keep, R) {
  const out = matchPath(p).filter(keep).map(m => ({ ...m, target: p }));
  const { long } = R.get(p);
  if (long && long !== p) {
    for (const m of matchPath(long)) {
      if (keep(m) && !out.some(x => x.ruleId === m.ruleId)) out.push({ ...m, snippet: snip(p), target: p });
    }
  }
  return out;
}

const synthetic = (ruleId, p) => ({ ruleId, category: 'path', severity: 'high', snippet: snip(p), target: p });

/**
 * Decide what to do with one tool call.
 * `origin` and `allowlist` may be values or zero-arg functions; functions are only called when the
 * decision depends on them (origin for `high`, allowlist for `critical`).
 * @returns {{ decision: 'deny'|'ask'|'log'|'none', ruleId?: string, severity?: string, reason?: string, snippet?: string }}
 */
export function decide({ toolName, toolInput, origin = null, allowlist = null, selfRoot, dataDir, cwd }) {
  const { targets: t, mcp, truncated } = extractTargetsEx(toolName, toolInput, cwd);
  const matches = [];
  for (const c of t.commands) matches.push(...commandMatches(c));
  for (const u of t.urls) matches.push(...commandMatches(u));
  const R = makeResolver(cwd, mcp);
  for (const p of t.readPaths) matches.push(...pathMatches(p, m => m.category === 'secret', R));
  for (const p of t.writePaths) matches.push(...pathMatches(p, WRITE_PROTECTED, R));

  const critical = matches.filter(m => m.severity === 'critical');
  if (critical.length) {
    const al = resolveLazy(allowlist) ?? { entries: [] };
    const blocked = critical.filter(m => !isCommandAllowed(al, { ruleId: m.ruleId, command: m.target }));
    if (blocked.length) {
      const m = blocked[0];
      return { decision: 'deny', ruleId: m.ruleId, severity: 'critical', reason: 'critical rule match', snippet: m.snippet };
    }
  }

  // Shell commands that mention the data dir or the install dir (any access, read or write) always ask:
  // a redirect like `echo ... > ~/.claude/skill-sentry/allowlist.json` must not slip through (§6.2).
  // Other `skill-sentry` segments ask only when they can name one of those dirs (Ruling R9).
  if (t.commands.length) {
    const roots = [dataDir, selfRoot].filter(str).flatMap(rootForms);
    const needles = [...roots, lowerOnWin('.claude/skill-sentry')];
    for (const c of t.commands) {
      if (isReadOnlySelfInvocation(c, selfRoot, toolName)) continue; // Rulings L2, L3
      // Line continuations (bash `\`, PowerShell backtick) are joined in the de-obfuscated copy.
      const joined = String(c).replace(/\\\r?\n/g, '').replace(/`\r?\n/g, ' ');
      const texts = [normCommandText(c), normCommandText(deobfuscate(joined))];
      const ctx = segmentContext(c, texts, { roots, cwd });
      if (texts.some(text => needles.some(n => mentions(text, n)) || segmentAsks(text, ctx))) {
        return { decision: 'ask', ruleId: 'SELF_PROTECT', severity: 'high', reason: 'shell command touches skill-sentry data or install directory', snippet: snip(c) };
      }
    }
  }

  if (t.writePaths.length) {
    const protectedRoots = [dataDir, selfRoot].filter(str);
    const roots = protectedRoots.map(canonRoot);
    const rootIds = new Set(protectedRoots.map(r => fileId(path.resolve(r))).filter(Boolean));
    for (const p of t.writePaths) {
      const r = R.get(p);
      const c = normForCompare(r.long ?? r.abs);
      if (roots.some(root => isUnder(c, root)) || (r.long && rootIds.size && rootIds.has(R.parentId(r)))) {
        return { decision: 'ask', ruleId: 'SELF_PROTECT_WRITE', severity: 'high', reason: 'write to skill-sentry data or install directory', snippet: snip(p) };
      }
    }
    // Ruling K: unusual write forms always ask (they may alias a protected file).
    const odd = t.writePaths.find(p => R.get(p).unusual);
    if (odd !== undefined) {
      return { decision: 'ask', ruleId: 'PATH_UNUSUAL_WRITE', severity: 'high', reason: 'write target uses an unusual path form', snippet: snip(odd) };
    }
  }

  // Ruling K: unusual read forms, and paths left unchecked (budget or collection cap), count as high.
  const oddRead = t.readPaths.find(p => R.get(p).unusual);
  if (oddRead !== undefined) matches.push(synthetic('PATH_UNUSUAL_READ', oddRead));
  if (R.state.unresolved || truncated) {
    matches.push({ ...synthetic('PATH_UNRESOLVED', ''), snippet: truncated ? 'tool arguments not fully inspected' : 'path budget exhausted' });
  }

  const high = matches.find(m => m.severity === 'high');
  if (high) {
    const o = resolveLazy(origin);
    return { decision: o ? 'ask' : 'log', ruleId: high.ruleId, severity: 'high', reason: 'high-risk rule match', snippet: high.snippet };
  }
  return { decision: 'none' };
}

/** One-line component check summary for the guard reason. */
export function scanSummary({ incomplete, verdict, score, count }) {
  if (incomplete) return 'component check skipped (time budget)';
  return `component verdict: ${verdict} (score ${score}), ${count} finding${count === 1 ? '' : 's'}`;
}

/**
 * Human-readable reason shown by Claude Code with the deny/ask prompt.
 * @param {{ decision: string, ruleId?: string, severity?: string, snippet?: string }} d
 * @param {string|null} originLabel
 * @param {string|null} summary
 */
export function formatReason(d, originLabel, summary) {
  // Quotes, C0 controls (ESC included) and DEL become \xNN: the quoted snippet cannot be closed early
  // and no terminal escape sequence reaches the prompt.
  const show = s => snip(s).replace(/[\x00-\x1f\x7f"]/g, ch => '\\x' + ch.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0'));
  const verb = d.decision === 'deny' ? 'blocked' : 'needs confirmation';
  const parts = [`skill-sentry: ${verb} by rule ${d.ruleId} (${d.severity}): "${show(d.snippet)}"`];
  parts.push(originLabel ? `likely source: ${show(originLabel)}` : 'no skill/plugin attributed');
  if (summary) parts.push(summary);
  let s = parts.join('; ') + '.';
  if (originLabel) s += ' Run /skill-sentry:audit for a full report.';
  return s;
}

/** Map an origin onto an inventoried component id (skill-sentry itself is never returned). */
export function originToComponentId(origin, components) {
  if (!origin || !Array.isArray(components)) return null;
  const base = c => {
    const n = String(c.name ?? '');
    const at = n.lastIndexOf('@');
    return at > 0 ? n.slice(0, at) : n;
  };
  const plugins = components.filter(c => c && c.kind === 'plugin' && !c.self);
  if (str(origin.mcpPlugin)) {
    const exact = plugins.find(c => base(c) === origin.mcpPlugin);
    if (exact) return exact.id;
    if (str(origin.mcpQualified)) {
      const cands = plugins.filter(c => origin.mcpQualified.startsWith(base(c) + '_'));
      cands.sort((a, b) => base(b).length - base(a).length);
      if (cands.length) return cands[0].id;
    }
    return null;
  }
  if (str(origin.skill)) {
    const colon = origin.skill.indexOf(':');
    if (colon > 0) return plugins.find(c => base(c) === origin.skill.slice(0, colon))?.id ?? null;
    for (const scope of ['user', 'project']) {
      const c = components.find(x => x && x.kind === 'skill' && x.scope === scope && x.name === origin.skill && !x.self);
      if (c) return c.id;
    }
  }
  return null;
}
