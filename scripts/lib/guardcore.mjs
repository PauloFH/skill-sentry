// Pure decision logic for the PreToolUse guard. Kept free of inventory/scanner imports so the
// common "no match" path stays fast.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { matchCommand, matchPath, CODEX_CONTROL_TAIL } from './rules.mjs';
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

/** Normalized shell text with `name/..` pairs removed (`.claude/plugins/../skill-sentry`), for needles. */
function collapseDotDot(s) {
  for (let prev = '', n = 0; prev !== s && n < 64; n++) {
    prev = s;
    s = s.replace(/\/(?!\.\.(?:[/\s'";|&)]|$))[^/\s'";|&()]+\/\.\.(?=[/\s'";|&)]|$)/g, '');
  }
  return s;
}

// `skill-sentry` path segment, not `some-skill-sentry-fork`. Boundary on both sides = start/end or any
// character outside [\w.-] (same notion as `mentions`). Trailing dots/spaces are accepted (Ruling K):
// Win32 strips them, so `skill-sentry.\x` is the same dir.
const SELF_SEGMENT = /(?:^|[^\w.-])skill-sentry[. ]*(?=$|[^\w.-])/i;

// Final review C1: a skill-sentry copy installed for the other agent (or from another marketplace) is not the
// guard's own install dir, yet tampering with it disables that agent's guard. Any `skill-sentry` segment below a
// `plugins/cache/` directory (`<home>/plugins/cache/<mkt>/skill-sentry/<version>`, or the marketplace dir itself
// named skill-sentry), of any Claude or Codex home, custom ones included, is protected; so is one directly below
// a `.claude` or `.codex` directory. Tested on normalized (`/`-separated) absolute paths.
const SIBLING_INSTALL = /(?:^|\/)plugins\/cache\/(?:[^/]+\/)?skill-sentry[. ]*(?:\/|$)/i;
const AGENT_HOME_CHILD = /(?:^|\/)\.(?:claude|codex)[. ]*\/skill-sentry[. ]*(?:\/|$)/i;
const siblingInstall = f => SIBLING_INSTALL.test(f) || AGENT_HOME_CHILD.test(f);

// ---- Ruling R9 (revised): one narrow exemption from the segment rule ----
// Every `skill-sentry` segment asks (Ruling J) unless its shell word is a literal absolute path that
// resolves (as written and through realpath) outside `~/.claude` and away from every protected root.

/**
 * Shell words of a command, quote-aware: `value` is the word as the shell would pass it (quotes
 * removed, escapes applied, `\` -> `/` where it is a separator), `raw` the source text with `\` -> `/`,
 * `literal` false when the word uses an escape (bash `\`, PowerShell backtick, cmd `^`) or an
 * unbalanced quote, and `cmd` true for a word in command position (statement start, or after
 * `;`, `&`, `|` or a newline). `sep` holds the unquoted separators (`;`, `&`, `|`, newline) seen since
 * the previous word ('' inside a statement; the `&` of `2>&1` and `&>` is a redirect, not a separator).
 * Never throws.
 */
function shellWords(cmd, ps) {
  const words = [];
  const s = String(cmd);
  let cur = null;
  let quote = null;
  let atCommand = true;
  let afterRedirect = false;
  let pendingSep = '';
  const begin = i => {
    if (!cur) {
      cur = { value: '', raw: '', start: i, literal: true, cmd: atCommand && !afterRedirect, sep: pendingSep };
      pendingSep = '';
    }
  };
  const end = i => {
    if (cur) {
      cur.raw = s.slice(cur.start, i).replace(/\\/g, '/');
      words.push(cur);
      if (cur.cmd) atCommand = false;
      afterRedirect = false;
      cur = null;
    }
  };
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    const next = s[i + 1];
    if (quote === "'") {
      if (ch === "'" && ps && next === "'") { cur.value += "'"; i++; } else if (ch === "'") quote = null;
      else cur.value += ch === '\\' ? '/' : ch;
      continue;
    }
    if (quote === '"') {
      if (ch === '"') { if (ps && next === '"') { cur.value += '"'; i++; } else quote = null; continue; }
      if (ch === '`' && ps) { cur.literal = false; if (next !== undefined) { cur.value += next; i++; } continue; }
      if (ch === '\\' && !ps && next !== undefined && '$`"\\\n'.includes(next)) { cur.literal = false; cur.value += next; i++; continue; }
      cur.value += ch === '\\' ? '/' : ch;
      continue;
    }
    if (/\s/.test(ch)) {
      end(i);
      // A lone CR ends a statement in PowerShell (fix round 1, I1): count it as a newline everywhere.
      if (ch === '\n' || ch === '\r') { atCommand = true; if (!(ch === '\r' && next === '\n')) pendingSep += '\n'; }
      continue;
    }
    if (ch === ';' || ch === '&' || ch === '|') {
      end(i);
      atCommand = true;
      if (!(ch === '&' && (s[i - 1] === '>' || s[i - 1] === '<' || next === '>'))) pendingSep += ch;
      continue;
    }
    if (ch === '<' || ch === '>') { end(i); afterRedirect = true; continue; }
    begin(i);
    if (ch === "'" || ch === '"') { quote = ch; continue; }
    if (ch === '^') { cur.literal = false; continue; }
    if (ch === '`') {
      cur.literal = false;
      if (ps && (next === '\n' || next === '\r')) { end(i); continue; } // line continuation
      if (ps && next !== undefined) { cur.value += next; i++; }
      continue;
    }
    if (ch === '\\') {
      if (ps) { cur.value += '/'; continue; }
      cur.literal = false;
      if (next === '\n') { i++; continue; } // line continuation joins the word
      if (next !== undefined) { cur.value += next; i++; }
      continue;
    }
    cur.value += ch;
  }
  if (cur && quote) cur.literal = false;
  end(s.length);
  return words;
}

// A literal path piece: letters, digits and `_ . - : /`; `~` only as a leading `~/`.
const LITERAL_PATH = /^[\p{L}\p{N}_.\-:/]*$/u;
// Realpath resolutions per decision for segment words; one more fails safe (asks).
const MAX_SEGMENT_REALPATHS = 16;
// Words after one of these carry a script for another shell (`bash -c "…"`, `cmd /c`, `eval "…"`).
const SCRIPT_FLAG = /^(?:-[a-z]*c[a-z]*|-command|-e|-ec|-enc|-encodedcommand|\/+[ck]|eval)$/i;

// A drive letter is a real OS volume (not a PowerShell `New-PSDrive` name); cached per process.
const driveCache = new Map();
function driveExists(letter) {
  if (process.platform !== 'win32') return false;
  const l = letter.toUpperCase();
  if (!driveCache.has(l)) {
    let e = false;
    try { e = fs.existsSync(`${l}:\\`); } catch { /* not a drive */ }
    driveCache.set(l, e);
  }
  return driveCache.get(l);
}

/**
 * Absolute form of one whitespace-free path piece, or null when it cannot be exempt: not literal, not
 * absolute, an unusual form (Ruling K), or the segment right under a root (`node -e … /skill-sentry`
 * can append it anywhere). Absolute means `X:/` on a real volume, an unquoted `~/`, Git Bash `/x/`
 * (win32, real volume) or `/…` (POSIX only: Git Bash maps `/tmp` and others to other places). Under
 * PowerShell a driveless root is never exempt (`Join-Path $p '/x'` and `$p + '/x'` append it).
 */
function exemptPiece(v, tildeOk, ps) {
  const body = v.startsWith('~/') ? v.slice(2) : v;
  if (!LITERAL_PATH.test(body) || isUnusualPath(v)) return null;
  if (/^\/+skill-sentry(?:[. ]*)(?:\/|$)/i.test(v)) return null;
  let p;
  if (/^[a-z]:\//i.test(v)) p = driveExists(v[0]) ? v : null;
  else if (v.startsWith('~/')) p = tildeOk ? os.homedir() + v.slice(1) : null;
  else if (ps || !v.startsWith('/')) p = null;
  else if (process.platform !== 'win32') p = v;
  else if (/^\/[a-z](?:\/|$)/i.test(v) && driveExists(v[1])) p = `${v[1]}:/${v.slice(3)}`;
  else p = null;
  if (p === null) return null;
  try { return path.resolve(p); } catch { return null; }
}

/**
 * Per-decision checker: does a `skill-sentry` word need confirmation? A word with whitespace (a quoted
 * command line) is split, and every piece holding the segment must be exempt on its own; such a word
 * after a script flag (`-c`, `/c`, `-Command`, `eval`) never is. Realpath is capped and deduped.
 */
function makeSegmentCheck(roots) {
  let claude;
  // Claude's home and the Codex homes (`~/.codex`, `$CODEX_HOME`) each hold a skill-sentry install (C1).
  const claudeForms = () => (claude ??= [path.join(os.homedir(), '.claude'), path.join(os.homedir(), '.codex'), process.env.CODEX_HOME]
    .filter(str).flatMap(rootForms));
  const hits = f => siblingInstall(f) || claudeForms().some(c => isUnder(f, c)) || roots.some(r => isUnder(f, r) || isUnder(r, f));
  const canon = new Map();
  /** Canonical (realpath) key of `abs`, deduped and capped per decision; null when the cap is hit or it throws. */
  const realKey = abs => {
    const key = lowerOnWin(slashes(abs));
    if (!canon.has(key)) {
      if (canon.size >= MAX_SEGMENT_REALPATHS) return null;
      let c;
      try { c = normForCompare(realpathish(abs)); } catch { return null; }
      canon.set(key, c);
    }
    return canon.get(key);
  };
  // P3: a directory a relative word may resolve against, or a path its command names: not protected (hits),
  // not above an agent home or protected root, not a home dir or above one, as written and through realpath;
  // with `noSegment`, not inside any `skill-sentry` dir either (a checkout or an install the guard cannot vouch for).
  const placeOk = (abs, noSegment) => {
    const c = realKey(abs);
    if (c === null) return false;
    return [lowerOnWin(slashes(abs)), c].every(f => !hits(f) && !claudeForms().some(h => isUnder(h, f))
      && !HOME_SHAPED.test(f) && !(noSegment && SELF_SEGMENT.test(f)));
  };
  const pieceAsks = (v, tildeOk, ps, rel) => {
    const abs = exemptPiece(v, tildeOk, ps) ?? (rel ? rel(v) : null);
    if (abs === null) return true;
    const key = lowerOnWin(slashes(abs));
    if (hits(key)) return true;
    const c = realKey(abs);
    return c === null || hits(c);
  };
  /**
   * `rel` (P3): null, or a function giving the absolute form of a relative piece of this word (null when its base
   * is unknown or protected; see relativeContext).
   */
  const check = (w, ps, afterScriptFlag, rel = null) => {
    if (!w.literal || isUnusualPath(w.value) || /^\s/.test(w.value)) return true;
    // `~` is home only when unquoted and followed directly by a separator (`~"/x"`, `~''/x` are not).
    if (!/\s/.test(w.value)) return pieceAsks(w.value, /^~\//.test(w.raw), ps, rel);
    if (afterScriptFlag) return true;
    const segs = w.value.split(/\s+/).filter(v => SELF_SEGMENT.test(v));
    return !segs.length || segs.some(v => pieceAsks(v, false, ps, rel));
  };
  return { check, placeOk };
}

// ---- v0.1.2 P3: relative `skill-sentry` segments ----
// A relative occurrence resolves against the shell's working directory, so it is exempt only when that directory
// is literal and known: the target of a literal absolute `cd`/`chdir`/`pushd`/`Set-Location`/`sl`/`Push-Location`
// in the statement right before it, joined by `&&` (it runs only if that cd succeeded), or, when nothing precedes
// it, the hook cwd (Claude Code only: a Codex shell call can carry its own `workdir`, which the hook payload does not
// show). The base and the result must pass placeOk. Anything in the command that can move, redefine or hide the
// working directory, run code in another shell or host, or re-anchor a name keeps the prompt for every relative
// word: expansions and grouping, escapes, a pipe or lone `&` before the word, `..`, a cd that is not literal (or
// whose target is protected), shell keywords and builtins that define or run code, prefix assignments, other shells
// and hosts, wrappers that run a command elsewhere, `claude`/`codex` (`codex plugin marketplace remove skill-sentry`
// names the plugin, not a path), a word naming `.claude`/`.codex`, and any absolute operand that is not placeOk.

// A home dir or a dir above one (keys: `/`-separated, lowercased on win32, no trailing slash; `/` is '').
const HOME_SHAPED = /^(?:[a-z]:(?:\/(?:users|documents and settings)(?:\/[^/]+)?)?|\/(?:home|users)(?:\/[^/]+)?|\/root|\/var\/root|\/mnt\/[a-z](?:\/users(?:\/[^/]+)?)?|\/mnt|)$/i;
const CD_ABS_VERBS = new Set(['cd', 'chdir', 'pushd', 'set-location', 'sl', 'push-location']);
const REL_KILL_WORDS = new Set([
  'cd', 'chdir', 'pushd', 'popd', 'set-location', 'sl', 'push-location', 'pop-location', 'z', 'zi', 'j', 'zoxide', 'autojump',
  'builtin', 'command', 'eval', 'exec', 'source', '.', 'alias', 'unalias', 'function', 'enable', 'shopt', 'set', 'export',
  'declare', 'typeset', 'local', 'readonly', 'trap', 'if', 'then', 'else', 'elif', 'fi', 'while', 'until', 'do', 'done', 'for',
  'case', 'esac', 'select', 'coproc', 'xargs', 'parallel', 'watch', '-exec', '-execdir', '-ok', '-okdir', '-x', '--exec', '--exec-batch',
  'env', 'sudo', 'doas', 'su', 'runas', 'runuser', 'ssh', 'wsl', 'docker', 'podman', 'kubectl', 'start', 'start-process', 'saps',
  'bash', 'sh', 'zsh', 'dash', 'ksh', 'fish', 'cmd', 'pwsh', 'powershell', 'set-alias', 'sal', 'new-alias', 'nal',
  'invoke-expression', 'iex', 'invoke-command', 'icm', 'claude', 'codex',
]);
const wordName = v => v.toLowerCase().replace(/^.*\//, '').replace(/\.(?:exe|cmd|bat|ps1)$/, '');
// PowerShell's built-in `cd..` and `cd\` functions (Set-Location .. and \); `\` reads as `/` in a word value.
const CD_SHORTHAND = /^cd(?:\.\.|[/\\~])$/i;
// Fix round 1 (M1). A word right after a find name test or a PowerShell -Filter / -Include (any unique prefix) is a
// pattern; a link-following flag anywhere in the statement (find -L / -follow, cp -L), a PowerShell -Recurse or -Depth
// (any prefix), or a name-search verb makes every relative word of the statement ask.
const NAME_FLAG = /^(?:-(?:i?name|i?path|i?regex|i?wholename|i?lname)|-f(?:i(?:l(?:t(?:e(?:r)?)?)?)?)?|-i(?:n(?:c(?:l(?:u(?:d(?:e)?)?)?)?)?)?)$/i;
const FOLLOW_FLAG = /^(?:-L|-follow|--dereference)$/;
const RECURSE_FLAG = /^-(?:r(?:e(?:c(?:u(?:r(?:s(?:e)?)?)?)?)?)?|de(?:p(?:t(?:h)?)?)?)$/i;
const SEARCH_VERBS = new Set(['fd', 'fdfind', 'locate', 'plocate', 'mlocate', 'es']);
const UNICODE_BREAKS =[0x85, 0x2028, 0x2029].map(n => String.fromCharCode(n)); // NEL, LINE and PARAGRAPH SEPARATOR
const killWord = v =>REL_KILL_WORDS.has(wordName(v)) || CD_SHORTHAND.test(v);
const DOT_DOT = /(?:^|\/)\.\.(?:\/|$)/;
const NAMES_AGENT_HOME = /\.claude|\.codex|claude_config_dir|codex_home/i;
const NULL_DEVICES = new Set(['/dev/null', '/dev/stdout', '/dev/stderr', 'nul']);
const PATH_LIKE = /^(?:[/~]|[a-z]:)/i;
/** A relative piece that can be resolved against a base: literal, no drive or `:`, no `..`, not an option. */
const relativePiece = v => LITERAL_PATH.test(v) && !v.includes(':') && !/^[/~-]/.test(v) && !DOT_DOT.test(v);

/**
 * Per-command P3 context: `forWord(k)` returns null or a resolver for relative pieces of word `k` (see above).
 * Lazy: built on the first relative piece. Never throws (any doubt -> no resolver -> the word asks).
 */
function relativeContext(cmd, words, ps, cwd, shellCwd, placeOk) {
  let ctx;
  const build = () => {
    // A lone CR splits statements in PowerShell but not in bash: one more reading to get wrong, so no exemption.
    // The same for the Unicode line breaks (NEL, U+2028, U+2029), whose reading differs between parsers.
    if (/\r(?!\n)/.test(cmd) || UNICODE_BREAKS.some(ch => cmd.includes(ch))) return { ok: false };
    const starts = words.flatMap((w, i) => (i === 0 || w.sep ? [i] : []));
    const stmtOf = [];
    const stmts = starts.map((s, n) => {
      const e = starts[n + 1] ?? words.length;
      for (let i = s; i < e; i++) stmtOf[i] = n;
      return words.slice(s, e);
    });
    const targets = [];
    const fail = { ok: false };
    if (words.some(w => w.sep.replace(/&&/g, '').includes('&'))) return fail;
    for (const [n, st] of stmts.entries()) {
      const verb = wordName(st[0].value);
      if (CD_ABS_VERBS.has(verb)) {
        let ops = st.slice(1);
        if (ps && ops.length === 2 && /^-(?:literal)?path$/i.test(ops[0].value)) ops = ops.slice(1);
        if (ops.length !== 1 || !ops[0].literal) return fail;
        const t = exemptPiece(ops[0].value, /^~\//.test(ops[0].raw), ps);
        if (t !== null) {
          if (!placeOk(t, false)) return fail;
          targets[n] = t;
          continue;
        }
        // Fix round 1 (I2): a relative target is not known either: bash looks it up through CDPATH first, and a
        // zoxide-style `cd` from the shell snapshot jumps to a frecency match (`~/.claude/plugins/cache/…`).
        return fail;
      }
      if (/^[A-Za-z_]\w*=/.test(st[0].value)) return fail; // prefix assignment (HOME=…, CDPATH=…)
      for (const [i, w] of st.entries()) {
        const name = wordName(w.value);
        if (!(i === 0 && CD_ABS_VERBS.has(verb)) && killWord(w.value) && (name !== '.' || i === 0)) return fail;
      }
    }
    for (const w of words) {
      if (!w.literal || /[$`(){}%]/.test(w.raw) || NAMES_AGENT_HOME.test(w.raw) || NAMES_AGENT_HOME.test(w.value)) return fail;
      const pieces = w.value.split(/\s+/).filter(Boolean);
      if (pieces.length > 1) { // a quoted command line handed to something else
        if (/[;&|]/.test(w.value) || pieces.some(killWord)) return fail;
        continue;
      }
      if (!pieces.length || SELF_SEGMENT.test(w.value) || NULL_DEVICES.has(w.value.toLowerCase())) continue;
      const v = w.value;
      const forms = [v];
      if (v.includes('=')) forms.push(v.slice(v.indexOf('=') + 1));
      if (/^-[A-Za-z][/~]/.test(v)) forms.push(v.slice(2));
      for (const f of forms) {
        if (DOT_DOT.test(f)) return fail;
        if (!PATH_LIKE.test(f)) continue;
        const abs = exemptPiece(f, f === v && /^~\//.test(w.raw), ps);
        if (abs === null || !placeOk(abs, false)) return fail;
      }
    }
    let cwdBase = null;
    if (shellCwd && str(cwd) && (process.platform === 'win32' ? /^[a-z]:[\\/]/i.test(cwd) : cwd.startsWith('/')) && !isUnusualPath(cwd)) {
      const b = path.resolve(cwd);
      if (placeOk(b, true)) cwdBase = b;
    }
    return { ok: true, starts, stmts, stmtOf, targets, cwdBase };
  };
  const baseOf = k => {
    ctx ??= build();
    if (!ctx.ok) return null;
    for (let i = 1; i <= k; i++) if (words[i].sep.includes('|')) return null;
    const n = ctx.stmtOf[k];
    // Fix round 1 (M1): a name pattern, or a statement that walks a tree or follows links, is not a path under the base.
    const st = ctx.stmts[n];
    const at = k - ctx.starts[n];
    if (at > 0 && NAME_FLAG.test(st[at - 1].value)) return null;
    if (SEARCH_VERBS.has(wordName(st[0].value))) return null;
    if (st.some(w => FOLLOW_FLAG.test(w.value) || (ps && RECURSE_FLAG.test(w.value)))) return null;
    if (n === 0) return ctx.cwdBase;
    const t = ctx.targets[n - 1];
    if (t === undefined || !/^&&\n*$/.test(words[ctx.starts[n]].sep)) return null;
    return placeOk(t, true) ? t : null;
  };
  return k => v => {
    if (!relativePiece(v)) return null;
    let base;
    try { base = baseOf(k); } catch { return null; }
    return base === null ? null : path.resolve(base, v);
  };
}

// ---- moves and links of Claude's home (independent of any skill-sentry mention) ----

// `mv ~/.claude ~/y` then `rm -rf ~/y/skill-sentry` (two calls) would leave a literal, unprotected-looking
// path; links made earlier are seen by realpath, but a moved directory is not. So these ask up front when
// an operand names `.claude` or is non-literal (`$`, `%`, backtick, `(`), or when the verb runs under
// `xargs` or `find -exec`/`fd -x` (Ruling R13). PowerShell drives (`New-PSDrive`/`ndr`/`mount`) and
// `subst`/`net use` count as links. Residual (documented): moves through an API rather than a verb,
// such as `[IO.Directory]::Move(...)` or an interpreter's `fs.renameSync(...)`.
const RELINK_VERBS = new Set(['mv', 'ln', 'mklink', 'subst', 'rename-item', 'ren', 'rename', 'rni', 'move-item', 'move', 'mi', 'new-psdrive', 'ndr', 'mount']);
const RELINK_RUNNERS = new Set(['-exec', '-execdir', '-ok', '-okdir', '-x', '-X', '--exec', '--exec-batch']);
// Non-literal relink operand (after a leading `~/`): expansions, substitutions, and `~` (8.3 `.CLAUD~1`, `~user`).
const NON_LITERAL = /[$%`(~]/;
const SHELL_WRAPPERS = new Set(['sudo', 'doas', 'command', 'exec', 'nohup', 'time', 'timeout', 'env', 'nice', 'ionice', 'stdbuf', 'busybox', 'xargs', 'call', 'start']);
const GROUPING_TOKENS = new Set(['{', '(', '&', '.']);

// Ruling R14: PowerShell resolves `C:\…` through the session's drive table, so a PowerShell command (or a
// `pwsh -c` script) that creates or removes a drive can redefine even a real letter. Any such token asks,
// module-qualified too (`Microsoft.PowerShell.Management\New-PSDrive`).
const PS_DRIVE_TOKEN = /^[({@&.]*(?:microsoft\.powershell\.management\/)?(?:new-psdrive|ndr|mount|remove-psdrive|rdr)[)};]*$/i;
// The cmdlet names (and module-qualified forms) count anywhere; the short aliases are everyday words.
const PS_DRIVE_EXPLICIT = /new-psdrive|remove-psdrive|microsoft\.powershell\.management\//i;
const PIPE_BEFORE = /(?:^|[^|])\|\s*$/;
// Keywords that take a pipeline: the word after them is a command too (`return ndr C FileSystem D:\`).
const PS_PIPELINE_KEYWORD = /^(?:return|throw|exit)$/i;
const PS_BLOCK_COMMENT = /<#[\s\S]*?(?:#>|$)/g;
// Unquoted openers that start a statement: `(`, `$(`, `@(`, `{` (`(ndr …)`, `$(ndr …)`, `if (1) { ndr … }`).
const PS_STATEMENT_OPENER = /^(?:\$\(|@\(|[({])+/;
const PS_OPENS_STATEMENT = /(?:^|[^"'])[({]$/;
// A `-c` / `-Command` script inside one quoted argument (`Start-Process pwsh -ArgumentList "-c ndr …"`).
const PWSH_INLINE_SCRIPT = /(?:^|\s)-c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?[\s:]+(\S[\s\S]*)$/i;
/**
 * Final review I2: `mount`, `ndr` and `rdr` (in `git commit -m "fix mount"`, `findstr mount`, `npm run ndr`)
 * count only as a command, with arguments or fed by a pipe (bare `mount` cannot create a drive without its
 * mandatory parameters); anywhere only when the text can build a command at run time (psRunTimeBuild: the call
 * operator, dot-sourcing, iex/sal/gcm and the like). A plain `$`, quotes or parentheses do not (I2 residual).
 * The text is read as written, with backtick-newline continuations joined, and with `<# … #>` block comments
 * removed (any reading can ask).
 */
function changesPsDrive(script, depth = 0) {
  const s = String(script);
  const readings = new Set([s, s.replace(/`\r?\n/g, ' ')]);
  for (const r of [...readings]) if (r.includes('<#')) readings.add(r.replace(PS_BLOCK_COMMENT, ' '));
  return [...readings].some(r => psDriveIn(r, depth));
}
const psRunTimeBuild = c => /(?<!>)&/.test(c.replace(/&&/g, '  ')) || PS_DOT_SOURCE.test(c) || PS_DYNAMIC_WORD_CORE.test(c);
function psDriveIn(script, depth) {
  const words = shellWords(script, true);
  const tokens = w => w.value.split(/[\s;|&]+/).filter(t => PS_DRIVE_TOKEN.test(t));
  if (words.some(w => tokens(w).some(t => PS_DRIVE_EXPLICIT.test(t)))) return true;
  if (psRunTimeBuild(script)) return words.some(w => tokens(w).length > 0);
  if (depth < 2 && RUNS_PWSH.test(script)) {
    for (const w of words) {
      const m = /\s/.test(w.value) && PWSH_INLINE_SCRIPT.exec(w.value);
      if (m && changesPsDrive(m[1], depth + 1)) return true;
    }
  }
  const atCommand = words.map(w => w.cmd || PS_STATEMENT_OPENER.test(w.raw));
  for (let k = 1; k < words.length; k++) {
    if (atCommand[k]) continue;
    if (PS_OPENS_STATEMENT.test(words[k - 1].raw) || (atCommand[k - 1] && PS_PIPELINE_KEYWORD.test(words[k - 1].value))) atCommand[k] = true;
  }
  return words.some((w, k) => atCommand[k] && PS_DRIVE_TOKEN.test(w.value.replace(PS_STATEMENT_OPENER, ''))
    && ((k + 1 < words.length && !words[k + 1].cmd) || PIPE_BEFORE.test(script.slice(0, w.start))));
}

// Ruling R14 (X5): a drive can also be made with no drive token in sight: an alias or `iex` of a name built
// at run time (`sal zq ('New-PS'+'Drive')`), the call operator, `gcm` wildcards, dot-sourcing, or the .NET
// API (`$executionContext.SessionState.Drive.New`), or the alias provider (`Set-Item alias:zq -Value:New-PSDrive`,
// `Rename-Item alias:ndr zq`, curly quotes). So a PowerShell command, or one that runs `pwsh` /
// `powershell`, with any dynamic construct gets no exemption at all (`~` neither: the FileSystem provider's
// Home can be reassigned). Residual (documented): a `-Scope Global` drive made by a `.ps1` script or module
// planted in an earlier call and run or imported here.
const RUNS_PWSH = /(?:^|[\s;|&('"/\\])(?:pwsh|powershell)(?:\.exe)?(?=$|[\s;|&)'"])/i;
const PS_DYNAMIC_CHAR = /[$({[@+`]/;
const PS_DOT_SOURCE = /(?:^|[;|{(\r\n]|&&)\s*\.(?=[\s'"])/;
const PS_DYNAMIC_WORD = /(?<![\w-])(?:(?:iex|invoke-expression|invoke-command|icm|sal|set-alias|nal|new-alias|gcm|get-command|new-object|add-type|new-psdrive|ndr|mount|remove-psdrive|rdr)(?![\w-])|(?:alias|function):)/i;
// The same without the drive words themselves (I2: a drive word must not make its own text "dynamic").
const PS_DYNAMIC_WORD_CORE = /(?<![\w-])(?:(?:iex|invoke-expression|invoke-command|icm|sal|set-alias|nal|new-alias|gcm|get-command|new-object|add-type)(?![\w-])|(?:alias|function):)/i;
/** PowerShell text that can build a command at run time (call operator `&`, not `&&` or `2>&1`). */
const psDynamic = c => PS_DYNAMIC_CHAR.test(c) || /(?<!>)&/.test(c.replace(/&&/g, '  ')) || PS_DOT_SOURCE.test(c) || PS_DYNAMIC_WORD.test(c);
const CLAUDE_SEGMENT = /(?:^|[^\w.-])\.claude[. ]*(?=$|[^\w.-])/i;

/** A glob component (`.cl*`, `.c?aude`, `.cl{a,}ude`, `[.]claude`) that can match `.claude`. */
function globMatchesClaude(text) {
  for (const comp of text.split(/[/\s]+/)) {
    if (!/[*?[{]/.test(comp)) continue;
    const re = comp.replace(/\{[^}]*\}/g, '\u0000').replace(/[.+^$()|\\]/g, '\\$&')
      .replace(/\*/g, '.*').replace(/\?/g, '.').replace(/\u0000/g, '.*');
    try { if (new RegExp(`^${re}$`, 'i').test('.claude')) return true; } catch { return true; }
  }
  return false;
}

const namesClaude = w => [w.value, w.raw].some(t => CLAUDE_SEGMENT.test(t) || /claude_config_dir/i.test(t) || globMatchesClaude(t));

/** A move/link/rename verb in command position whose operands name `.claude` (nested `-c` scripts too). */
function relinksClaude(cmd, ps, depth = 0) {
  const words = shellWords(cmd, ps);
  for (let i = 0; i < words.length; i++) {
    if (!words[i].cmd) continue;
    let j = i;
    const verbAt = k => words[k]?.value.toLowerCase().replace(/^[({]+/, '').replace(/^.*\//, '').replace(/\.exe$/, '') ?? '';
    // Skip grouping (`{ … }`, `( … )`, `& { … }`, `. x`), wrappers, assignments, and wrapper flags/counts.
    const skip = k => GROUPING_TOKENS.has(words[k].value) || SHELL_WRAPPERS.has(verbAt(k)) || /^\w+=/.test(words[k].value)
      || (k > i && (words[k].value.startsWith('-') || /^\d+(?:\.\d+)?[smhd]?$/.test(words[k].value)));
    while (j < words.length && skip(j)) j++;
    let verb = verbAt(j);
    const stmtEnd = (() => { let k = j + 1; while (k < words.length && !words[k].cmd) k++; return k; })();
    const args = words.slice(j + 1, stmtEnd);
    // A relink verb run by xargs or find -exec / fd -x: its operands are not visible here.
    for (let k = i; k < stmtEnd - 1; k++) {
      if (verbAt(k) === 'xargs' ? words.slice(k + 1, stmtEnd).some((_, m) => RELINK_VERBS.has(verbAt(k + 1 + m)))
        : RELINK_RUNNERS.has(words[k].value) && RELINK_VERBS.has(verbAt(k + 1))) return true;
    }
    if (verb === 'cmd' && args.length && /^\/+[ck]$/i.test(args[0].value)) {
      if (depth < 2 && relinksClaude(args.slice(1).map(a => a.raw).join(' '), false, depth + 1)) return true;
      continue;
    }
    const shell = /^(?:ba|z|da|k)?sh$/.test(verb) ? 'sh' : /^(?:pwsh|powershell)$/.test(verb) ? 'ps' : null;
    const inner = shell && args.findIndex(a => (shell === 'sh' ? /^-[a-z]*c[a-z]*$/i : /^-c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?$/i).test(a.value));
    if (shell && inner !== -1 && args[inner + 1]) {
      const script = args.slice(inner + 1).map(a => a.value).join(' ');
      if (shell === 'ps' && changesPsDrive(script)) return true;
      if (depth < 2 && relinksClaude(script, shell === 'ps', depth + 1)) return true;
      continue;
    }
    const vals = args.map(a => a.value.toLowerCase());
    if (verb === 'new-item' || verb === 'ni') verb = vals.some(v => /(?:^|:)(?:junction|symboliclink|hardlink)$/.test(v)) ? 'ln' : '';
    else if (verb === 'robocopy') verb = vals.some(v => /^\/mov(?:e)?$/.test(v)) ? 'mv' : '';
    else if (verb === 'cp') verb = vals.some(v => /^-[a-z]*[ls][a-z]*$|^--(?:link|symbolic-link)$/.test(v)) ? 'ln' : '';
    else if (verb === 'fsutil') verb = vals.includes('hardlink') ? 'ln' : '';
    else if (verb === 'net') verb = vals[0] === 'use' ? 'mount' : '';
    if (RELINK_VERBS.has(verb) && args.some(a => namesClaude(a) || NON_LITERAL.test(a.raw.replace(/^~\//, '')))) return true;
  }
  return false;
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

const AGENT_VALUES = new Set(['claude', 'codex', 'all']);
/** Fixed tokens only: flags from `flags` (repeatable) and, with `agentFlag`, one `--agent claude|codex|all` pair. */
function fixedTokens(args, flags, agentFlag) {
  let agent = false;
  for (let i = 0; i < args.length; i++) {
    if (flags.has(args[i])) continue;
    if (agentFlag && !agent && args[i] === '--agent' && AGENT_VALUES.has(args[i + 1])) { agent = true; i++; continue; }
    return false;
  }
  return true;
}
const SCAN_FLAGS = new Set(['--json', '--diff-only']);

/**
 * Exact read-only self invocation (Ruling M); mutating or parameterized forms return false.
 * `agentFlag` (Codex only, T7) also accepts one `--agent claude|codex|all` pair after `scan.mjs` or `harden.mjs check`:
 * a closed set of values that only narrows what is read (and a partial scan never writes the baseline).
 */
export function isReadOnlySelfInvocation(cmd, selfRoot, toolName = 'Bash', { agentFlag = false } = {}) {
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
  if (is('harden.mjs')) return args[0] === 'check' && fixedTokens(args.slice(1), new Set(), agentFlag);
  return is('scan.mjs') && fixedTokens(args, SCAN_FLAGS, agentFlag);
}

// Codex only (T7): Codex has no Skill tool, the model loads a skill by reading its SKILL.md with the shell.
// Exempt fixed forms only: one read verb (`cat`, `sed -n 'N,Mp'`; under PowerShell also `type` and
// `Get-Content`/`gc` with optional `-Raw` and `-LiteralPath`/`-Path`) and one operand that is an absolute literal
// path (same character rules as Ruling M) resolving exactly to `<selfRoot>/skills/<name>/SKILL.md`. Redirects,
// pipes, chains, more operands, other flags, other files: no match. Under bash/zsh `type`, `Get-Content` and `gc`
// are not cmdlets (Codex on Windows is still covered: the Bash payload is also read as PowerShell, R15).
const VIEW_OPERAND = String.raw`(?:"([^"]*)"|'([^']*)'|([^ "']+))`;
const SELF_VIEWS = [
  new RegExp(String.raw`^(?:cat|sed +-n +(?:'\d+,\d+p'|"\d+,\d+p"|\d+,\d+p)) +${VIEW_OPERAND} *$`, 'i'),
];
const SELF_VIEWS_POWERSHELL = [
  ...SELF_VIEWS,
  new RegExp(String.raw`^type +${VIEW_OPERAND} *$`, 'i'),
  new RegExp(String.raw`^(?:get-content|gc)(?: +-raw)?(?: +-(?:literal)?path)? +${VIEW_OPERAND}(?: +-raw)? *$`, 'i'),
];

/** Exact read-only view of one of our own skills' SKILL.md (Codex only; callers opt in). */
export function isReadOnlySelfView(cmd, selfRoot, toolName = 'Bash') {
  if (!str(cmd) || !str(selfRoot)) return false;
  const m = (toolName === 'PowerShell' ? SELF_VIEWS_POWERSHELL : SELF_VIEWS).map(re => re.exec(cmd)).find(Boolean);
  if (!m) return false;
  const file = m[1] ?? m[2] ?? m[3];
  if (!SELF_PATH.test(file) || (m[3] !== undefined && file.includes(' '))) return false;
  if (file.includes('\\') && toolName !== 'PowerShell') return false;
  if (!/^(?:[A-Za-z]:[\\/]|\/(?![\\/]))/.test(file) || isUnusualPath(file)) return false;
  const target = lowerOnWin(slashes(path.resolve(file)));
  return rootForms(selfRoot).some(f => {
    const rest = target.startsWith(`${f}/skills/`) ? target.slice(f.length + '/skills/'.length) : null;
    return rest !== null && /^[a-z0-9_-]+\/skill\.md$/i.test(rest);
  });
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

/** I3: Codex control files under a custom Codex home (`$CODEX_HOME`, SKILL_SENTRY_CODEX_HOME: no `.codex` segment). */
function underCustomCodexHome(forms) {
  const homes = [process.env.CODEX_HOME, process.env.SKILL_SENTRY_CODEX_HOME].filter(str);
  if (!homes.length) return false;
  const roots = homes.flatMap(rootForms);
  return forms.some(f => roots.some(r => f.startsWith(r + '/') && CODEX_CONTROL_TAIL.test(f.slice(r.length + 1))));
}

/** Path rule matches on the path as given plus its resolved long form (symlinks, junctions, subst). */
function pathMatches(p, keep, R) {
  const out = matchPath(p).filter(keep).map(m => ({ ...m, target: p }));
  const { abs, long } = R.get(p);
  if (long && long !== p) {
    for (const m of matchPath(long)) {
      if (keep(m) && !out.some(x => x.ruleId === m.ruleId)) out.push({ ...m, snippet: snip(p), target: p });
    }
  }
  const codex = { ruleId: 'PERSIST_PATH_CODEX_CONFIG', category: 'persistence', severity: 'high', line: 1, snippet: snip(p), target: p };
  if (keep(codex) && !out.some(x => x.ruleId === codex.ruleId) && underCustomCodexHome([abs, long].filter(str).map(f => lowerOnWin(slashes(f))))) {
    out.push(codex);
  }
  return out;
}

const synthetic = (ruleId, p) => ({ ruleId, category: 'path', severity: 'high', snippet: snip(p), target: p });

/**
 * Decide what to do with one tool call.
 * `origin` and `allowlist` may be values or zero-arg functions; functions are only called when the
 * decision depends on them (origin for `high`, allowlist for `critical`).
 * `extraWritePaths` (Codex apply_patch header paths) join the write targets; Claude callers never pass it.
 * `selfViews` (Codex only) exempts a plain read of one of our own SKILL.md files from SELF_PROTECT.
 * `shellCwd` (P3): `cwd` is the directory the shell command runs in (Claude Code); Codex passes false.
 * A `high` decision also carries `highs` (every high match: ruleId, category, snippet) for the Codex tiers.
 * @returns {{ decision: 'deny'|'ask'|'log'|'none', ruleId?: string, severity?: string, reason?: string, snippet?: string,
 *   highs?: { ruleId: string, category: string, snippet: string }[] }}
 */
export function decide({ toolName, toolInput, origin = null, allowlist = null, selfRoot, dataDir, cwd, extraWritePaths = null, selfViews = false, shellCwd = true }) {
  const { targets: t, mcp, truncated } = extractTargetsEx(toolName, toolInput, cwd);
  if (Array.isArray(extraWritePaths)) t.writePaths.push(...extraWritePaths.filter(str));
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
  // Any other `skill-sentry` segment asks too (Ruling J), unless its word is a literal absolute path
  // that resolves away from Claude's home and the protected roots (Ruling R9 revised), or a relative one
  // whose literal, known base and resolution do (P3, relativeContext).
  if (t.commands.length) {
    const ps = toolName === 'PowerShell';
    const roots = [dataDir, selfRoot].filter(str).flatMap(rootForms);
    const needles = [...roots, lowerOnWin('.claude/skill-sentry')];
    const { check: segmentAsks, placeOk } = makeSegmentCheck(roots);
    for (const c of t.commands) {
      const ask = reason => ({ decision: 'ask', ruleId: 'SELF_PROTECT', severity: 'high', reason, snippet: snip(c) });
      if (ps && changesPsDrive(c)) return ask('PowerShell command creates or removes a drive (Ruling R14)');
      if (relinksClaude(c, ps)) return ask('shell command moves or links the Claude config directory');
      if (isReadOnlySelfInvocation(c, selfRoot, toolName, { agentFlag: selfViews })) continue; // Rulings L2, L3 (+ Codex --agent)
      if (selfViews && isReadOnlySelfView(c, selfRoot, toolName)) continue; // Codex skill loading (T7)
      // Line continuations (bash `\`, PowerShell backtick) are joined in the de-obfuscated copy.
      const joined = String(c).replace(/\\\r?\n/g, '').replace(/`\r?\n/g, ' ');
      const texts = [normCommandText(c), normCommandText(deobfuscate(joined))];
      texts.push(...texts.map(collapseDotDot).filter((x, k) => x !== texts[k]));
      const words = shellWords(c, ps);
      const scriptAt = words.findIndex(w => SCRIPT_FLAG.test(w.value));
      const segAt = words.flatMap((w, k) => (SELF_SEGMENT.test(w.value) || SELF_SEGMENT.test(w.raw) ? [k] : []));
      const dynamicPs = segAt.length > 0 && (ps || RUNS_PWSH.test(c)) && psDynamic(String(c));
      const rel = segAt.length ? relativeContext(String(c), words, ps, cwd, shellCwd, placeOk) : null; // P3
      if (texts.some(text => needles.some(n => mentions(text, n)))
        || segAt.some(k => dynamicPs || segmentAsks(words[k], ps, scriptAt !== -1 && k > scriptAt, rel(k)))
        || (!segAt.length && texts.some(text => SELF_SEGMENT.test(text)))) {
        return ask('shell command touches skill-sentry data or install directory');
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
      // C1: a sibling skill-sentry install (the other agent's, or another marketplace's) counts as protected too.
      if (roots.some(root => isUnder(c, root)) || siblingInstall(c) || siblingInstall(normForCompare(r.abs))
        || (r.long && rootIds.size && rootIds.has(R.parentId(r)))) {
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
    const highs = matches.filter(m => m.severity === 'high').map(m => ({ ruleId: m.ruleId, category: m.category, snippet: m.snippet }));
    return { decision: o ? 'ask' : 'log', ruleId: high.ruleId, severity: 'high', reason: 'high-risk rule match', snippet: high.snippet, highs };
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

/**
 * Ruling R23: whether `originToComponentId` could map this origin onto a plugin named skill-sentry (a
 * `skill-sentry:<skill>` skill, MCP plugin `skill-sentry`, or a qualified MCP name starting `skill-sentry_`).
 * Only then does the guard need to know whether an installed skill-sentry copy is self.
 */
export function originMayNameSkillSentry(origin) {
  if (!origin || typeof origin !== 'object') return false;
  const name = 'skill-sentry';
  if (str(origin.mcpPlugin)) return origin.mcpPlugin === name || (str(origin.mcpQualified) && origin.mcpQualified.startsWith(`${name}_`));
  return str(origin.skill) && origin.skill.startsWith(`${name}:`);
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
