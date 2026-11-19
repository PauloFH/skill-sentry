// Pure decision logic for the PreToolUse guard. Kept free of inventory/scanner imports so the
// common "no match" path stays fast.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { matchCommand, matchPath } from './rules.mjs';
import { escapeInvisible, truncate } from './text.mjs';
import { isCommandAllowed } from './allowlist.mjs';

const MAX_MCP_STRINGS = 64;
const MAX_MCP_DEPTH = 5;
// MCP argument keys that carry content, never a path (content is never inspected, §6.2).
const MCP_CONTENT_KEYS = new Set(['content', 'contents', 'text', 'body', 'data', 'new_string', 'old_string', 'new_source', 'message', 'prompt']);
const MCP_WRITE_TOOL = /write|edit|create|move|copy|append|rename|delete|remove|upload|save|put/i;

const str = v => typeof v === 'string' && v.length > 0;
const pathLike = s => str(s) && s.length <= 4096 && !/[\r\n]/.test(s) && (s.includes('/') || s.includes('\\') || s.startsWith('~'));

function collectPathStrings(value, out, depth = 0, key = '') {
  if (out.length >= MAX_MCP_STRINGS || depth > MAX_MCP_DEPTH || MCP_CONTENT_KEYS.has(key)) return;
  if (typeof value === 'string') { if (pathLike(value)) out.push(value); return; }
  if (Array.isArray(value)) { for (const v of value) collectPathStrings(v, out, depth + 1, ''); return; }
  if (value && typeof value === 'object') {
    for (const [k, v] of Object.entries(value)) collectPathStrings(v, out, depth + 1, k.toLowerCase());
  }
}

/**
 * Pull the inspectable targets out of a tool call. Write/Edit content is never returned.
 * @returns {{ commands: string[], readPaths: string[], writePaths: string[], urls: string[] }}
 */
export function extractTargets(toolName, toolInput) {
  const t = { commands: [], readPaths: [], writePaths: [], urls: [] };
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
        collectPathStrings(i, t.readPaths);
        if (MCP_WRITE_TOOL.test(toolName.slice(toolName.lastIndexOf('__') + 2))) t.writePaths.push(...t.readPaths);
      }
  }
  return t;
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

const reEscape = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
// Hosts that make a UNC admin share (`\\host\C$\...`) point back at a local drive.
const LOCAL_HOST = `(?:localhost|127\\.0\\.0\\.1|\\[?::1\\]?${os.hostname() ? '|' + reEscape(os.hostname()) : ''})`;
const ADMIN_SHARE_PREFIX = new RegExp(`^[\\\\/]{2}(?:[?.][\\\\/]UNC[\\\\/])?${LOCAL_HOST}[\\\\/]([a-z])\\$(?=[\\\\/]|$)`, 'i');
const DEVICE_PREFIX = /^[\\/]{2}[?.][\\/](?=[a-z]:)/i;
const ADMIN_SHARE_IN_TEXT = new RegExp(`//(?:[?.]/unc/)?${LOCAL_HOST}/([a-z])\\$(?=/|$|[\\s'"])`, 'gi');

/** `\\localhost\C$\x`, `\\?\UNC\localhost\C$\x`, `\\?\C:\x` -> `C:\x`; `~` expanded. */
function plainPath(p) {
  let s = String(p).replace(ADMIN_SHARE_PREFIX, '$1:').replace(DEVICE_PREFIX, '');
  if (s === '~' || s.startsWith('~/') || s.startsWith('~\\')) s = os.homedir() + s.slice(1);
  return s;
}

const LOCAL_HOST_ONLY = new RegExp(`^${LOCAL_HOST}$`, 'i');

/** Host of a UNC path (`\\host\`, `\\?\UNC\host\`, `//host/`); '' for other device paths; null if not UNC. */
function uncHost(abs) {
  const s = String(abs);
  if (!/^[\\/]{2}/.test(s)) return null;
  const dev = /^[\\/]{2}[?.][\\/](?:UNC[\\/]([^\\/]*))?/i.exec(s);
  if (dev) return dev[1] ?? '';
  return /^[\\/]{2}([^\\/]*)/.exec(s)[1];
}

/**
 * Whether the filesystem may be touched for `abs`. Never for UNC/device paths on a non-local host
 * (an unreachable host blocks for ~20 s and would push the guard past its timeout). `io.left` caps
 * the number of paths that get realpath/stat work in one decision.
 */
const MAX_IO_PATHS = 32;
function mayTouch(abs, io) {
  const host = uncHost(abs);
  if (host !== null && !LOCAL_HOST_ONLY.test(host)) return false;
  if (!io) return true;
  if (io.left <= 0) return false;
  io.left--;
  return true;
}

/** Absolute long form: resolved, admin shares mapped, symlinks and 8.3 names expanded where allowed. */
function longPath(p, cwd, io) {
  const abs = path.resolve(cwd || process.cwd(), plainPath(p));
  return mayTouch(abs, io) ? realpathish(abs) : abs;
}

function canon(p, cwd, io) {
  let out = longPath(p, cwd, io).replace(/\\/g, '/');
  if (out.length > 1 && out.endsWith('/')) out = out.replace(/\/+$/, '');
  return process.platform === 'win32' ? out.toLowerCase() : out;
}

const isUnder = (p, root) => p === root || p.startsWith(root.endsWith('/') ? root : root + '/');

const fileId = p => {
  try {
    const st = fs.statSync(p, { bigint: true, throwIfNoEntry: false });
    return st && st.ino !== 0n ? `${st.dev}:${st.ino}` : null;
  } catch { return null; }
};

/** True if `abs` or one of its existing ancestors is the same file (dev+ino) as a protected root. */
function underByIdentity(abs, rootIds, io) {
  if (!rootIds.size || !mayTouch(abs, io)) return false;
  let cur = abs;
  for (let n = 0; n < 64; n++) {
    const id = fileId(cur);
    if (id && rootIds.has(id)) return true;
    const parent = path.dirname(cur);
    if (parent === cur) return false;
    cur = parent;
  }
  return false;
}

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

// Bare `skill-sentry` path segment (relative forms after `cd ~/.claude`), not `some-skill-sentry-fork`.
// Boundary on both sides = start/end or any character outside [\w.-] (same notion as `mentions`).
const SELF_SEGMENT = /(?:^|[^\w.-])skill-sentry(?=$|[^\w.-])/i;

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
  return [...new Set([lowerOnWin(slashes(path.resolve(r))), canon(r)])].filter(f => f.length > 3);
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

/** Path rule matches on the path as given plus its long form (8.3 names, symlinks, admin shares). */
function pathMatches(p, cwd, keep, io) {
  const out = matchPath(p).filter(keep).map(m => ({ ...m, target: p }));
  let long = null;
  try { long = longPath(p, cwd, io); } catch { /* unresolvable: raw form only */ }
  if (long && long !== p) {
    for (const m of matchPath(long)) {
      if (keep(m) && !out.some(x => x.ruleId === m.ruleId)) out.push({ ...m, snippet: snip(p), target: p });
    }
  }
  return out;
}

/**
 * Decide what to do with one tool call.
 * `origin` and `allowlist` may be values or zero-arg functions; functions are only called when the
 * decision depends on them (origin for `high`, allowlist for `critical`).
 * @returns {{ decision: 'deny'|'ask'|'log'|'none', ruleId?: string, severity?: string, reason?: string, snippet?: string }}
 */
export function decide({ toolName, toolInput, origin = null, allowlist = null, selfRoot, dataDir, cwd }) {
  const t = extractTargets(toolName, toolInput);
  const matches = [];
  for (const c of t.commands) matches.push(...commandMatches(c));
  for (const u of t.urls) matches.push(...commandMatches(u));
  const io = { left: MAX_IO_PATHS }; // shared fs budget for this decision
  for (const p of t.readPaths) matches.push(...pathMatches(p, cwd, m => m.category === 'secret', io));
  for (const p of t.writePaths) matches.push(...pathMatches(p, cwd, WRITE_PROTECTED, io));

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
  if (t.commands.length) {
    const needles = [...[dataDir, selfRoot].filter(str).flatMap(rootForms), lowerOnWin('.claude/skill-sentry')];
    for (const c of t.commands) {
      const texts = [normCommandText(c), normCommandText(deobfuscate(c))];
      if (texts.some(text => SELF_SEGMENT.test(text) || needles.some(n => mentions(text, n)))) {
        return { decision: 'ask', ruleId: 'SELF_PROTECT', severity: 'high', reason: 'shell command touches skill-sentry data or install directory', snippet: snip(c) };
      }
    }
  }

  if (t.writePaths.length) {
    const protectedRoots = [dataDir, selfRoot].filter(str);
    const roots = protectedRoots.map(r => canon(r));
    const rootIds = new Set(protectedRoots.map(r => path.resolve(r)).filter(r => mayTouch(r)).map(fileId).filter(Boolean));
    for (const p of t.writePaths) {
      const c = canon(p, cwd, io);
      let raw = null;
      try { raw = path.resolve(cwd || process.cwd(), plainPath(p)); } catch { /* string compare only */ }
      if (roots.some(r => isUnder(c, r)) || (raw && underByIdentity(raw, rootIds, io))) {
        return { decision: 'ask', ruleId: 'SELF_PROTECT_WRITE', severity: 'high', reason: 'write to skill-sentry data or install directory', snippet: snip(p) };
      }
    }
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
  if (incomplete) return 'component check incomplete';
  return `component verdict: ${verdict} (score ${score}), ${count} finding${count === 1 ? '' : 's'}`;
}

/**
 * Human-readable reason shown by Claude Code with the deny/ask prompt.
 * @param {{ decision: string, ruleId?: string, severity?: string, snippet?: string }} d
 * @param {string|null} originLabel
 * @param {string|null} summary
 */
export function formatReason(d, originLabel, summary) {
  const verb = d.decision === 'deny' ? 'blocked' : 'needs confirmation';
  const parts = [`skill-sentry: ${verb} by rule ${d.ruleId} (${d.severity}): "${snip(d.snippet)}"`];
  parts.push(originLabel ? `likely source: ${snip(originLabel)}` : 'no skill/plugin attributed');
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
