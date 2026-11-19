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

function canon(p, cwd) {
  let s = String(p);
  if (s === '~' || s.startsWith('~/') || s.startsWith('~\\')) s = os.homedir() + s.slice(1);
  let out = realpathish(path.resolve(cwd || process.cwd(), s)).replace(/\\/g, '/');
  if (out.length > 1 && out.endsWith('/')) out = out.replace(/\/+$/, '');
  return process.platform === 'win32' ? out.toLowerCase() : out;
}

const isUnder = (p, root) => p === root || p.startsWith(root.endsWith('/') ? root : root + '/');

const lowerOnWin = s => (process.platform === 'win32' ? s.toLowerCase() : s);
const slashes = s => String(s).replace(/\\/g, '/').replace(/\/+$/, '');

/** Shell text with backslashes -> '/', home references expanded, lowercased on win32. */
function normCommandText(cmd) {
  const home = slashes(os.homedir());
  let s = String(cmd).replace(/\\/g, '/');
  s = s.replace(/\$\{HOME\}|\$HOME\b|%USERPROFILE%|%HOMEDRIVE%%HOMEPATH%|\$\{env:USERPROFILE\}|\$env:USERPROFILE\b|\$env:HOME\b/gi, home);
  s = s.replace(/(^|[\s'"=(:;|&>])~(?=\/|$|[\s'";|&)])/g, (_, pre) => pre + home);
  return lowerOnWin(s);
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
function commandMatches(target) {
  const ms = matchCommand(target);
  const escalate = new Set();
  if (ms.some(m => m.category === 'secret') && ms.some(m => m.category === 'exfil')) {
    const statements = target.replace(/\\\r?\n[ \t]*/g, ' ').split(/&&|\|\||;|\r?\n/);
    for (const s of statements) {
      const sm = matchCommand(s);
      if (sm.some(m => m.category === 'secret')) for (const m of sm) if (m.category === 'exfil') escalate.add(m.ruleId);
    }
  }
  return ms.map(m => (escalate.has(m.ruleId) && m.severity !== 'critical'
    ? { ...m, severity: 'critical', escalated: true, target } : { ...m, target }));
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
  for (const p of t.readPaths) for (const m of matchPath(p)) if (m.category === 'secret') matches.push({ ...m, target: p });
  for (const p of t.writePaths) for (const m of matchPath(p)) if (WRITE_PROTECTED(m)) matches.push({ ...m, target: p });

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
      const text = normCommandText(c);
      if (needles.some(n => mentions(text, n))) {
        return { decision: 'ask', ruleId: 'SELF_PROTECT', severity: 'high', reason: 'shell command touches skill-sentry data or install directory', snippet: snip(c) };
      }
    }
  }

  if (t.writePaths.length) {
    const roots = [dataDir, selfRoot].filter(str).map(r => canon(r));
    for (const p of t.writePaths) {
      const c = canon(p, cwd);
      if (roots.some(r => isUnder(c, r))) {
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
