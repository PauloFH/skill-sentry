// Guard policy for OpenAI Codex PreToolUse calls (spec §5, the user's tiered policy, Rulings R15/R16).
//
// Codex has no "ask" (permissionDecision "ask" marks the hook Failed and the tool runs) and hooks fail open, so
// the Claude decisions are remapped:
//   1. critical                                  -> deny (as Claude)
//   2. high signalling malware or exfiltration   -> deny, even without an origin: categories
//      rce/exfil/miner/destructive; a secret plus network egress in the same call; or session taint (a secret
//      read earlier in this session by an attributed call) plus a network-capable call
//   3. other high with an origin                 -> paused (R16): denied the first time with the "doubt" in the
//      reason and a retry token; the identical call in the same session within 10 minutes runs (token consumed)
//   4. high without origin                       -> log only
//   5. SELF_PROTECT / SELF_PROTECT_WRITE (and PATH_UNUSUAL_WRITE, which may alias a protected file) -> deny,
//      telling the user to run the command themselves in a terminal. Ruling M read-only self invocations pass.
// Tiers 1, 2 and 5 never get a retry token.
//
// Output (codex-rs hooks/schema/generated/pre-tool-use.command.output.schema.json + engine/output_parser.rs):
// the only output is deny = {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny",
// "permissionDecisionReason":"…"}}; anything else prints nothing. (Codex rejects permissionDecision "allow"
// without updatedInput and "ask"; a decision-less {"hookSpecificOutput":{…,"additionalContext":"…"}} is accepted
// but only reaches the model after the call ran, which is why tier 3 pauses instead.)
//
// Data dir (Ruling Q1): resolved exactly as for Claude Code (SKILL_SENTRY_DATA_DIR or <home>/.claude/skill-sentry
// of the OS the guard runs on). A Codex running inside WSL therefore keeps its own session store, baseline and
// allowlist under the WSL home; nothing is shared across the Windows/WSL boundary.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { decide, formatReason, isReadOnlySelfInvocation } from '../guardcore.mjs';
import { dataDirPath } from '../datadir.mjs';
import { loadAllowlist } from '../allowlist.mjs';
import { escapeInvisible, truncate } from '../text.mjs';
import { findCodexOrigin } from './origin.mjs';
import { scanPatch, shellPatch, PATCH_MAX_BYTES, PATCH_MAX_PATHS } from './patch.mjs';

/** Codex input: has a string turn_id and no prompt_id (Ruling R6 FINAL; environment variables are not used). */
export function isCodexInput(input) {
  return !!input && typeof input === 'object' && typeof input.turn_id === 'string' && !('prompt_id' in input);
}

// ---------------------------------------------------------------- network capability

const NET_TOOL = /(?:^|[\s;|&(){}`'"=])(?:curl|wget|nc|ncat|netcat|scp|sftp|ftp|iwr|irm|invoke-webrequest|invoke-restmethod|start-bitstransfer)(?:\.exe)?(?=$|[\s;|&(){}`'"])/i;
const NET_API = /net\.webclient|net\.http\.httpclient|\/dev\/(?:tcp|udp)\//i;
const RSYNC = /(?:^|[\s;|&(])rsync(?:\.exe)?\s/i;
// rsync://, or a `[user@]host:path` operand with a host of 2+ characters (`C:/x` is a drive, not a host).
const RSYNC_REMOTE = /rsync:\/\/|\s(?:[\w.-]+@)?[\w-][\w.-]+:(?![\\/]{2})\S/i;
// `git push` naming a URL or scp-style remote; a bare push or a named remote (origin) is not counted.
const GIT_PUSH_URL = /\bgit(?:\.exe)?\s(?:[^;&|\n]*\s)?push\s[^;&|\n]*?(?:[a-z][\w+.-]*:\/\/|[\w.-]+@[\w.-]+:)/i;
const WEB_MCP_NAME = /fetch|http|request|browse|navigate|download|upload|webhook|scrape|crawl|curl|wget|url/i;
const URL_VALUE = /^\s*(?:https?|wss?|ftp):\/\//i;
const MAX_MCP_NODES = 5000;

function mcpHasUrl(root) {
  const stack = [root];
  let n = 0;
  while (stack.length && n++ < MAX_MCP_NODES) {
    const v = stack.pop();
    if (typeof v === 'string') { if (URL_VALUE.test(v)) return true; } else if (v && typeof v === 'object') {
      for (const x of Array.isArray(v) ? v : Object.values(v)) stack.push(x);
    }
  }
  return false;
}

/** The call can send data off the machine (used for secret+egress and for session taint). */
export function isNetworkCapable(toolName, toolInput) {
  if (!toolInput || typeof toolInput !== 'object' || typeof toolName !== 'string') return false;
  if (toolName === 'Bash' || toolName === 'PowerShell') {
    const c = toolInput.command;
    if (typeof c !== 'string') return false;
    return NET_TOOL.test(c) || NET_API.test(c) || (RSYNC.test(c) && RSYNC_REMOTE.test(c)) || GIT_PUSH_URL.test(c);
  }
  if (toolName.startsWith('mcp__')) return WEB_MCP_NAME.test(toolName.slice(5)) || mcpHasUrl(toolInput);
  return false;
}

// ---------------------------------------------------------------- session store (taint + retry tokens)

export const TAINT_LIMITS = Object.freeze({
  ttlMs: 24 * 60 * 60 * 1000, maxBytes: 1024, maxFiles: 500, retryMs: 10 * 60 * 1000, maxRetries: 8,
});
const SKEW_MS = 60_000;
// No separators, dots or drive letters; 8+ characters also rules out Windows device names (CON, NUL, COM1).
const SESSION_ID = /^[A-Za-z0-9_-]{8,128}$/;
const HASH = /^[0-9a-f]{64}$/;

/** `<dataDir>/guard-sessions/<session_id>.json`, or null for an unusable session id. */
export function taintFile(dataDir, sessionId) {
  if (typeof dataDir !== 'string' || !dataDir || typeof sessionId !== 'string' || !SESSION_ID.test(sessionId)) return null;
  return path.join(dataDir, 'guard-sessions', `${sessionId}.json`);
}

/**
 * Retry-token key: sha256 of tool_name, NUL, canonical JSON of tool_input (object keys sorted, arrays in
 * order). Only this hash is stored, never the call text. Null when the input cannot be serialized.
 */
export function retryHash(toolName, toolInput) {
  try {
    const canon = JSON.stringify(toolInput, (k, v) => (v && typeof v === 'object' && !Array.isArray(v)
      ? Object.fromEntries(Object.keys(v).sort().map(x => [x, v[x]])) : v));
    if (typeof canon !== 'string') return null;
    return crypto.createHash('sha256').update(`${toolName}\0${canon}`).digest('hex');
  } catch {
    return null;
  }
}

const fresh = (t, now, maxAge) => typeof t === 'number' && t <= now + SKEW_MS && now - t <= maxAge;

/**
 * `<dataDir>/guard-sessions/<session_id>.taint`: a create-only marker whose mtime is the time of the secret
 * read. Kept apart from the retry-token JSON so a concurrent token update can never drop it (no
 * read-modify-write).
 */
export function taintMarker(dataDir, sessionId) {
  const f = taintFile(dataDir, sessionId);
  return f ? f.slice(0, -'.json'.length) + '.taint' : null;
}

/** Unexpired retry tokens of a session; empty on any problem. Never throws. */
function readRetries(dataDir, sessionId, now) {
  try {
    const f = taintFile(dataDir, sessionId);
    if (!f) return [];
    const st = fs.lstatSync(f, { throwIfNoEntry: false });
    if (!st || !st.isFile() || st.size > TAINT_LIMITS.maxBytes) return [];
    const v = JSON.parse(fs.readFileSync(f, 'utf8'));
    return v && Array.isArray(v.retry)
      ? v.retry.filter(r => r && typeof r.h === 'string' && HASH.test(r.h) && fresh(r.t, now, TAINT_LIMITS.retryMs)).map(r => ({ h: r.h, t: r.t }))
      : [];
  } catch {
    return [];
  }
}

/** True when this session read a secret through an attributed call within the TTL. Never throws. */
export function readTaint(dataDir, sessionId, now = Date.now()) {
  try {
    const m = taintMarker(dataDir, sessionId);
    const st = m && fs.lstatSync(m, { throwIfNoEntry: false });
    // Whole ms: markTaint sets ms times, and ext4/APFS read them back a hair below (utimes takes double seconds).
    return !!st && st.isFile() && fresh(Math.round(st.mtimeMs), now, TAINT_LIMITS.ttlMs);
  } catch {
    return false;
  }
}

/** True when an unexpired retry token for `hash` exists in this session. Never throws. */
export function hasRetry(dataDir, sessionId, hash, now = Date.now()) {
  return typeof hash === 'string' && HASH.test(hash) && readRetries(dataDir, sessionId, now).some(r => r.h === hash);
}

const STORE_FILE = /\.(?:json|taint)$/;

/** Drop expired files, then the oldest beyond maxFiles (never `keep`). */
function prune(dir, keep, now) {
  const files = [];
  for (const name of fs.readdirSync(dir)) {
    if (!STORE_FILE.test(name)) continue;
    const f = path.join(dir, name);
    try {
      const st = fs.lstatSync(f);
      if (!st.isFile()) continue;
      if (f !== keep && now - st.mtimeMs > TAINT_LIMITS.ttlMs) fs.rmSync(f, { force: true });
      else files.push({ f, t: st.mtimeMs });
    } catch { /* skip */ }
  }
  if (files.length <= TAINT_LIMITS.maxFiles) return;
  files.sort((a, b) => a.t - b.t);
  let extra = files.length - TAINT_LIMITS.maxFiles;
  for (const { f } of files) {
    if (extra <= 0) break;
    if (f === keep) continue;
    try { fs.rmSync(f, { force: true }); extra--; } catch { /* skip */ }
  }
}

/** rename, retried once (Windows reports EPERM/EBUSY/EACCES while another process holds the target). */
function renameRetry(from, to) {
  try {
    fs.renameSync(from, to);
  } catch {
    fs.renameSync(from, to);
  }
}

/** Read-modify-write of the retry tokens (compact JSON, at most maxBytes, atomic rename). False on any failure. */
function updateRetries(dataDir, sessionId, now, change) {
  try {
    const f = taintFile(dataDir, sessionId);
    if (!f) return false;
    let retry = change(readRetries(dataDir, sessionId, now)).slice(-TAINT_LIMITS.maxRetries);
    let text;
    for (;;) {
      text = JSON.stringify(retry.length ? { v: 1, retry } : { v: 1 });
      if (Buffer.byteLength(text) <= TAINT_LIMITS.maxBytes || !retry.length) break;
      retry = retry.slice(1); // oldest token first
    }
    fs.mkdirSync(path.dirname(f), { recursive: true });
    const tmp = `${f}.${process.pid}-${crypto.randomBytes(4).toString('hex')}.tmp`;
    try {
      fs.writeFileSync(tmp, text);
      renameRetry(tmp, f);
    } finally {
      try { fs.rmSync(tmp, { force: true }); } catch { /* best effort */ }
    }
    try { prune(path.dirname(f), f, now); } catch { /* pruning is best effort */ }
    return true;
  } catch {
    return false;
  }
}

/**
 * Record the taint fact (never the matched text): create the marker with `wx` (EEXIST is success) and set
 * its mtime to `now`. False on any failure.
 */
export function markTaint(dataDir, sessionId, now = Date.now()) {
  try {
    const m = taintMarker(dataDir, sessionId);
    if (!m) return false;
    fs.mkdirSync(path.dirname(m), { recursive: true });
    try {
      fs.writeFileSync(m, '', { flag: 'wx' });
    } catch (e) {
      if (e.code !== 'EEXIST') throw e;
      if (!fs.lstatSync(m).isFile()) return false;
    }
    // mtime = time of the (latest) secret read: the TTL counts from it.
    fs.utimesSync(m, now / 1000, now / 1000);
    try { prune(path.dirname(m), m, now); } catch { /* pruning is best effort */ }
    return true;
  } catch {
    return false;
  }
}

/** Store a retry token (hash only) for a paused call. */
export function issueRetry(dataDir, sessionId, hash, now = Date.now()) {
  if (typeof hash !== 'string' || !HASH.test(hash)) return false;
  return updateRetries(dataDir, sessionId, now, r => [...r.filter(x => x.h !== hash), { h: hash, t: now }]);
}

/** Remove a used retry token; `taint` also records (separately) that the retried call read a secret. */
export function consumeRetry(dataDir, sessionId, hash, now = Date.now(), { taint = false } = {}) {
  const marked = taint ? markTaint(dataDir, sessionId, now) : true;
  const consumed = updateRetries(dataDir, sessionId, now, r => r.filter(x => x.h !== hash));
  return marked && consumed;
}

// ---------------------------------------------------------------- decision

const TIER2 = new Set(['rce', 'exfil', 'miner', 'destructive']);
const SELF_RULES = new Set(['SELF_PROTECT', 'SELF_PROTECT_WRITE', 'PATH_UNUSUAL_WRITE']);
const NO_ASK = 'Codex cannot ask for confirmation.';
const RUN_YOURSELF = `skill-sentry protects its own data and install directories, and ${NO_ASK} `
  + 'Tell the user: if they want this, they must run this command themselves in a terminal.';
const UNUSUAL_WRITE = `The write target uses an unusual path form that may alias a skill-sentry file, and ${NO_ASK} `
  + 'Tell the user: if they want this, they must run this command themselves in a terminal.';
const OWN_TERMINAL = 'If the user asked for exactly this, they can run it themselves in their own terminal; '
  + 'otherwise do not retry it in another form, and tell the user what was blocked and why.';
const MALWARE = 'Under Codex, high-risk matches that signal malware execution or data exfiltration are always blocked, '
  + `even when no skill or plugin is attributed. ${OWN_TERMINAL}`;
const SECRET_EGRESS = `This call touches secret material and can send data off this machine. ${OWN_TERMINAL}`;
const TAINT = 'A skill or plugin read secret material earlier in this Codex session and this call can send data off this machine. '
  + OWN_TERMINAL;
const CWD_PROTECTED = `The command would run with its working directory inside skill-sentry's data or install directory, and ${NO_ASK} `
  + 'Tell the user: if they want this, they must run this command themselves in a terminal.';
const PATCH_TOO_LARGE = 'The patch is too large for skill-sentry to inspect (more than '
  + `${PATCH_MAX_PATHS} file headers or ${PATCH_MAX_BYTES / (1024 * 1024)} MiB). Split it into smaller patches.`;
const PATCH_NOT_INLINE = 'This command runs apply_patch without the patch inline (stdin, a file, a substitution or more than one '
  + 'invocation), so skill-sentry cannot see which files it writes. Use the apply_patch tool with the patch inline instead.';

const originName = o => (o ? o.skill ?? o.mcpPlugin ?? null : null);
const show = s => truncate(escapeInvisible(String(s ?? '')), 200)
  .replace(/[\x00-\x1f\x7f"]/g, ch => '\\x' + ch.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0'));

/** Tier-3 pause (R16): the doubt travels in the deny reason, before the call runs. */
function pauseText(d, label) {
  return `skill-sentry paused this ${d.ruleId} (high) call from ${show(label)}: "${show(d.snippet)}". `
    + 'Before retrying, confirm that the user explicitly asked for it, that it does not execute downloaded code, '
    + 'and that it will not send restricted data off this machine. If any of that is uncertain, stop and tell the user. '
    + 'If it is legitimate, re-run the exact same command (within 10 minutes).';
}

/**
 * Map a guardcore decision onto the Codex tiers. Never returns "ask"; only "deny" produces output.
 * @param {{ decision: string, ruleId?: string, severity?: string, snippet?: string, highs?: object[] }} base
 * `ctx.origin` is only read, never computed here: the label of a deny must not wait on the rollout (C4).
 * @param {{ origin: object|null|(() => object|null), net: boolean, tainted: () => boolean, retry?: () => boolean,
 *   patchTruncated?: boolean, cwdProtected?: boolean, snippet?: string, toolName?: string }} ctx
 * @returns {{ decision: 'deny'|'log'|'none', ruleId?: string, severity?: string, snippet?: string, label?: string|null,
 *   reason?: string, retry?: 'issued'|'consumed', markTaint?: boolean }}
 */
export function codexDecision(base, ctx) {
  const origin = () => (typeof ctx.origin === 'function' ? ctx.origin() : ctx.origin) ?? null;
  const deny = (m, extra, label = originName(origin())) => ({
    decision: 'deny', ruleId: m.ruleId, severity: m.severity ?? 'high', snippet: m.snippet, label,
    reason: formatReason({ decision: 'deny', ruleId: m.ruleId, severity: m.severity ?? 'high', snippet: m.snippet }, label, null) + (extra ? ` ${extra}` : ''),
  });
  // Ruling R17: rule id and tool name only; the command (which may carry an exfiltrated value) never appears.
  const taintDeny = () => deny({ ruleId: 'SESSION_TAINT_EGRESS', severity: 'high', snippet: String(ctx.toolName ?? 'tool') }, TAINT, null);
  const tainted = () => !!(ctx.net && ctx.tainted && ctx.tainted());

  if (base && base.decision === 'deny') return deny(base, '');                              // tier 1
  if (ctx.cwdProtected) {                                                                    // tier 5 (C3)
    return deny({ ruleId: 'SELF_PROTECT_CWD', severity: 'high', snippet: ctx.snippet ?? '' }, CWD_PROTECTED);
  }
  if (base && base.decision === 'ask' && SELF_RULES.has(base.ruleId)) {                      // tier 5
    return deny(base, base.ruleId === 'PATH_UNUSUAL_WRITE' ? UNUSUAL_WRITE : RUN_YOURSELF);
  }
  // A patch past the scan caps (C1), or a shell apply_patch whose patch is not inline (R18), could not be
  // inspected: fail closed, no retry token.
  if (ctx.patchTruncated || ctx.patchNotInline) {
    return deny({ ruleId: 'PATCH_UNINSPECTABLE', severity: 'high', snippet: String(ctx.toolName ?? 'apply_patch') }, ctx.patchTruncated ? PATCH_TOO_LARGE : PATCH_NOT_INLINE);
  }
  if (!base || base.decision === 'none') return tainted() ? taintDeny() : { decision: 'none' };
  if (base.decision !== 'ask' && base.decision !== 'log') return { decision: 'none' };

  const highs = Array.isArray(base.highs) && base.highs.length ? base.highs : [{ ruleId: base.ruleId, category: null, snippet: base.snippet }];
  const malware = highs.find(h => TIER2.has(h.category));
  if (malware) return deny({ ...malware, severity: 'high' }, MALWARE);                     // tier 2
  const secret = highs.find(h => h.category === 'secret');
  if (secret && ctx.net) return deny({ ...secret, severity: 'high' }, SECRET_EGRESS);      // tier 2
  if (tainted()) return taintDeny();                                                       // tier 2
  if (base.decision === 'ask') {                                                           // tier 3 (R16)
    const label = originName(origin());
    const common = { ruleId: base.ruleId, severity: 'high', snippet: base.snippet, label };
    if (ctx.retry && ctx.retry()) return { decision: 'log', ...common, retry: 'consumed', markTaint: !!secret };
    return { decision: 'deny', ...common, reason: pauseText(base, label), retry: 'issued' };
  }
  return { decision: 'log', ruleId: base.ruleId, severity: 'high', snippet: base.snippet, label: null };  // tier 4
}

/**
 * Ruling R15: Codex on Windows runs `Bash` tool calls through PowerShell. Self-protection follows the
 * PowerShell reading only; critical and tier-2 matches take the union of both readings. (guardcore's rule
 * matching does not depend on the reading today, so the union is defensive.)
 */
export function mergeWin32Readings(bash, ps) {
  if (ps.decision === 'deny') return ps;
  if (bash.decision === 'deny') return bash;
  if (ps.decision === 'ask' && SELF_RULES.has(ps.ruleId)) return ps;
  const extra = (bash.decision === 'ask' || bash.decision === 'log') && !SELF_RULES.has(bash.ruleId) && Array.isArray(bash.highs)
    ? bash.highs.filter(h => TIER2.has(h.category) || h.category === 'secret') : [];
  if (!extra.length) return ps;
  if (ps.decision === 'ask' || ps.decision === 'log') {
    const have = new Set((ps.highs ?? []).map(h => h.ruleId));
    return { ...ps, highs: [...(ps.highs ?? []), ...extra.filter(h => !have.has(h.ruleId))] };
  }
  const first = extra.find(h => TIER2.has(h.category)) ?? extra[0];
  return { decision: 'log', ruleId: first.ruleId, severity: 'high', reason: 'high-risk rule match', snippet: first.snippet, highs: extra };
}

// ---------------------------------------------------------------- hook handling

const safe = s => (s == null ? null : truncate(escapeInvisible(String(s)), 200));
const SHELL_TOOLS = new Set(['Bash', 'PowerShell']);

const normDir = s => {
  let x = String(s).replace(/\\/g, '/');
  while (x.length > 1 && x.endsWith('/') && !/^[A-Za-z]:\/$/.test(x)) x = x.slice(0, -1);
  return process.platform === 'win32' ? x.toLowerCase() : x;
};
/** Lexical and real (symlinks, junctions, 8.3 names) forms of a directory. */
function dirForms(p) {
  let abs;
  try { abs = path.resolve(p); } catch { return []; }
  const out = [normDir(abs)];
  try { out.push(normDir(fs.realpathSync.native(abs))); } catch { /* missing: lexical only */ }
  return out;
}
const isUnderDir = (c, r) => c === r || c.startsWith(r.endsWith('/') ? r : r + '/');

/** True when `cwd` is (inside) one of `roots`, comparing lexical and real forms. Never throws. */
export function cwdInside(cwd, roots) {
  try {
    if (typeof cwd !== 'string' || !cwd) return false;
    const cs = dirForms(cwd);
    // A filesystem root as a protected root would match everything: never the case for data/install dirs.
    const rs = roots.filter(r => typeof r === 'string' && r).flatMap(dirForms).filter(r => r !== '/' && !/^[a-z]:\/?$/i.test(r));
    return cs.some(c => rs.some(r => isUnderDir(c, r)));
  } catch {
    return false;
  }
}

function readAllowlist(dir) {
  try { return loadAllowlist(dir); } catch { return { version: 1, entries: [] }; }
}

/**
 * Handle one Codex PreToolUse payload. The decision is written first; the session-store write (retry token,
 * consumption, taint) and the log line follow (Ruling L1). Unknown or malformed shapes produce no output.
 * @param {{ input: object, selfRoot: string, write: (s: string) => void, log: (entry: object) => void,
 *   now?: () => number, deadline?: number, shellPatch?: typeof shellPatch }} io  `deadline` (epoch ms) bounds
 *   the rollout read for the origin; `shellPatch` replaces the shell-form patch scanner (tests).
 */
export async function handleCodex({ input, selfRoot, write, log, now = Date.now, deadline = Infinity, shellPatch: shellPatchFn = shellPatch }) {
  const toolName = input.tool_name;
  const toolInput = input.tool_input;
  if (!toolInput || typeof toolInput !== 'object' || Array.isArray(toolInput)) return;
  const dir = dataDirPath();
  const t = now();
  const sid = input.session_id;
  const shell = SHELL_TOOLS.has(toolName);
  const cmd = typeof toolInput.command === 'string' ? toolInput.command : null;

  let extraWritePaths = null;
  let patchTruncated = false;
  let patchNotInline = false;
  if (toolName === 'apply_patch') {
    if (cmd === null) return;
    ({ paths: extraWritePaths, truncated: patchTruncated } = scanPatch(cmd));
  } else if (shell && cmd !== null) {
    // I1: `[cd <dir> &&] apply_patch <<'EOF' …` is applied by Codex itself; its headers are write targets.
    // R20.1: runs before decide(), so a throw here must never fail the whole call open.
    let sp;
    try { sp = shellPatchFn(cmd); } catch { sp = { paths: [], truncated: false, workdir: null, inline: false }; }
    if (sp) {
      patchTruncated = sp.truncated;
      patchNotInline = !sp.inline;
      const from = typeof input.cwd === 'string' && input.cwd ? input.cwd : process.cwd();
      extraWritePaths = sp.workdir === null ? sp.paths : sp.paths.map(p => path.resolve(from, sp.workdir, p));
    }
  }

  // C3: a shell call whose working directory is inside the data or install dir can touch it with bare
  // relative names. Only an exact Ruling M read-only self invocation is exempt.
  const cwdProtected = shell && cmd !== null && cwdInside(input.cwd, [dir, selfRoot])
    && !isReadOnlySelfInvocation(cmd, selfRoot, toolName, { agentFlag: true })
    && !(process.platform === 'win32' && isReadOnlySelfInvocation(cmd, selfRoot, 'PowerShell', { agentFlag: true }));

  let originMemo;
  const origin = () => (originMemo === undefined ? (originMemo = findCodexOrigin(input.transcript_path, undefined, toolName, deadline)) : originMemo);
  // P3: the hook cwd is not a base for relative names (a Codex shell call may run in its own `workdir`).
  const args = { toolName, toolInput, origin, allowlist: () => readAllowlist(dir), selfRoot, dataDir: dir, cwd: input.cwd, extraWritePaths, selfViews: true, shellCwd: false };
  const base = process.platform === 'win32' && toolName === 'Bash'
    ? mergeWin32Readings(decide(args), decide({ ...args, toolName: 'PowerShell' }))
    : decide(args);

  let hashMemo;
  const hash = () => (hashMemo === undefined ? (hashMemo = retryHash(toolName, toolInput)) : hashMemo);
  const d = codexDecision(base, {
    // Peek only (C4): decide() already resolved the origin when a high match needed it.
    origin: () => originMemo ?? null,
    net: isNetworkCapable(toolName, toolInput), patchTruncated, patchNotInline, cwdProtected, toolName,
    tainted: () => readTaint(dir, sid, t),
    retry: () => hasRetry(dir, sid, hash(), t),
    snippet: cmd !== null && toolName !== 'apply_patch' ? cmd : toolName,
  });
  if (d.decision === 'none') return;

  if (d.decision === 'deny') {
    write(JSON.stringify({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: d.reason } }));
  }
  log({
    agent: 'codex', tool: safe(toolName), ruleId: d.ruleId, severity: d.severity, snippet: safe(d.snippet), origin: safe(d.label),
    decision: d.decision, ...(d.retry ? { retry: d.retry } : {}),
  });
  if (d.retry === 'issued') issueRetry(dir, sid, hash(), t);
  else if (d.retry === 'consumed') consumeRetry(dir, sid, hash(), t, { taint: !!d.markTaint });
  else if (d.markTaint) markTaint(dir, sid, t);
}
