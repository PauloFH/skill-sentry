import path from 'node:path';
import { rawConfigOf } from '../inventory.mjs';
import { matchText } from '../rules.mjs';
import { redactSecrets, redactArgs, TOKEN_SHAPES } from '../text.mjs';
import { CONFIG_FILE, finding, commandFindings, urlFindings } from '../cmdfindings.mjs';

/**
 * Deterministic rules over Codex components (spec §4). Detection runs on the RAW config
 * (rawConfigOf); a finding only ever shows key paths, rule patterns (redacted) and the source file
 * name, never a config value that could be a credential. Every finding is filed under `<config>`, the
 * pseudo-file the baseline and allowlist hash for config-only components.
 */

// Assembled so this detector's own source never carries the literal flag.
const BYPASS_FLAG = ['--dangerously-', 'bypass-hook-trust'].join('');

const rule = (id, category, severity, description) => ({ id, category, severity, description });

export const CODEX_RULES = [
  rule('CODEX_NO_APPROVAL_FULL_ACCESS', 'config', 'high',
    'approval_policy "never" with sandbox_mode "danger-full-access" in the same layer: every command runs unsandboxed with no prompt'),
  rule('CODEX_APPROVAL_NEVER', 'config', 'medium', 'approval_policy "never": Codex never asks before running a command'),
  rule('CODEX_SANDBOX_FULL_ACCESS', 'config', 'medium', 'sandbox_mode "danger-full-access": commands run without a sandbox'),
  rule('CODEX_RULE_BROAD_ALLOW', 'permissions', 'high',
    'execpolicy allow rule ending at a shell/interpreter or its code flag: arbitrary code runs outside the sandbox with no prompt'),
  rule('CODEX_RULE_ALLOW', 'permissions', 'info', 'execpolicy allow rule: matching commands run outside the sandbox with no prompt'),
  rule('CODEX_RULE_UNPARSED', 'config', 'info', 'prefix_rule call the scanner could not parse; review it by hand'),
  rule('CODEX_SECRET_IN_CONFIG', 'secret', 'high',
    'Secret-looking literal in Codex config (environment, MCP env/headers, OAuth secret, bearer token, URL credentials)'),
  rule('CODEX_MCP_AUTO_APPROVE', 'config', 'medium',
    'MCP tools auto-approved (approval mode "approve"); high when the server comes from a plugin or is remote'),
  rule('CODEX_TRUSTED_TMP_PROJECT', 'config', 'medium', 'Project under a temp directory marked trusted: its config, hooks and rules load'),
  rule('CODEX_HOOK_TRUST_BYPASS', 'config', 'high', 'Hook trust bypass flag: unreviewed hooks run without the trust check'),
  rule('CODEX_HOOKS_DISABLED', 'config', 'medium', '[features] hooks = false: no hook runs, including the skill-sentry guard'),
  rule('CODEX_ENV_SECRETS_PASSED', 'config', 'info',
    'shell_environment_policy.ignore_default_excludes is true or unset (default true): secret-looking env vars reach commands'),
  rule('CODEX_RULES_ERROR', 'config', 'info', 'The Codex config rules failed on this component; it was not evaluated (verdict at least review)'),
];
const RULE = Object.fromEntries(CODEX_RULES.map(r => [r.id, r]));

const emit = (id, snippet, line = 0, severity = RULE[id].severity) =>
  finding(id, RULE[id].category, severity, CONFIG_FILE, snippet, line);

const isObj = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const entries = v => (isObj(v) ? Object.entries(v) : []);

/** `a.b."c d"[2]` from key parts (numbers are array indexes). */
const keyPath = parts => parts.reduce((s, p) => {
  if (typeof p === 'number') return `${s}[${p}]`;
  const k = /^[A-Za-z0-9_-]+$/.test(p) ? p : JSON.stringify(p);
  return s ? `${s}.${k}` : k;
}, '');

// ---------------------------------------------------------------- secrets

// Env names are matched on whole `_`/`-` segments: ANTHROPIC_AUTH_TOKEN, PAD_KEY, MY_API_KEY; never
// GIT_AUTHOR_NAME, MAX_TOKENS, TOKENIZERS_PARALLELISM or OAUTHLIB_*.
const SECRET_NAME = /(?:^|[_-])(?:token|secret|passw(?:or)?d|pwd|api[_-]?key|access[_-]?key|private[_-]?key|credentials?|cookie|auth(?:[_-]?token)?|bearer|session[_-]?id|key)(?:[_-]|$)/i;
const SECRET_HEADER = /authorization|token|api[_-]?key|secret|cookie|auth|session/i;
const SECRET_ANYWHERE = /^(?:(?:experimental_)?bearer(?:_token)?|api[_-]?key|password|passwd|client_secret|access_token|auth_token)$/i;
const SECRET_PARENT = /^(?:oauth|auth|credentials?|secrets?)$/i;
const SECRET_UNDER_PARENT = /token|secret|passw|pwd|api[_-]?key|private[_-]?key|credential|cookie|^value$/i;
const NAME_ONLY = /env_var$|^env_key$/i; // values are names of env vars, not credentials
const ENV_REF = /^\s*(?:\$\{(?:env:)?[A-Za-z_]\w*(?::?-[^}]*)?\}|\$[A-Za-z_]\w*|%[A-Za-z_]\w*%|env:[A-Za-z_]\w*)\s*$/;
// Loose form only where a credential is expected (headers, env, set); elsewhere (prose such as
// developer_instructions) the token must look like one: 16+ chars with a digit.
const BEARER = /\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}/;
const BEARER_STRICT = /\b(?:Bearer|Basic)\s+(?=[A-Za-z._~+/=-]*\d)[A-Za-z0-9._~+/=-]{16,}/;
const URL_USERINFO = /[a-z][\w+.-]*:\/\/[^/?#@\s:]*:[^/?#@\s]+@/i;
// Query parameter NAMED like a credential (`key`, `api_key`, `access_token`), not `author`/`keyword`.
const URL_SECRET_QUERY = /[?&](?:[\w-]*[_-])?(?:token|key|apikey|secret|sig|signature|password|passwd|auth)=[^&#\s]+/i;

const secretValue = (v, loose) => TOKEN_SHAPES.test(v) || (loose ? BEARER : BEARER_STRICT).test(v) || URL_USERINFO.test(v) || URL_SECRET_QUERY.test(v);
/**
 * A value that could be a credential, for name-based decisions: 8+ chars without spaces (after an auth
 * scheme), not a boolean, number, plain short word, filesystem path or plain URL.
 */
function credentialLike(v) {
  const s = v.trim().replace(/^(?:Bearer|Basic|Token)\s+/i, '');
  if (s.length < 8 || /\s/.test(s)) return false;
  if (/^(?:true|false|yes|no|on|off|null|none)$/i.test(s) || /^[-+]?\d+(?:\.\d+)?$/.test(s)) return false;
  if (/^[A-Za-z]+$/.test(s) && s.length < 20) return false;
  if (/^(?:[A-Za-z]:[\\/]|[\\/~.])/.test(s) || /^[a-z][\w+.-]*:\/\//i.test(s)) return false;
  return true;
}
/** Text that is shown: redactSecrets also masks well-known token shapes and credential headers. */
const hide = s => redactSecrets(s);

function isSecretLeaf(parts, v) {
  if (typeof v !== 'string' || !v.trim() || ENV_REF.test(v)) return false;
  const keys = parts.filter(p => typeof p === 'string');
  const k = keys.at(-1) ?? '';
  const parent = keys.at(-2);
  if (keys.includes('env_http_headers') || NAME_ONLY.test(k)) return false;
  const inEnv = parent === 'env' || (parent === 'set' && keys.at(-3) === 'shell_environment_policy');
  const inHeaders = parent === 'http_headers' || parent === 'headers';
  if (secretValue(v, inEnv || inHeaders)) return true;
  if (!credentialLike(v)) return false;
  if (inEnv) return SECRET_NAME.test(k);
  if (inHeaders) return SECRET_HEADER.test(k);
  if (keys.slice(0, -1).some(a => SECRET_PARENT.test(a))) return SECRET_UNDER_PARENT.test(k);
  return SECRET_ANYWHERE.test(k);
}

/** Every scalar leaf under `v` as [parts, value]; bounded depth, own keys only. */
function leaves(v, parts, out = [], depth = 0) {
  if (depth > 32) return out;
  if (Array.isArray(v)) v.forEach((x, i) => leaves(x, [...parts, i], out, depth + 1));
  else if (isObj(v)) for (const [k, x] of Object.entries(v)) leaves(x, [...parts, k], out, depth + 1);
  else out.push([parts, v]);
  return out;
}

// ---------------------------------------------------------------- per-layer settings

// Subtrees of a config layer (kind `config`) that are inventoried as their own components and scanned
// there. An agent TOML's subtrees are not inventoried, so they are scanned on the agent component.
const OWNED = new Set(['mcp_servers', 'hooks', 'notify', 'apps', 'marketplaces']);

const isMainConfig = c => c.kind === 'config' && c.scope === 'user' && c.name === 'config.toml';

function layerFindings(c, raw, src) {
  const out = [];
  const layers = [{ where: '', v: raw }];
  for (const [n, v] of entries(raw.profiles)) if (isObj(v)) layers.push({ where: `[${keyPath(['profiles', n])}] `, v });
  for (const { where, v } of layers) {
    const never = v.approval_policy === 'never';
    const full = v.sandbox_mode === 'danger-full-access';
    if (never && full) out.push(emit('CODEX_NO_APPROVAL_FULL_ACCESS', `${where}approval_policy = "never" with sandbox_mode = "danger-full-access" in ${src}`));
    else if (never) out.push(emit('CODEX_APPROVAL_NEVER', `${where}approval_policy = "never" in ${src}`));
    else if (full) out.push(emit('CODEX_SANDBOX_FULL_ACCESS', `${where}sandbox_mode = "danger-full-access" in ${src}`));
    if (isObj(v.features) && v.features.hooks === false) out.push(emit('CODEX_HOOKS_DISABLED', `${where}features.hooks = false in ${src}`));
    const sep = isObj(v.shell_environment_policy) ? v.shell_environment_policy.ignore_default_excludes : undefined;
    if (sep === true) out.push(emit('CODEX_ENV_SECRETS_PASSED', `${where}shell_environment_policy.ignore_default_excludes = true in ${src}`));
    else if (sep === undefined && where === '' && isMainConfig(c)) {
      out.push(emit('CODEX_ENV_SECRETS_PASSED', `shell_environment_policy.ignore_default_excludes is unset (defaults to true) in ${src}`));
    }
  }
  return out;
}

const TEMP_PATHS = [
  /^(?:\/private)?(?:\/var)?\/tmp(?:\/|$)/,
  /(?:^|\/)appdata\/local\/temp(?:\/|$)/,
  /^[a-z]:\/windows\/temp(?:\/|$)/,
  /^(?:%te?mp%|\$env:te?mp)(?:\/|$)/,
];
const isTempPath = p => {
  const s = String(p).replace(/\\/g, '/').toLowerCase();
  return TEMP_PATHS.some(re => re.test(s));
};

function trustedTmpFinding(raw, src) {
  const hits = entries(raw.projects).filter(([p, v]) => isObj(v) && v.trust_level === 'trusted' && isTempPath(p)).map(([p]) => p);
  if (!hits.length) return [];
  const shown = hits.slice(0, 3).map(hide).join(', ') + (hits.length > 3 ? `, ... (+${hits.length - 3} more)` : '');
  return [emit('CODEX_TRUSTED_TMP_PROJECT', `${hits.length} trusted project(s) under temp dirs in ${src}: ${shown}`)];
}

// ---------------------------------------------------------------- MCP approval

function approveFindings(server, parts, high) {
  if (!isObj(server)) return [];
  const sev = high || typeof server.url === 'string' ? 'high' : 'medium';
  const out = [];
  if (server.default_tools_approval_mode === 'approve') {
    out.push(emit('CODEX_MCP_AUTO_APPROVE', `${keyPath([...parts, 'default_tools_approval_mode'])} = "approve": every tool of this server runs with no prompt`, 0, sev));
  }
  for (const [t, tv] of entries(server.tools)) {
    if (isObj(tv) && tv.approval_mode === 'approve') {
      out.push(emit('CODEX_MCP_AUTO_APPROVE', `${keyPath([...parts, 'tools', t, 'approval_mode'])} = "approve": this tool runs with no prompt`, 0, sev));
    }
  }
  return out;
}

// ---------------------------------------------------------------- execpolicy rules

const INTERPRETER = /^(?:pwsh|powershell|cmd|bash|sh|zsh|python(?:\d+(?:\.\d+)*)?w?|node|ruby|perl)$/;
// Code / startup flags of shells and interpreters (compared lowercased). A tail of only these still
// lets the caller supply the code. `-executionpolicy` takes a value (the next element, any word).
const CODE_FLAGS = new Set([
  '-command', '--command', '-c', '/c', '-e', '--eval', '-p', '-i', '-l', '-lc',
  '-noprofile', '-nologo', '-noninteractive', '-encodedcommand', '-enc', '-ec', '-executionpolicy',
]);
const VALUE_FLAGS = new Set(['-executionpolicy']);
const alts = e => (Array.isArray(e) ? e : [e]).map(String);
const exeName = s => s.replace(/^.*[\\/]/, '').toLowerCase().replace(/\.exe$/, '');

/** Allows any code: first element an interpreter, every later element only a code flag (any alternative). */
export function isBroadAllow(pattern) {
  if (!Array.isArray(pattern) || !pattern.length) return false;
  if (!alts(pattern[0]).some(a => INTERPRETER.test(exeName(a)))) return false;
  for (let i = 1; i < pattern.length; i++) {
    const flags = alts(pattern[i]).map(a => a.toLowerCase());
    if (!flags.some(a => CODE_FLAGS.has(a))) return false;
    if (flags.some(a => VALUE_FLAGS.has(a))) i++; // skip the flag's value (e.g. Bypass)
  }
  return true;
}

/** The pattern as shown: credential flags' values, bearer tokens and token shapes redacted. */
function showPattern(pattern) {
  const flat = pattern.map(e => alts(e).join('|'));
  const red = redactArgs(flat, flat[0]);
  const shown = pattern.map((e, i) => {
    if (red[i] === '<redacted>' && flat[i] !== '<redacted>') return '<redacted>';
    return Array.isArray(e) ? alts(e).map(hide) : hide(String(e));
  });
  return JSON.stringify(shown);
}

function rulesFindings(raw, src) {
  const out = [];
  for (const r of Array.isArray(raw.rules) ? raw.rules : []) {
    if (!isObj(r) || !Array.isArray(r.pattern) || r.decision !== 'allow') continue;
    const line = Number.isInteger(r.line) ? r.line : 0;
    const shown = `prefix_rule(pattern=${showPattern(r.pattern)}, decision="allow")`;
    if (isBroadAllow(r.pattern)) out.push(emit('CODEX_RULE_BROAD_ALLOW', `${shown} in ${src}: any code runs outside the sandbox with no prompt`, line));
    else out.push(emit('CODEX_RULE_ALLOW', `${shown} in ${src}`, line));
  }
  for (const n of Array.isArray(raw.unparsed) ? raw.unparsed : []) {
    if (Number.isInteger(n)) out.push(emit('CODEX_RULE_UNPARSED', `prefix_rule call at line ${n} of ${src} could not be parsed; review it by hand`, n));
  }
  return out;
}

// ---------------------------------------------------------------- commands

function commandsOf(c, raw) {
  const out = [];
  const args = Array.isArray(raw.args) ? raw.args.map(String) : [];
  if (c.kind === 'hook') {
    if (typeof raw.command === 'string') out.push(...commandFindings([raw.command, ...args]));
    if (typeof raw.command_windows === 'string') out.push(...commandFindings([raw.command_windows]));
    if (typeof raw.prompt === 'string') {
      for (const m of matchText(raw.prompt, 'markdown')) out.push({ ...m, snippet: redactSecrets(m.snippet), file: CONFIG_FILE });
    }
  } else if (c.kind === 'mcp' || c.kind === 'notify') {
    if (typeof raw.command === 'string') out.push(...commandFindings([raw.command, ...args]));
    for (const h of [raw.http_headers_helper, raw.headersHelper]) {
      if (typeof h === 'string') out.push(...commandFindings([h]));
      else if (Array.isArray(h) && h.length && h.every(x => typeof x === 'string')) out.push(...commandFindings(h));
    }
    if (typeof raw.url === 'string') out.push(...urlFindings(raw.url));
  }
  return out;
}

// ---------------------------------------------------------------- entry points

const PREFIX = {
  mcp: c => ['mcp_servers', String(c.name)],
  notify: () => ['notify'],
  app: c => ['apps', String(c.name)],
  marketplace: c => ['marketplaces', String(c.name)],
  hook: c => ['hooks', String(c.meta?.event ?? c.name)],
};
const SCANNED_KINDS = new Set(['config', 'agent', 'rules', 'mcp', 'hook', 'notify', 'app', 'marketplace']);

/**
 * All CODEX_* findings (plus matchCommand / SUPPLY_* for configured commands) of one Codex component.
 * Never throws; returns [] for kinds without a config (skills, plugins, instructions, prompts).
 * @returns {Array<import('../scanner.mjs').Finding>}
 */
export function codexConfigFindings(c) {
  try {
    // Unparseable TOML: reported once by the inventory as a CONFIG_UNREADABLE problem line.
    if (c?.meta?.parseError) return [];
    if (!c || !SCANNED_KINDS.has(c.kind)) return [];
    const raw = rawConfigOf(c.config);
    if (!isObj(raw)) return [];
    const src = path.basename(String(c.meta?.file ?? c.meta?.source ?? c.name ?? 'config'));
    const out = [];
    const tomlLayer = c.kind === 'config' || c.kind === 'agent';
    if (tomlLayer) {
      out.push(...layerFindings(c, raw, src));
      out.push(...trustedTmpFinding(raw, src));
      for (const [p, pv] of entries(raw.plugins)) {
        for (const [n, s] of entries(isObj(pv) ? pv.mcp_servers : null)) out.push(...approveFindings(s, ['plugins', p, 'mcp_servers', n], true));
      }
    }
    if (c.kind === 'agent') {
      for (const [n, s] of entries(raw.mcp_servers)) {
        if (!isObj(s)) continue;
        out.push(...approveFindings(s, ['mcp_servers', n], false));
        out.push(...commandsOf({ kind: 'mcp' }, s));
      }
    }
    if (c.kind === 'rules') out.push(...rulesFindings(raw, src));
    if (c.kind === 'mcp') out.push(...approveFindings(raw, PREFIX.mcp(c), c.scope === 'plugin'));
    out.push(...commandsOf(c, raw));

    // Secrets and the trust-bypass flag over every string leaf (owned subtrees skipped in a config file).
    const prefix = PREFIX[c.kind]?.(c) ?? [];
    const seen = new Set();
    for (const [parts, v] of leaves(raw, [])) {
      if (c.kind === 'config' && OWNED.has(parts[0])) continue;
      if (c.kind === 'rules' && parts[0] !== 'rules') continue;
      const kp = keyPath([...prefix, ...parts]);
      if (c.kind !== 'rules' && !seen.has(kp) && isSecretLeaf([...prefix, ...parts], v)) {
        seen.add(kp);
        out.push(emit('CODEX_SECRET_IN_CONFIG', `${kp} in ${src} holds a secret-looking literal (value not shown)`));
      }
      if (typeof v === 'string' && v.toLowerCase().includes(BYPASS_FLAG)) {
        const line = c.kind === 'rules' && Number.isInteger(raw.rules?.[parts[1]]?.line) ? raw.rules[parts[1]].line : 0;
        out.push(emit('CODEX_HOOK_TRUST_BYPASS', `${kp} in ${src} contains ${BYPASS_FLAG}`, line));
      }
    }
    return out;
  } catch {
    // A rule bug must never read as a clean component: the report forces `review` on this rule id.
    return [emit('CODEX_RULES_ERROR', 'Codex config rules could not evaluate this component; review it by hand')];
  }
}

/** CODEX_HOOK_TRUST_BYPASS over scanned file text (instructions, skills, plugin files of Codex components). */
export function codexTextFindings(text) {
  const out = [];
  const lines = String(text ?? '').split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    if (!lines[i].toLowerCase().includes(BYPASS_FLAG)) continue;
    const { id, category, severity } = RULE.CODEX_HOOK_TRUST_BYPASS;
    const { file, ...m } = finding(id, category, severity, '', hide(lines[i].trim()), i + 1);
    out.push(m);
  }
  return out;
}
