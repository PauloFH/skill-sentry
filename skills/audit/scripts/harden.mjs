#!/usr/bin/env node
// skill-sentry harden helper.
//   node harden.mjs check                 -> JSON array of recommendations
//   node harden.mjs apply <id> [<id>...]  -> back up settings.json, merge the requested ids, print the backup path
// Env: SKILL_SENTRY_CLAUDE_HOME (default ~/.claude).
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { writeJsonAtomic } from './lib/datadir.mjs';
import { rawConfigOf } from './lib/inventory.mjs';
import { codexHomes } from './lib/codex/homes.mjs';
import { discoverCodex } from './lib/codex/inventory.mjs';
import { codexConfigFindings } from './lib/codex/rules.mjs';

const RULES = {
  'ask-curl': { list: 'ask', rule: 'Bash(curl *)', title: 'Ask before running curl', why: 'curl can send local data to any server. A permission prompt makes every download or upload visible.' },
  'ask-wget': { list: 'ask', rule: 'Bash(wget *)', title: 'Ask before running wget', why: 'wget can fetch and save arbitrary remote content. A permission prompt makes every download visible.' },
  'deny-ssh-read': { list: 'deny', rule: 'Read(~/.ssh/**)', title: 'Deny reading SSH keys', why: 'Private keys in ~/.ssh are a prime target for credential theft by a malicious skill or hook.' },
  'deny-aws-read': { list: 'deny', rule: 'Read(~/.aws/**)', title: 'Deny reading AWS credentials', why: 'Cloud credentials in ~/.aws are a prime target for credential theft by a malicious skill or hook.' },
  'ask-env-read': { list: 'ask', rule: 'Read(**/.env)', title: 'Ask before reading .env files', why: '.env files usually hold API keys and tokens. A prompt makes any read of them visible.' },
};

const SKILL_SHELL = {
  id: 'disable-skill-shell',
  title: 'Disable shell execution inside skills',
  why: 'Sets disableSkillShellExecution so skills and custom commands cannot run inline shell lines. Warning: it also disables !`git status`-style lines in official and trusted plugins, which may then stop working as designed.',
};

const OFFICIAL_REPO = /^anthropics\//i;

function has(settings, list, rule) {
  const arr = settings?.permissions?.[list];
  return Array.isArray(arr) && arr.includes(rule);
}

function thirdParty(known) {
  if (!known || typeof known !== 'object') return [];
  return Object.keys(known).filter(name => {
    const src = known[name]?.source ?? {};
    const repo = src.repo ?? '';
    return !(src.source === 'github' && OFFICIAL_REPO.test(repo));
  });
}

/** @returns {{id:string,title:string,why:string,applicable:boolean,present:boolean}[]} */
export function checkHardening(settings, knownMarketplaces) {
  const s = settings && typeof settings === 'object' ? settings : {};
  const recs = [];
  for (const [id, r] of Object.entries(RULES)) {
    recs.push({ id, title: r.title, why: `${r.why} Adds "${r.rule}" to permissions.${r.list}.`, applicable: true, present: has(s, r.list, r.rule) });
  }
  recs.push({ ...SKILL_SHELL, applicable: true, present: s.disableSkillShellExecution === true });
  const tp = thirdParty(knownMarketplaces);
  recs.push({
    id: 'third-party-autoupdate',
    title: 'Review third-party marketplaces',
    why: tp.length
      ? `Third-party marketplaces can ship updated plugin code that you never reviewed: ${tp.join(', ')}. Disable auto-update for them in /plugin and re-audit after each update. Info only, nothing to apply.`
      : 'No third-party marketplaces found. Info only, nothing to apply.',
    applicable: false,
    present: tp.length === 0,
  });
  recs.push({
    id: 'managed-settings',
    title: 'Restrict marketplaces and hooks with managed settings',
    why: 'Organizations can set strictKnownMarketplaces and allowManagedHooksOnly in managed settings to block unknown marketplaces and user-defined hooks. These keys are only honored from managed settings, so skill-sentry does not apply them. Info only.',
    applicable: false,
    present: s.strictKnownMarketplaces !== undefined && s.allowManagedHooksOnly === true,
  });
  return recs;
}

/** Merge one recommendation id into settings (mutates). */
function applyOne(settings, id) {
  if (id === 'disable-skill-shell') { settings.disableSkillShellExecution = true; return; }
  const { list, rule } = RULES[id];
  if (!settings.permissions || typeof settings.permissions !== 'object' || Array.isArray(settings.permissions)) settings.permissions = {};
  if (!Array.isArray(settings.permissions[list])) settings.permissions[list] = [];
  if (!settings.permissions[list].includes(rule)) settings.permissions[list].push(rule);
}

function readSettings(file) {
  let text;
  try { text = fs.readFileSync(file, 'utf8'); } catch (e) {
    if (e.code === 'ENOENT') return { settings: {}, exists: false };
    throw new Error(`cannot read ${file}: ${e.message}`);
  }
  try {
    const v = JSON.parse(text.replace(/^﻿/, ''));
    if (!v || typeof v !== 'object' || Array.isArray(v)) throw new Error('not a JSON object');
    return { settings: v, exists: true };
  } catch (e) {
    throw new Error(`${file} is not valid JSON (${e.message}); fix it manually, nothing was changed`);
  }
}

function readKnownMarketplaces(claudeHome) {
  try {
    return JSON.parse(fs.readFileSync(path.join(claudeHome, 'plugins', 'known_marketplaces.json'), 'utf8').replace(/^﻿/, ''));
  } catch { return {}; }
}

// ---------------------------------------------------------------- Codex (recommend only)
// skill-sentry never edits Codex's config.toml or rules files: every recommendation has applicable:false and a
// snippet built from FIXED text. Config values are never echoed (they may be secrets); only key paths, line
// numbers and file names, the same facts the audit findings already show. "Risky shape" is decided by the audit
// rules (codexConfigFindings), so harden and audit cannot disagree.

const CODEX_PREFIX = 'codex-';
const isObj = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const MAX_KEYS = 5;

const keyList = keys => {
  const uniq = [...new Set(keys)];
  return uniq.slice(0, MAX_KEYS).join(', ') + (uniq.length > MAX_KEYS ? `, ... (+${uniq.length - MAX_KEYS} more)` : '');
};

/** The key path at the start of an audit snippet (`<key path> = "..."` / `<key path> in <file> ...`). */
const keyOf = (snippet, re) => re.exec(snippet)?.[1];

const CODEX_RECS = [
  {
    id: 'approval-sandbox', rules: ['CODEX_NO_APPROVAL_FULL_ACCESS', 'CODEX_APPROVAL_NEVER', 'CODEX_SANDBOX_FULL_ACCESS'],
    title: 'Keep Codex sandboxed and asking',
    why: 'approval_policy "never" or sandbox_mode "danger-full-access" lets every command run with no prompt or no sandbox, so a malicious skill or hook can act freely. Use the sandboxed, ask-on-request defaults.',
    snippet: () => '# config.toml (top level, and inside any [profiles.<name>] that sets these)\napproval_policy = "on-request"\nsandbox_mode = "workspace-write"',
  },
  {
    id: 'broad-allow-rules', rules: ['CODEX_RULE_BROAD_ALLOW'],
    title: 'Replace broad allow rules with prompt rules',
    why: 'An execpolicy allow rule that ends at a shell or interpreter lets any code run outside the sandbox with no prompt. Remove it, or make it prompt.',
    snippet: hits => `${hits.map(({ c, f }) => `# remove the allow rule at line ${f.line} of ${path.basename(String(c.meta?.file ?? 'the rules file'))}`).slice(0, MAX_KEYS).join('\n')}\n# then, if you still want a rule, ask instead of allowing everything:\nprefix_rule(pattern=["<command>", "<subcommand>"], decision="prompt")`,
  },
  {
    id: 'secrets-in-config', rules: ['CODEX_SECRET_IN_CONFIG'],
    title: 'Move secrets out of config.toml',
    why: 'Literal tokens in config.toml (MCP env or headers, OAuth secrets, shell environment settings) are readable by every skill, hook and tool that can read the file. Reference an environment variable instead and keep the value in your shell or OS keychain.',
    snippet: hits => [
      `# Keys holding a secret-looking literal (values not shown): ${keyList(hits.map(({ f }) => keyOf(f.snippet, /^(.*?) in \S+ holds a secret-looking literal/)).filter(Boolean))}`,
      '# Remote MCP server: read the bearer token from an environment variable',
      '[mcp_servers.<name>]',
      'bearer_token_env_var = "<NAME>_TOKEN"',
      '# Other request headers: name the environment variable that holds the value',
      '[mcp_servers.<name>.env_http_headers]',
      '<Header-Name> = "<ENV_VAR_NAME>"',
      '# Local MCP server env or shell environment: delete the literal and export the variable in your shell',
    ].join('\n'),
  },
  {
    id: 'env-excludes', rules: ['CODEX_ENV_SECRETS_PASSED'],
    title: 'Keep default environment excludes',
    why: 'With ignore_default_excludes true (or unset, which defaults to true) secret-looking environment variables such as *_KEY, *_SECRET and *_TOKEN are passed to every command Codex runs. Set it to false.',
    snippet: () => '[shell_environment_policy]\nignore_default_excludes = false',
  },
  {
    id: 'mcp-auto-approve', rules: ['CODEX_MCP_AUTO_APPROVE'],
    title: 'Do not auto-approve MCP tools',
    why: 'Approval mode "approve" lets an MCP server or tool run with no prompt. A third-party or remote server can then act on your machine unseen. Use "prompt".',
    snippet: hits => `# Change each of these to "prompt" (or delete the line)\n${hits.map(({ f }) => keyOf(f.snippet, /^(.*?) = "approve"/)).filter(Boolean).slice(0, MAX_KEYS).map(k => `${k} = "prompt"`).join('\n')}`,
  },
  {
    id: 'approvals-reviewer', title: 'Review approvals yourself',
    why: 'approvals_reviewer chooses who answers approval requests. Anything other than "user" lets an automated reviewer approve commands in your place.',
    snippet: () => 'approvals_reviewer = "user"',
  },
  {
    id: 'trusted-tmp-projects', rules: ['CODEX_TRUSTED_TMP_PROJECT'],
    title: 'Do not trust projects in temp directories',
    why: 'A trusted project loads its own config, hooks and rules. A project under a temp directory is usually a freshly downloaded or generated folder that nobody reviewed.',
    snippet: () => '[projects."<path of the temp project>"]\ntrust_level = "untrusted"',
  },
  {
    id: 'hooks-enabled', rules: ['CODEX_HOOKS_DISABLED'],
    title: 'Keep Codex hooks enabled',
    why: 'features.hooks = false (or the deprecated features.codex_hooks = false) turns every hook off, including the skill-sentry guard, so risky commands are no longer checked.',
    snippet: () => '[features]\nhooks = true\n# and delete any "codex_hooks = false" line',
  },
  {
    id: 'trust-guard-hook', title: 'Trust the skill-sentry hook',
    why: 'Codex skips a hook until you trust it. Until the skill-sentry hook is trusted the runtime guard does not run. A guard cannot trust itself, so do it yourself.',
    snippet: () => '# Inside Codex, open /hooks (or the desktop "Review hooks"), review the skill-sentry hook and trust it.\n# Re-trust it after every skill-sentry update.',
  },
];

const reviewerNotUser = c => {
  const raw = rawConfigOf(c.config);
  if (!isObj(raw)) return false;
  const bad = v => v !== undefined && v !== 'user';
  return bad(raw.approvals_reviewer) || Object.values(isObj(raw.profiles) ? raw.profiles : {}).some(p => isObj(p) && bad(p.approvals_reviewer));
};

const guardHook = c => {
  if (c.kind !== 'hook') return false;
  const raw = rawConfigOf(c.config);
  const texts = [raw?.command, raw?.command_windows, c.meta?.source, c.meta?.file].filter(t => typeof t === 'string');
  return texts.some(t => /skill-sentry/i.test(t));
};

/**
 * Recommendations for a Codex install. Recommend only: applicable is always false.
 * @param {object[]} components output of discoverCodex().components (kinds config, rules, mcp, hook, ...)
 * @param {{ noHome?: boolean }} [opts] `noHome`: no Codex home was found, so nothing could be checked (m2): every
 *   item is `present: null` with a note instead of reading as already done.
 * @returns {{id:string,title:string,why:string,snippet:string,applicable:false,present:boolean|null,homes?:string[],note?:string}[]}
 */
export function checkCodexHardening(components, { noHome = false } = {}) {
  const list = Array.isArray(components) ? components : [];
  const hits = new Map(); // rule id -> [{c, f}]
  const reviewer = [];
  const guards = [];
  for (const c of list) {
    for (const f of codexConfigFindings(c)) {
      if (!hits.has(f.ruleId)) hits.set(f.ruleId, []);
      hits.get(f.ruleId).push({ c, f });
    }
    if (c.kind === 'config' && reviewerNotUser(c)) reviewer.push({ c });
    if (guardHook(c) && c.meta?.trusted !== true) guards.push({ c });
  }
  return CODEX_RECS.map(r => {
    const found = r.id === 'approvals-reviewer' ? reviewer
      : r.id === 'trust-guard-hook' ? guards
      : r.rules.flatMap(id => hits.get(id) ?? []);
    const rec = { id: CODEX_PREFIX + r.id, title: r.title, why: r.why, snippet: r.snippet(found), applicable: false, present: found.length === 0 };
    if (found.length) rec.homes = [...new Set(found.map(({ c }) => c.meta?.home).filter(Boolean))];
    if (noHome) Object.assign(rec, { present: null, note: 'no Codex home found' });
    return rec;
  });
}

const CODEX_ONLY_MSG = 'Codex hardening is recommend-only: skill-sentry never edits Codex files. Edit config.toml or the rules file yourself, using the snippet from "check --agent codex".';

/** Flags of `check`: --agent claude|codex|all (default claude), --codex-home <dir> (repeatable), --no-wsl. */
function parseCheckArgs(argv) {
  const o = { agent: 'claude', codexHomes: [], noWsl: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--no-wsl') o.noWsl = true;
    else if (a === '--agent' || a === '--codex-home') {
      const v = argv[++i];
      if (v === undefined) return { error: `missing value for ${a}` };
      if (v.startsWith('-') || /\s-/.test(v)) return { error: `invalid value for ${a}` };
      if (a === '--codex-home') o.codexHomes.push(v);
      else if (!['claude', 'codex', 'all'].includes(v)) return { error: 'invalid value for --agent (expected claude, codex or all)' };
      else o.agent = v;
    } else return { error: `unknown argument: ${a.slice(0, 40)}` };
  }
  return o;
}

function codexRecommendations(o) {
  const homeDir = path.resolve(process.env.SKILL_SENTRY_HOME_DIR || os.homedir());
  const homes = codexHomes({
    env: process.env, homeDir, platform: process.platform, explicit: o.codexHomes,
    includeWsl: !o.noWsl && process.env.SKILL_SENTRY_NO_WSL !== '1', problems: [],
  });
  return checkCodexHardening(discoverCodex({ homes }).components, { noHome: homes.length === 0 });
}

function main(argv) {
  const claudeHome = path.resolve(process.env.SKILL_SENTRY_CLAUDE_HOME || path.join(os.homedir(), '.claude'));
  const file = path.join(claudeHome, 'settings.json');
  const [cmd, ...ids] = argv;
  const fail = msg => { process.stderr.write(`${msg}\nusage: node harden.mjs check [--agent claude|codex|all] [--codex-home <dir>]... [--no-wsl] | apply <id> [<id>...]\n`); process.exitCode = 2; };
  try {
    if (cmd === 'check') {
      const o = parseCheckArgs(ids);
      if (o.error) return fail(o.error);
      const recs = [];
      if (o.agent !== 'codex') {
        const { settings } = readSettings(file);
        recs.push(...checkHardening(settings, readKnownMarketplaces(claudeHome)));
      }
      if (o.agent !== 'claude') recs.push(...codexRecommendations(o));
      process.stdout.write(JSON.stringify(recs, null, 2) + '\n');
    } else if (cmd === 'apply') {
      if (!ids.length) return fail('apply needs at least one id');
      if (ids.some(i => i.startsWith(CODEX_PREFIX))) return fail(CODEX_ONLY_MSG);
      const applicable = new Set(Object.keys(RULES).concat(SKILL_SHELL.id));
      const bad = ids.filter(i => !applicable.has(i));
      if (bad.length) return fail(`unknown or non-applicable id: ${bad.join(', ')}`);
      const { settings, exists } = readSettings(file);
      let backup = null;
      if (exists) {
        backup = `${file}.skill-sentry-${new Date().toISOString().replace(/[:.]/g, '-')}.bak`;
        fs.copyFileSync(file, backup);
      }
      for (const id of ids) applyOne(settings, id);
      writeJsonAtomic(file, settings);
      process.stdout.write(`${backup ?? '(no previous settings.json, no backup needed)'}\n`);
    } else {
      fail(cmd ? `unknown command: ${cmd}` : 'missing command');
    }
  } catch (e) {
    fail(e.message);
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main(process.argv.slice(2));
