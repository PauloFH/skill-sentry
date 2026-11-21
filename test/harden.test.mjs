import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { checkHardening, checkCodexHardening } from '../scripts/harden.mjs';
import { codexHomes } from '../scripts/lib/codex/homes.mjs';
import { discoverCodex } from '../scripts/lib/codex/inventory.mjs';
import { tmpFactory } from './helpers/tmp.mjs';

const HARDEN = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'scripts', 'harden.mjs');
const IDS = ['ask-curl', 'ask-wget', 'deny-ssh-read', 'deny-aws-read', 'ask-env-read', 'disable-skill-shell', 'third-party-autoupdate', 'managed-settings'];
const APPLICABLE = IDS.slice(0, 6);

const tmpHome = tmpFactory('ss-harden-');
const run = (home, args) => spawnSync(process.execPath, [HARDEN, ...args], {
  encoding: 'utf8', env: { ...process.env, SKILL_SENTRY_CLAUDE_HOME: home },
});
const readSettings = home => JSON.parse(fs.readFileSync(path.join(home, 'settings.json'), 'utf8').replace(/^﻿/, ''));

test('check on empty settings lists every id; applicable ones are not present', () => {
  const recs = checkHardening({}, {});
  assert.deepEqual(recs.map(r => r.id), IDS);
  for (const r of recs) {
    assert.equal(typeof r.title, 'string');
    assert.equal(typeof r.why, 'string');
    assert.equal(r.applicable, APPLICABLE.includes(r.id), r.id);
    if (r.applicable) assert.equal(r.present, false, r.id);
  }
  const skillShell = recs.find(r => r.id === 'disable-skill-shell');
  assert.match(skillShell.why, /!`git status`/);
});

test('check detects present rules and lists third-party marketplaces', () => {
  const settings = {
    permissions: { ask: ['Bash(curl *)'], deny: ['Read(~/.ssh/**)'] },
    disableSkillShellExecution: true,
  };
  const known = { official: { source: { source: 'github', repo: 'anthropics/claude-plugins-official' } }, shady: { source: { source: 'github', repo: 'x/y' } } };
  const recs = Object.fromEntries(checkHardening(settings, known).map(r => [r.id, r]));
  assert.equal(recs['ask-curl'].present, true);
  assert.equal(recs['ask-wget'].present, false);
  assert.equal(recs['deny-ssh-read'].present, true);
  assert.equal(recs['disable-skill-shell'].present, true);
  assert.match(recs['third-party-autoupdate'].why, /shady/);
  assert.equal(recs['third-party-autoupdate'].applicable, false);
});

test('CLI check prints a JSON array', () => {
  const home = tmpHome();
  const r = run(home, ['check']);
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(JSON.parse(r.stdout).map(x => x.id), IDS);
});

test('apply merges only requested ids, keeps unrelated keys and order, backs up', () => {
  const home = tmpHome();
  const file = path.join(home, 'settings.json');
  const original = { model: 'opus', permissions: { allow: ['Bash(ls)'], ask: ['Bash(curl *)'] }, env: { A: '1' }, hooks: { Stop: [] } };
  fs.writeFileSync(file, '﻿' + JSON.stringify(original, null, 2));
  const r = run(home, ['apply', 'ask-curl', 'deny-ssh-read']);
  assert.equal(r.status, 0, r.stderr);
  const s = readSettings(home);
  assert.deepEqual(Object.keys(s), ['model', 'permissions', 'env', 'hooks']);
  assert.deepEqual(s.permissions.allow, ['Bash(ls)']);
  assert.deepEqual(s.permissions.ask, ['Bash(curl *)']);
  assert.deepEqual(s.permissions.deny, ['Read(~/.ssh/**)']);
  assert.deepEqual(s.env, { A: '1' });
  const baks = fs.readdirSync(home).filter(n => /^settings\.json\.skill-sentry-.+\.bak$/.test(n));
  assert.equal(baks.length, 1);
  assert.ok(r.stdout.includes(baks[0]));
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(home, baks[0]), 'utf8').replace(/^﻿/, '')), original);
  assert.ok(fs.readFileSync(file, 'utf8').includes('\n  "model"'), '2-space indent');
});

test('applying twice does not duplicate entries', () => {
  const home = tmpHome();
  fs.writeFileSync(path.join(home, 'settings.json'), '{"x":1}');
  for (let i = 0; i < 2; i++) assert.equal(run(home, ['apply', 'ask-curl', 'ask-wget', 'ask-env-read', 'deny-aws-read', 'disable-skill-shell']).status, 0);
  const s = readSettings(home);
  assert.deepEqual(s.permissions.ask, ['Bash(curl *)', 'Bash(wget *)', 'Read(**/.env)']);
  assert.deepEqual(s.permissions.deny, ['Read(~/.aws/**)']);
  assert.equal(s.disableSkillShellExecution, true);
  assert.equal(s.x, 1);
});

test('apply creates settings.json when it does not exist', () => {
  const home = tmpHome();
  assert.equal(run(home, ['apply', 'ask-curl']).status, 0);
  assert.deepEqual(readSettings(home), { permissions: { ask: ['Bash(curl *)'] } });
});

test('unknown or non-applicable id exits 2 and leaves the file untouched', () => {
  const home = tmpHome();
  const file = path.join(home, 'settings.json');
  fs.writeFileSync(file, '{"a":1}');
  for (const bad of ['no-such-id', 'managed-settings']) {
    const r = run(home, ['apply', 'ask-curl', bad]);
    assert.equal(r.status, 2, bad);
    assert.equal(fs.readFileSync(file, 'utf8'), '{"a":1}');
  }
  assert.deepEqual(fs.readdirSync(home), ['settings.json']);
});

test('unreadable settings.json exits 2 and is not overwritten', () => {
  const home = tmpHome();
  const file = path.join(home, 'settings.json');
  fs.writeFileSync(file, '{ not json');
  const r = run(home, ['apply', 'ask-curl']);
  assert.equal(r.status, 2);
  assert.equal(fs.readFileSync(file, 'utf8'), '{ not json');
});

// ---------------------------------------------------------------- Codex (recommend only)

const CODEX_IDS = [
  'codex-approval-sandbox', 'codex-broad-allow-rules', 'codex-secrets-in-config', 'codex-env-excludes',
  'codex-mcp-auto-approve', 'codex-approvals-reviewer', 'codex-trusted-tmp-projects', 'codex-hooks-enabled', 'codex-trust-guard-hook',
];
// A secret-looking value assembled at runtime; it must never reach any output.
const SENTINEL = ['gh', 'p_', 'Zq9Xk2Lm4Vb7Nc1Rt5Yw8Hd3Jf6Sa0Pe'].join('');

const tmpCodex = tmpFactory('ss-harden-cx-');
const SAFE_CONFIG = [
  'approval_policy = "on-request"',
  'sandbox_mode = "workspace-write"',
  '[shell_environment_policy]',
  'ignore_default_excludes = false',
  '',
].join('\n');

/** Components of a throwaway Codex home holding the given files. */
function inventory(files) {
  const dir = tmpCodex();
  for (const [name, text] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, name)), { recursive: true });
    fs.writeFileSync(path.join(dir, name), text);
  }
  const homes = codexHomes({ env: { SKILL_SENTRY_CODEX_HOME: dir }, homeDir: tmpCodex(), platform: process.platform, includeWsl: false, explicit: [] });
  return { dir, ...discoverCodex({ homes }) };
}
const recsOf = files => Object.fromEntries(checkCodexHardening(inventory(files).components).map(r => [r.id, r]));
const runCx = (dir, args) => spawnSync(process.execPath, [HARDEN, ...args], {
  encoding: 'utf8',
  env: { ...process.env, SKILL_SENTRY_CLAUDE_HOME: tmpHome(), SKILL_SENTRY_HOME_DIR: tmpCodex(), SKILL_SENTRY_CODEX_HOME: dir, SKILL_SENTRY_NO_WSL: '1' },
});

test('codex: every recommendation is recommend-only and carries a fixed snippet', () => {
  const recs = checkCodexHardening(inventory({ 'config.toml': SAFE_CONFIG }).components);
  assert.deepEqual(recs.map(r => r.id), CODEX_IDS);
  for (const r of recs) {
    assert.equal(r.applicable, false, r.id);
    assert.equal(typeof r.title, 'string');
    assert.equal(typeof r.why, 'string');
    assert.equal(typeof r.snippet, 'string', r.id);
    assert.ok(r.snippet.length > 0, r.id);
    assert.equal(typeof r.present, 'boolean', r.id);
  }
});

test('codex: a safe config leaves every recommendation present', () => {
  // The guard hook is not installed here: nothing to trust.
  for (const r of checkCodexHardening(inventory({ 'config.toml': SAFE_CONFIG }).components)) assert.equal(r.present, true, r.id);
});

test('codex: approval_policy never / danger-full-access fires codex-approval-sandbox', () => {
  assert.equal(recsOf({ 'config.toml': SAFE_CONFIG })['codex-approval-sandbox'].present, true);
  for (const bad of ['approval_policy = "never"\n', 'sandbox_mode = "danger-full-access"\n', 'approval_policy = "never"\nsandbox_mode = "danger-full-access"\n']) {
    const r = recsOf({ 'config.toml': bad + '[shell_environment_policy]\nignore_default_excludes = false\n' })['codex-approval-sandbox'];
    assert.equal(r.present, false, bad);
    assert.match(r.snippet, /approval_policy = "on-request"/);
    assert.match(r.snippet, /sandbox_mode = "workspace-write"/);
  }
});

test('codex: a broad allow rule fires codex-broad-allow-rules; a narrow one does not', () => {
  const narrow = 'prefix_rule(pattern=["git", "status"], decision="allow")\n';
  const broad = 'prefix_rule(pattern=["bash", "-c"], decision="allow")\n';
  assert.equal(recsOf({ 'config.toml': SAFE_CONFIG, 'rules/default.rules': narrow })['codex-broad-allow-rules'].present, true);
  assert.equal(recsOf({ 'config.toml': SAFE_CONFIG })['codex-broad-allow-rules'].present, true);
  const r = recsOf({ 'config.toml': SAFE_CONFIG, 'rules/default.rules': narrow + broad })['codex-broad-allow-rules'];
  assert.equal(r.present, false);
  assert.match(r.snippet, /line 2 of default\.rules/);
  assert.match(r.snippet, /decision="prompt"/);
});

test('codex: a secret-looking literal fires codex-secrets-in-config; env references do not', () => {
  const safe = `${SAFE_CONFIG}[mcp_servers.s]\nurl = "https://example.invalid/mcp"\nbearer_token_env_var = "S_TOKEN"\n`;
  assert.equal(recsOf({ 'config.toml': safe })['codex-secrets-in-config'].present, true);
  const risky = `${SAFE_CONFIG}[mcp_servers.s]\ncommand = "node"\n[mcp_servers.s.env]\nAPI_TOKEN = "${SENTINEL}"\n`;
  const r = recsOf({ 'config.toml': risky })['codex-secrets-in-config'];
  assert.equal(r.present, false);
  assert.match(r.snippet, /bearer_token_env_var/);
  assert.match(r.snippet, /mcp_servers\.s\.env\.API_TOKEN/);
  assert.ok(!r.snippet.includes(SENTINEL));
});

test('codex: ignore_default_excludes true or unset fires codex-env-excludes; false does not', () => {
  assert.equal(recsOf({ 'config.toml': SAFE_CONFIG })['codex-env-excludes'].present, true);
  assert.equal(recsOf({ 'config.toml': 'approval_policy = "on-request"\n' })['codex-env-excludes'].present, false);
  const r = recsOf({ 'config.toml': '[shell_environment_policy]\nignore_default_excludes = true\n' })['codex-env-excludes'];
  assert.equal(r.present, false);
  assert.match(r.snippet, /ignore_default_excludes = false/);
});

test('codex: approve on an MCP server or tool fires codex-mcp-auto-approve', () => {
  const safe = `${SAFE_CONFIG}[mcp_servers.s]\ncommand = "node"\ndefault_tools_approval_mode = "prompt"\n`;
  assert.equal(recsOf({ 'config.toml': safe })['codex-mcp-auto-approve'].present, true);
  const server = `${SAFE_CONFIG}[mcp_servers.s]\ncommand = "node"\ndefault_tools_approval_mode = "approve"\n`;
  const tool = `${SAFE_CONFIG}[mcp_servers.s]\ncommand = "node"\n[mcp_servers.s.tools.t]\napproval_mode = "approve"\n`;
  for (const cfg of [server, tool]) {
    const r = recsOf({ 'config.toml': cfg })['codex-mcp-auto-approve'];
    assert.equal(r.present, false);
    assert.match(r.snippet, /"prompt"/);
    assert.match(r.snippet, /mcp_servers\.s/);
  }
});

test('codex: a reviewer other than the user fires codex-approvals-reviewer', () => {
  assert.equal(recsOf({ 'config.toml': SAFE_CONFIG })['codex-approvals-reviewer'].present, true);
  assert.equal(recsOf({ 'config.toml': `approvals_reviewer = "user"\n${SAFE_CONFIG}` })['codex-approvals-reviewer'].present, true);
  const r = recsOf({ 'config.toml': `approvals_reviewer = "auto_review"\n${SAFE_CONFIG}` })['codex-approvals-reviewer'];
  assert.equal(r.present, false);
  assert.match(r.snippet, /approvals_reviewer = "user"/);
});

test('codex: a trusted project under a temp dir fires codex-trusted-tmp-projects', () => {
  const safe = `${SAFE_CONFIG}[projects.'/home/me/code/app']\ntrust_level = "trusted"\n`;
  assert.equal(recsOf({ 'config.toml': safe })['codex-trusted-tmp-projects'].present, true);
  const risky = `${SAFE_CONFIG}[projects.'/tmp/scratch']\ntrust_level = "trusted"\n`;
  const r = recsOf({ 'config.toml': risky })['codex-trusted-tmp-projects'];
  assert.equal(r.present, false);
  assert.match(r.snippet, /trust_level = "untrusted"/);
  assert.ok(!r.snippet.includes('/tmp/scratch'), 'paths are not echoed');
});

test('codex: features.hooks = false fires codex-hooks-enabled', () => {
  assert.equal(recsOf({ 'config.toml': `${SAFE_CONFIG}[features]\nhooks = true\n` })['codex-hooks-enabled'].present, true);
  const r = recsOf({ 'config.toml': `${SAFE_CONFIG}[features]\nhooks = false\n` })['codex-hooks-enabled'];
  assert.equal(r.present, false);
  assert.match(r.snippet, /hooks = true/);
});

test('codex: a skill-sentry hook that is not trusted fires codex-trust-guard-hook', () => {
  const hook = trusted => ({
    id: 'hook:x', kind: 'hook', name: 'PreToolUse[0]', scope: 'plugin', agent: 'codex',
    config: { command: 'node /plugins/skill-sentry/scripts/guard.mjs' },
    meta: { event: 'PreToolUse', home: 'win', ...(trusted === undefined ? {} : { trusted }) },
  });
  const other = { ...hook(false), config: { command: 'node /plugins/other/run.mjs' } };
  assert.equal(checkCodexHardening([other]).find(r => r.id === 'codex-trust-guard-hook').present, true);
  assert.equal(checkCodexHardening([hook(true)]).find(r => r.id === 'codex-trust-guard-hook').present, true);
  for (const t of [false, undefined]) {
    const r = checkCodexHardening([hook(t)]).find(x => x.id === 'codex-trust-guard-hook');
    assert.equal(r.present, false);
    assert.match(r.snippet, /\/hooks/);
  }
});

test('codex: shipped snippets never spell the hook-trust bypass flag', () => {
  const dashed = '--dangerously-' + 'bypass-hook-trust';
  const all = checkCodexHardening(inventory({ 'config.toml': 'approval_policy = "never"\n' }).components);
  for (const r of all) assert.ok(!JSON.stringify(r).toLowerCase().includes(dashed), r.id);
  assert.ok(!fs.readFileSync(HARDEN, 'utf8').toLowerCase().includes(dashed));
});

test('codex CLI: check --agent codex prints only codex recommendations and leaks no secret', () => {
  const dir = tmpCodex();
  fs.writeFileSync(path.join(dir, 'config.toml'), [
    'approval_policy = "never"',
    '[shell_environment_policy.set]',
    `MY_API_TOKEN = "${SENTINEL}"`,
    '[mcp_servers.s]',
    'command = "node"',
    '[mcp_servers.s.env]',
    `API_TOKEN = "${SENTINEL}"`,
    '[mcp_servers.s.http_headers]',
    `Authorization = "Bearer ${SENTINEL}"`,
    '',
  ].join('\n'));
  const r = runCx(dir, ['check', '--agent', 'codex']);
  assert.equal(r.status, 0, r.stderr);
  assert.ok(!r.stdout.includes(SENTINEL) && !r.stderr.includes(SENTINEL));
  const recs = JSON.parse(r.stdout);
  assert.deepEqual(recs.map(x => x.id), CODEX_IDS);
  assert.equal(recs.find(x => x.id === 'codex-secrets-in-config').present, false);
  assert.equal(recs.find(x => x.id === 'codex-approval-sandbox').present, false);
  assert.ok(recs.every(x => x.applicable === false));
});

test('codex CLI: --codex-home adds a home; --agent all appends codex to the claude list', () => {
  const dir = tmpCodex();
  fs.writeFileSync(path.join(dir, 'config.toml'), SAFE_CONFIG);
  const extra = tmpCodex();
  fs.writeFileSync(path.join(extra, 'config.toml'), 'sandbox_mode = "danger-full-access"\n');
  const r = runCx(dir, ['check', '--agent', 'codex', '--codex-home', extra, '--no-wsl']);
  assert.equal(r.status, 0, r.stderr);
  assert.equal(JSON.parse(r.stdout).find(x => x.id === 'codex-approval-sandbox').present, false);
  const all = runCx(dir, ['check', '--agent', 'all']);
  assert.equal(all.status, 0, all.stderr);
  assert.deepEqual(JSON.parse(all.stdout).map(x => x.id), [...IDS, ...CODEX_IDS]);
});

test('codex CLI: the default agent stays claude and output is unchanged', () => {
  const dir = tmpCodex();
  const r = runCx(dir, ['check']);
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(JSON.parse(r.stdout).map(x => x.id), IDS);
  assert.equal(runCx(dir, ['check', '--agent', 'claude']).stdout, r.stdout);
});

test('codex CLI: bad flags exit 2', () => {
  const dir = tmpCodex();
  for (const args of [['check', '--agent', 'nope'], ['check', '--agent'], ['check', '--bogus'], ['check', '--codex-home', '--x']]) {
    assert.equal(runCx(dir, args).status, 2, args.join(' '));
  }
});

test('codex CLI: apply refuses codex ids, exits 2 and touches no file', () => {
  const dir = tmpCodex();
  const cfg = path.join(dir, 'config.toml');
  fs.writeFileSync(cfg, 'approval_policy = "never"\n');
  const home = tmpHome();
  fs.writeFileSync(path.join(home, 'settings.json'), '{"a":1}');
  const r = spawnSync(process.execPath, [HARDEN, 'apply', 'ask-curl', 'codex-approval-sandbox'], {
    encoding: 'utf8', env: { ...process.env, SKILL_SENTRY_CLAUDE_HOME: home, SKILL_SENTRY_CODEX_HOME: dir },
  });
  assert.equal(r.status, 2);
  assert.match(r.stderr, /recommend-only/);
  assert.match(r.stderr, /edit/i);
  assert.equal(fs.readFileSync(cfg, 'utf8'), 'approval_policy = "never"\n');
  assert.equal(fs.readFileSync(path.join(home, 'settings.json'), 'utf8'), '{"a":1}');
  assert.deepEqual(fs.readdirSync(home), ['settings.json']);
});
