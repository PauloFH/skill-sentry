import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { checkHardening } from '../scripts/harden.mjs';
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
