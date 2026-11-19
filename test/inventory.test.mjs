import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { discover } from '../scripts/lib/inventory.mjs';
import { readJsonSafe } from '../scripts/lib/jsonsafe.mjs';

const FIX = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures');
const HOME = path.join(FIX, 'home');
const H = path.join(HOME, '.claude');
const P = path.join(FIX, 'project');

const run = (o = {}) => discover({ claudeHome: H, homeDir: HOME, projectDir: P, selfRoot: null, ...o });
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'ss-inv-'));
const write = (f, s) => { fs.mkdirSync(path.dirname(f), { recursive: true }); fs.writeFileSync(f, s); };

test('discovers all component kinds from fixtures', () => {
  const { components } = run();
  const ids = components.map(c => c.id);
  for (const id of [
    'plugin:alpha@mkt', 'plugin:beta@mkt',
    'hook:plugin:alpha:SessionStart:0',
    'mcp:plugin:beta:some-mcp',
    'mcp:user:files',
    'skill:user:notes',
    'statusline:user',
    'hook:user:PreToolUse:0',
    'hook:project:SessionStart:0',
    'instructions:project:CLAUDE.md',
    'marketplace:mkt',
  ]) assert.ok(ids.includes(id), id);
  assert.equal(new Set(ids).size, ids.length, 'ids unique');
});

test('component shapes and scopes', () => {
  const by = Object.fromEntries(run().components.map(c => [c.id, c]));
  assert.equal(by['plugin:alpha@mkt'].kind, 'plugin');
  assert.equal(by['plugin:alpha@mkt'].meta.version, '1.0.0');
  assert.equal(by['plugin:alpha@mkt'].root, path.join(H, 'plugins', 'cache', 'alpha'));
  assert.equal(by['hook:plugin:alpha:SessionStart:0'].scope, 'plugin');
  assert.equal(by['hook:user:PreToolUse:0'].scope, 'user');
  assert.equal(by['skill:user:notes'].scope, 'user');
  assert.ok(by['skill:user:notes'].files.some(f => f.endsWith('SKILL.md')));
});

test('hook config keeps raw entry (Ruling A)', () => {
  const h = run().components.find(c => c.id === 'hook:plugin:alpha:SessionStart:0');
  assert.deepEqual(h.config, {
    event: 'SessionStart', matcher: 'startup', type: 'command',
    command: 'node', args: ['${CLAUDE_PLUGIN_ROOT}/start.js'], timeout: 5,
  });
  const u = run().components.find(c => c.id === 'hook:user:PreToolUse:0');
  assert.equal(u.config.matcher, 'Bash');
  assert.equal(u.config.command, 'echo pre');
});

test('mcp env values are redacted, keys kept', () => {
  const { components } = run();
  const m = components.find(c => c.id === 'mcp:plugin:beta:some-mcp');
  assert.equal(m.config.command, 'npx');
  assert.deepEqual(m.config.args, ['-y', 'some-mcp@latest']);
  assert.deepEqual(m.config.env, { API_KEY: '<redacted>' });
  const g = components.find(c => c.id === 'mcp:user:files');
  assert.deepEqual(g.config.env, { TOKEN: '<redacted>' });
  assert.ok(!JSON.stringify(components).includes('super-secret-value'));
  assert.ok(!JSON.stringify(components).includes('abc123'));
});

test('hook index counts across matcher groups per event', () => {
  const home = tmp();
  write(path.join(home, 'settings.json'), JSON.stringify({ hooks: { PreToolUse: [
    { matcher: 'Bash', hooks: [{ type: 'command', command: 'a' }, { type: 'command', command: 'b' }] },
    { matcher: 'Edit', hooks: [{ type: 'command', command: 'c' }] },
  ], Stop: [{ hooks: [{ type: 'command', command: 'd' }] }] } }));
  const ids = discover({ claudeHome: home, homeDir: home, projectDir: null, selfRoot: null }).components.map(c => c.id);
  assert.deepEqual(ids.filter(i => i.startsWith('hook:')).sort(),
    ['hook:user:PreToolUse:0', 'hook:user:PreToolUse:1', 'hook:user:PreToolUse:2', 'hook:user:Stop:0']);
});

test('project mcp from ~/.claude.json matches slash-insensitively', () => {
  const home = tmp();
  const proj = path.join(home, 'proj');
  fs.mkdirSync(proj);
  const key = process.platform === 'win32' ? proj.replace(/\\/g, '/').toUpperCase() : proj;
  write(path.join(home, '.claude.json'), JSON.stringify({ projects: { [key]: { mcpServers: { pm: { command: 'x' } } } } }));
  write(path.join(proj, '.mcp.json'), JSON.stringify({ mcpServers: { local: { type: 'http', url: 'http://localhost:1' } } }));
  const ids = discover({ claudeHome: path.join(home, '.claude'), homeDir: home, projectDir: proj, selfRoot: null }).components.map(c => c.id);
  assert.ok(ids.includes('mcp:project:pm'));
  assert.ok(ids.includes('mcp:project:local'));
});

test('missing installed_plugins.json does not throw', () => {
  const home = tmp();
  const r = discover({ claudeHome: path.join(home, '.claude'), homeDir: home, projectDir: null, selfRoot: null });
  assert.deepEqual(r.components, []);
  assert.deepEqual(r.configFindings, []);
});

test('settings.json with BOM parses', () => {
  const home = tmp();
  write(path.join(home, 'settings.json'), '﻿' + JSON.stringify({ statusLine: { type: 'command', command: 'x' } }));
  const r = discover({ claudeHome: home, homeDir: home, projectDir: null, selfRoot: null });
  assert.ok(r.components.some(c => c.id === 'statusline:user'));
  assert.deepEqual(r.configFindings, []);
});

test('garbage settings.json yields CONFIG_UNREADABLE info finding', () => {
  const home = tmp();
  const f = path.join(home, 'settings.json');
  write(f, '{ not json at all');
  const r = discover({ claudeHome: home, homeDir: home, projectDir: null, selfRoot: null });
  assert.equal(r.configFindings.length, 1);
  const x = r.configFindings[0];
  assert.equal(x.ruleId, 'CONFIG_UNREADABLE');
  assert.equal(x.category, 'config');
  assert.equal(x.severity, 'info');
  assert.equal(x.line, 0);
  assert.equal(x.file, f);
  assert.ok(x.snippet.length > 0 && x.snippet.length <= 201);
});

test('selfRoot plugin flagged self', () => {
  const { components } = run({ selfRoot: path.join(H, 'plugins', 'cache', 'alpha') });
  assert.equal(components.find(c => c.id === 'plugin:alpha@mkt').self, true);
  assert.ok(!components.find(c => c.id === 'plugin:beta@mkt').self);
});

test('readJsonSafe: missing, BOM, garbage', () => {
  const d = tmp();
  assert.deepEqual(readJsonSafe(path.join(d, 'nope.json')), { ok: false, error: 'missing' });
  write(path.join(d, 'a.json'), '﻿{"a":1}');
  assert.deepEqual(readJsonSafe(path.join(d, 'a.json')), { ok: true, value: { a: 1 } });
  write(path.join(d, 'b.json'), '{bad');
  const r = readJsonSafe(path.join(d, 'b.json'));
  assert.equal(r.ok, false);
  assert.notEqual(r.error, 'missing');
});

test('plugin.json inline hooks and mcpServers are discovered', () => {
  const ids = run().components.map(c => c.id);
  assert.ok(ids.includes('hook:plugin:gamma:SessionStart:0'));
  assert.ok(ids.includes('mcp:plugin:gamma:inline-mcp'));
});

test('plugin.json path references are read once and continue the counter', () => {
  const { components } = run();
  const ids = components.map(c => c.id);
  assert.ok(ids.includes('hook:plugin:delta:Stop:0'));
  assert.ok(!ids.includes('hook:plugin:delta:Stop:1'));
  assert.ok(ids.includes('mcp:plugin:delta:filemcp'));
  assert.equal(components.find(c => c.id === 'hook:plugin:delta:Stop:0').config.command, 'echo stop');
});

test('manifest hooks continue the counter after hooks/hooks.json', () => {
  const home = tmp();
  const root = path.join(home, 'p');
  write(path.join(home, 'plugins', 'installed_plugins.json'), JSON.stringify({ plugins: { 'p@m': [{ installPath: root }] } }));
  const h = { SessionStart: [{ hooks: [{ type: 'command', command: 'a' }] }] };
  write(path.join(root, 'hooks', 'hooks.json'), JSON.stringify({ hooks: h }));
  write(path.join(root, '.claude-plugin', 'plugin.json'), JSON.stringify({ hooks: h }));
  const ids = discover({ claudeHome: home, homeDir: home, projectDir: null, selfRoot: null }).components.map(c => c.id);
  assert.ok(ids.includes('hook:plugin:p:SessionStart:0') && ids.includes('hook:plugin:p:SessionStart:1'));
});
