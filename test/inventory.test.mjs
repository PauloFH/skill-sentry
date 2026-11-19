import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { discover, listFiles } from '../scripts/lib/inventory.mjs';
import { scanComponent } from '../scripts/lib/scanner.mjs';
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

const mkHome = () => { const h = tmp(); return { h, d: () => ({ claudeHome: h, homeDir: h, projectDir: null, selfRoot: null }) }; };

test('hook config keeps non-command fields (http hook url)', () => {
  const { h, d } = mkHome();
  write(path.join(h, 'settings.json'), JSON.stringify({ hooks: { Stop: [{ hooks: [
    { type: 'http', url: 'http://example.test/x', headers: { Authorization: 'Bearer s3cret' } }] }] } }));
  const c = discover(d()).components.find(x => x.id === 'hook:user:Stop:0');
  assert.equal(c.config.url, 'http://example.test/x');
  assert.equal(c.config.event, 'Stop');
  assert.deepEqual(c.config.headers, { Authorization: '<redacted>' });
  assert.ok(!('matcher' in c.config) && !('command' in c.config));
});

test('mcp config keeps headers, headersHelper, cwd; redacts header values; no empty env', () => {
  const { h, d } = mkHome();
  write(path.join(h, '.claude.json'), JSON.stringify({ mcpServers: {
    r: { type: 'http', url: 'http://x.test', headers: { 'X-Key': 'zzz' }, headersHelper: 'node get.js', cwd: '/w' } } }));
  const c = discover(d()).components.find(x => x.id === 'mcp:user:r');
  assert.deepEqual(c.config.headers, { 'X-Key': '<redacted>' });
  assert.equal(c.config.headersHelper, 'node get.js');
  assert.equal(c.config.cwd, '/w');
  assert.ok(!('env' in c.config) && !('command' in c.config));
  assert.ok(!JSON.stringify(c).includes('zzz'));
});

test('colliding statusLine entries are all inventoried with suffixed ids and meta.source', () => {
  const { h, d } = mkHome();
  write(path.join(h, 'settings.json'), JSON.stringify({ statusLine: { type: 'command', command: 'one' } }));
  write(path.join(h, 'settings.local.json'), JSON.stringify({ statusLine: { type: 'command', command: 'two' } }));
  const by = Object.fromEntries(discover(d()).components.map(c => [c.id, c]));
  assert.equal(by['statusline:user'].config.command, 'one');
  assert.equal(by['statusline:user#2'].config.command, 'two');
  assert.equal(by['statusline:user#2'].meta.source, path.join(h, 'settings.local.json'));
});

test('project mcp in ~/.claude.json and .mcp.json with same name both kept', () => {
  const home = tmp();
  const proj = path.join(home, 'proj');
  write(path.join(home, '.claude.json'), JSON.stringify({ projects: { [proj]: { mcpServers: { dup: { command: 'a' } } } } }));
  write(path.join(proj, '.mcp.json'), JSON.stringify({ mcpServers: { dup: { command: 'b' } } }));
  const by = Object.fromEntries(discover({ claudeHome: path.join(home, '.claude'), homeDir: home, projectDir: proj, selfRoot: null })
    .components.map(c => [c.id, c]));
  assert.equal(by['mcp:project:dup'].config.command, 'a');
  assert.equal(by['mcp:project:dup#2'].config.command, 'b');
  assert.ok(by['mcp:project:dup'].meta.source.endsWith('.claude.json'));
  assert.ok(by['mcp:project:dup#2'].meta.source.endsWith('.mcp.json'));
});

test('symlinked file inside a skill pointing inside it is listed; one pointing outside is not followed', t => {
  const { h, d } = mkHome();
  const skill = path.join(h, 'skills', 's');
  write(path.join(skill, 'SKILL.md'), 'x');
  write(path.join(skill, 'data', 'in.txt'), 'z');
  const outside = path.join(h, 'outside.txt');
  write(outside, 'y');
  try {
    fs.symlinkSync(path.join(skill, 'data', 'in.txt'), path.join(skill, 'inlink.txt'));
    fs.symlinkSync(outside, path.join(skill, 'link.txt'));
  } catch (e) { if (e.code === 'EPERM' || e.code === 'EACCES') return t.skip('symlinks not permitted'); throw e; }
  const c = discover(d()).components.find(x => x.id === 'skill:user:s');
  assert.ok(c.files.some(f => f.endsWith('inlink.txt')));
  assert.ok(!c.files.some(f => f.endsWith('link.txt') && !f.endsWith('inlink.txt')));
  assert.deepEqual(c.meta.symlinksOutside.map(o => path.basename(o.path)), ['link.txt']);
});

/** Junction (Windows) or dir symlink; null when the platform refuses. */
function junction(target, link) {
  try { fs.symlinkSync(target, link, 'junction'); return true; }
  catch (e) { if (['EPERM', 'EACCES', 'ENOSYS'].includes(e.code)) return false; throw e; }
}

test('junction from a skill to a large directory outside it is not followed (SCAN_SYMLINK_OUTSIDE)', t => {
  const { h, d } = mkHome();
  const skill = path.join(h, 'skills', 's');
  write(path.join(skill, 'SKILL.md'), 'x');
  const big = path.join(tmp(), 'big');
  for (let i = 0; i < 30; i++) write(path.join(big, `d${i}`, 'f.js'), 'x');
  if (!junction(big, path.join(skill, 'linked'))) return t.skip('junctions not permitted');
  const c = discover(d()).components.find(x => x.id === 'skill:user:s');
  assert.ok(!c.files.some(f => f.includes(`${path.sep}linked${path.sep}`)), 'files behind the junction are not listed');
  assert.equal(c.meta.symlinksOutside.length, 1);
  const r = scanComponent(c);
  const f = r.findings.filter(x => x.ruleId === 'SCAN_SYMLINK_OUTSIDE');
  assert.equal(f.length, 1);
  assert.equal(f[0].category, 'config');
  assert.equal(f[0].severity, 'info');
  assert.equal(f[0].file, 'linked');
  // A plugin root walked by the scanner itself behaves the same.
  const pr = scanComponent({ id: 'plugin:x@y', kind: 'plugin', name: 'x@y', scope: 'user', root: skill, meta: {} });
  assert.equal(pr.findings.filter(x => x.ruleId === 'SCAN_SYMLINK_OUTSIDE').length, 1);
  assert.ok(!pr.files.some(x => x.path.startsWith('linked/')));
});

test('symlink to a drive root or filesystem root is a medium SCAN_SYMLINK_OUTSIDE', t => {
  const { h, d } = mkHome();
  const skill = path.join(h, 'skills', 's');
  write(path.join(skill, 'SKILL.md'), 'x');
  if (!junction(path.parse(os.tmpdir()).root, path.join(skill, 'root'))) return t.skip('junctions not permitted');
  const c = discover(d()).components.find(x => x.id === 'skill:user:s');
  const f = scanComponent(c).findings.filter(x => x.ruleId === 'SCAN_SYMLINK_OUTSIDE');
  assert.equal(f.length, 1);
  assert.equal(f[0].severity, 'medium');
});

test('directories count against the walk caps and the walk ends at the cap', () => {
  const { h, d } = mkHome();
  const skill = path.join(h, 'skills', 's');
  write(path.join(skill, 'SKILL.md'), 'x');
  for (let i = 0; i < 40; i++) fs.mkdirSync(path.join(skill, `e${i}`, 'a', 'b'), { recursive: true });
  const c = discover({ ...d(), limits: { maxDirs: 10 } }).components.find(x => x.id === 'skill:user:s');
  assert.equal(c.meta.filesTruncated, true);
  const r = listFiles(skill, { maxDirs: 10 });
  assert.equal(r.truncated, true);
  // Files in later directories are not listed once the cap ended the walk.
  for (let i = 0; i < 40; i++) write(path.join(skill, `e${i}`, 'a', 'b', 'f.txt'), 'y');
  assert.ok(listFiles(skill, { maxDirs: 10 }).files.length < 10);
});

test('discover honors a deadline: skills past it are kept, marked incomplete, and not walked', () => {
  const { h, d } = mkHome();
  write(path.join(h, 'skills', 's', 'SKILL.md'), 'x');
  write(path.join(h, 'skills', 's', 'more.md'), 'x');
  const c = discover({ ...d(), deadline: Date.now() - 1 }).components.find(x => x.id === 'skill:user:s');
  assert.ok(c, 'skill still listed');
  assert.equal(c.meta.incomplete, true);
  assert.deepEqual(c.files, []);
  assert.equal(scanComponent(c).incomplete, true);
});

test('discover with skillFiles: false leaves skill files to the scanner', () => {
  const { h, d } = mkHome();
  write(path.join(h, 'skills', 's', 'SKILL.md'), 'x');
  const c = discover({ ...d(), skillFiles: false }).components.find(x => x.id === 'skill:user:s');
  assert.equal(c.files, undefined);
  assert.ok(scanComponent(c).files.some(f => f.path === 'SKILL.md'));
});

test('self is detected through a junctioned install path', t => {
  const h = tmp();
  const real = path.join(h, 'real-self');
  write(path.join(real, '.claude-plugin', 'plugin.json'), '{}');
  write(path.join(real, 'scripts', 'x.js'), 'x');
  const link = path.join(h, 'linked-self');
  if (!junction(real, link)) return t.skip('junctions not permitted');
  write(path.join(h, 'plugins', 'installed_plugins.json'), JSON.stringify({ version: 2, plugins: { 'skill-sentry@m': [{ scope: 'user', installPath: real }] } }));
  const viaLink = discover({ claudeHome: h, homeDir: h, projectDir: null, selfRoot: link }).components.find(c => c.id === 'plugin:skill-sentry@m');
  assert.equal(viaLink.self, true);
  write(path.join(h, 'plugins', 'installed_plugins.json'), JSON.stringify({ version: 2, plugins: { 'skill-sentry@m': [{ scope: 'user', installPath: link }] } }));
  const viaInstall = discover({ claudeHome: h, homeDir: h, projectDir: null, selfRoot: real }).components.find(c => c.id === 'plugin:skill-sentry@m');
  assert.equal(viaInstall.self, true);
});

test('every install entry of a plugin is inventoried (deduped by real path)', () => {
  const h = tmp();
  const a = path.join(h, 'plugins', 'cache', 'm', 'p', '1.0.0');
  const b = path.join(h, 'proj', '.claude', 'p');
  write(path.join(a, 'hooks', 'hooks.json'), JSON.stringify({ hooks: { Stop: [{ hooks: [{ type: 'command', command: 'one' }] }] } }));
  write(path.join(b, 'hooks', 'hooks.json'), JSON.stringify({ hooks: { Stop: [{ hooks: [{ type: 'command', command: 'two' }] }] } }));
  write(path.join(h, 'plugins', 'installed_plugins.json'), JSON.stringify({ version: 2, plugins: { 'p@m': [
    { scope: 'user', installPath: a, version: '1.0.0' },
    { scope: 'project', installPath: b, version: '2.0.0' },
    { scope: 'local', installPath: a + path.sep, version: '1.0.0' },
  ] } }));
  const comps = discover({ claudeHome: h, homeDir: h, projectDir: null, selfRoot: null }).components;
  const plugins = comps.filter(c => c.kind === 'plugin');
  assert.deepEqual(plugins.map(c => c.id), ['plugin:p@m', 'plugin:p@m#2']);
  assert.equal(plugins[0].root, a);
  assert.equal(plugins[1].root, b);
  const cmds = comps.filter(c => c.kind === 'hook').map(c => c.config.command).sort();
  assert.deepEqual(cmds, ['one', 'two']);
});

test('symlink directory cycle terminates', t => {
  const { h, d } = mkHome();
  const skill = path.join(h, 'skills', 's');
  write(path.join(skill, 'SKILL.md'), 'x');
  try { fs.symlinkSync(skill, path.join(skill, 'loop'), 'dir'); }
  catch (e) { if (e.code === 'EPERM' || e.code === 'EACCES') return t.skip('symlinks not permitted'); throw e; }
  const c = discover(d()).components.find(x => x.id === 'skill:user:s');
  assert.ok(c.files.some(f => f.endsWith('SKILL.md')));
});

test('file cap truncation sets meta.filesTruncated', () => {
  const { h, d } = mkHome();
  const skill = path.join(h, 'skills', 's');
  write(path.join(skill, 'SKILL.md'), 'x');
  for (let i = 0; i < 5; i++) write(path.join(skill, `f${i}.txt`), 'y');
  const small = discover({ ...d(), limits: { maxFiles: 3 } }).components.find(x => x.id === 'skill:user:s');
  assert.equal(small.meta.filesTruncated, true);
  const full = discover(d()).components.find(x => x.id === 'skill:user:s');
  assert.ok(!full.meta.filesTruncated);
});

// ---- home directory used as the project (Claude Code started from ~) ----
test('projectDir = home: user-scope settings and skills are not listed again as project scope', () => {
  const ids = discover({ claudeHome: H, homeDir: HOME, projectDir: HOME, selfRoot: null }).components.map(c => c.id);
  assert.equal(new Set(ids).size, ids.length, 'ids unique');
  assert.ok(!ids.some(id => /#\d+$/.test(id)), `no collision suffixes: ${ids.filter(id => /#\d+$/.test(id))}`);
  assert.ok(!ids.some(id => /^(?:hook|statusline|skill):project\b/.test(id)), 'no project copies of user settings/skills');
  for (const id of ['statusline:user', 'hook:user:PreToolUse:0', 'skill:user:notes', 'marketplace:mkt']) assert.ok(ids.includes(id), id);
});

test('projectDir = home matched case-insensitively (win32) and through a trailing separator', { skip: process.platform !== 'win32' }, () => {
  const ids = discover({ claudeHome: H.toUpperCase(), homeDir: HOME, projectDir: HOME.toLowerCase() + path.sep, selfRoot: null }).components.map(c => c.id);
  assert.ok(!ids.some(id => /^(?:hook|statusline|skill):project\b/.test(id)));
});

test('projectDir = home still includes project-only sources (.mcp.json, CLAUDE.md, AGENTS.md, ~/.claude.json projects)', () => {
  const home = tmp();
  const ch = path.join(home, '.claude');
  write(path.join(ch, 'settings.json'), JSON.stringify({ statusLine: { type: 'command', command: 'hud' }, hooks: { Stop: [{ hooks: [{ type: 'command', command: 'x' }] }] } }));
  write(path.join(ch, 'skills', 's', 'SKILL.md'), 'x');
  write(path.join(home, '.mcp.json'), JSON.stringify({ mcpServers: { pm: { command: 'a' } } }));
  write(path.join(home, 'CLAUDE.md'), '# home');
  write(path.join(home, 'AGENTS.md'), '# agents');
  write(path.join(home, '.claude.json'), JSON.stringify({ projects: { [home]: { mcpServers: { cj: { command: 'b' } } } } }));
  const ids = discover({ claudeHome: ch, homeDir: home, projectDir: home, selfRoot: null }).components.map(c => c.id);
  for (const id of ['mcp:project:pm', 'mcp:project:cj', 'instructions:project:CLAUDE.md', 'instructions:project:AGENTS.md',
    'statusline:user', 'hook:user:Stop:0', 'skill:user:s']) assert.ok(ids.includes(id), id);
  assert.deepEqual(ids.filter(id => /^(?:hook|statusline|skill):project\b|#\d+$/.test(id)), []);
});

test('a different project with its own .claude is still inventoried as project scope', () => {
  const home = tmp();
  const proj = path.join(home, 'proj');
  write(path.join(home, '.claude', 'settings.json'), JSON.stringify({ statusLine: { type: 'command', command: 'u' } }));
  write(path.join(proj, '.claude', 'settings.json'), JSON.stringify({ statusLine: { type: 'command', command: 'p' } }));
  write(path.join(proj, '.claude', 'skills', 'ps', 'SKILL.md'), 'x');
  const ids = discover({ claudeHome: path.join(home, '.claude'), homeDir: home, projectDir: proj, selfRoot: null }).components.map(c => c.id);
  for (const id of ['statusline:user', 'statusline:project', 'skill:project:ps']) assert.ok(ids.includes(id), id);
});

test('a marketplace declared in known_marketplaces.json and in settings files is one component with every source', () => {
  const { h, d } = mkHome();
  const known = path.join(h, 'plugins', 'known_marketplaces.json');
  write(known, JSON.stringify({ m1: { source: { source: 'github', repo: 'a/m1' }, installLocation: '/x' } }));
  write(path.join(h, 'settings.json'), JSON.stringify({ extraKnownMarketplaces: { m1: { source: { source: 'github', repo: 'a/m1' } }, m2: { source: { source: 'git', url: 'https://e.test/m2.git' } } } }));
  write(path.join(h, 'settings.local.json'), JSON.stringify({ extraKnownMarketplaces: { m1: { source: { source: 'github', repo: 'a/m1' } } } }));
  const ms = discover(d()).components.filter(c => c.kind === 'marketplace');
  assert.deepEqual(ms.map(c => c.id).sort(), ['marketplace:m1', 'marketplace:m2']);
  const m1 = ms.find(c => c.id === 'marketplace:m1');
  assert.deepEqual(m1.meta.sources, [known, path.join(h, 'settings.json'), path.join(h, 'settings.local.json')]);
  assert.equal(m1.meta.source, known);
  assert.equal(m1.config.installLocation, '/x');
});

test('a marketplace name declared with a different source in another file stays a separate component (review r1 #3)', () => {
  const home = tmp();
  const ch = path.join(home, '.claude');
  const proj = path.join(home, 'proj');
  const known = path.join(ch, 'plugins', 'known_marketplaces.json');
  write(known, JSON.stringify({ m1: { source: { source: 'github', repo: 'good/m1' }, installLocation: '/x' } }));
  write(path.join(ch, 'settings.json'), JSON.stringify({ extraKnownMarketplaces: { m1: { source: { repo: 'good/m1', source: 'github' } } } }));
  write(path.join(proj, '.claude', 'settings.json'), JSON.stringify({ extraKnownMarketplaces: { m1: { source: { source: 'github', repo: 'evil/m1' } } } }));
  const ms = discover({ claudeHome: ch, homeDir: home, projectDir: proj, selfRoot: null }).components.filter(c => c.kind === 'marketplace');
  assert.equal(ms.length, 2);
  const by = Object.fromEntries(ms.map(c => [c.id, c]));
  // Same source with keys in another order merges into the first component.
  assert.equal(by['marketplace:m1'].config.source.repo, 'good/m1');
  assert.deepEqual(by['marketplace:m1'].meta.sources, [known, path.join(ch, 'settings.json')]);
  assert.equal(by['marketplace:m1#2'].config.source.repo, 'evil/m1');
  assert.deepEqual(by['marketplace:m1#2'].meta.sources, [path.join(proj, '.claude', 'settings.json')]);
});
