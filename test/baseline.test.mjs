import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { loadBaseline, saveBaseline, diffBaseline, baselineLoadError } from '../scripts/lib/baseline.mjs';
import { dataDir } from '../scripts/lib/datadir.mjs';
import { scanComponent } from '../scripts/lib/scanner.mjs';
import { discover } from '../scripts/lib/inventory.mjs';
import { fileMap } from '../scripts/lib/baseline.mjs';

const tmps = [];
after(() => tmps.forEach(d => fs.rmSync(d, { recursive: true, force: true })));
const tmp = () => { const d = fs.mkdtempSync(path.join(os.tmpdir(), 'ss-bl-')); tmps.push(d); return d; };
const res = (id, files = {}, config) => ({
  component: { id, kind: 'plugin', name: id, ...(config !== undefined ? { config } : {}) },
  files: Object.entries(files).map(([p, sha256]) => ({ path: p, sha256, kind: 'code', size: 1 })),
  findings: [], incomplete: false,
});

test('dataDir honours env and creates the directory', () => {
  const d = path.join(tmp(), 'nested', 'dir');
  const old = process.env.SKILL_SENTRY_DATA_DIR;
  process.env.SKILL_SENTRY_DATA_DIR = d;
  try {
    assert.equal(dataDir(), d);
    assert.ok(fs.statSync(d).isDirectory());
  } finally {
    if (old === undefined) delete process.env.SKILL_SENTRY_DATA_DIR; else process.env.SKILL_SENTRY_DATA_DIR = old;
  }
});

test('first run: firstRun true and everything added', () => {
  const d = diffBaseline(null, [res('a'), res('b')]);
  assert.deepEqual(d, { firstRun: true, added: ['a', 'b'], removed: [], changed: [], incomplete: [] });
  assert.equal(loadBaseline(tmp()), null);
});

test('save/load round trip leaves no tmp file and diff is empty', () => {
  const dir = tmp();
  const r = [res('a', { 'x.js': 'h1' }), res('b', { 'y.md': 'h2' })];
  saveBaseline(dir, r);
  assert.deepEqual(fs.readdirSync(dir), ['baseline.json']);
  const b = loadBaseline(dir);
  assert.equal(b.version, 1);
  assert.deepEqual({ ...b.components.a.files }, { 'x.js': 'h1' });
  assert.deepEqual(diffBaseline(b, r), { firstRun: false, added: [], removed: [], changed: [], incomplete: [] });
});

test('modified, added and removed files and components are reported', () => {
  const dir = tmp();
  saveBaseline(dir, [res('a', { 'x.js': 'h1', 'gone.js': 'g' }), res('b', { 'y': '1' })]);
  const d = diffBaseline(loadBaseline(dir), [res('a', { 'x.js': 'CHANGED', 'new.js': 'n' }), res('c', { 'z': '1' })]);
  assert.deepEqual(d.added, ['c']);
  assert.deepEqual(d.removed, ['b']);
  assert.equal(d.changed.length, 1);
  assert.equal(d.changed[0].id, 'a');
  assert.deepEqual(d.changed[0].files.sort(), ['gone.js', 'new.js', 'x.js']);
});

test('real scan: editing a file in a tmp component shows in changed[0].files', () => {
  const root = tmp();
  fs.writeFileSync(path.join(root, 'a.js'), 'console.log(1)\n');
  fs.writeFileSync(path.join(root, 'b.md'), '# hi\n');
  const comp = { id: 'plugin:t', kind: 'plugin', name: 't', scope: 'user', root, meta: {} };
  const dir = tmp();
  saveBaseline(dir, [scanComponent(comp)]);
  fs.writeFileSync(path.join(root, 'a.js'), 'console.log(2)\n');
  const d = diffBaseline(loadBaseline(dir), [scanComponent(comp)]);
  assert.deepEqual(d.changed, [{ id: 'plugin:t', files: ['a.js'] }]);
});

test('config-only component is hashed as pseudo-file <config>', () => {
  const dir = tmp();
  saveBaseline(dir, [res('hook:x', {}, { command: 'echo a' })]);
  const b = loadBaseline(dir);
  assert.deepEqual(Object.keys(b.components['hook:x'].files), ['<config>']);
  assert.match(b.components['hook:x'].files['<config>'], /^[0-9a-f]{64}$/);
  assert.deepEqual(diffBaseline(b, [res('hook:x', {}, { command: 'echo a' })]).changed, []);
  assert.deepEqual(diffBaseline(b, [res('hook:x', {}, { command: 'curl evil' })]).changed, [{ id: 'hook:x', files: ['<config>'] }]);
});

test('ids with collision suffix are opaque', () => {
  const dir = tmp();
  saveBaseline(dir, [res('statusline:user', {}, { c: 1 }), res('statusline:user#2', {}, { c: 2 })]);
  const d = diffBaseline(loadBaseline(dir), [res('statusline:user', {}, { c: 1 }), res('statusline:user#2', {}, { c: 3 })]);
  assert.deepEqual(d.changed, [{ id: 'statusline:user#2', files: ['<config>'] }]);
});

test('corrupt baseline: null (first run), error exposed, file quarantined on save', () => {
  const dir = tmp();
  fs.writeFileSync(path.join(dir, 'baseline.json'), '{not json');
  assert.equal(loadBaseline(dir), null);
  assert.ok(baselineLoadError(dir));
  assert.equal(baselineLoadError(tmp()), null);
  saveBaseline(dir, [res('a', { f: '1' })]);
  assert.equal(baselineLoadError(dir), null);
  assert.ok(fs.readdirSync(dir).some(f => f.startsWith('baseline.json.corrupt-')));
});

test('incomplete scan: no removals, id listed in incomplete', () => {
  const dir = tmp();
  saveBaseline(dir, [res('a', { 'x.js': 'h1', 'y.js': 'h2' })]);
  const partial = { ...res('a', { 'x.js': 'h1' }), incomplete: true };
  const d = diffBaseline(loadBaseline(dir), [partial]);
  assert.deepEqual(d.changed, []);
  assert.deepEqual(d.incomplete, ['a']);
  const partial2 = { ...res('a', { 'x.js': 'NEW', 'z.js': 'n' }), incomplete: true };
  const d2 = diffBaseline(loadBaseline(dir), [partial2]);
  assert.deepEqual(d2.changed[0].files.sort(), ['x.js', 'z.js']);
  assert.deepEqual(diffBaseline(loadBaseline(dir), [res('a', { 'x.js': 'h1', 'y.js': 'h2' })]).incomplete, []);
  assert.deepEqual(diffBaseline(null, [partial]).incomplete, []);
});

test('saving an incomplete result keeps previously hashed files', () => {
  const dir = tmp();
  saveBaseline(dir, [res('a', { 'x.js': 'h1', 'y.js': 'h2' })]);
  saveBaseline(dir, [{ ...res('a', { 'x.js': 'NEW' }), incomplete: true }]);
  assert.deepEqual({ ...loadBaseline(dir).components.a.files }, { 'x.js': 'NEW', 'y.js': 'h2' });
});

test('prototype-named files: modification and deletion are detected', () => {
  const dir = tmp();
  // build a result with a real own "__proto__" path
  const files = [['__proto__', 'p1'], ['constructor', 'c1'], ['toString', 't1']]
    .map(([p, sha256]) => ({ path: p, sha256, kind: 'code', size: 1 }));
  const mk = fs => ({ component: { id: 'a' }, files: fs, findings: [], incomplete: false });
  saveBaseline(dir, [mk(files)]);
  const b = loadBaseline(dir);
  assert.equal(Object.hasOwn(b.components.a.files, '__proto__'), true);
  assert.deepEqual(diffBaseline(b, [mk(files)]).changed, []);
  const mod = files.map(f => ({ ...f, sha256: f.sha256 + 'X' }));
  assert.deepEqual(diffBaseline(b, [mk(mod)]).changed[0].files.sort(), ['__proto__', 'constructor', 'toString']);
  assert.deepEqual(diffBaseline(b, [mk([])]).changed[0].files.sort(), ['__proto__', 'constructor', 'toString']);
});

test('corrupt component entries: no throw, error reported', () => {
  const dir = tmp();
  fs.writeFileSync(path.join(dir, 'baseline.json'), JSON.stringify({
    version: 1, createdAt: 't',
    components: { x: null, y: { files: 5 }, z: { files: { 'a.js': 1 } }, ok: { files: { 'a.js': 'h' } } },
  }));
  const b = loadBaseline(dir);
  assert.ok(baselineLoadError(dir));
  assert.doesNotThrow(() => diffBaseline(b, [res('x', { f: '1' }), res('ok', { 'a.js': 'h' })]));
  assert.deepEqual(Object.keys(b.components), ['ok']);
});

// The "<config>" hash covers the RAW config (the stored copy is redacted): a package, query, key-file
// or env change confined to a redacted value must still show as "changed".
test('<config> hash is taken over the raw MCP config: redacted-value swaps appear in the diff', () => {
  const pairs = [
    ['npx -p package swap', { command: 'npx', args: ['-y', '-p', 'good-mcp@1.2.3', 'good-mcp'] }, { command: 'npx', args: ['-y', '-p', 'evil-mcp@latest', 'good-mcp'] }],
    ['url query swap', { type: 'http', url: 'https://mcp.example.com/m?upstream=good.example' }, { type: 'http', url: 'https://mcp.example.com/m?upstream=evil.example' }],
    ['--key file swap', { command: 'node', args: ['srv.js', '--key', 'a.pem'] }, { command: 'node', args: ['srv.js', '--key', '/tmp/attacker.pem'] }],
    ['env value swap', { command: 'node', args: ['srv.js'], env: { NODE_OPTIONS: '' } }, { command: 'node', args: ['srv.js'], env: { NODE_OPTIONS: '--import=./x.mjs' } }],
  ];
  const scanWith = server => {
    const h = tmp();
    fs.writeFileSync(path.join(h, '.claude.json'), JSON.stringify({ mcpServers: { srv: server } }));
    const c = discover({ claudeHome: h, homeDir: h, projectDir: null, selfRoot: null }).components.find(x => x.id === 'mcp:user:srv');
    return scanComponent(c);
  };
  for (const [label, before, after] of pairs) {
    const a = scanWith(before);
    const b = scanWith(after);
    assert.notEqual(fileMap(a)['<config>'], fileMap(b)['<config>'], label);
    const dir = tmp();
    saveBaseline(dir, [a]);
    const stored = fs.readFileSync(path.join(dir, 'baseline.json'), 'utf8');
    for (const raw of ['good-mcp@1.2.3', 'good.example', 'a.pem']) assert.ok(!stored.includes(raw), `${label}: baseline stores hashes only`);
    const diff = diffBaseline(loadBaseline(dir), [b]);
    assert.deepEqual(diff.changed, [{ id: 'mcp:user:srv', files: ['<config>'] }], label);
    assert.deepEqual(diffBaseline(loadBaseline(dir), [scanWith(before)]).changed, [], `${label}: unchanged config stays unchanged`);
  }
});

test('npx -p package names are not redacted: the SUPPLY_UNPINNED_RUNTIME snippet names the package', () => {
  const h = tmp();
  fs.writeFileSync(path.join(h, '.claude.json'), JSON.stringify({ mcpServers: { srv: { command: 'npx', args: ['-y', '-p', 'evil-mcp@latest', 'good-mcp'] } } }));
  const c = discover({ claudeHome: h, homeDir: h, projectDir: null, selfRoot: null }).components.find(x => x.id === 'mcp:user:srv');
  assert.deepEqual(c.config.args, ['-y', '-p', 'evil-mcp@latest', 'good-mcp']);
  const f = scanComponent(c).findings.find(x => x.ruleId === 'SUPPLY_UNPINNED_RUNTIME');
  assert.ok(f, 'unpinned runtime reported');
  assert.match(f.snippet, /-p evil-mcp@latest good-mcp/);
});
