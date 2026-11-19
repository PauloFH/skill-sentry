import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { loadBaseline, saveBaseline, diffBaseline, baselineLoadError } from '../scripts/lib/baseline.mjs';
import { dataDir } from '../scripts/lib/datadir.mjs';
import { scanComponent } from '../scripts/lib/scanner.mjs';

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
  assert.deepEqual(d, { firstRun: true, added: ['a', 'b'], removed: [], changed: [] });
  assert.equal(loadBaseline(tmp()), null);
});

test('save/load round trip leaves no tmp file and diff is empty', () => {
  const dir = tmp();
  const r = [res('a', { 'x.js': 'h1' }), res('b', { 'y.md': 'h2' })];
  saveBaseline(dir, r);
  assert.deepEqual(fs.readdirSync(dir), ['baseline.json']);
  const b = loadBaseline(dir);
  assert.equal(b.version, 1);
  assert.deepEqual(b.components.a.files, { 'x.js': 'h1' });
  assert.deepEqual(diffBaseline(b, r), { firstRun: false, added: [], removed: [], changed: [] });
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
