import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { tmpFactory } from './helpers/tmp.mjs';
import { setVersion } from '../tools/ci/set-version.mjs';

const tmp = tmpFactory('ss-setver-');
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const FILES = ['.claude-plugin/plugin.json', '.claude-plugin/marketplace.json', 'package.json'];
const SCRIPT = path.join(ROOT, 'tools', 'ci', 'set-version.mjs');

const copyManifests = () => {
  const d = tmp('root');
  for (const f of FILES) {
    fs.mkdirSync(path.dirname(path.join(d, f)), { recursive: true });
    fs.copyFileSync(path.join(ROOT, f), path.join(d, f));
  }
  return d;
};

test('set-version: writes the version into plugin.json, marketplace.json and package.json, nothing else', () => {
  const d = copyManifests();
  const before = Object.fromEntries(FILES.map(f => [f, fs.readFileSync(path.join(d, f), 'utf8')]));
  setVersion(d, '9.8.7');
  const read = f => JSON.parse(fs.readFileSync(path.join(d, f), 'utf8'));
  assert.equal(read('.claude-plugin/plugin.json').version, '9.8.7');
  assert.equal(read('.claude-plugin/marketplace.json').plugins[0].version, '9.8.7');
  assert.equal(read('package.json').version, '9.8.7');
  // Formatting is kept: only the version values differ.
  for (const f of FILES) {
    const old = JSON.parse(before[f]).version ?? JSON.parse(before[f]).plugins[0].version;
    assert.equal(fs.readFileSync(path.join(d, f), 'utf8'), before[f].split(`"${old}"`).join('"9.8.7"'), f);
  }
});

test('set-version: refuses a non-semver value and leaves the files untouched', () => {
  const d = copyManifests();
  const before = FILES.map(f => fs.readFileSync(path.join(d, f), 'utf8'));
  for (const bad of ['', '1.2', 'v1.2.3', '1.2.3"; x', '1.2.3\n']) assert.throws(() => setVersion(d, bad), /not a semantic version/);
  assert.deepEqual(FILES.map(f => fs.readFileSync(path.join(d, f), 'utf8')), before);
});

test('set-version CLI: exit 0 with a version, exit 1 without one', () => {
  const d = copyManifests();
  const ok = spawnSync(process.execPath, [SCRIPT, '1.2.3', '--root', d], { encoding: 'utf8' });
  assert.equal(ok.status, 0, ok.stderr);
  assert.equal(JSON.parse(fs.readFileSync(path.join(d, 'package.json'), 'utf8')).version, '1.2.3');
  const bad = spawnSync(process.execPath, [SCRIPT, '--root', d], { encoding: 'utf8' });
  assert.equal(bad.status, 1);
});
