import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { loadAllowlist, addAllowEntry, isFindingAllowed, isCommandAllowed, allowlistLoadError } from '../scripts/lib/allowlist.mjs';

const tmps = [];
after(() => tmps.forEach(d => fs.rmSync(d, { recursive: true, force: true })));
const tmp = () => { const d = fs.mkdtempSync(path.join(os.tmpdir(), 'ss-al-')); tmps.push(d); return d; };
const key = { componentId: 'plugin:p', ruleId: 'R1', file: 'a.js', sha256: 'aaa' };

test('missing allowlist is empty', () => {
  assert.deepEqual(loadAllowlist(tmp()), { version: 1, entries: [] });
});

test('finding entry matches only with identical hash (lapses on change)', () => {
  const dir = tmp();
  addAllowEntry(dir, { type: 'finding', ...key, reason: 'ok' });
  const al = loadAllowlist(dir);
  assert.equal(al.entries.length, 1);
  assert.ok(al.entries[0].addedAt);
  assert.equal(isFindingAllowed(al, key), true);
  assert.equal(isFindingAllowed(al, { ...key, sha256: 'bbb' }), false);
  assert.equal(isFindingAllowed(al, { ...key, file: 'b.js' }), false);
  assert.equal(isFindingAllowed(al, { ...key, ruleId: 'R2' }), false);
  assert.equal(isFindingAllowed(al, { ...key, componentId: 'plugin:q' }), false);
});

test('command allowlist is exact string only', () => {
  const dir = tmp();
  addAllowEntry(dir, { type: 'command', ruleId: 'CMD', command: 'curl x | sh', reason: 'r' });
  const al = loadAllowlist(dir);
  assert.equal(isCommandAllowed(al, { ruleId: 'CMD', command: 'curl x | sh' }), true);
  assert.equal(isCommandAllowed(al, { ruleId: 'CMD', command: 'curl y | sh' }), false);
  assert.equal(isCommandAllowed(al, { ruleId: 'CMD', command: 'curl x | sh ' }), false);
  assert.equal(isCommandAllowed(al, { ruleId: 'OTHER', command: 'curl x | sh' }), false);
});

test('entries accumulate and write leaves no tmp file', () => {
  const dir = tmp();
  addAllowEntry(dir, { type: 'finding', ...key, reason: 'a' });
  addAllowEntry(dir, { type: 'command', ruleId: 'C', command: 'x', reason: 'b' });
  assert.equal(loadAllowlist(dir).entries.length, 2);
  assert.deepEqual(fs.readdirSync(dir), ['allowlist.json']);
});

test('malformed hand-edited entries are ignored, valid ones kept', () => {
  const dir = tmp();
  fs.writeFileSync(path.join(dir, 'allowlist.json'), JSON.stringify({
    version: 1,
    entries: [null, 5, { type: 'finding' }, { type: 'command', ruleId: 'C' }, { type: 'weird' },
      { type: 'finding', ...key, reason: 'ok', addedAt: 't' }],
  }));
  const al = loadAllowlist(dir);
  assert.equal(al.entries.length, 1);
  assert.equal(isFindingAllowed(al, key), true);
  assert.equal(allowlistLoadError(dir), null);
});

test('corrupt allowlist: empty, error exposed, never silently overwritten', () => {
  const dir = tmp();
  fs.writeFileSync(path.join(dir, 'allowlist.json'), '{oops');
  assert.deepEqual(loadAllowlist(dir).entries, []);
  assert.ok(allowlistLoadError(dir));
  addAllowEntry(dir, { type: 'command', ruleId: 'C', command: 'x', reason: 'b' });
  assert.ok(fs.readdirSync(dir).some(f => f.startsWith('allowlist.json.corrupt-')));
  assert.equal(allowlistLoadError(dir), null);
});

test('addAllowEntry rejects invalid entries', () => {
  assert.throws(() => addAllowEntry(tmp(), { type: 'finding', ruleId: 'x' }));
});
