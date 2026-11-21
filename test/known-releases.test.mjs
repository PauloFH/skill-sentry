import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { tmpFactory } from './helpers/tmp.mjs';
import * as releases from '../scripts/lib/releases.mjs';
import { knownRelease } from '../scripts/lib/selfcopy.mjs';
import { releaseEntry, addRelease } from '../tools/release-hashes.mjs';

const { KNOWN_RELEASES, KNOWN_RELEASE_SIZES } = releases;
const tmp = tmpFactory('ss-knownrel-');
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const RELEASES_FILE = path.join(ROOT, 'scripts', 'lib', 'releases.mjs');
const UNAVAILABLE = 'git archive of the release tags unavailable (git missing or no v* tags; run git fetch --tags)';

/** v* release tags reachable from HEAD, newest first; null when git or the tags are unavailable. */
function reachableTags() {
  const r = spawnSync('git', ['-C', ROOT, 'tag', '--merged', 'HEAD', '--sort=-v:refname', '--list', 'v*'], { encoding: 'utf8' });
  if (r.status !== 0) return null;
  const tags = r.stdout.split(/\r?\n/).filter(t => /^v\d+\.\d+\.\d+$/.test(t));
  return tags.length ? tags : null;
}

function exportTag(tag) {
  const out = tmp('export');
  const a = spawnSync('git', ['-C', ROOT, 'archive', '--format=tar', tag], { maxBuffer: 256 * 1024 * 1024 });
  assert.equal(a.status, 0, `git archive ${tag}: ${a.stderr}`);
  const x = spawnSync('tar', ['-xf', '-'], { input: a.stdout, cwd: out, encoding: 'utf8' });
  assert.equal(x.status, 0, x.stderr);
  return out;
}

// The release pipeline records each release in KNOWN_RELEASES in the NEXT release commit
// (tools/ci/record-release.mjs; docs/RELEASING.md), so only the newest reachable tag may be missing. Every entry
// present must match a clean export of its tag byte for byte: that table is how a newer scanner recognises the older
// copy still installed for the other agent.
test('releases: every release tag but the newest is in KNOWN_RELEASES, and every entry matches its git archive', t => {
  const tags = reachableTags();
  if (!tags) {
    t.skip(UNAVAILABLE);
    return;
  }
  const [newest, ...older] = tags;
  for (const tag of older) {
    assert.ok(KNOWN_RELEASES[tag.slice(1)], `KNOWN_RELEASES has no entry for ${tag.slice(1)}: the release after it should have recorded it`);
  }
  for (const tag of [newest, ...older].filter(x => KNOWN_RELEASES[x.slice(1)])) {
    assert.equal(knownRelease(exportTag(tag)), tag.slice(1), `a clean export of ${tag} must match KNOWN_RELEASES["${tag.slice(1)}"]`);
  }
});

// The pipeline edits releases.mjs with tools/release-hashes.mjs --write, so the writer must reproduce the file's
// own format exactly: removing the latest entry and adding it back from `git archive` gives the same bytes.
test('release-hashes --write: re-adding the latest recorded release reproduces releases.mjs byte for byte', t => {
  const tags = reachableTags();
  if (!tags) {
    t.skip(UNAVAILABLE);
    return;
  }
  const version = tags.map(x => x.slice(1)).find(v => KNOWN_RELEASES[v]);
  assert.ok(version, 'no reachable release tag is recorded');
  const original = fs.readFileSync(RELEASES_FILE, 'utf8').replace(/\r\n/g, '\n'); // a Windows checkout may be CRLF
  const esc = version.replace(/\./g, '\\.');
  const stripped = original.replace(new RegExp(`\\n  '${esc}': \\{\\n[\\s\\S]*?\\n  \\},`, 'g'), '');
  assert.notEqual(stripped, original);
  const without = obj => Object.fromEntries(Object.entries(obj).filter(([v]) => v !== version));
  const current = { KNOWN_RELEASES: without(KNOWN_RELEASES), KNOWN_RELEASE_SIZES: without(KNOWN_RELEASE_SIZES) };
  const entry = releaseEntry(exportTag(`v${version}`));
  const { text, changed } = addRelease(stripped, current, version, entry);
  assert.equal(changed, true);
  assert.equal(text, original);
  // CRLF in, CRLF out.
  const crlf = addRelease(stripped.replace(/\n/g, '\r\n'), current, version, entry);
  assert.equal(crlf.text, original.replace(/\n/g, '\r\n'));
});

test('release-hashes --write: an entry already present is a no-op, a different one is refused', () => {
  const original = fs.readFileSync(RELEASES_FILE, 'utf8').replace(/\r\n/g, '\n');
  const version = Object.keys(KNOWN_RELEASES).at(-1);
  const same = addRelease(original, releases, version, { hashes: KNOWN_RELEASES[version], sizes: KNOWN_RELEASE_SIZES[version] });
  assert.equal(same.changed, false);
  assert.equal(same.text, original);
  assert.throws(() => addRelease(original, releases, version, { hashes: { 'x.txt': 'ab' }, sizes: { 'x.txt': 1 } }), /different entry/);
  assert.throws(() => addRelease(original, releases, 'v9', { hashes: {}, sizes: {} }), /not a release version/);
  // A new version is appended as the last entry of both tables.
  const added = addRelease(original, releases, '99.0.0', { hashes: { "a'b.txt": 'cd' }, sizes: { "a'b.txt": 2 } });
  assert.equal(added.changed, true);
  assert.match(added.text, /\n  '99\.0\.0': \{\n    'a\\'b\.txt': 'cd',\n  \},\n\};\n\nexport const KNOWN_RELEASE_SIZES/);
  assert.match(added.text, /\n  '99\.0\.0': \{\n    'a\\'b\.txt': 2,\n  \},\n\};\n?$/);
});
