import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { tmpFactory } from './helpers/tmp.mjs';
import { KNOWN_RELEASES } from '../scripts/lib/releases.mjs';
import { knownRelease } from '../scripts/lib/selfcopy.mjs';

const tmp = tmpFactory('ss-knownrel-');
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const git = (...args) => spawnSync('git', ['-C', ROOT, ...args], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });

/**
 * The newest v* tag reachable from HEAD, leaving out a tag on HEAD itself (a release commit is tagged with its own
 * version, and a release cannot carry its own hashes). null when git or the tags are unavailable.
 */
function previousReleaseTag() {
  const merged = git('tag', '--merged', 'HEAD', '--sort=-v:refname', '--list', 'v*');
  const here = git('tag', '--points-at', 'HEAD', '--list', 'v*');
  if (merged.status !== 0 || here.status !== 0) return null;
  const onHead = new Set(here.stdout.split(/\r?\n/).filter(Boolean));
  return merged.stdout.split(/\r?\n/).filter(t => /^v\d+\.\d+\.\d+$/.test(t) && !onHead.has(t))[0] ?? null;
}

// Each release must be added to KNOWN_RELEASES (tools/release-hashes.mjs, docs/RELEASING.md) before the next one:
// that table is how a newer scanner recognises the older copy still installed for the other agent. This fails on
// every pull request after a release until the entry lands, so the next release always carries it.
test('releases: the previous release tag is in KNOWN_RELEASES and a git archive of it is recognised', t => {
  const tag = previousReleaseTag();
  if (!tag) {
    t.skip('git archive of the previous release tag unavailable (git missing or no v* tags; run git fetch --tags)');
    return;
  }
  const version = tag.slice(1);
  assert.ok(KNOWN_RELEASES[version], `KNOWN_RELEASES has no entry for ${version}: add it with tools/release-hashes.mjs (see docs/RELEASING.md)`);
  const out = tmp('export');
  const a = spawnSync('git', ['-C', ROOT, 'archive', '--format=tar', tag], { maxBuffer: 256 * 1024 * 1024 });
  assert.equal(a.status, 0, `git archive ${tag}: ${a.stderr}`);
  const x = spawnSync('tar', ['-xf', '-'], { input: a.stdout, cwd: out, encoding: 'utf8' });
  assert.equal(x.status, 0, x.stderr);
  assert.equal(knownRelease(out), version, `a clean export of ${tag} must match KNOWN_RELEASES["${version}"] byte for byte`);
});
