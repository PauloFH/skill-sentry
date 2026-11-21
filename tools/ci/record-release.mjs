#!/usr/bin/env node
// Records a published release in skills/audit/scripts/lib/releases.mjs (KNOWN_RELEASES / KNOWN_RELEASE_SIZES).
// Run by semantic-release's prepare step with the previous release's tag (tools/ci/release/release.config.cjs):
//
//   node tools/ci/record-release.mjs <tag>        e.g. v0.1.2; an empty argument (first release) does nothing
//
// Exports the tag with `git archive` into a tmp dir, computes its entry with tools/release-hashes.mjs and appends it
// when missing, so the next release commit carries it (a release cannot carry its own hashes). CI-only tooling.
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { releaseEntry, writeRelease } from '../release-hashes.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const RELEASES = path.join(ROOT, 'skills', 'audit', 'scripts', 'lib', 'releases.mjs');

async function main(tag) {
  if (!tag) {
    console.log('record-release: no previous release tag, nothing to record');
    return 0;
  }
  const m = /^v(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)$/.exec(tag);
  if (!m) { console.error(`record-release: not a release tag: ${JSON.stringify(tag)}`); return 1; }
  // Escape hatch for a release whose tree can never be recorded (docs/RELEASING.md, "Recovery"):
  // tools/ci/release/unrecordable.json maps "<version>" to the reason.
  const skipFile = path.join(ROOT, 'tools', 'ci', 'release', 'unrecordable.json');
  const skip = fs.existsSync(skipFile) ? JSON.parse(fs.readFileSync(skipFile, 'utf8')) : {};
  if (Object.hasOwn(skip, m[1])) {
    console.log(`record-release: ${m[1]} is listed in tools/ci/release/unrecordable.json (${skip[m[1]]}); not recorded`);
    return 0;
  }
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ss-record-'));
  try {
    const a = spawnSync('git', ['-C', ROOT, 'archive', '--format=tar', tag], { maxBuffer: 256 * 1024 * 1024 });
    if (a.status !== 0) { console.error(`record-release: git archive ${tag} failed: ${a.stderr}`); return 1; }
    const x = spawnSync('tar', ['-xf', '-'], { input: a.stdout, cwd: dir, encoding: 'utf8' });
    if (x.status !== 0) { console.error(`record-release: tar failed: ${x.stderr}`); return 1; }
    const pkgVersion = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8')).version;
    if (pkgVersion !== m[1]) { console.error(`record-release: ${tag} carries package.json version ${pkgVersion}`); return 1; }
    const entry = releaseEntry(dir);
    const changed = await writeRelease(RELEASES, m[1], entry);
    console.log(`record-release: ${changed ? 'added' : 'already present:'} ${m[1]} (${entry.files} files)`);
    return 0;
  } catch (e) {
    console.error(`record-release: ${e.message}`);
    return 1;
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

process.exitCode = await main(process.argv[2] ?? '');
