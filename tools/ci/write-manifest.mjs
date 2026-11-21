#!/usr/bin/env node
// Writes the self-manifest of a release tree, skills/audit/scripts/lib/selfmanifest.json, or checks it:
//
//   node tools/ci/write-manifest.mjs <rootDir>             write it
//   node tools/ci/write-manifest.mjs <rootDir> --verify    exit 1 unless the file equals what would be written
//
// Shape: { "version": "<package.json version>", "files": { "<relpath>": "<lfSha256>" } }, keys sorted, 2-space JSON, LF,
// trailing newline (serializeManifest). It lists every file of the release tree except the manifest itself, `.git`
// and install markers. In a git work tree (semantic-release's prepare step) that is the tracked files, read from the
// work tree as the release commit will hold them; ignored files (tools/ci/release/node_modules) and untracked ones
// are never released. In any other dir (a `git archive` export of a tag) it is every regular file, walked with the
// runtime's own rules (shippedFiles: links and special files refused, markers left out).
//
// Run by semantic-release's prepare step LAST, after every other file of the release commit changed (set-version,
// record-release, the changelog); see tools/ci/release/release.config.cjs and docs/RELEASING.md. CI-only tooling.
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { shippedFiles, lfSha256, serializeManifest, MANIFEST_REL } from '../../skills/audit/scripts/lib/selfcopy.mjs';

const LIMITS = { maxFiles: 3000, maxDirs: 500, maxBytes: 64 * 1024 * 1024 };

/** Relpaths of the release tree under `root`, sorted, the manifest itself left out. Throws when not clean. */
function releaseFiles(root) {
  let rels;
  if (fs.existsSync(path.join(root, '.git'))) {
    const top = spawnSync('git', ['-C', root, 'rev-parse', '--show-toplevel'], { encoding: 'utf8' });
    const key = p => (process.platform === 'win32' ? path.resolve(p).toLowerCase() : path.resolve(p));
    if (top.status !== 0 || key(fs.realpathSync.native(top.stdout.trim())) !== key(fs.realpathSync.native(root))) {
      throw new Error(`${root} is not the top of its git work tree`);
    }
    const ls = spawnSync('git', ['-C', root, 'ls-files', '-z'], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
    if (ls.status !== 0) throw new Error(`git ls-files failed: ${ls.stderr}`);
    rels = ls.stdout.split('\0').filter(Boolean);
    for (const r of rels) {
      const st = fs.lstatSync(path.join(root, ...r.split('/')), { throwIfNoEntry: false });
      if (!st?.isFile()) throw new Error(`tracked file is not a regular file in the work tree: ${r}`);
    }
  } else {
    const files = shippedFiles(path.resolve(root), { limits: LIMITS });
    if (!files) throw new Error('not a clean release tree: links, special files, read errors or limits');
    rels = [...files.keys()];
  }
  return rels.filter(r => r !== MANIFEST_REL).sort();
}

/** The manifest text for the release tree at `root`. */
export function buildManifest(root) {
  const version = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).version;
  if (typeof version !== 'string' || !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(version)) throw new Error(`package.json version: ${JSON.stringify(version)}`);
  const files = {};
  for (const rel of releaseFiles(root)) files[rel] = lfSha256(fs.readFileSync(path.join(root, ...rel.split('/'))));
  return serializeManifest({ version, files });
}

function main(argv) {
  const verify = argv.includes('--verify');
  const rest = argv.filter(a => a !== '--verify');
  if (rest.length !== 1) {
    console.error('usage: node tools/ci/write-manifest.mjs <rootDir> [--verify]');
    return 2;
  }
  const root = path.resolve(rest[0]);
  const file = path.join(root, ...MANIFEST_REL.split('/'));
  try {
    const text = buildManifest(root);
    const count = Object.keys(JSON.parse(text).files).length;
    if (verify) {
      const have = fs.existsSync(file) ? fs.readFileSync(file, 'utf8').replace(/\r\n/g, '\n') : null;
      if (have === text) {
        console.log(`write-manifest: ${MANIFEST_REL} matches the tree (${count} files)`);
        return 0;
      }
      const want = JSON.parse(text);
      let got = null;
      try { got = have === null ? null : JSON.parse(have); } catch { /* reported below */ }
      const diff = got?.files ? [...new Set([...Object.keys(want.files), ...Object.keys(got.files)])]
        .filter(r => want.files[r] !== got.files[r]).slice(0, 20) : [];
      console.error(`write-manifest: ${MANIFEST_REL} does not match the tree${have === null ? ' (missing)' : ''}`
        + `${got && got.version !== want.version ? `; version ${got.version} != ${want.version}` : ''}`
        + `${diff.length ? `; differing files: ${diff.join(', ')}` : ''}`);
      return 1;
    }
    fs.writeFileSync(file, text);
    console.log(`write-manifest: wrote ${MANIFEST_REL} (${count} files)`);
    return 0;
  } catch (e) {
    console.error(`write-manifest: ${e.message}`);
    return 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) process.exitCode = main(process.argv.slice(2));
