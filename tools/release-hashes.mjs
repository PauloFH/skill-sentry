#!/usr/bin/env node
// Dev tool: prints the KNOWN_RELEASES / KNOWN_RELEASE_SIZES entries (scripts/lib/releases.mjs) for one release.
// Not part of the plugin runtime: nothing under scripts/ imports it.
//
// For each new release, after tagging it (example: v0.1.1):
//   1. Export the tagged tree into an empty temp dir (exactly what a marketplace install of the tag contains):
//        mkdir <tmp> && git archive v0.1.1 | tar -x -C <tmp>
//   2. Print its entry:
//        node tools/release-hashes.mjs <tmp>
//      The version comes from <tmp>/package.json; pass it as a second argument to override.
//   3. Add the printed "hashes" object under KNOWN_RELEASES["<version>"] and "sizes" under
//      KNOWN_RELEASE_SIZES["<version>"]. The table is cumulative: keep every older entry.
//   4. Ship the updated table in the NEXT release (a release cannot carry its own hashes), and check that
//      scanning a clean export of the tag with the new scanner reports SKILL_SENTRY_OLD_VERSION, not malicious.
//
// Files are walked with the runtime's own rules (shippedFiles: regular files only, Claude Code's `.in_use/<pid>`
// markers left out) and hashed with its LF normalisation (lfSha256), so the two cannot drift.
import fs from 'node:fs';
import path from 'node:path';
import { shippedFiles, lfBytes, lfSha256 } from '../scripts/lib/selfcopy.mjs';

const [dir, versionArg] = process.argv.slice(2);
if (!dir) {
  process.stderr.write('usage: node tools/release-hashes.mjs <clean-export-dir> [version]\n');
  process.exit(2);
}
const root = path.resolve(dir);
const version = versionArg ?? JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).version;
const files = shippedFiles(root, { limits: { maxFiles: 3000, maxDirs: 500, maxBytes: 64 * 1024 * 1024 } });
if (!files || !files.size) {
  process.stderr.write('not a clean release tree: links, special files, read errors or limits\n');
  process.exit(1);
}
const hashes = {};
const sizes = {};
for (const rel of [...files.keys()].sort()) {
  const buf = fs.readFileSync(path.join(root, ...rel.split('/')));
  hashes[rel] = lfSha256(buf);
  sizes[rel] = lfBytes(buf).length;
}
process.stdout.write(`${JSON.stringify({ version, files: files.size, hashes, sizes }, null, 2)}\n`);
