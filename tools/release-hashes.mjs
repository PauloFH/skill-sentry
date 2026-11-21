#!/usr/bin/env node
// Dev tool: the KNOWN_RELEASES / KNOWN_RELEASE_SIZES entries (skills/audit/scripts/lib/releases.mjs) for one release.
// Not part of the plugin runtime: nothing under skills/audit/scripts/ imports it.
//
//   node tools/release-hashes.mjs <clean-export-dir> [version]                  print the entry as JSON
//   node tools/release-hashes.mjs <clean-export-dir> [version] --write <file>   add it to releases.mjs
//
// <clean-export-dir> is exactly what a marketplace install of the tag contains: `git archive <tag> | tar -x -C <dir>`.
// The version comes from <dir>/package.json unless given.
//
// The release pipeline runs this itself (tools/ci/record-release.mjs, from semantic-release's prepare step; see
// docs/RELEASING.md): each release commit records the previous release's entry, the earliest point possible since
// a release cannot carry its own hashes. --write appends the entry at the end of both tables in the file's own
// format, does nothing when the same entry is already there, and refuses a different entry for that version.
//
// Files are walked with the runtime's own rules (shippedFiles: regular files only, Claude Code's `.in_use/<pid>`
// and Codex's `.codex-marketplace-install.json` markers left out) and hashed with its LF normalisation (lfSha256), so the two cannot drift.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { shippedFiles, lfBytes, lfSha256 } from '../skills/audit/scripts/lib/selfcopy.mjs';

const VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;

/** { files, hashes, sizes } of a clean release tree (relpaths sorted); throws when the tree is not clean. */
export function releaseEntry(root) {
  const files = shippedFiles(path.resolve(root), { limits: { maxFiles: 3000, maxDirs: 500, maxBytes: 64 * 1024 * 1024 } });
  if (!files || !files.size) throw new Error('not a clean release tree: links, special files, read errors or limits');
  const hashes = {};
  const sizes = {};
  for (const rel of [...files.keys()].sort()) {
    const buf = fs.readFileSync(path.join(root, ...rel.split('/')));
    hashes[rel] = lfSha256(buf);
    sizes[rel] = lfBytes(buf).length;
  }
  return { files: files.size, hashes, sizes };
}

const quote = s => `'${String(s).replace(/\\/g, '\\\\').replace(/'/g, "\\'")}'`;
const block = (version, map, value) => [
  `  ${quote(version)}: {`,
  ...Object.keys(map).map(rel => `    ${quote(rel)}: ${value(map[rel])},`),
  '  },',
].join('\n');

/** Insert `entry` as the last item of `export const <name> = {` ... `};`. */
function appendToTable(text, name, entry) {
  const start = text.indexOf(`export const ${name} = {\n`);
  if (start === -1) throw new Error(`releases file has no "export const ${name} = {"`);
  const end = text.indexOf('\n};', start);
  if (end === -1) throw new Error(`releases file: ${name} is not closed by "};"`);
  return `${text.slice(0, end + 1)}${entry}\n${text.slice(end + 1)}`;
}

/**
 * Add the entry for `version` to the text of releases.mjs. `current` is the module's present tables
 * ({ KNOWN_RELEASES, KNOWN_RELEASE_SIZES }). Returns { text, changed }; throws on a conflicting entry.
 */
export function addRelease(text, current, version, { hashes, sizes }) {
  if (!VERSION.test(version)) throw new Error(`not a release version: ${JSON.stringify(version)}`);
  const have = [current.KNOWN_RELEASES?.[version], current.KNOWN_RELEASE_SIZES?.[version]];
  if (have[0] || have[1]) {
    const same = JSON.stringify(have[0]) === JSON.stringify(hashes) && JSON.stringify(have[1]) === JSON.stringify(sizes);
    if (!same) throw new Error(`releases file already has a different entry for ${version}`);
    return { text, changed: false };
  }
  // Edited as LF text and written back with the file's own line endings (a Windows checkout may have CRLF).
  const crlf = text.includes('\r\n');
  let out = appendToTable(text.replace(/\r\n/g, '\n'), 'KNOWN_RELEASES', block(version, hashes, quote));
  out = appendToTable(out, 'KNOWN_RELEASE_SIZES', block(version, sizes, n => String(n)));
  return { text: crlf ? out.replace(/\n/g, '\r\n') : out, changed: true };
}

/** Add the entry to the releases file on disk (fresh import of its tables). Returns true when it changed. */
export async function writeRelease(file, version, entry) {
  const abs = path.resolve(file);
  const current = await import(`${pathToFileURL(abs).href}?t=${Date.now()}`);
  const { text, changed } = addRelease(fs.readFileSync(abs, 'utf8'), current, version, entry);
  if (changed) fs.writeFileSync(abs, text);
  return changed;
}

async function main(argv) {
  const writeIdx = argv.indexOf('--write');
  const writeFile = writeIdx !== -1 ? argv[writeIdx + 1] : null;
  const rest = argv.filter((_, i) => writeIdx === -1 || (i !== writeIdx && i !== writeIdx + 1));
  const [dir, versionArg] = rest;
  if (!dir || (writeIdx !== -1 && (!writeFile || writeFile.startsWith('--')))) {
    process.stderr.write('usage: node tools/release-hashes.mjs <clean-export-dir> [version] [--write <releases.mjs>]\n');
    return 2;
  }
  const root = path.resolve(dir);
  const version = versionArg ?? JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).version;
  let entry;
  try { entry = releaseEntry(root); } catch (e) { process.stderr.write(`${e.message}\n`); return 1; }
  if (!writeFile) {
    process.stdout.write(`${JSON.stringify({ version, ...entry }, null, 2)}\n`);
    return 0;
  }
  try {
    const changed = await writeRelease(writeFile, version, entry);
    process.stdout.write(`${changed ? 'added' : 'already present:'} ${version} (${entry.files} files) in ${writeFile}\n`);
    return 0;
  } catch (e) {
    process.stderr.write(`${e.message}\n`);
    return 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = await main(process.argv.slice(2));
}
