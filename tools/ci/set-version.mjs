#!/usr/bin/env node
// Writes a release version into the manifests: .claude-plugin/plugin.json, every "version" field of
// .claude-plugin/marketplace.json, and package.json. Run by semantic-release (@semantic-release/exec prepareCmd,
// see tools/ci/release.config.cjs). Zero dependencies; CI-only tooling, never imported by scripts/.
//
//   node tools/ci/set-version.mjs <version> [--root <dir>]
//
// Only the version string values are replaced, so the files keep their formatting byte for byte otherwise.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const FIELD = /("version"\s*:\s*)"[^"\\]*"/g;

/** Replace every "version" string value in `text`; returns { text, count }. */
export function replaceVersions(text, version) {
  let count = 0;
  const out = text.replace(FIELD, (_, key) => { count++; return `${key}"${version}"`; });
  return { text: out, count };
}

/** Collect every "version" value of a parsed JSON value (to check the rewrite). */
function versionsOf(v, out = []) {
  if (Array.isArray(v)) v.forEach(x => versionsOf(x, out));
  else if (v && typeof v === 'object') {
    for (const [k, x] of Object.entries(v)) {
      if (k === 'version') out.push(x);
      else versionsOf(x, out);
    }
  }
  return out;
}

export function setVersion(root, version) {
  if (!VERSION.test(version)) throw new Error(`not a semantic version: ${JSON.stringify(version)}`);
  // [file, how many "version" fields it must have at least]
  const files = [['.claude-plugin/plugin.json', 1], ['.claude-plugin/marketplace.json', 1], ['package.json', 1]];
  const updates = files.map(([rel, min]) => {
    const file = path.join(root, rel);
    const { text, count } = replaceVersions(fs.readFileSync(file, 'utf8'), version);
    const found = versionsOf(JSON.parse(text));
    if (count < min || found.length !== count || found.some(v => v !== version)) {
      throw new Error(`${rel}: unexpected "version" fields (${count} replaced, ${found.length} in the JSON)`);
    }
    return [file, text, rel, count];
  });
  for (const [file, text] of updates) fs.writeFileSync(file, text);
  return updates.map(([, , rel, count]) => `${rel} (${count})`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const rootIdx = args.indexOf('--root');
  const root = rootIdx !== -1 ? path.resolve(args[rootIdx + 1]) : path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
  const version = args.find((a, i) => !a.startsWith('--') && (rootIdx === -1 || i !== rootIdx + 1));
  try {
    console.log(`version ${version}: ${setVersion(root, version ?? '').join(', ')}`);
  } catch (e) {
    console.error(`set-version: ${e.message}`);
    process.exitCode = 1;
  }
}
