#!/usr/bin/env node
// Dev tool: runs the test suite (`npm test`). Not part of the plugin runtime: nothing under skills/audit/scripts/ imports it.
// `node --test test/` worked on Node 18, but Node 22 reads its arguments as file or glob patterns and no longer
// accepts a directory; a quoted glob is not expanded by Node 18 or by cmd.exe. So the test files are listed here
// and passed by name, which works on every Node version and OS. Extra arguments go to `node --test` first
// (for example `npm test -- --test-name-pattern=P3`).
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const dir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'test');
const files = fs.readdirSync(dir).filter(f => f.endsWith('.test.mjs')).sort().map(f => path.join(dir, f));
if (!files.length) {
  process.stderr.write(`no *.test.mjs files in ${dir}\n`);
  process.exit(1);
}
const r = spawnSync(process.execPath, ['--test', ...process.argv.slice(2), ...files], { stdio: 'inherit' });
process.exit(r.status ?? 1);
