#!/usr/bin/env node
// CI entry for the unit suite: runs `node --test test/` with the TAP reporter, echoes the output, lists every
// skipped test and fails when a skip looks like a missing git tag or history (the known-release tests need
// `git archive v0.1.1`, so a shallow checkout without tags must fail the job instead of silently skipping).
// CI-only tooling: never imported by scripts/.
import { spawn } from 'node:child_process';
import fs from 'node:fs';

// A skip whose name or reason mentions one of these means the checkout lacks tags or history.
const FORBIDDEN_SKIP = /\b(tags?|git archive|fetch-depth|shallow|v\d+\.\d+\.\d+)\b/i;

// Explicit file list: `node --test test/` is not portable (Node 22 on Linux/macOS treats the argument as a
// module path and fails; Node 18 runs every .mjs under test/, helpers included). test/e2e/ is not part of it.
const files = fs.readdirSync('test').filter(f => f.endsWith('.test.mjs')).sort().map(f => `test/${f}`);
const child = spawn(process.execPath, ['--test', '--test-reporter=tap', ...files], { stdio: ['ignore', 'pipe', 'inherit'] });
let tap = '';
child.stdout.on('data', c => { tap += c; process.stdout.write(c); });
const code = await new Promise(resolve => child.on('close', resolve));

// TAP skip lines (subtests are indented): `ok 12 - <name> # SKIP <reason>`.
const skips = [];
for (const line of tap.split(/\r?\n/)) {
  const m = /^\s*ok \d+ - (.*?)\s+# SKIP\b\s*(.*)$/i.exec(line);
  if (m) skips.push({ name: m[1], reason: m[2] });
}
const bad = skips.filter(s => FORBIDDEN_SKIP.test(`${s.name} ${s.reason}`));

const lines = [`### Skipped tests (${process.platform}, node ${process.version}): ${skips.length}`, '',
  ...skips.map(s => `- ${s.name}${s.reason ? ` (${s.reason})` : ''}`)];
console.log('\n' + lines.join('\n'));
if (process.env.GITHUB_STEP_SUMMARY) {
  try { fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, lines.join('\n') + '\n'); } catch { /* best effort */ }
}
for (const s of bad) console.log(`::error::test skipped because of missing tags or history: ${s.name} ${s.reason}`);
process.exitCode = bad.length ? 1 : (code ?? 1);
