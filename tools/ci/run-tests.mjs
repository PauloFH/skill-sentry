#!/usr/bin/env node
// CI entry for the unit suite: runs `npm test` (the same command as locally) with the TAP reporter, echoes the
// output, lists every skipped test in the job summary and fails when a skip looks like a missing git tag or
// history (the known-release tests need `git archive v0.1.1`, so a checkout without tags must fail the job instead
// of silently skipping). CI-only tooling: never imported by scripts/.
import { spawn } from 'node:child_process';
import fs from 'node:fs';

// A skip whose name or reason mentions one of these means the checkout lacks tags or history.
const FORBIDDEN_SKIP = /\b(tags?|git archive|fetch-depth|shallow|v\d+\.\d+\.\d+)\b/i;

// `npm test` passes the arguments after `--` on to `node --test` (tools/test.mjs). A fixed command string, so the
// shell (needed for npm.cmd on Windows) sees no outside input.
const child = spawn('npm test -- --test-reporter=tap', { shell: true, stdio: ['ignore', 'pipe', 'inherit'] });
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
const ran = /^# tests (\d+)/m.exec(tap)?.[1];

const lines = [`### Unit tests (${process.platform}, node ${process.version}): ${ran ?? '?'} tests, ${skips.length} skipped`, '',
  ...skips.map(s => `- skipped: ${s.name}${s.reason ? ` (${s.reason})` : ''}`)];
console.log('\n' + lines.join('\n'));
if (process.env.GITHUB_STEP_SUMMARY) {
  try { fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, lines.join('\n') + '\n'); } catch { /* best effort */ }
}
for (const s of bad) console.log(`::error::test skipped because of missing tags or history: ${s.name} ${s.reason}`);
if (ran === undefined) console.log('::error::no TAP summary from npm test');
process.exitCode = bad.length || ran === undefined ? 1 : (code ?? 1);
