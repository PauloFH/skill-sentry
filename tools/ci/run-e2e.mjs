#!/usr/bin/env node
// CI entry for an e2e file: `node tools/ci/run-e2e.mjs <test file> <minimum test count>`. Runs it with the TAP
// reporter and fails unless it ran at least that many tests, none failed and none was skipped, so a missing opt-in
// variable (the e2e files define no tests without it) can never pass as "0 tests, 0 failures".
// CI-only tooling: never imported by scripts/.
import { spawn } from 'node:child_process';
import fs from 'node:fs';

const [file, minArg] = process.argv.slice(2);
const min = Number(minArg);
if (!file || !Number.isInteger(min) || min < 1) {
  console.error('usage: node tools/ci/run-e2e.mjs <test file> <minimum test count>');
  process.exit(2);
}
const child = spawn(process.execPath, ['--test', '--test-reporter=tap', file], { stdio: ['ignore', 'pipe', 'inherit'] });
let tap = '';
child.stdout.on('data', c => { tap += c; process.stdout.write(c); });
const code = await new Promise(resolve => child.on('close', resolve));

const count = key => Number(new RegExp(`^# ${key} (\\d+)`, 'm').exec(tap)?.[1] ?? NaN);
const [tests, fail, skipped] = [count('tests'), count('fail'), count('skipped')];
const problems = [];
if (!(tests >= min)) problems.push(`ran ${Number.isNaN(tests) ? 'no' : tests} tests, expected at least ${min}`);
if (fail !== 0) problems.push(`${Number.isNaN(fail) ? '?' : fail} failed`);
if (skipped !== 0) problems.push(`${Number.isNaN(skipped) ? '?' : skipped} skipped`);
const line = `### e2e ${file} (${process.platform}): ${tests} tests, ${fail} failed, ${skipped} skipped`;
console.log(`\n${line}`);
if (process.env.GITHUB_STEP_SUMMARY) {
  try { fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${line}\n`); } catch { /* best effort */ }
}
for (const p of problems) console.log(`::error::e2e ${file}: ${p}`);
process.exitCode = problems.length ? 1 : (code ?? 1);
