#!/usr/bin/env node
// skill-sentry PreToolUse guard. Reads the hook JSON on stdin; prints a deny/ask decision or nothing.
// Fails open: any internal error -> line in guard.log, exit 0, no stdout.
// Env: SKILL_SENTRY_DATA_DIR, SKILL_SENTRY_CLAUDE_HOME, SKILL_SENTRY_HOME_DIR (same as scan.mjs).
// Static imports are Node built-ins only, so a project module that fails to load still fails open:
// the decision logic is loaded with a dynamic import inside the error handling below.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

// Ruling L1: the ask-path component check must finish within 1500 ms of process start (module loading
// included); the 5 s hook timeout would otherwise discard the decision.
const DEADLINE = performance.timeOrigin + 1500;
const LOG_MAX_BYTES = 1024 * 1024;

/** Creates the data dir on demand; any failure is swallowed and never affects the decision (Ruling J). */
function appendLog(entry) {
  try {
    const dir = process.env.SKILL_SENTRY_DATA_DIR || path.join(os.homedir(), '.claude', 'skill-sentry');
    fs.mkdirSync(dir, { recursive: true });
    const file = path.join(dir, 'guard.log');
    try {
      if (fs.statSync(file).size > LOG_MAX_BYTES) fs.renameSync(file, file + '.1');
    } catch { /* missing log or rotation failure: keep appending */ }
    fs.appendFileSync(file, JSON.stringify({ ts: new Date().toISOString(), ...entry }) + '\n');
  } catch { /* logging must never break the guard */ }
}

function readStdin() {
  return new Promise((resolve, reject) => {
    const chunks = [];
    process.stdin.on('data', c => chunks.push(c));
    process.stdin.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    process.stdin.on('error', reject);
  });
}

async function main() {
  const [raw, { handle }, { roots }] = await Promise.all([readStdin(), import('./lib/guardmain.mjs'), import('./lib/roots.mjs')]);
  // Ruling D: selfRoot is the plugin root (the directory containing skills/audit/scripts/), else the skill root.
  // Ruling M: the read-only self invocations are the scripts next to this file (`<skillRoot>/scripts/`).
  const { skillRoot, pluginRoot } = roots(import.meta.url);
  const selfRoot = pluginRoot ?? skillRoot;
  await handle({ raw, selfRoot, selfSkill: skillRoot, deadline: DEADLINE, write: s => process.stdout.write(s), log: appendLog });
}

main().catch(e => {
  // Printable ASCII only, capped: the message may quote attacker-controlled input.
  appendLog({ decision: 'error', error: String(e && e.message ? e.message : e).replace(/[^\x20-\x7e]/g, '?').slice(0, 200) });
}).finally(() => {
  process.exitCode = 0;
});
