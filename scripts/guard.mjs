#!/usr/bin/env node
// skill-sentry PreToolUse guard. Reads the hook JSON on stdin; prints a deny/ask decision or nothing.
// Fails open: any internal error -> line in guard.log, exit 0, no stdout.
// Env: SKILL_SENTRY_DATA_DIR, SKILL_SENTRY_CLAUDE_HOME, SKILL_SENTRY_HOME_DIR (same as scan.mjs).
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide, formatReason, scanSummary, originToComponentId } from './lib/guardcore.mjs';
import { findOrigin } from './lib/origin.mjs';
import { dataDir } from './lib/datadir.mjs';
import { loadAllowlist, isFindingAllowed } from './lib/allowlist.mjs';
import { escapeInvisible, truncate } from './lib/text.mjs';

// Ruling D: selfRoot is the directory containing scripts/.
const selfRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SCAN_BUDGET_MS = 2000;
const LOG_MAX_BYTES = 1024 * 1024;

const safe = s => (s == null ? null : truncate(escapeInvisible(String(s)), 200));

function appendLog(entry) {
  try {
    const file = path.join(dataDir(), 'guard.log');
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

/** Scan only the attributed component within the time budget. */
async function checkComponent(origin, cwd) {
  const deadline = Date.now() + SCAN_BUDGET_MS;
  const [{ discover }, { scanComponent }, { scoreComponent }] = await Promise.all([
    import('./lib/inventory.mjs'), import('./lib/scanner.mjs'), import('./lib/scoring.mjs'),
  ]);
  const claudeHome = path.resolve(process.env.SKILL_SENTRY_CLAUDE_HOME || path.join(os.homedir(), '.claude'));
  const homeDir = path.resolve(process.env.SKILL_SENTRY_HOME_DIR || os.homedir());
  const projectDir = typeof cwd === 'string' && cwd ? path.resolve(cwd) : undefined;
  const { components } = discover({ claudeHome, homeDir, projectDir, selfRoot });
  const id = originToComponentId(origin, components);
  if (!id) return { id: null, summary: null };
  if (Date.now() >= deadline) return { id, summary: scanSummary({ incomplete: true }) };
  const component = components.find(c => c.id === id);
  const r = scanComponent(component, { deadline });
  if (r.incomplete) return { id, summary: scanSummary({ incomplete: true }) };
  const al = loadAllowlist(dataDir());
  const sha = Object.fromEntries(r.files.map(f => [f.path, f.sha256]));
  const active = r.findings.filter(f => !isFindingAllowed(al, { componentId: id, ruleId: f.ruleId, file: f.file, sha256: sha[f.file] }));
  const s = scoreComponent(active);
  return { id, summary: scanSummary({ incomplete: false, verdict: s.verdict, score: s.score, count: active.length }) };
}

const originName = o => (o ? o.skill ?? o.mcpPlugin ?? null : null);

async function main() {
  const raw = await readStdin();
  let input;
  try {
    input = JSON.parse(raw);
  } catch {
    // Fixed message: parser errors may echo input (which can include file content).
    appendLog({ decision: 'error', error: 'malformed stdin' });
    return;
  }
  if (!input || typeof input !== 'object' || Array.isArray(input) || typeof input.tool_name !== 'string') return;

  const toolName = input.tool_name;
  const dir = dataDir();
  let originMemo;
  const origin = () => (originMemo === undefined ? (originMemo = findOrigin(input.transcript_path, undefined, toolName)) : originMemo);
  // Lazy: the allowlist file is read only when a critical match is about to be denied.
  const allowlist = () => loadAllowlist(dir);

  const d = decide({ toolName, toolInput: input.tool_input, origin, allowlist, selfRoot, dataDir: dir, cwd: input.cwd });
  if (d.decision === 'none') return;

  const o = origin();
  let label = originName(o);
  let summary = null;
  if ((d.decision === 'deny' || d.decision === 'ask') && o) {
    try {
      const c = await checkComponent(o, input.cwd);
      if (c.id) label = c.id;
      summary = c.summary;
    } catch {
      summary = scanSummary({ incomplete: true });
    }
  }

  appendLog({ tool: safe(toolName), ruleId: d.ruleId, severity: d.severity, snippet: safe(d.snippet), origin: safe(label), decision: d.decision });
  if (d.decision === 'deny' || d.decision === 'ask') {
    process.stdout.write(JSON.stringify({
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: d.decision,
        permissionDecisionReason: formatReason(d, label, summary),
      },
    }));
  }
}

main().catch(e => {
  appendLog({ decision: 'error', error: safe(e && e.message ? e.message : e) });
}).finally(() => {
  process.exitCode = 0;
});
