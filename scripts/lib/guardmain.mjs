// Hook handling for guard.mjs, kept out of the entry script so guard.mjs can load it inside a try.
import os from 'node:os';
import path from 'node:path';
import { decide, formatReason, scanSummary, originToComponentId } from './guardcore.mjs';
import { findOrigin } from './origin.mjs';
import { dataDirPath } from './datadir.mjs';
import { loadAllowlist, isFindingAllowed } from './allowlist.mjs';
import { escapeInvisible, truncate } from './text.mjs';
import { isCodexInput, handleCodex } from './codex/guardpolicy.mjs';

const safe = s => (s == null ? null : truncate(escapeInvisible(String(s)), 200));
const originName = o => (o ? o.skill ?? o.mcpPlugin ?? null : null);
const SKIPPED = () => scanSummary({ incomplete: true });

/** Missing, unreadable or blocked data dir -> empty allowlist (never an exception). */
function readAllowlist(dir) {
  try { return loadAllowlist(dir); } catch { return { version: 1, entries: [] }; }
}

/**
 * Scan only the attributed component. Every step checks `deadline` (the walks are synchronous, so the
 * budget is cooperative): past it, the summary says the check was skipped.
 */
async function checkComponent(origin, cwd, selfRoot, deadline) {
  if (Date.now() >= deadline) return { id: null, summary: SKIPPED() };
  const [{ discover }, { scanComponent }, { scoreComponent }, { fileMap }] = await Promise.all([
    import('./inventory.mjs'), import('./scanner.mjs'), import('./scoring.mjs'), import('./baseline.mjs'),
  ]);
  const claudeHome = path.resolve(process.env.SKILL_SENTRY_CLAUDE_HOME || path.join(os.homedir(), '.claude'));
  const homeDir = path.resolve(process.env.SKILL_SENTRY_HOME_DIR || os.homedir());
  const projectDir = typeof cwd === 'string' && cwd ? path.resolve(cwd) : undefined;
  // Skill folders are not walked here: only the attributed component is scanned below.
  const { components } = discover({ claudeHome, homeDir, projectDir, selfRoot, deadline, skillFiles: false });
  const id = originToComponentId(origin, components);
  if (!id) return { id: null, summary: Date.now() >= deadline ? SKIPPED() : null };
  if (Date.now() >= deadline) return { id, summary: SKIPPED() };
  const r = scanComponent(components.find(c => c.id === id), { deadline });
  if (r.incomplete || Date.now() >= deadline) return { id, summary: SKIPPED() };
  const al = readAllowlist(dataDirPath());
  const sha = fileMap(r); // same keys as the audit, including the "<config>" pseudo-file
  const active = r.findings.filter(f => !isFindingAllowed(al, { componentId: id, ruleId: f.ruleId, file: f.file, sha256: sha[f.file] }));
  const s = scoreComponent(active);
  return { id, summary: scanSummary({ incomplete: false, verdict: s.verdict, score: s.score, count: active.length }) };
}

/**
 * Handle one PreToolUse payload (Ruling L1): the decision is written before the log line, `deny` never
 * waits for a component check, and `ask` runs the check only until `deadline` (epoch ms).
 * @param {{ raw: string, selfRoot: string, deadline: number, write: (s: string) => void, log: (entry: object) => void }} io
 */
export async function handle({ raw, selfRoot, deadline, write, log }) {
  let input;
  try {
    input = JSON.parse(raw);
  } catch {
    // Fixed message: parser errors may echo input (which can include file content).
    log({ decision: 'error', error: 'malformed stdin' });
    return;
  }
  if (!input || typeof input !== 'object' || Array.isArray(input) || typeof input.tool_name !== 'string') return;
  // OpenAI Codex (Ruling R6): its own tiered policy, since Codex has no "ask".
  if (isCodexInput(input)) {
    await handleCodex({ input, selfRoot, write, log, deadline });
    return;
  }

  const toolName = input.tool_name;
  // Path only: the decision must not depend on the data dir existing or being creatable (Ruling J).
  const dir = dataDirPath();
  let originMemo;
  const origin = () => (originMemo === undefined ? (originMemo = findOrigin(input.transcript_path, undefined, toolName)) : originMemo);
  // Lazy: the allowlist file is read only when a critical match is about to be denied.
  const allowlist = () => readAllowlist(dir);

  const d = decide({ toolName, toolInput: input.tool_input, origin, allowlist, selfRoot, dataDir: dir, cwd: input.cwd });
  if (d.decision === 'none') return;

  const o = origin();
  let label = originName(o);
  let summary = null;
  if (d.decision === 'ask' && o) {
    try {
      const c = await checkComponent(o, input.cwd, selfRoot, deadline);
      if (c.id) label = c.id;
      summary = c.summary;
    } catch {
      summary = 'component check unavailable';
    }
  }

  if (d.decision === 'deny' || d.decision === 'ask') {
    write(JSON.stringify({
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: d.decision,
        permissionDecisionReason: formatReason(d, label, summary),
      },
    }));
  }
  log({ tool: safe(toolName), ruleId: d.ruleId, severity: d.severity, snippet: safe(d.snippet), origin: safe(label), decision: d.decision });
}
