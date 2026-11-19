import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { listFiles, isSensitiveLinkTarget, rawConfigOf } from './inventory.mjs';
import { matchText, matchCommand, findInvisible } from './rules.mjs';
import { analyzeSkillMarkdown } from './skillmd.mjs';
import { classifyFile, truncate, escapeInvisible, redactSecrets, redactArgs } from './text.mjs';

/**
 * @typedef {import('./rules.mjs').Match & { file: string }} Finding
 * @typedef {{ path: string, sha256: string, kind: 'code'|'markdown'|'config'|'binary'|'other', size: number }} FileEntry
 */

const DEFAULT_MAX_FILE_BYTES = 2 * 1024 * 1024;
const CONFIG_ONLY_KINDS = new Set(['hook', 'mcp', 'statusline']);
const CONFIG_FILE = '<config>';
const LIFECYCLE = ['preinstall', 'install', 'postinstall'];

const finding = (ruleId, category, severity, file, snippet, line = 1) =>
  ({ ruleId, category, severity, line, snippet: truncate(escapeInvisible(String(snippet))), file });

/** SHA-256 of a file, read in chunks so huge files are never held in memory; stops at `deadline`. */
function hashFile(file, size, maxBytes, deadline) {
  const hash = crypto.createHash('sha256');
  if (size <= maxBytes) {
    const buf = fs.readFileSync(file);
    hash.update(buf);
    return { sha256: hash.digest('hex'), buf };
  }
  const fd = fs.openSync(file, 'r');
  try {
    const chunk = Buffer.allocUnsafe(1 << 20);
    let n;
    while ((n = fs.readSync(fd, chunk, 0, chunk.length, null)) > 0) {
      hash.update(chunk.subarray(0, n));
      if (deadline !== undefined && Date.now() >= deadline) return { sha256: null, buf: null, timedOut: true };
    }
  } finally { fs.closeSync(fd); }
  return { sha256: hash.digest('hex'), buf: null };
}

const isSkillMarkdown = rel => /(^|\/)SKILL\.md$/i.test(rel) || /(^|\/)(?:commands|agents)\/.+\.md$/i.test(rel);

/** Runner invoked without a pinned version, `npx -y`, `uvx` or `@latest`. */
function unpinnedRuntime(cmd) {
  if (/@latest\b/i.test(cmd)) return true;
  const tokens = cmd.split(/\s+/).filter(Boolean);
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i].replace(/^.*[\\/]/, '').replace(/\.(?:cmd|exe)$/i, '').toLowerCase();
    const isDlx = t === 'pnpm' && tokens[i + 1] === 'dlx';
    const isPipx = t === 'pipx' && tokens[i + 1] === 'run';
    if (!['npx', 'uvx', 'bunx'].includes(t) && !isDlx && !isPipx) continue;
    const rest = tokens.slice(i + (isDlx || isPipx ? 2 : 1));
    if (t === 'npx' && rest.some(a => a === '-y' || a === '--yes')) return true;
    if (t === 'uvx') return true;
    const pkg = rest.find(a => !a.startsWith('-'));
    if (!pkg) return true;
    if (!/@\d|==\d|@[a-z]*\d/i.test(pkg.replace(/^@/, ''))) return true;
  }
  return false;
}

/**
 * Rules run on the unredacted config (a payload placed after `--token` must still match); every
 * snippet taken from it is redacted, so credentials never reach the report or Claude.
 */
function scanConfig(c, findings) {
  const cfg = rawConfigOf(c.config);
  if (!cfg || typeof cfg !== 'object') return;
  const push = m => findings.push({ ...m, snippet: redactSecrets(m.snippet), file: CONFIG_FILE });
  const args = Array.isArray(cfg.args) ? cfg.args.map(String) : [];
  const commands = [];
  if (typeof cfg.command === 'string') commands.push([cfg.command, ...args]);
  if (typeof cfg.headersHelper === 'string') commands.push([cfg.headersHelper]);
  for (const argv of commands) {
    const cmd = argv.join(' ');
    const shown = [argv[0], ...redactArgs(argv.slice(1))].map(redactSecrets).join(' ');
    for (const m of matchCommand(cmd)) push(m);
    if (unpinnedRuntime(cmd)) findings.push(finding('SUPPLY_UNPINNED_RUNTIME', 'supply', 'medium', CONFIG_FILE, shown));
  }
  if (typeof cfg.url === 'string') {
    findings.push(finding('SUPPLY_REMOTE_MCP', 'supply', 'info', CONFIG_FILE, redactSecrets(cfg.url)));
    for (const m of matchCommand(cfg.url)) push(m);
  }
  if (typeof cfg.prompt === 'string') {
    for (const m of matchText(cfg.prompt, 'markdown')) push(m);
  }
}

/**
 * Scan one inventoried component: hash its files and collect findings.
 * @param {object} c Component
 * @param {{ maxFileBytes?: number, deadline?: number }} [opts]
 * @returns {{ component: object, files: FileEntry[], findings: Finding[], incomplete: boolean }}
 */
export function scanComponent(c, opts = {}) {
  const maxBytes = opts.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
  const { deadline } = opts;
  const files = [];
  const findings = [];
  let incomplete = false;

  // --- file list ---
  let list = [];
  let skipped = new Set();
  let outside = [];
  if (c.meta?.incomplete) incomplete = true; // inventory walk cut off by its deadline
  if (!CONFIG_ONLY_KINDS.has(c.kind)) {
    if (Array.isArray(c.files)) {
      list = c.files;
      if (Array.isArray(c.meta?.symlinksOutside)) outside = c.meta.symlinksOutside;
    } else if (c.root) {
      const r = listFiles(c.root, undefined, { deadline });
      list = r.files; skipped = r.skipped; outside = r.outside;
      if (r.timedOut) incomplete = true;
      if (r.truncated || r.timedOut) c = { ...c, meta: { ...c.meta, filesTruncated: true } };
    }
  }
  const relOf = abs => {
    let rel = c.root ? path.relative(c.root, abs).replaceAll('\\', '/') : '';
    if (!rel || rel.startsWith('../') || path.isAbsolute(rel)) rel = abs.replace(/\\/g, '/');
    return rel;
  };
  if (c.meta?.filesTruncated && !c.self) {
    findings.push(finding('SCAN_TRUNCATED', 'config', 'info', '<scan>', 'File listing was truncated by a limit; some files were not scanned'));
  }
  if (!c.self) {
    for (const o of outside) {
      const sev = isSensitiveLinkTarget(o.target) ? 'medium' : 'info';
      findings.push(finding('SCAN_SYMLINK_OUTSIDE', 'config', sev, relOf(o.path), `Link to a path outside the component was not followed: ${o.target}`));
    }
  }
  if (skipped.has('node_modules') && !c.self) {
    findings.push(finding('SUPPLY_BUNDLED_DEPS', 'supply', 'info', 'node_modules', 'node_modules present (not scanned)'));
  }

  // --- files ---
  const seenObf = new Set();
  for (const abs of list) {
    if (deadline !== undefined && Date.now() >= deadline) { incomplete = true; break; }
    const rel = relOf(abs);
    let st;
    try { st = fs.statSync(abs); } catch { continue; }
    if (!st.isFile()) continue;
    let hashed;
    try { hashed = hashFile(abs, st.size, maxBytes, deadline); } catch { continue; }
    if (hashed.timedOut) { incomplete = true; break; }
    const kind = classifyFile(rel);
    files.push({ path: rel, sha256: hashed.sha256, kind, size: st.size });
    if (c.self) continue;

    const add = m => {
      if (m.category === 'obfuscation') {
        const key = `${rel}\0${m.ruleId}`;
        if (seenObf.has(key)) return;
        seenObf.add(key);
      }
      findings.push({ ...m, file: rel });
    };

    if (kind === 'binary') {
      findings.push(finding('SUPPLY_BINARY', 'supply', /(^|\/)bin\//i.test(rel) ? 'high' : 'info', rel, `Binary file: ${rel}`));
      continue;
    }
    const skipSev = kind === 'code' || kind === 'markdown' ? 'medium' : 'info';
    if (!hashed.buf) { // over maxFileBytes: hashed only
      findings.push(finding('SCAN_SKIPPED_LARGE', 'config', skipSev, rel, `File exceeds ${maxBytes} bytes and was not scanned`));
      continue;
    }
    if (hashed.buf.subarray(0, 4096).includes(0)) { // not text
      findings.push(finding('SCAN_NOT_TEXT', 'config', skipSev, rel, 'File contains NUL bytes and was not scanned'));
      continue;
    }
    const text = hashed.buf.toString('utf8');

    if (rel === 'package.json') {
      try {
        const scripts = JSON.parse(text.replace(/^﻿/, '')).scripts;
        for (const k of LIFECYCLE) {
          if (scripts && typeof scripts[k] === 'string') findings.push(finding('SUPPLY_INSTALL_SCRIPT', 'supply', 'medium', rel, `${k}: ${scripts[k]}`));
        }
      } catch { /* unparsable package.json: text rules still apply */ }
    }
    for (const m of matchText(text, kind)) add(m);
    for (const m of findInvisible(text, kind)) add(m);
    if (kind === 'markdown' && isSkillMarkdown(rel)) for (const m of analyzeSkillMarkdown(text)) add(m);
  }

  // --- config (hooks, MCP servers, statusLine, monitors) ---
  if (!c.self) scanConfig(c, findings);

  return { component: c, files, findings, incomplete };
}
