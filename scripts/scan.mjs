#!/usr/bin/env node
// skill-sentry scan CLI. Env: SKILL_SENTRY_DATA_DIR (data dir), SKILL_SENTRY_CLAUDE_HOME (default ~/.claude),
// SKILL_SENTRY_HOME_DIR (default os.homedir(); where ~/.claude.json is read from).
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { discover } from './lib/inventory.mjs';
import { scanComponent } from './lib/scanner.mjs';
import { loadBaseline, baselineLoadError, saveBaseline, diffBaseline } from './lib/baseline.mjs';
import { loadAllowlist, allowlistLoadError } from './lib/allowlist.mjs';
import { dataDir } from './lib/datadir.mjs';
import { buildReport, renderMarkdown } from './lib/report.mjs';

// Ruling D: selfRoot is the directory containing scripts/.
const selfRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SCAN_BUDGET_MS = 120_000;

const USAGE = `usage: node scan.mjs [--json] [--path <dir>] [--component <id>] [--diff-only] [--update-baseline] [--claude-home <dir>] [--project <dir>]`;

function parseArgs(argv) {
  const o = { json: false, diffOnly: false, updateBaseline: false };
  const withValue = { '--path': 'path', '--component': 'component', '--claude-home': 'claudeHome', '--project': 'project' };
  const flags = { '--json': 'json', '--diff-only': 'diffOnly', '--update-baseline': 'updateBaseline' };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (Object.hasOwn(flags, a)) o[flags[a]] = true;
    else if (Object.hasOwn(withValue, a)) {
      const v = argv[++i];
      if (v === undefined || v.startsWith('--')) return { error: `missing value for ${a}` };
      o[withValue[a]] = v;
    } else return { error: `unknown argument: ${a}` };
  }
  return o;
}

function skillspectorOnPath() {
  const names = ['skillspector', 'skillspector.exe', 'skillspector.cmd'];
  for (const dir of (process.env.PATH ?? '').split(path.delimiter)) {
    if (dir && names.some(n => fs.existsSync(path.join(dir, n)))) return true;
  }
  return false;
}

function pathComponent(dir) {
  const root = path.resolve(dir);
  const isPlugin = fs.existsSync(path.join(root, '.claude-plugin')) || fs.existsSync(path.join(root, 'hooks'));
  return { id: `path:${path.basename(root)}`, kind: isPlugin ? 'plugin' : 'skill', name: path.basename(root), scope: 'external', root, meta: {} };
}

const opts = parseArgs(process.argv.slice(2));
if (opts.error) {
  process.stderr.write(`${opts.error}\n${USAGE}\n`);
  process.exit(2);
}
if (opts.path && !(fs.existsSync(opts.path) && fs.statSync(opts.path).isDirectory())) {
  process.stderr.write(`--path is not a directory: ${opts.path}\n${USAGE}\n`);
  process.exit(2);
}

const claudeHome = path.resolve(opts.claudeHome ?? process.env.SKILL_SENTRY_CLAUDE_HOME ?? path.join(os.homedir(), '.claude'));
const homeDir = path.resolve(process.env.SKILL_SENTRY_HOME_DIR ?? os.homedir());
const projectDir = path.resolve(opts.project ?? process.cwd());
const dir = dataDir();
const deadline = Date.now() + SCAN_BUDGET_MS;
const problems = [];
const meta = { version: JSON.parse(fs.readFileSync(path.join(selfRoot, 'package.json'), 'utf8')).version };

let components;
if (opts.path) {
  components = [pathComponent(opts.path)];
  if (skillspectorOnPath()) meta.skillspectorAvailable = true;
} else {
  const inv = discover({ claudeHome, homeDir, projectDir, selfRoot });
  // CONFIG_UNREADABLE findings are surfaced as report-level problems (not attached to a component).
  for (const f of inv.configFindings) problems.push(`${f.ruleId}: ${f.file}: ${f.snippet}`);
  components = inv.components;
  if (opts.component) {
    components = components.filter(c => c.id === opts.component);
    if (!components.length) problems.push(`component not found: ${opts.component}`);
  }
}

let results = components.map(c => scanComponent(c, { deadline }));

const allowErr = allowlistLoadError(dir);
if (allowErr) problems.push(`allowlist.json: ${allowErr}`);
const baseErr = baselineLoadError(dir);
if (baseErr) problems.push(`baseline.json: ${baseErr}`);

// Baseline: never read or written for --path; never written for --component.
let diff = null;
if (!opts.path) {
  const prev = loadBaseline(dir);
  diff = diffBaseline(prev, results);
  if (opts.component) diff.removed = [];
  const exists = fs.existsSync(path.join(dir, 'baseline.json'));
  if (!opts.component && (opts.updateBaseline || !exists)) saveBaseline(dir, results);
  if (opts.diffOnly) {
    const keep = new Set([...diff.added, ...diff.changed.map(c => c.id)]);
    results = results.filter(r => keep.has(r.component.id));
  }
}

const report = buildReport({ results, diff, allowlist: loadAllowlist(dir), meta: { ...meta, problems } });

if (opts.json) {
  process.stdout.write(JSON.stringify(report, null, 2) + '\n');
} else {
  const reports = path.join(dir, 'reports');
  fs.mkdirSync(reports, { recursive: true });
  const stamp = report.generatedAt.replaceAll(':', '-');
  const jsonFile = path.join(reports, `${stamp}.json`);
  const mdFile = path.join(reports, `${stamp}.md`);
  fs.writeFileSync(jsonFile, JSON.stringify(report, null, 2) + '\n');
  fs.writeFileSync(mdFile, renderMarkdown(report) + '\n');
  const bv = report.summary.byVerdict;
  console.log(jsonFile);
  console.log(mdFile);
  console.log(`skill-sentry: ${report.summary.components} components (malicious ${bv.malicious}, suspicious ${bv.suspicious}, review ${bv.review}, ok ${bv.ok})`);
}
process.exitCode = 0; // let stdout drain; do not process.exit()
