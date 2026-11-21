#!/usr/bin/env node
// skill-sentry scan CLI. Env: SKILL_SENTRY_DATA_DIR (data dir), SKILL_SENTRY_CLAUDE_HOME (default ~/.claude),
// SKILL_SENTRY_HOME_DIR (default os.homedir(); where ~/.claude.json and ~/.codex are read from),
// SKILL_SENTRY_CODEX_HOME (scan this Codex home instead of $CODEX_HOME / ~/.codex),
// SKILL_SENTRY_NO_WSL=1 (do not look for Codex homes inside WSL distributions; the --no-wsl flag does the same).
// Flags: --agent claude|codex|all (default all), --codex-home <dir> (repeatable, added to the default home).
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { discover } from './lib/inventory.mjs';
import { codexHomes } from './lib/codex/homes.mjs';
import { discoverCodex } from './lib/codex/inventory.mjs';
import { scanComponent } from './lib/scanner.mjs';
import { loadBaseline, baselineLoadError, saveBaseline, diffBaseline, fileMap } from './lib/baseline.mjs';
import { loadAllowlist, allowlistLoadError, addAllowEntry } from './lib/allowlist.mjs';
import { dataDir } from './lib/datadir.mjs';
import { buildReport, renderMarkdown } from './lib/report.mjs';
import { untrusted } from './lib/text.mjs';
import { roots } from './lib/roots.mjs';
import { loadSelfManifest } from './lib/selfcopy.mjs';

// Ruling D: selfRoot is the plugin root (the directory containing skills/audit/scripts/), else the skill root.
const { skillRoot, pluginRoot } = roots(import.meta.url);
const selfRoot = pluginRoot ?? skillRoot;
const SCAN_BUDGET_MS = 120_000;

/**
 * The report version: the running self-manifest's (it exists in both layouts and carries the release version), else
 * the plugin's package.json, else 'unknown'. Never throws.
 */
function selfVersion() {
  const m = loadSelfManifest();
  if (m) return m.version;
  try {
    const v = JSON.parse(fs.readFileSync(path.join(selfRoot, 'package.json'), 'utf8')).version;
    if (typeof v === 'string' && v) return v;
  } catch { /* standalone install or unreadable */ }
  return 'unknown';
}

const USAGE = `usage: node scan.mjs [--json] [--path <dir>] [--component <id>] [--diff-only] [--update-baseline] [--claude-home <dir>] [--project <dir>]
                    [--agent claude|codex|all] [--codex-home <dir>]... [--no-wsl]
       node scan.mjs --allow <componentId> <ruleId> <file> [--reason <text>]`;

function parseArgs(argv) {
  const o = { json: false, diffOnly: false, updateBaseline: false, noWsl: false, agent: 'all', codexHomes: [] };
  const withValue = {
    '--path': 'path', '--component': 'component', '--claude-home': 'claudeHome', '--project': 'project', '--reason': 'reason',
    '--agent': 'agent', '--codex-home': 'codexHomes',
  };
  const flags = { '--json': 'json', '--diff-only': 'diffOnly', '--update-baseline': 'updateBaseline', '--no-wsl': 'noWsl' };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (Object.hasOwn(flags, a)) o[flags[a]] = true;
    else if (a === '--allow') {
      const v = argv.slice(i + 1, i + 4);
      if (v.length < 3 || v.some(x => x.startsWith('--'))) return { error: '--allow needs <componentId> <ruleId> <file>' };
      o.allow = v;
      i += 3;
    }
    else if (Object.hasOwn(withValue, a)) {
      const v = argv[++i];
      if (v === undefined) return { error: `missing value for ${a}` };
      // Ruling L3 (defense in depth): a value never starts with `-` nor hides a flag after whitespace.
      if (v.startsWith('-') || /\s-/.test(v)) return { error: `invalid value for ${a}: ${untrusted(v)}` };
      if (a === '--codex-home') o.codexHomes.push(v);
      else if (a === '--agent') {
        if (!['claude', 'codex', 'all'].includes(v)) return { error: `invalid value for --agent: ${untrusted(v)} (expected claude, codex or all)` };
        o.agent = v;
      } else o[withValue[a]] = v;
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
const meta = { version: selfVersion() };

let components;
if (opts.path) {
  components = [pathComponent(opts.path)];
  if (skillspectorOnPath()) meta.skillspectorAvailable = true;
} else {
  // Same deadline as the scan: skills the inventory could not walk in time are reported as incomplete.
  // --agent claude never looks at a Codex home; --agent codex never reads the Claude homes.
  const none = { components: [], configFindings: [] };
  const inv = opts.agent === 'codex' ? none : discover({ claudeHome, homeDir, projectDir, selfRoot, deadline });
  let cx = none;
  if (opts.agent !== 'claude') {
    const homes = codexHomes({
      env: process.env, homeDir, platform: process.platform, deadline, explicit: opts.codexHomes,
      includeWsl: !opts.noWsl && process.env.SKILL_SENTRY_NO_WSL !== '1', problems,
    });
    cx = discoverCodex({ homes, projectDir, selfRoot, deadline });
  }
  // CONFIG_UNREADABLE findings are surfaced as report-level problems (not attached to a component).
  for (const f of [...inv.configFindings, ...cx.configFindings]) problems.push(`${f.ruleId}: ${f.file}: ${f.snippet}`);
  components = [...inv.components, ...cx.components];
  if (opts.component) {
    // Accept the id as the report shows it (escaped) as well as the raw id.
    const want = opts.component;
    const exact = components.filter(c => c.id === want);
    components = exact.length ? exact : components.filter(c => untrusted(c.id) === want);
    if (!components.length) problems.push(`component not found: ${want}`);
  }
}

let results = components.map(c => scanComponent(c, { deadline }));

if (opts.allow) {
  // Only finding-type entries are created here; command-type (critical) entries are never created by this flag.
  // The report shows ids and paths escaped (untrusted()); both that form and the raw one are accepted,
  // and the entry stores the raw value so it matches later scans.
  const [idArg, ruleId, fileArg] = opts.allow;
  const found = results.find(r => r.component.id === idArg) ?? results.find(r => untrusted(r.component.id) === idArg);
  if (!found) {
    process.stderr.write(`component not found: ${untrusted(idArg)}\n`);
    process.exit(2);
  }
  const componentId = found.component.id;
  const files = fileMap(found);
  const file = Object.hasOwn(files, fileArg) ? fileArg : Object.keys(files).find(f => untrusted(f) === fileArg);
  if (file === undefined) {
    process.stderr.write(`file not found in component ${untrusted(componentId)}: ${untrusted(fileArg)}\n`);
    process.exit(2);
  }
  const entry = { type: 'finding', componentId, ruleId, file, sha256: files[file], reason: opts.reason ?? 'user approved', addedAt: new Date().toISOString() };
  addAllowEntry(dir, entry);
  const shown = { ...entry, componentId: untrusted(componentId), file: untrusted(file), ruleId: untrusted(ruleId), reason: untrusted(entry.reason) };
  await new Promise(resolve => process.stdout.write(JSON.stringify(shown, null, 2) + '\n', resolve));
  process.exit(0);
}

const allowErr = allowlistLoadError(dir);
if (allowErr) problems.push(`allowlist.json: ${allowErr}`);
const baseErr = baselineLoadError(dir);
if (baseErr) problems.push(`baseline.json: ${baseErr}`);

// Baseline: never read or written for --path; never written for --component.
let diff = null;
if (!opts.path) {
  const prev = loadBaseline(dir);
  diff = diffBaseline(prev, results);
  // A partial scan (one component or one agent) cannot say what was removed and must not rewrite the baseline.
  const partial = !!opts.component || opts.agent !== 'all';
  if (partial) diff.removed = [];
  const exists = fs.existsSync(path.join(dir, 'baseline.json'));
  if (!partial && (opts.updateBaseline || !exists)) saveBaseline(dir, results);
  if (opts.diffOnly) {
    const keep = new Set([...diff.added, ...diff.changed.map(c => c.id)]);
    results = results.filter(r => keep.has(r.component.id));
  }
}

const report = buildReport({ results, diff, allowlist: loadAllowlist(dir), meta: { ...meta, problems } });

// Every run keeps reports/<ts>.{json,md} (spec 6.1); --json also prints the report.
const reports = path.join(dir, 'reports');
const stamp = report.generatedAt.replaceAll(':', '-');
const jsonFile = path.join(reports, `${stamp}.json`);
const mdFile = path.join(reports, `${stamp}.md`);
const writeReports = () => {
  fs.mkdirSync(reports, { recursive: true });
  fs.writeFileSync(jsonFile, JSON.stringify(report, null, 2) + '\n');
  fs.writeFileSync(mdFile, renderMarkdown(report) + '\n');
};

if (opts.json) {
  // A report file that cannot be written must not cost the caller the JSON on stdout.
  try { writeReports(); } catch (e) { process.stderr.write(`could not write report files: ${untrusted(e.message)}\n`); }
  process.stdout.write(JSON.stringify(report, null, 2) + '\n');
} else {
  writeReports();
  const bv = report.summary.byVerdict;
  console.log(jsonFile);
  console.log(mdFile);
  console.log(`skill-sentry: ${report.summary.components} components (malicious ${bv.malicious}, suspicious ${bv.suspicious}, review ${bv.review}, ok ${bv.ok})`);
}
process.exitCode = 0; // let stdout drain; do not process.exit()
