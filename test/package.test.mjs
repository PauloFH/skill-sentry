import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { tmpFactory, copyTree } from './helpers/tmp.mjs';

const tmpDir = tmpFactory('ss-');

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SCAN = path.join(ROOT, 'skills', 'audit', 'scripts', 'scan.mjs');
const readJson = rel => JSON.parse(fs.readFileSync(path.join(ROOT, rel), 'utf8'));
const MATCHER = 'Bash|PowerShell|Read|Write|Edit|NotebookEdit|Grep|Glob|WebFetch|mcp__.*';

test('manifests parse and carry the expected identity', () => {
  const plugin = readJson('.claude-plugin/plugin.json');
  const market = readJson('.claude-plugin/marketplace.json');
  readJson('hooks/hooks.json');
  assert.equal(plugin.name, 'skill-sentry');
  // Versions are set by the release pipeline: the three version fields only have to agree.
  assert.match(plugin.version, /^\d+\.\d+\.\d+$/);
  assert.equal(readJson('package.json').version, plugin.version, 'package.json version matches plugin.json');
  // The self-manifest is written last in every release (tools/ci/write-manifest.mjs): same version, and committed.
  const manifest = readJson('skills/audit/scripts/lib/selfmanifest.json');
  assert.deepEqual(Object.keys(manifest), ['version', 'files']);
  assert.equal(manifest.version, plugin.version, 'selfmanifest.json version matches plugin.json');
  assert.equal(plugin.license, 'MIT');
  assert.equal(plugin.repository, 'https://github.com/PauloFH/skill-sentry');
  assert.equal(plugin.homepage, 'https://github.com/PauloFH/skill-sentry');
  assert.ok(plugin.author?.name);
  assert.equal(market.$schema, 'https://anthropic.com/claude-code/marketplace.schema.json');
  assert.equal(market.name, 'skill-sentry');
  assert.ok(market.owner?.name);
  assert.equal(market.plugins.length, 1);
  const p = market.plugins[0];
  assert.equal(p.name, 'skill-sentry');
  assert.equal(p.source, './');
  assert.equal(p.version, plugin.version, 'marketplace.json version matches plugin.json');
  assert.equal(p.category, 'security');
  for (const f of ['plugin.json', 'marketplace.json']) {
    assert.ok(!/email|@[a-z0-9-]+\.[a-z]/i.test(fs.readFileSync(path.join(ROOT, '.claude-plugin', f), 'utf8').replace(/https?:\/\/\S+/g, '')), `${f} has no email`);
  }
});

test('npm test runs every test file by name (Node 22 no longer accepts a directory for --test)', () => {
  const script = readJson('package.json').scripts.test;
  assert.equal(script, 'node tools/test.mjs');
  const runner = fs.readFileSync(path.join(ROOT, 'tools', 'test.mjs'), 'utf8');
  assert.match(runner, /\.test\.mjs/);
  assert.doesNotMatch(runner, /'--test',\s*'test\/?'/, 'no directory argument');
  // The runner sees exactly the suite's files.
  const files = fs.readdirSync(path.join(ROOT, 'test')).filter(f => f.endsWith('.test.mjs'));
  assert.ok(files.includes('package.test.mjs') && files.length >= 15, files.join(','));
});

test('hooks.json registers the guard on the exact matcher', () => {
  const h = readJson('hooks/hooks.json');
  const pre = h.hooks.PreToolUse;
  assert.equal(pre.length, 1);
  assert.equal(pre[0].matcher, MATCHER);
  assert.deepEqual(pre[0].hooks, [{ type: 'command', command: 'node "${CLAUDE_PLUGIN_ROOT}/skills/audit/scripts/guard.mjs"', timeout: 5 }]);
});

test('script paths referenced by hooks.json and the skills exist', () => {
  const h = readJson('hooks/hooks.json');
  for (const g of h.hooks.PreToolUse) {
    for (const hk of g.hooks) {
      const m = /\$\{CLAUDE_PLUGIN_ROOT\}\/([^"\s]+)/.exec(hk.command);
      assert.ok(m, hk.command);
      assert.ok(fs.statSync(path.join(ROOT, m[1])).isFile(), m[1]);
    }
  }
  for (const [name, script] of [['audit', 'scan.mjs'], ['harden', 'harden.mjs']]) {
    const skillDir = path.join(ROOT, 'skills', name);
    const text = fs.readFileSync(path.join(skillDir, 'SKILL.md'), 'utf8');
    const refs = [...text.matchAll(/<(?:base directory|skill dir)>\/([^"\s`]+\.mjs)/g)].map(m => m[1]);
    assert.ok(refs.some(r => r.endsWith(`scripts/${script}`)), `${name} references scripts/${script}`);
    for (const r of refs) assert.ok(fs.statSync(path.resolve(skillDir, r)).isFile(), `${name}: ${r}`);
  }
});

test('runtime code lives under skills/audit/scripts and nothing remains in scripts/', () => {
  assert.ok(!fs.existsSync(path.join(ROOT, 'scripts')), 'scripts/ is gone');
  const h = readJson('hooks/hooks.json');
  assert.equal(h.hooks.PreToolUse[0].hooks[0].command, 'node "${CLAUDE_PLUGIN_ROOT}/skills/audit/scripts/guard.mjs"');
  for (const [name, script] of [['audit', 'scripts/scan.mjs'], ['harden', '../audit/scripts/harden.mjs']]) {
    const skillDir = path.join(ROOT, 'skills', name);
    const text = fs.readFileSync(path.join(skillDir, 'SKILL.md'), 'utf8');
    const refs = [...text.matchAll(/<(?:base directory|skill dir)>\/([^"'\s`]+)/g)].map(m => m[1]);
    assert.ok(refs.includes(script), `${name} references <skill dir>/${script}: ${refs.join(', ')}`);
    for (const r of refs) assert.ok(fs.statSync(path.resolve(skillDir, r)).isFile(), `${name}: ${r} exists`);
  }
  const runtime = path.join(ROOT, 'skills', 'audit', 'scripts');
  const walk = rel => fs.readdirSync(path.join(runtime, rel), { withFileTypes: true })
    .flatMap(e => (e.isDirectory() ? walk(path.join(rel, e.name)) : [path.join(rel, e.name)]));
  const files = fs.existsSync(runtime) ? walk('').filter(f => f.endsWith('.mjs')) : [];
  assert.ok(files.length >= 20, files.join(','));
  for (const f of files) {
    assert.doesNotMatch(fs.readFileSync(path.join(runtime, f), 'utf8'), /child_process/, `${f} imports no child_process`);
  }
});

test('release tooling names files that exist (committed assets, the release table)', () => {
  const config = fs.readFileSync(path.join(ROOT, 'tools', 'ci', 'release', 'release.config.cjs'), 'utf8');
  const assets = [.../assets: \[([^\]]*)\]/.exec(config)[1].matchAll(/'([^']+)'/g)].map(m => m[1]);
  assert.ok(assets.includes('skills/audit/scripts/lib/releases.mjs'), assets.join(', '));
  assert.ok(assets.includes('skills/audit/scripts/lib/selfmanifest.json'), assets.join(', '));
  // Prepare order: the manifest is written after every other file of the release commit changed (version,
  // KNOWN_RELEASES, CHANGELOG.md), then checked against the tree.
  const at = s => { const i = config.indexOf(s); assert.ok(i !== -1, s); return i; };
  assert.ok(at('set-version.mjs') < at('record-release.mjs'), 'set-version, then record-release');
  assert.ok(at('record-release.mjs') < at("'@semantic-release/changelog'"), 'then the changelog');
  assert.ok(at("'@semantic-release/changelog'") < at('write-manifest.mjs .'), 'then the manifest');
  assert.ok(at('write-manifest.mjs .') < at('write-manifest.mjs . --verify'), 'then its check');
  assert.ok(at('write-manifest.mjs . --verify') < at("'@semantic-release/git'"), 'all before the commit');
  for (const a of assets) assert.ok(fs.statSync(path.join(ROOT, a)).isFile(), a);
  const record = fs.readFileSync(path.join(ROOT, 'tools', 'ci', 'record-release.mjs'), 'utf8');
  const parts = [.../const RELEASES = path\.join\(ROOT, ([^)]*)\)/.exec(record)[1].matchAll(/'([^']+)'/g)].map(m => m[1]);
  assert.equal(parts.join('/'), 'skills/audit/scripts/lib/releases.mjs');
});

test('skills have name/description frontmatter and no allowed-tools or shell injection lines', () => {
  for (const name of ['audit', 'harden']) {
    const text = fs.readFileSync(path.join(ROOT, 'skills', name, 'SKILL.md'), 'utf8');
    const fm = /^---\r?\n([\s\S]*?)\r?\n---/.exec(text);
    assert.ok(fm, `${name} frontmatter`);
    assert.match(fm[1], new RegExp(`^name: ${name}$`, 'm'));
    assert.match(fm[1], /^description: .{20,}/m);
    assert.ok(!/allowed-tools/i.test(text), `${name}: no allowed-tools`);
    assert.ok(!text.includes('!`'), `${name}: no !-backtick lines`);
  }
});

test('self-scan: shipped skills, hooks and manifests pass the plugin\'s own rules', () => {
  const tmp = tmpDir('self');
  const data = tmpDir('selfdata');
  for (const d of ['skills', 'hooks', '.claude-plugin']) copyTree(path.join(ROOT, d), path.join(tmp, d));
  // The runtime code (its rules quote the very patterns they detect) is not part of this check.
  fs.rmSync(path.join(tmp, 'skills', 'audit', 'scripts'), { recursive: true });
  const r = spawnSync(process.execPath, [SCAN, '--path', tmp, '--json'], {
    encoding: 'utf8', env: { ...process.env, SKILL_SENTRY_DATA_DIR: data, SKILL_SENTRY_CODEX_HOME: tmpDir('codex'), SKILL_SENTRY_NO_WSL: '1' },
  });
  assert.equal(r.status, 0, r.stderr);
  const report = JSON.parse(r.stdout);
  const bad = report.components.flatMap(c => c.findings ?? []).map(f => `${f.ruleId} ${f.file}`);
  assert.equal(report.components[0].scannerVerdict, 'ok', `findings: ${bad.join(', ')}`);
});
