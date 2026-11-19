import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SCAN = path.join(ROOT, 'scripts', 'scan.mjs');
const readJson = rel => JSON.parse(fs.readFileSync(path.join(ROOT, rel), 'utf8'));
const MATCHER = 'Bash|PowerShell|Read|Write|Edit|NotebookEdit|Grep|Glob|WebFetch|mcp__.*';

test('manifests parse and carry the expected identity', () => {
  const plugin = readJson('.claude-plugin/plugin.json');
  const market = readJson('.claude-plugin/marketplace.json');
  readJson('hooks/hooks.json');
  assert.equal(plugin.name, 'skill-sentry');
  assert.equal(plugin.version, '0.1.0');
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
  assert.equal(p.version, '0.1.0');
  assert.equal(p.category, 'security');
  for (const f of ['plugin.json', 'marketplace.json']) {
    assert.ok(!/email|@[a-z0-9-]+\.[a-z]/i.test(fs.readFileSync(path.join(ROOT, '.claude-plugin', f), 'utf8').replace(/https?:\/\/\S+/g, '')), `${f} has no email`);
  }
});

test('hooks.json registers the guard on the exact matcher', () => {
  const h = readJson('hooks/hooks.json');
  const pre = h.hooks.PreToolUse;
  assert.equal(pre.length, 1);
  assert.equal(pre[0].matcher, MATCHER);
  assert.deepEqual(pre[0].hooks, [{ type: 'command', command: 'node "${CLAUDE_PLUGIN_ROOT}/scripts/guard.mjs"', timeout: 5 }]);
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
    const refs = [...text.matchAll(/<base directory>\/([^"\s`]+\.mjs)/g)].map(m => m[1]);
    assert.ok(refs.some(r => r.endsWith(`scripts/${script}`)), `${name} references scripts/${script}`);
    for (const r of refs) assert.ok(fs.statSync(path.resolve(skillDir, r)).isFile(), `${name}: ${r}`);
  }
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
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ss-self-'));
  const data = fs.mkdtempSync(path.join(os.tmpdir(), 'ss-selfdata-'));
  for (const d of ['skills', 'hooks', '.claude-plugin']) fs.cpSync(path.join(ROOT, d), path.join(tmp, d), { recursive: true });
  const r = spawnSync(process.execPath, [SCAN, '--path', tmp, '--json'], {
    encoding: 'utf8', env: { ...process.env, SKILL_SENTRY_DATA_DIR: data },
  });
  assert.equal(r.status, 0, r.stderr);
  const report = JSON.parse(r.stdout);
  const bad = report.components.flatMap(c => c.findings ?? []).map(f => `${f.ruleId} ${f.file}`);
  assert.equal(report.components[0].scannerVerdict, 'ok', `findings: ${bad.join(', ')}`);
});
