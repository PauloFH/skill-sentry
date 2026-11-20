import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { codexHomes } from '../scripts/lib/codex/homes.mjs';
import { discoverCodex } from '../scripts/lib/codex/inventory.mjs';
import { discover, rawConfigOf } from '../scripts/lib/inventory.mjs';
import { scanComponent } from '../scripts/lib/scanner.mjs';
import { fileMap } from '../scripts/lib/baseline.mjs';
import { tmpFactory } from './helpers/tmp.mjs';
import { SENTINEL, buildCodexFixture, buildWslTree, buildBrokenCodexHome } from './helpers/codexfixtures.mjs';

const SCAN = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'scripts', 'scan.mjs');
const tmp = tmpFactory('ss-cx-');

const fixture = () => buildCodexFixture(tmp('fx'));
const run = (fx, o = {}) => discoverCodex({ homes: [fx.home], projectDir: fx.projectDir, selfRoot: null, ...o });
const byId = comps => Object.fromEntries(comps.map(c => [c.id, c]));

// --- codexHomes ---

test('codexHomes: default ~/.codex is labelled win and carries the user home and system layer', () => {
  const fx = fixture();
  const sys = tmp('pd');
  const homes = codexHomes({ env: { ProgramData: sys }, homeDir: fx.userHome, platform: 'win32', includeWsl: false });
  assert.deepEqual(homes, [{ label: 'win', root: fx.codexHome, userHome: fx.userHome, systemDir: path.join(sys, 'OpenAI', 'Codex') }]);
});

test('codexHomes: no system layer without ProgramData on win32; /etc/codex elsewhere', () => {
  const fx = fixture();
  const [w] = codexHomes({ env: {}, homeDir: fx.userHome, platform: 'win32', includeWsl: false });
  assert.equal(w.systemDir, undefined);
  const [l] = codexHomes({ env: {}, homeDir: fx.userHome, platform: 'linux', includeWsl: true, wslRoot: tmp('nowsl') });
  assert.equal(l.label, 'win');
  assert.equal(l.systemDir, '/etc/codex');
});

test('codexHomes: missing default home is skipped silently', () => {
  const problems = [];
  assert.deepEqual(codexHomes({ env: {}, homeDir: tmp('empty'), platform: 'win32', includeWsl: false, problems }), []);
  assert.deepEqual(problems, []);
});

test('codexHomes: $CODEX_HOME elsewhere is the default home but labelled h0', () => {
  const fx = fixture();
  const other = tmp('cxh');
  const homes = codexHomes({ env: { CODEX_HOME: other }, homeDir: fx.userHome, platform: 'win32', includeWsl: false });
  assert.deepEqual(homes, [{ label: 'h0', root: other, userHome: fx.userHome }]);
});

test('codexHomes: SKILL_SENTRY_CODEX_HOME replaces the default; explicit homes get no user home nor system layer', () => {
  const fx = fixture();
  const ov = tmp('ov');
  const extra = tmp('extra');
  const problems = [];
  const homes = codexHomes({
    env: { SKILL_SENTRY_CODEX_HOME: ov, CODEX_HOME: fx.codexHome, ProgramData: tmp('pd') },
    homeDir: fx.userHome, platform: 'win32', includeWsl: false, explicit: [extra, path.join(extra, 'missing')], problems,
  });
  assert.deepEqual(homes, [{ label: 'h0', root: ov }, { label: 'h1', root: extra }]);
  assert.equal(problems.length, 1);
  assert.match(problems[0], /codex home not found/);
});

test('codexHomes: the same directory given twice is listed once', () => {
  const fx = fixture();
  const homes = codexHomes({ env: {}, homeDir: fx.userHome, platform: 'win32', includeWsl: false, explicit: [fx.codexHome] });
  assert.deepEqual(homes.map(h => h.label), ['win']);
});

test('codexHomes: WSL distros/users with a .codex dir are found under the injected root', () => {
  const base = tmp('wsl');
  const { wslRoot, aliceCodex } = buildWslTree(base);
  const problems = [];
  const homes = codexHomes({ env: {}, homeDir: tmp('nohome'), platform: 'win32', includeWsl: true, wslRoot, deadline: Date.now() + 10_000, problems });
  assert.deepEqual(homes, [{
    label: 'wsl:Ubuntu:alice', root: aliceCodex, userHome: path.dirname(aliceCodex),
    systemDir: path.join(wslRoot, 'Ubuntu', 'etc', 'codex'), distroRoot: path.join(wslRoot, 'Ubuntu'),
  }]);
  assert.deepEqual(problems, []);
});

test('codexHomes: WSL is skipped when disabled, off win32, or missing; past the deadline it is a problem line', () => {
  const { wslRoot } = buildWslTree(tmp('wsl'));
  const home = tmp('nohome');
  assert.deepEqual(codexHomes({ env: {}, homeDir: home, platform: 'win32', includeWsl: false, wslRoot }), []);
  assert.deepEqual(codexHomes({ env: {}, homeDir: home, platform: 'linux', includeWsl: true, wslRoot }), []);
  const p1 = [];
  assert.deepEqual(codexHomes({ env: {}, homeDir: home, platform: 'win32', includeWsl: true, wslRoot: path.join(wslRoot, 'nope'), problems: p1 }), []);
  assert.deepEqual(p1, []);
  const p2 = [];
  assert.deepEqual(codexHomes({ env: {}, homeDir: home, platform: 'win32', includeWsl: true, wslRoot, deadline: Date.now() - 1, problems: p2 }), []);
  assert.equal(p2.length, 1);
  assert.match(p2[0], /WSL/);
});

test('codexHomes: an unlistable WSL root is a problem line, never a throw', () => {
  const notDir = path.join(tmp('wslf'), 'file');
  fs.writeFileSync(notDir, 'x');
  const problems = [];
  assert.deepEqual(codexHomes({ env: {}, homeDir: tmp('nohome'), platform: 'win32', includeWsl: true, wslRoot: notDir, problems }), []);
  assert.equal(problems.length, 1);
  assert.match(problems[0], /WSL/);
});

// --- discoverCodex ---

const EXPECTED = [
  'config', 'config:profile:work', 'config:system', 'config:system:requirements', 'config:project',
  'notify', 'mcp:user:pad', 'mcp:user:remote', 'mcp:profile:work:w', 'mcp:project:projmcp',
  'hook:config:PreToolUse:0',
  'hook:user:SessionStart:0', 'hook:user:PreToolUse:0', 'hook:user:PreToolUse:1',
  'hook:system:Stop:0', 'hook:project:PostToolUse:0',
  'hook:plugin:p@mkt:PreToolUse:0', 'hook:plugin:p@mkt:SessionStart:0',
  'plugin:p@mkt', 'mcp:plugin:p@mkt:pm', 'marketplace:mkt', 'app:github',
  'skill:user:agent-skill', 'skill:home:home-skill', 'skill:system:sys-skill',
  'skill:project:proj-skill', 'skill:project:sub-skill',
  'rules:default.rules', 'rules:system:managed.rules', 'rules:project:proj.rules',
  'instructions:AGENTS.md', 'instructions:model_instructions_file', 'instructions:project:AGENTS.override.md',
  'agent:reviewer', 'prompts',
].map(s => `codex[win]:${s}`);

test('discoverCodex: inventories every surface of the fake home', () => {
  const fx = fixture();
  const { components } = run(fx);
  const ids = components.map(c => c.id);
  for (const id of EXPECTED) assert.ok(ids.includes(id), `missing ${id}\n${ids.join('\n')}`);
  assert.deepEqual([...ids].sort(), [...EXPECTED].sort(), 'no unexpected component');
  assert.equal(new Set(ids).size, ids.length, 'ids unique');
  for (const c of components) {
    assert.equal(c.agent, 'codex', c.id);
    assert.equal(c.meta.home, 'win', c.id);
  }
});

test('discoverCodex: bundled .system skills, auth.json and sessions are never inventoried', () => {
  const fx = fixture();
  const { components } = run(fx);
  assert.ok(!components.some(c => c.id.includes('sys-bundled')));
  for (const c of components) {
    if (c.root) assert.notEqual(path.resolve(c.root), path.resolve(fx.codexHome), `${c.id} walks the Codex home`);
    for (const f of c.files ?? []) assert.ok(!/auth\.json|sessions/.test(f), `${c.id}: ${f}`);
  }
  for (const c of components) {
    const r = scanComponent(c);
    for (const f of r.files) assert.ok(!/auth\.json|rollout/.test(f.path), `${c.id} hashed ${f.path}`);
  }
});

test('discoverCodex: the project AGENTS.md of the scanned dir is left to the Claude inventory', () => {
  const fx = fixture();
  const { components } = run(fx);
  assert.ok(!components.some(c => (c.files ?? []).includes(path.join(fx.projectDir, 'AGENTS.md'))));
  const claude = discover({ claudeHome: path.join(tmp('ch'), '.claude'), homeDir: tmp('hd'), projectDir: fx.projectDir, selfRoot: null });
  assert.ok(claude.components.some(c => c.id === 'instructions:project:AGENTS.md' && c.agent === 'claude'));
});

test('discoverCodex: plugin under plugins/cache/<mkt>/<p>/<version> with a .claude-plugin manifest', () => {
  const fx = fixture();
  const by = byId(run(fx).components);
  const p = by['codex[win]:plugin:p@mkt'];
  assert.equal(p.kind, 'plugin');
  assert.equal(p.root, fx.plug);
  assert.equal(p.meta.version, '1.0.0');
  assert.equal(p.meta.manifest, '.claude-plugin/plugin.json');
  assert.equal(p.meta.enabled, true);
  const m = by['codex[win]:mcp:plugin:p@mkt:pm'];
  assert.equal(m.scope, 'plugin');
  assert.equal(m.config.command, 'node');
  assert.equal(m.meta.policy.default_tools_approval_mode, 'approve');
});

test('discoverCodex: hook trust/enabled come from [hooks.state]; unknown stays undefined', () => {
  const fx = fixture();
  const by = byId(run(fx).components);
  const pre = by['codex[win]:hook:plugin:p@mkt:PreToolUse:0'];
  assert.equal(pre.meta.trusted, true);
  assert.equal(pre.meta.enabled, true);
  assert.equal(pre.meta.event, 'PreToolUse');
  assert.equal(pre.config.matcher, 'Bash');
  const ss = by['codex[win]:hook:plugin:p@mkt:SessionStart:0'];
  assert.equal(ss.meta.trusted, false);
  assert.equal(ss.meta.enabled, false);
  for (const id of ['hook:user:SessionStart:0', 'hook:config:PreToolUse:0', 'hook:project:PostToolUse:0']) {
    const h = by[`codex[win]:${id}`];
    assert.equal(h.meta.trusted, undefined, id);
    assert.equal(h.meta.enabled, undefined, id);
  }
});

test('discoverCodex: inline [[hooks.PreToolUse]] and hooks.json commands are kept for the rules', () => {
  const fx = fixture();
  const by = byId(run(fx).components);
  const inline = by['codex[win]:hook:config:PreToolUse:0'];
  assert.equal(inline.kind, 'hook');
  assert.deepEqual(inline.config, { event: 'PreToolUse', matcher: 'Bash', type: 'command', command: 'node C:/guard/guard.js', timeout: 5 });
  assert.equal(by['codex[win]:hook:user:PreToolUse:1'].config.command, 'echo b');
  assert.equal(by['codex[win]:hook:user:PreToolUse:1'].meta.source, path.join(fx.codexHome, 'hooks.json'));
});

test('discoverCodex: notify, skills, rules, instructions, agents, prompts shapes', () => {
  const fx = fixture();
  const by = byId(run(fx).components);
  const n = by['codex[win]:notify'];
  assert.equal(n.kind, 'notify');
  assert.equal(n.config.command, 'node');
  assert.deepEqual(n.config.args.slice(0, 1), ['C:/tools/notify.js']);
  assert.equal(by['codex[win]:skill:user:agent-skill'].root, path.join(fx.userHome, '.agents', 'skills', 'agent-skill'));
  assert.ok(by['codex[win]:skill:user:agent-skill'].files.some(f => f.endsWith('SKILL.md')));
  assert.equal(by['codex[win]:skill:home:home-skill'].meta.enabled, false, '[[skills.config]] enabled=false');
  const r = by['codex[win]:rules:default.rules'];
  assert.equal(r.kind, 'rules');
  assert.deepEqual(r.config.rules.map(x => x.decision), ['allow', 'prompt']);
  assert.deepEqual(r.config.rules[0].pattern, ['pwsh', '-NoProfile', '-Command']);
  assert.equal(r.meta.file, path.join(fx.codexHome, 'rules', 'default.rules'));
  assert.deepEqual(by['codex[win]:instructions:AGENTS.md'].files, [path.join(fx.codexHome, 'AGENTS.md')]);
  assert.deepEqual(by['codex[win]:instructions:project:AGENTS.override.md'].files, [path.join(fx.project, 'AGENTS.override.md')]);
  assert.deepEqual(by['codex[win]:instructions:model_instructions_file'].files, [path.join(fx.userHome, 'instr.md')]);
  assert.equal(by['codex[win]:agent:reviewer'].kind, 'agent');
  assert.equal(by['codex[win]:agent:reviewer'].config.developer_instructions, 'Review code.');
  assert.ok(by['codex[win]:prompts'].files.some(f => f.endsWith('fix.md')));
  assert.equal(by['codex[win]:config:project'].meta.trust, 'trusted');
  assert.equal(by['codex[win]:config'].config.approval_policy, 'never');
  assert.deepEqual(by['codex[win]:config'].files, []);
});

test('discoverCodex: secrets never reach a component; raw values stay reachable through rawConfigOf', () => {
  const fx = fixture();
  const { components } = run(fx);
  assert.ok(!JSON.stringify(components).includes(SENTINEL), 'sentinel leaked into components');
  const by = byId(components);
  const cfg = by['codex[win]:config'];
  assert.equal(cfg.config.shell_environment_policy.set.ANTHROPIC_AUTH_TOKEN, '<redacted>');
  assert.equal(rawConfigOf(cfg.config).shell_environment_policy.set.ANTHROPIC_AUTH_TOKEN, SENTINEL);
  assert.ok(rawConfigOf(by['codex[win]:mcp:user:pad'].config).args.includes(SENTINEL));
  assert.ok(rawConfigOf(by['codex[win]:notify'].config).args.some(a => a.includes(SENTINEL)));
  assert.ok(rawConfigOf(by['codex[win]:hook:plugin:p@mkt:PreToolUse:0'].config).command.includes(SENTINEL));
  // Scanning and hashing never put the raw value in a result either.
  const results = components.map(c => scanComponent(c));
  assert.ok(!JSON.stringify(results).includes(SENTINEL), 'sentinel leaked into scan results');
  const h1 = fileMap(results.find(r => r.component.id === 'codex[win]:config'))['<config>'];
  assert.match(h1, /^[0-9a-f]{64}$/);
});

test('discoverCodex: the config hash follows the raw (secret) value', () => {
  const fx = fixture();
  const hashOf = () => fileMap(scanComponent(byId(run(fx).components)['codex[win]:config']))['<config>'];
  const before = hashOf();
  const f = path.join(fx.codexHome, 'config.toml');
  fs.writeFileSync(f, fs.readFileSync(f, 'utf8').replace(`ANTHROPIC_AUTH_TOKEN = "${SENTINEL}"`, 'ANTHROPIC_AUTH_TOKEN = "other-value-123456"'));
  assert.notEqual(hashOf(), before);
});

test('discoverCodex: unparseable config.toml is still a component with a parse-error marker', () => {
  const root = buildBrokenCodexHome(tmp('br'));
  const { components, configFindings } = discoverCodex({ homes: [{ label: 'h0', root }], projectDir: null, selfRoot: null });
  const c = components.find(x => x.id === 'codex[h0]:config');
  assert.ok(c, components.map(x => x.id).join(','));
  assert.equal(c.kind, 'config');
  assert.equal(c.meta.parseError.line, 3);
  assert.match(c.meta.parseError.message, /duplicate key/);
  assert.ok(!JSON.stringify(components).includes(SENTINEL));
  assert.ok(configFindings.some(f => f.ruleId === 'CONFIG_UNREADABLE' && f.file === path.join(root, 'config.toml')));
  assert.match(fileMap(scanComponent(c))['<config>'], /^[0-9a-f]{64}$/);
});

test('discoverCodex: WSL home gets its own label, system layer and POSIX paths mapped into the distro', () => {
  const { wslRoot } = buildWslTree(tmp('wsl'));
  const homes = codexHomes({ env: {}, homeDir: tmp('nohome'), platform: 'win32', includeWsl: true, wslRoot });
  const { components } = discoverCodex({ homes, projectDir: null, selfRoot: null });
  const ids = components.map(c => c.id);
  const L = 'codex[wsl:Ubuntu:alice]:';
  for (const id of ['config', 'notify', 'instructions:AGENTS.md', 'skill:user:wsl-skill', 'hook:system:Stop:0', 'instructions:model_instructions_file']) {
    assert.ok(ids.includes(L + id), `missing ${L + id}: ${ids.join(', ')}`);
  }
  const mi = components.find(c => c.id === `${L}instructions:model_instructions_file`);
  assert.deepEqual(mi.files, [path.join(wslRoot, 'Ubuntu', 'home', 'alice', '.codex', 'instr.md')]);
});

test('discoverCodex: two homes keep separate ids; project surfaces come with the first home only', () => {
  const fx = fixture();
  const second = { label: 'h1', root: buildBrokenCodexHome(tmp('b2')) };
  const { components } = discoverCodex({ homes: [fx.home, second], projectDir: fx.projectDir, selfRoot: null });
  assert.ok(components.some(c => c.id === 'codex[win]:config:project'));
  assert.ok(components.some(c => c.id === 'codex[h1]:config'));
  assert.ok(!components.some(c => c.id.startsWith('codex[h1]:') && c.scope === 'project'));
});

test('discoverCodex: past the deadline nothing throws and the cut is reported', () => {
  const fx = fixture();
  const { components, configFindings } = run(fx, { deadline: Date.now() - 1 });
  assert.deepEqual(components, []);
  assert.ok(configFindings.some(f => f.ruleId === 'SCAN_TRUNCATED'));
});

test('discoverCodex: a missing or empty home yields nothing and never throws', () => {
  const r = discoverCodex({ homes: [{ label: 'h0', root: path.join(tmp('nx'), 'nope') }, { label: 'h1', root: tmp('empty') }], projectDir: null, selfRoot: null });
  assert.deepEqual(r.components, []);
});

test('discoverCodex: a model_instructions_file on a network path is never opened', () => {
  const root = path.join(tmp('unc'), '.codex');
  fs.mkdirSync(root, { recursive: true });
  fs.writeFileSync(path.join(root, 'config.toml'), "model_instructions_file = '\\\\nohost.invalid\\share\\x.md'\n");
  const ids = discoverCodex({ homes: [{ label: 'h0', root }], projectDir: null, selfRoot: null }).components.map(c => c.id);
  assert.deepEqual(ids, ['codex[h0]:config']);
});

test('discoverCodex: a project config cannot point model_instructions_file outside the project', () => {
  for (const ref of ['ABS', "~/.codex/auth.json", '../../home/.codex/auth.json']) {
    const fx = fixture();
    const auth = path.join(fx.codexHome, 'auth.json');
    const value = ref === 'ABS' ? auth : ref;
    fs.writeFileSync(path.join(fx.project, '.codex', 'config.toml'), `model_instructions_file = '${value}'\n`);
    const { components, configFindings } = run(fx);
    assert.ok(!components.some(c => c.id.includes('model_instructions_file:project')), ref);
    for (const c of components) assert.ok(!(c.files ?? []).some(f => path.resolve(f) === path.resolve(auth)), `${ref}: ${c.id}`);
    assert.ok(configFindings.some(f => f.snippet === 'path outside project'), ref);
  }
  const fx = fixture();
  fs.writeFileSync(path.join(fx.project, '.codex', 'config.toml'), "model_instructions_file = 'docs/instr.md'\n");
  fs.mkdirSync(path.join(fx.project, '.codex', 'docs'), { recursive: true });
  fs.writeFileSync(path.join(fx.project, '.codex', 'docs', 'instr.md'), '# Project model instructions\n');
  const c = byId(run(fx).components)['codex[win]:instructions:model_instructions_file:project'];
  assert.deepEqual(c.files, [path.join(fx.project, '.codex', 'docs', 'instr.md')]);
});

test('discoverCodex: the skill-sentry checkout itself is marked self', () => {
  const fx = fixture();
  const p = byId(run(fx, { selfRoot: fx.plug }).components)['codex[win]:plugin:p@mkt'];
  assert.equal(p.self, true);
});

// --- scan.mjs integration ---

test('scan.mjs merges Claude and Codex components; secrets stay out of every output', () => {
  const fx = fixture();
  const data = tmp('data');
  const home = tmp('home');
  const r = spawnSync(process.execPath, [SCAN, '--json', '--claude-home', path.join(home, '.claude'), '--project', fx.projectDir], {
    encoding: 'utf8',
    env: { ...process.env, SKILL_SENTRY_DATA_DIR: data, SKILL_SENTRY_HOME_DIR: home, SKILL_SENTRY_CODEX_HOME: fx.codexHome, SKILL_SENTRY_NO_WSL: '1' },
  });
  assert.equal(r.status, 0, r.stderr);
  const rep = JSON.parse(r.stdout);
  const ids = rep.components.map(c => c.id);
  assert.ok(ids.includes('codex[h0]:config'), ids.join(', '));
  assert.ok(ids.includes('codex[h0]:hook:plugin:p@mkt:PreToolUse:0'));
  assert.ok(ids.includes('instructions:project:AGENTS.md'), 'Claude ids unchanged');
  assert.ok(!ids.some(id => id.startsWith('codex[win]') || id.startsWith('codex[wsl:')));
  assert.ok(!r.stdout.includes(SENTINEL), 'sentinel in stdout');
  const md = fs.readdirSync(path.join(data, 'reports')).find(f => f.endsWith('.md'));
  const mdText = fs.readFileSync(path.join(data, 'reports', md), 'utf8');
  for (const id of ['config', 'notify', 'rules:default.rules', 'agent:reviewer', 'prompts', 'app:github']) {
    assert.ok(mdText.includes(`codex\\[h0\\]:${id}`), `markdown lists codex[h0]:${id}`);
  }
  const outputs = [];
  for (const f of fs.readdirSync(path.join(data, 'reports'))) outputs.push(fs.readFileSync(path.join(data, 'reports', f), 'utf8'));
  outputs.push(fs.readFileSync(path.join(data, 'baseline.json'), 'utf8'));
  for (const o of outputs) assert.ok(!o.includes(SENTINEL), 'sentinel in a written file');
  assert.ok(Object.keys(JSON.parse(outputs.at(-1)).components).includes('codex[h0]:config'));
});
