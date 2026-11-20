// Inventory of OpenAI Codex extension surfaces, as components for the existing scan pipeline.
// Ids: `codex[<home label>]:<kind>:...`; every component carries `agent: 'codex'` and `meta.home`.
// Secrets: stored configs are redacted copies; the raw parsed values are only reachable through
// rawConfigOf() (rules and baseline hashing), never serialized (Ruling A).
// TOML files (config.toml, profiles, requirements.toml, agents/*.toml) and *.rules files are config-only
// components (`files: []`, raw text never scanned as a file), so no line of them reaches a snippet.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { listFiles, realDir, remoteLinkTarget, isInsideRoot, isRemoteLinkText, bindRawConfig } from '../inventory.mjs';
import { readJsonSafe } from '../jsonsafe.mjs';
import { parseToml } from '../toml.mjs';
import { parseRules } from '../codexrules.mjs';
import { normalizePath, truncate, redactSecrets, redactArgs } from '../text.mjs';

const isObj = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const hasOwn = (o, k) => isObj(o) && Object.hasOwn(o, k);
const normDir = p => normalizePath(path.resolve(p)).replace(/\/+$/, '');
const sha256 = s => crypto.createHash('sha256').update(s).digest('hex');
const snake = e => String(e).replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();
const DEFAULT_MAX_DIRS = 2000;
const MAX_TOML_BYTES = 4 * 1024 * 1024;
const MAX_TRUSTED_PROJECTS = 50;
const PLUGIN_MANIFESTS = ['.codex-plugin/plugin.json', 'plugin.json', '.claude-plugin/plugin.json', '.cursor-plugin/plugin.json'];

// --- redaction ---
const R = '<redacted>';
// Values under these keys are all credentials (env vars, headers, OAuth), whatever their names.
const SECRET_CONTAINERS = new Set(['env', 'set', 'http_headers', 'env_http_headers', 'headers', 'oauth']);
const SECRET_KEY = /token|secret|key|pass|auth|credential|cookie/i; // superset of text.mjs SECRET_NAME
const setOwn = (o, k, v) => Object.defineProperty(o, k, { value: v, enumerable: true, writable: true, configurable: true });

function redactValue(v, key, secret, command) {
  if (typeof v === 'string') return secret || SECRET_KEY.test(key) ? R : redactSecrets(v);
  if (Array.isArray(v)) {
    if (secret || SECRET_KEY.test(key)) return v.map(x => redactValue(x, key, true));
    if (v.length && v.every(x => typeof x === 'string')) return redactArgs(v, command);
    return v.map(x => redactValue(x, key, false));
  }
  if (isObj(v)) {
    const out = {};
    const cmd = typeof v.command === 'string' ? v.command : '';
    for (const [k, x] of Object.entries(v)) setOwn(out, k, redactValue(x, k, secret || SECRET_CONTAINERS.has(k), cmd));
    return out;
  }
  return v;
}

/** Redacted copy to store, with the raw `{ ...extra, ...raw }` bound for rawConfigOf(). */
function redactConfig(raw, extra = {}) {
  const rawCopy = {};
  for (const [k, v] of Object.entries(extra)) setOwn(rawCopy, k, v);
  if (isObj(raw)) for (const [k, v] of Object.entries(raw)) setOwn(rawCopy, k, v);
  return bindRawConfig(redactValue(rawCopy, '', false, ''), rawCopy);
}

// --- small fs helpers (never throw) ---
const dirents = dir => { try { return fs.readdirSync(dir, { withFileTypes: true }); } catch { return []; } };
const isDir = p => { try { return fs.statSync(p).isDirectory(); } catch { return false; } };
const isFile = p => { try { return fs.statSync(p).isFile(); } catch { return false; } };
// A link to a network path is never followed (no SMB connection).
const subdirs = dir => dirents(dir).filter(e => e.isDirectory() || (e.isSymbolicLink() && remoteLinkTarget(path.join(dir, e.name)) === null))
  .map(e => e.name).filter(n => isDir(path.join(dir, n)));

/**
 * Discover Codex components in each home (see homes.mjs for the home entries).
 * Project surfaces (`<projectDir>` chain up to its git root: `.codex/` layer, `.agents/skills`,
 * AGENTS.override.md / AGENTS.md) are listed once, under the first home's label. The scanned dir's own
 * AGENTS.md is left to the Claude inventory (`instructions:project:AGENTS.md`), which always runs too.
 * @returns {{ components: object[], configFindings: object[] }}
 */
export function discoverCodex({ homes = [], projectDir, selfRoot, deadline, limits } = {}) {
  const components = [];
  const configFindings = [];
  const late = () => deadline !== undefined && Date.now() >= deadline;
  const selfReal = selfRoot ? realDir(selfRoot) : null;
  const maxDirs = limits?.maxDirs ?? DEFAULT_MAX_DIRS;
  homes.forEach((home, i) => {
    if (late()) {
      configFindings.push({ ruleId: 'SCAN_TRUNCATED', category: 'config', severity: 'info', line: 0, file: home.root, snippet: 'scan time budget exhausted before this Codex home was inventoried' });
      return;
    }
    try {
      inventoryHome({ home, projectDir: i === 0 ? projectDir : null, homes, components, configFindings, late, selfReal, maxDirs, limits, deadline });
    } catch (e) {
      configFindings.push({ ruleId: 'CONFIG_UNREADABLE', category: 'config', severity: 'info', line: 0, file: home.root, snippet: truncate(`Codex home inventory failed: ${e?.code ?? e?.message ?? 'error'}`) });
    }
  });
  return { components, configFindings };
}

function inventoryHome({ home, projectDir, homes, components, configFindings, late, selfReal, maxDirs, limits, deadline }) {
  const { label, root } = home;
  if (!isDir(root)) return;
  const seen = new Set(components.map(c => c.id));
  let cut = false;
  const step = fn => {
    if (cut) return;
    if (late()) {
      cut = true;
      configFindings.push({ ruleId: 'SCAN_TRUNCATED', category: 'config', severity: 'info', line: 0, file: root, snippet: 'scan time budget exhausted; this Codex home was partly inventoried' });
      return;
    }
    fn();
  };

  const add = (c, source) => {
    c.id = `codex[${label}]:${c.id}`;
    c.agent = 'codex';
    c.meta = { ...c.meta, home: label, ...(source ? { source } : {}) };
    const base = c.id;
    for (let k = 2; seen.has(c.id); k++) c.id = `${base}#${k}`;
    seen.add(c.id);
    components.push(c);
    return c;
  };
  const unreadable = (file, snippet, line = 0) => configFindings.push({ ruleId: 'CONFIG_UNREADABLE', category: 'config', severity: 'info', line, snippet: truncate(snippet), file });
  const readJson = file => {
    const r = readJsonSafe(file);
    if (r.ok) return r.value;
    if (r.error !== 'missing') unreadable(file, r.error);
    return null;
  };
  // Path written in this home's config: `~/` -> user home; POSIX absolute in a WSL home -> inside the distro.
  const mapPath = p => {
    const s = String(p);
    if ((s.startsWith('~/') || s.startsWith('~\\')) && home.userHome) return path.join(home.userHome, s.slice(2));
    if (home.distroRoot && s.startsWith('/')) return path.join(home.distroRoot, ...s.split('/').filter(Boolean));
    return path.resolve(root, s);
  };

  /**
   * One TOML file as a config-only component. Returns the parsed value, or null (missing/unparseable).
   * Unparseable: the component is still emitted, with `meta.parseError` and a raw config holding only
   * the text hash (baseline still sees edits); a CONFIG_UNREADABLE config finding is also recorded.
   */
  const tomlComponent = (file, id, kind, scope, name = path.basename(file)) => {
    let text;
    try {
      if (fs.statSync(file).size > MAX_TOML_BYTES) { unreadable(file, 'file too large'); return null; }
      text = fs.readFileSync(file, 'utf8').replace(/^﻿/, '');
    } catch (e) {
      if (e.code !== 'ENOENT' && e.code !== 'ENOTDIR') unreadable(file, e.code ?? 'unreadable');
      return null;
    }
    const r = parseToml(text);
    if (!r.ok) {
      const parseError = { message: truncate(r.error), line: r.line };
      const config = bindRawConfig({}, { parseError, sha256: sha256(text) });
      add({ id, kind, name, scope, root: null, files: [], config, meta: { file, parseError } }, file);
      unreadable(file, `TOML: ${r.error}`, r.line);
      return null;
    }
    add({ id, kind, name, scope, root: null, files: [], config: redactConfig(r.value), meta: { file } }, file);
    return r.value;
  };

  // Hook index n counts within one source and event across groups; g/h are the group and handler
  // indexes Codex uses in `[hooks.state."<prefix>:<event_snake>:<g>:<h>"]`.
  const counters = new Map();
  const addHooks = (hooksObj, source, scope, hroot, file, statePrefix, state) => {
    if (!isObj(hooksObj)) return;
    for (const [event, groups] of Object.entries(hooksObj)) {
      if (!Array.isArray(groups)) continue; // e.g. [hooks.state]
      let n = counters.get(`${source}:${event}`) || 0;
      groups.forEach((g, gi) => {
        if (!isObj(g) || !Array.isArray(g.hooks)) return;
        g.hooks.forEach((h, hi) => {
          if (!isObj(h)) return;
          const meta = { event };
          const key = statePrefix ? `${statePrefix}:${snake(event)}:${gi}:${hi}` : null;
          if (key && hasOwn(state, key) && isObj(state[key])) {
            const st = state[key];
            meta.trusted = typeof st.trusted_hash === 'string' && st.trusted_hash !== '';
            if (typeof st.enabled === 'boolean') meta.enabled = st.enabled;
          }
          const config = redactConfig(h, g.matcher !== undefined ? { event, matcher: g.matcher } : { event });
          add({ id: `hook:${source}:${event}:${n}`, kind: 'hook', name: `${event}[${n}]`, scope, root: hroot, config, meta }, file);
          n++;
        });
      });
      counters.set(`${source}:${event}`, n);
    }
  };
  const hooksIn = v => (isObj(v) && isObj(v.hooks) ? v.hooks : v);

  const addMcp = (servers, idScope, scope, mroot, file, policies) => {
    if (!isObj(servers)) return;
    for (const [name, raw] of Object.entries(servers)) {
      if (!isObj(raw)) continue;
      const meta = {};
      if (hasOwn(policies, name) && isObj(policies[name])) meta.policy = redactValue(policies[name], '', false, '');
      add({ id: `mcp:${idScope}:${name}`, kind: 'mcp', name, scope, root: mroot, config: redactConfig(raw), meta }, file);
    }
  };

  const addInstructions = (file, id, scope) => {
    // A network path is read only inside this home's own tree (a WSL home lives on \\wsl.localhost\).
    const n = normDir(file);
    const ownTree = [root, home.userHome, home.distroRoot].filter(Boolean).some(d => n.startsWith(normDir(d) + '/'));
    if ((isRemoteLinkText(file) && !ownTree) || remoteLinkTarget(file) !== null || !isFile(file)) return;
    // root null: a root equal to the Codex home could be walked (auth.json, sessions) if `files` were lost.
    add({ id, kind: 'instructions', name: path.basename(file), scope, root: null, files: [file], meta: {} });
  };

  /** Surfaces read out of one parsed config layer. `layer` is `user` for the home's config.toml. */
  // `confine` ({ base, top }): a project layer is repo-controlled, so the files it names are resolved
  // against its own dir and must stay inside the project chain top (never ~/.codex/auth.json & co).
  const fromLayer = (value, layer, scope, file, confine) => {
    if (!isObj(value)) return;
    const sfx = layer === 'user' ? '' : `:${layer}`;
    const pfx = layer === 'user' ? '' : `${layer}:`;
    addMcp(value.mcp_servers, layer, scope, null, file);
    addHooks(hooksIn(value.hooks), `config${sfx}`, scope, null, file);
    if (Array.isArray(value.notify) && value.notify.length && value.notify.every(x => typeof x === 'string')) {
      add({ id: `notify${sfx}`, kind: 'notify', name: 'notify', scope, root: null, config: redactConfig({ command: value.notify[0], args: value.notify.slice(1) }), meta: {} }, file);
    }
    if (isObj(value.apps)) for (const [id, raw] of Object.entries(value.apps)) {
      add({ id: `app:${pfx}${id}`, kind: 'app', name: id, scope, root: null, config: redactConfig(raw), meta: {} }, file);
    }
    if (isObj(value.marketplaces)) for (const [name, raw] of Object.entries(value.marketplaces)) {
      add({ id: `marketplace:${pfx}${name}`, kind: 'marketplace', name, scope, root: null, config: redactConfig(raw), meta: {} }, file);
    }
    const mif = value.model_instructions_file;
    if (typeof mif === 'string' && mif) {
      const id = `instructions:model_instructions_file${sfx}`;
      if (!confine) addInstructions(mapPath(mif), id, scope);
      else if (!confine.skipInstructions) {
        const tilde = mif.startsWith('~');
        const f = tilde ? mapPath(mif) : path.resolve(confine.base, mif);
        if (tilde || !isInsideRoot(confine.top, f)) unreadable(f, 'path outside project');
        else addInstructions(f, id, scope);
      }
    }
  };

  const addRules = (dir, idPrefix, scope) => {
    for (const e of dirents(dir)) {
      if (!e.name.endsWith('.rules')) continue;
      const file = path.join(dir, e.name);
      let text;
      try { if (!isFile(file)) continue; text = fs.readFileSync(file, 'utf8'); } catch (err) { unreadable(file, err.code ?? 'unreadable'); continue; }
      const { rules, unparsed } = parseRules(text);
      const config = redactConfig({ rules, unparsed, sha256: sha256(text) });
      add({ id: `rules:${idPrefix}${e.name}`, kind: 'rules', name: e.name, scope, root: null, files: [], config, meta: { file } }, file);
    }
  };

  // [[skills.config]] entries disabling a skill by name or path.
  let skillsConfig = [];
  const disabled = (name, sroot) => skillsConfig.some(s => isObj(s) && s.enabled === false
    && (s.name === name || (typeof s.path === 'string' && [sroot, path.join(sroot, 'SKILL.md')].some(p => normDir(mapPath(s.path)) === normDir(p)))));
  const addSkills = (dir, idScope, scope) => {
    let count = 0;
    for (const e of dirents(dir)) {
      if (e.name === '.system') continue; // bundled with Codex
      if (!e.isDirectory() && !e.isSymbolicLink()) continue;
      const sroot = path.join(dir, e.name);
      if (++count > maxDirs) {
        configFindings.push({ ruleId: 'SCAN_TRUNCATED', category: 'config', severity: 'info', line: 0, file: dir, snippet: `skills directory has more than ${maxDirs} entries; the rest were not inspected` });
        break;
      }
      const remote = e.isSymbolicLink() ? remoteLinkTarget(sroot) : null;
      if (remote === null && !isFile(path.join(sroot, 'SKILL.md'))) continue;
      const comp = { id: `skill:${idScope}:${e.name}`, kind: 'skill', name: e.name, scope, root: sroot, meta: {} };
      if (remote !== null) {
        comp.files = [];
        comp.meta.symlinksOutside = [{ path: sroot, target: remote }];
      } else if (late()) {
        comp.files = [];
        comp.meta.filesTruncated = true;
        comp.meta.incomplete = true;
      } else {
        const r = listFiles(sroot, limits, { deadline });
        comp.files = r.files;
        if (r.truncated || r.timedOut) comp.meta.filesTruncated = true;
        if (r.timedOut) comp.meta.incomplete = true;
        if (r.outside.length) comp.meta.symlinksOutside = r.outside;
      }
      if (disabled(e.name, sroot)) comp.meta.enabled = false;
      add(comp);
    }
  };

  // --- user config layer (config.toml) and its home-wide tables ---
  const cfgFile = path.join(root, 'config.toml');
  let cfg = null;
  step(() => { cfg = tomlComponent(cfgFile, 'config', 'config', 'user'); });
  const state = isObj(cfg?.hooks) && isObj(cfg.hooks.state) ? cfg.hooks.state : null;
  const plugCfg = isObj(cfg?.plugins) ? cfg.plugins : {};
  if (Array.isArray(cfg?.skills?.config)) skillsConfig = cfg.skills.config;
  step(() => fromLayer(cfg, 'user', 'user', cfgFile));

  // --- profiles (<name>.config.toml) and requirements.toml in the home ---
  step(() => {
    for (const e of dirents(root)) {
      const m = /^(.+)\.config\.toml$/.exec(e.name);
      if (!m || !e.isFile()) continue;
      const f = path.join(root, e.name);
      fromLayer(tomlComponent(f, `config:profile:${m[1]}`, 'config', 'user'), `profile:${m[1]}`, 'user', f);
    }
    const req = path.join(root, 'requirements.toml');
    fromLayer(tomlComponent(req, 'config:requirements', 'config', 'user'), 'requirements', 'user', req);
  });

  // --- hooks.json, rules, instructions, agents, prompts, skills of the home ---
  step(() => { const f = path.join(root, 'hooks.json'); addHooks(hooksIn(readJson(f)), 'user', 'user', null, f); });
  step(() => addRules(path.join(root, 'rules'), '', 'user'));
  step(() => {
    for (const f of ['AGENTS.md', 'AGENTS.override.md']) addInstructions(path.join(root, f), `instructions:${f}`, 'user');
  });
  step(() => {
    const dir = path.join(root, 'agents');
    for (const e of dirents(dir)) {
      if (!e.name.endsWith('.toml') || !e.isFile()) continue;
      const name = e.name.slice(0, -'.toml'.length);
      tomlComponent(path.join(dir, e.name), `agent:${name}`, 'agent', 'user', name);
    }
  });
  step(() => {
    const dir = path.join(root, 'prompts');
    if (!isDir(dir)) return;
    const r = listFiles(dir, limits, { deadline });
    const meta = {};
    if (r.truncated || r.timedOut) meta.filesTruncated = true;
    if (r.timedOut) meta.incomplete = true;
    if (r.outside.length) meta.symlinksOutside = r.outside;
    add({ id: 'prompts', kind: 'prompts', name: 'prompts', scope: 'user', root: dir, files: r.files, meta });
  });
  step(() => { if (home.userHome) addSkills(path.join(home.userHome, '.agents', 'skills'), 'user', 'user'); });
  step(() => addSkills(path.join(root, 'skills'), 'home', 'user'));

  // --- plugins: plugins/cache/<marketplace>/<plugin>/<version>/ ---
  step(() => {
    const cache = path.join(root, 'plugins', 'cache');
    let count = 0;
    for (const mkt of subdirs(cache)) {
      for (const p of subdirs(path.join(cache, mkt))) {
        const versions = subdirs(path.join(cache, mkt, p)).sort((a, b) => b.localeCompare(a, 'en', { numeric: true }));
        for (const v of versions) {
          if (++count > maxDirs || late()) {
            configFindings.push({ ruleId: 'SCAN_TRUNCATED', category: 'config', severity: 'info', line: 0, file: cache, snippet: 'plugin cache listing stopped by a limit; the rest were not inspected' });
            return;
          }
          addPlugin(path.join(cache, mkt, p, v), p, mkt, v);
        }
      }
    }
  });

  function addPlugin(proot, p, mkt, v) {
    const key = `${p}@${mkt}`;
    let manifest = null;
    let manifestRel;
    for (const rel of PLUGIN_MANIFESTS) {
      const f = path.join(proot, ...rel.split('/'));
      if (!isFile(f)) continue;
      manifest = readJson(f);
      manifestRel = rel;
      break;
    }
    const meta = { version: typeof manifest?.version === 'string' ? manifest.version : v, versionDir: v, marketplace: mkt };
    if (manifestRel) meta.manifest = manifestRel;
    if (hasOwn(plugCfg, key) && typeof plugCfg[key]?.enabled === 'boolean') meta.enabled = plugCfg[key].enabled;
    const comp = { id: `plugin:${key}`, kind: 'plugin', name: key, scope: 'user', root: proot, meta };
    if (selfReal && realDir(proot) === selfReal) comp.self = true;
    add(comp);

    const readOnce = new Set();
    const readIn = f => {
      const k = normDir(f);
      if (readOnce.has(k)) return null;
      readOnce.add(k);
      if (!isInsideRoot(proot, f)) { unreadable(f, 'path outside plugin root'); return null; }
      return readJson(f);
    };
    const resolveRel = s => path.resolve(proot, String(s).replace(/^\$\{(?:CLAUDE_)?PLUGIN_ROOT\}[\\/]?/, ''));
    const relKey = f => path.relative(proot, f).replaceAll('\\', '/');
    const policies = isObj(plugCfg[key]?.mcp_servers) && hasOwn(plugCfg, key) ? plugCfg[key].mcp_servers : null;
    const src = `plugin:${key}`;

    const hooksFile = path.join(proot, 'hooks', 'hooks.json');
    addHooks(hooksIn(readIn(hooksFile)), src, 'plugin', proot, hooksFile, `${key}:hooks/hooks.json`, state);
    for (const mf of ['.mcp.json', 'mcp.json']) {
      const f = path.join(proot, mf);
      const v2 = readIn(f);
      if (isObj(v2)) addMcp(isObj(v2.mcpServers) ? v2.mcpServers : v2, `plugin:${key}`, 'plugin', proot, f, policies);
    }
    addAppFile(proot, key, readIn);
    if (!isObj(manifest)) return;
    const manifestFile = path.join(proot, ...manifestRel.split('/'));
    const h = manifest.hooks;
    if (isObj(h)) addHooks(hooksIn(h), src, 'plugin', proot, manifestFile);
    else for (const s of [].concat(typeof h === 'string' || Array.isArray(h) ? h : [])) {
      if (typeof s !== 'string') continue;
      const f = resolveRel(s);
      addHooks(hooksIn(readIn(f)), src, 'plugin', proot, f, `${key}:${relKey(f)}`, state);
    }
    const m = manifest.mcpServers;
    if (isObj(m)) addMcp(m, `plugin:${key}`, 'plugin', proot, manifestFile, policies);
    else for (const s of [].concat(typeof m === 'string' || Array.isArray(m) ? m : [])) {
      if (typeof s !== 'string') continue;
      const f = resolveRel(s);
      const v2 = readIn(f);
      if (isObj(v2)) addMcp(isObj(v2.mcpServers) ? v2.mcpServers : v2, `plugin:${key}`, 'plugin', proot, f, policies);
    }
    const a = manifest.apps;
    if (isObj(a)) addApp(a, `plugin:${key}:manifest`, manifestFile);
    else for (const s of [].concat(typeof a === 'string' || Array.isArray(a) ? a : [])) {
      if (typeof s !== 'string') continue;
      const f = resolveRel(s);
      addApp(readIn(f), `plugin:${key}:${relKey(f)}`, f);
    }
  }

  // Plugin app/connector declarations (`.app.json`, manifest `apps`): shape unverified, so the whole
  // JSON is kept as one config-only component (redacted; raw for the rules).
  function addAppFile(proot, key, readIn) {
    const f = path.join(proot, '.app.json');
    addApp(readIn(f), `plugin:${key}:.app.json`, f);
  }
  function addApp(value, id, file) {
    if (!isObj(value)) return;
    add({ id: `app:${id}`, kind: 'app', name: path.basename(file), scope: 'plugin', root: null, files: [], config: redactConfig(value), meta: {} }, file);
  }

  // --- system layer (/etc/codex, %ProgramData%\OpenAI\Codex): default and WSL homes only ---
  if (home.systemDir) {
    const sys = home.systemDir;
    step(() => {
      if (isRemoteLinkText(sys) && !home.distroRoot) return;
      if (!isDir(sys)) return;
      const f = path.join(sys, 'config.toml');
      fromLayer(tomlComponent(f, 'config:system', 'config', 'system'), 'system', 'system', f);
      const req = path.join(sys, 'requirements.toml');
      fromLayer(tomlComponent(req, 'config:system:requirements', 'config', 'system'), 'system:requirements', 'system', req);
      const hf = path.join(sys, 'hooks.json');
      addHooks(hooksIn(readJson(hf)), 'system', 'system', null, hf);
      addRules(path.join(sys, 'rules'), 'system:', 'system');
      addSkills(path.join(sys, 'skills'), 'system', 'system');
    });
  }

  // --- project chain (first home only) ---
  const homeRoots = new Set(homes.map(h => realDir(h.root)));
  const currentDirs = new Set();
  if (projectDir) step(() => {
    const chain = projectChain(projectDir, homes);
    for (const d of chain) currentDirs.add(realDir(d));
    const top = chain[0];
    const trustOf = () => {
      const projects = isObj(cfg?.projects) ? cfg.projects : {};
      for (const d of [...chain].reverse()) {
        for (const [k, v] of Object.entries(projects)) {
          if (isObj(v) && typeof v.trust_level === 'string' && normDir(mapPath(k)) === normDir(d)) return v.trust_level;
        }
      }
      return undefined;
    };
    const trust = trustOf();
    const userSkillDirs = new Set(homes.filter(h => h.userHome).map(h => realDir(path.join(h.userHome, '.agents', 'skills'))));
    const before = components.length;
    for (const d of chain) {
      if (late()) break;
      for (const f of ['AGENTS.override.md', 'AGENTS.md']) {
        if (f === 'AGENTS.md' && normDir(d) === normDir(projectDir)) continue; // Claude inventory lists it
        const file = path.join(d, f);
        addInstructions(file, `instructions:project:${path.relative(top, file).replaceAll('\\', '/')}`, 'project');
      }
      const dotCodex = path.join(d, '.codex');
      if (isDir(dotCodex) && !homeRoots.has(realDir(dotCodex))) {
        const f = path.join(dotCodex, 'config.toml');
        fromLayer(tomlComponent(f, 'config:project', 'config', 'project'), 'project', 'project', f, { base: dotCodex, top });
        const hf = path.join(dotCodex, 'hooks.json');
        addHooks(hooksIn(readJson(hf)), 'project', 'project', null, hf);
        addRules(path.join(dotCodex, 'rules'), 'project:', 'project');
      }
      const sk = path.join(d, '.agents', 'skills');
      if (isDir(sk) && !userSkillDirs.has(realDir(sk))) addSkills(sk, 'project', 'project');
    }
    if (trust !== undefined) for (const c of components.slice(before)) c.meta.trust = trust;
  });

  // `[projects.'<key>']` -> local dir, or null when it cannot be read safely (relative, `..`, network).
  const projectPath = k => {
    const s = String(k);
    if (home.distroRoot) {
      const segs = s.split('/').filter(Boolean);
      return s.startsWith('/') && !segs.includes('..') ? path.join(home.distroRoot, ...segs) : null;
    }
    if (isRemoteLinkText(s) || !path.isAbsolute(s) || s.split(/[\\/]/).includes('..')) return null;
    return path.resolve(s);
  };

  // --- other trusted projects of this home: their .codex hooks, config (MCP...) and rules execute ---
  // Instruction files and skills of non-current projects are not listed. In a WSL home, project keys
  // are Linux paths and are mapped into the distro. Missing dirs are skipped silently.
  step(() => {
    const projects = isObj(cfg?.projects) ? cfg.projects : {};
    let count = 0;
    for (const [k, v] of Object.entries(projects)) {
      if (!isObj(v) || v.trust_level !== 'trusted') continue;
      if (late()) {
        configFindings.push({ ruleId: 'SCAN_TRUNCATED', category: 'config', severity: 'info', line: 0, file: cfgFile, snippet: 'scan time budget exhausted; some trusted projects were not inventoried' });
        return;
      }
      if (++count > MAX_TRUSTED_PROJECTS) {
        configFindings.push({ ruleId: 'SCAN_TRUNCATED', category: 'config', severity: 'info', line: 0, file: cfgFile, snippet: `more than ${MAX_TRUSTED_PROJECTS} trusted projects; the rest were not inspected` });
        return;
      }
      const pdir = projectPath(k);
      if (pdir === null || remoteLinkTarget(pdir) !== null || !isDir(pdir) || currentDirs.has(realDir(pdir))) continue;
      const dotCodex = path.join(pdir, '.codex');
      if (!isDir(dotCodex) || homeRoots.has(realDir(dotCodex))) continue;
      const T = `trusted:${k}`;
      const before = components.length;
      const f = path.join(dotCodex, 'config.toml');
      fromLayer(tomlComponent(f, `config:${T}`, 'config', 'project'), T, 'project', f, { base: dotCodex, top: pdir, skipInstructions: true });
      const hf = path.join(dotCodex, 'hooks.json');
      addHooks(hooksIn(readJson(hf)), T, 'project', null, hf);
      addRules(path.join(dotCodex, 'rules'), `${T}:`, 'project');
      for (const c of components.slice(before)) c.meta = { ...c.meta, trust: 'trusted', project: pdir };
    }
  });
}

/**
 * Directories Codex reads project files from: git root -> projectDir (only projectDir when no `.git`
 * ancestor exists). Never climbs past a found git root; home directories are dropped from the chain.
 */
function projectChain(projectDir, homes) {
  const start = path.resolve(projectDir);
  const dirs = [];
  let gitRoot = null;
  for (let d = start, i = 0; i < 64; i++) {
    dirs.unshift(d);
    try { if (fs.existsSync(path.join(d, '.git'))) { gitRoot = d; break; } } catch { /* unreadable: keep climbing */ }
    const up = path.dirname(d);
    if (up === d) break;
    d = up;
  }
  const chain = gitRoot ? dirs : [start];
  const homeDirs = new Set([os.homedir(), ...homes.map(h => h.userHome).filter(Boolean)].map(normDir));
  return chain.filter(d => !homeDirs.has(normDir(d)));
}
