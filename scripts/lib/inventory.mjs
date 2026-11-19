import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { readJsonSafe } from './jsonsafe.mjs';
import { normalizePath, truncate, redactSecrets, redactArgs } from './text.mjs';

const isObj = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const normDir = p => normalizePath(path.resolve(p)).replace(/\/+$/, '');

/** JSON with object keys sorted at every level (deep-equality key that ignores key order). */
function canonJson(v) {
  const sort = x => (Array.isArray(x) ? x.map(sort)
    : isObj(x) ? Object.fromEntries(Object.keys(x).sort().map(k => [k, sort(x[k])])) : x);
  return JSON.stringify(sort(v) ?? null);
}

/** Canonical directory key: realpath when it exists (symlinks/junctions resolved), case-insensitive on win32. */
function realDir(p) {
  let r = path.resolve(p);
  try { r = fs.realpathSync.native(r); } catch { /* missing: compare the resolved form */ }
  return normDir(r);
}

const DEFAULT_LIMITS = { maxFiles: 2000, maxDirs: 2000, maxDepth: 6 };

const SKIP_DIRS = new Set(['node_modules', '.git', '.venv', '__pycache__']);

const realKey = p => normDir(fs.realpathSync.native(p));
const isInside = (p, root) => p === root || p.startsWith(root + '/');

/** Link target that would expose a whole home directory or filesystem: a drive root, `/`, or a home dir. */
export function isSensitiveLinkTarget(target) {
  const n = normDir(target);
  if (n === '' || /^[a-z]:$/i.test(n) || path.parse(path.resolve(target)).root === path.resolve(target)) return true;
  if (n === normDir(os.homedir())) return true;
  return /^(?:[a-z]:)?\/(?:users|home)\/[^/]+$/i.test(n);
}

/**
 * Recursively list files under dir. Symlinks and junctions are followed only when their real path
 * stays inside dir's real path; the others are returned in `outside` ({ path, target }) and never read.
 * Skips node_modules, .git, .venv and __pycache__ (the names seen are returned in `skipped`).
 * Directories count against `maxDirs` and files against `maxFiles`; when a cap or `deadline` (epoch ms)
 * stops the walk, the whole walk ends: `truncated` is set for a cap, `timedOut` for the deadline.
 * `maxDepth` prunes deeper branches only (sets `truncated`).
 */
export function listFiles(dir, limits, { deadline } = {}) {
  const { maxFiles, maxDirs, maxDepth } = { ...DEFAULT_LIMITS, ...limits };
  const files = [];
  const skipped = new Set();
  const outside = [];
  let truncated = false;
  let timedOut = false;
  let stop = false;
  let dirs = 0;
  const visited = new Set();
  let rootReal;
  try { rootReal = realKey(dir); } catch { return { files, truncated, skipped, timedOut, outside }; }
  const late = () => {
    if (deadline !== undefined && Date.now() >= deadline) { timedOut = true; stop = true; }
    return stop;
  };
  const walk = (d, depth) => {
    if (late()) return;
    let real;
    try { real = realKey(d); } catch { return; }
    if (visited.has(real)) return;
    visited.add(real);
    if (depth > maxDepth) { truncated = true; return; }
    if (++dirs > maxDirs) { truncated = true; stop = true; return; }
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (late()) return;
      if (SKIP_DIRS.has(e.name)) { skipped.add(e.name); continue; }
      const full = path.join(d, e.name);
      let isDir = e.isDirectory();
      let isFile = e.isFile();
      if (e.isSymbolicLink()) {
        let target = null;
        try { target = fs.realpathSync.native(full); } catch { /* broken link: listed, the scanner skips it */ }
        if (target === null) isFile = true;
        else if (!isInside(normDir(target), rootReal)) { outside.push({ path: full, target }); continue; }
        else {
          try { const st = fs.statSync(full); isDir = st.isDirectory(); isFile = !isDir; } catch { isFile = true; }
        }
      }
      if (isDir) { walk(full, depth + 1); continue; }
      if (!isFile) continue;
      if (files.length >= maxFiles) { truncated = true; stop = true; return; }
      files.push(full);
    }
  };
  walk(dir, 0);
  return { files, truncated, skipped, timedOut, outside };
}

// Stored config -> unredacted copy, for the scanner's rules only (never serialized: a WeakMap entry
// survives `{ ...component }` copies and is invisible to JSON.stringify).
const RAW_CONFIG = new WeakMap();

/** Unredacted config of a discovered component (falls back to the stored config). */
export function rawConfigOf(config) {
  return (config && RAW_CONFIG.get(config)) ?? config;
}

/**
 * Copy of a raw config entry safe to store and show: VALUES of env/headers/oauth replaced by
 * "<redacted>" (keys kept); credentials inside url, command, headersHelper and args redacted.
 */
function redactRaw(raw, extra = {}) {
  const out = { ...extra };
  if (isObj(raw)) for (const [k, v] of Object.entries(raw)) out[k] = v;
  const rawCopy = { ...out };
  for (const k of ['env', 'headers', 'oauth']) {
    if (isObj(out[k])) out[k] = Object.fromEntries(Object.keys(out[k]).map(key => [key, '<redacted>']));
  }
  for (const k of ['url', 'command', 'headersHelper']) {
    if (typeof out[k] === 'string') out[k] = redactSecrets(out[k]);
  }
  if (Array.isArray(out.args)) out.args = redactArgs(out.args.map(String));
  RAW_CONFIG.set(out, rawCopy);
  return out;
}

/**
 * Discover every inspectable component.
 *
 * Conventions:
 * - A relative `installPath` in installed_plugins.json is resolved against `<claudeHome>/plugins`.
 * - Hook index `n` counts within one event across all matcher groups of one source; the user
 *   (or project) `settings.json` and `settings.local.json` form a single source, read in that order.
 */
export function discover({ claudeHome, homeDir, projectDir, selfRoot, limits, deadline, skillFiles = true }) {
  const components = [];
  const configFindings = [];
  const seen = new Set();

  // Never drop a colliding entry: later ones get a deterministic "#2", "#3" ... suffix.
  const add = (c, source) => {
    if (source) c.meta = { ...c.meta, source };
    const base = c.id;
    for (let n = 2; seen.has(c.id); n++) c.id = `${base}#${n}`;
    seen.add(c.id);
    components.push(c);
  };

  const read = file => {
    const r = readJsonSafe(file);
    if (r.ok) return r.value;
    if (r.error !== 'missing') {
      configFindings.push({
        ruleId: 'CONFIG_UNREADABLE', category: 'config', severity: 'info',
        line: 0, snippet: truncate(r.error), file,
      });
    }
    return null;
  };

  const addHooks = (hooksObj, scope, label, root, source) => {
    if (!isObj(hooksObj)) return;
    for (const [event, groups] of Object.entries(hooksObj)) {
      if (!Array.isArray(groups)) continue;
      let n = counters.get(`${label}:${event}`) || 0;
      for (const g of groups) {
        if (!isObj(g) || !Array.isArray(g.hooks)) continue;
        for (const h of g.hooks) {
          if (!isObj(h)) continue;
          const config = redactRaw(h, g.matcher !== undefined ? { event, matcher: g.matcher } : { event });
          add({ id: `hook:${label}:${event}:${n}`, kind: 'hook', name: `${event}[${n}]`, scope, root, config, meta: { event } }, source);
          n++;
        }
      }
      counters.set(`${label}:${event}`, n);
    }
  };
  const counters = new Map();

  const addMcp = (servers, idScope, scope, root, source) => {
    if (!isObj(servers)) return;
    for (const [name, raw] of Object.entries(servers)) {
      add({ id: `mcp:${idScope}:${name}`, kind: 'mcp', name, scope, root, config: redactRaw(raw), meta: {} }, source);
    }
  };

  // A marketplace declared under the same name AND the same `source` (deep-equal, key order ignored) in
  // known_marketplaces.json and in settings files is one component; `meta.sources` lists every file.
  // A different `source` under the same name stays a separate `#n` component (shadowing), so a
  // divergent repository is never hidden behind the first declaration.
  const marketplaces = new Map(); // name -> [{ key, comp }]
  const addMarketplace = (name, info, source) => {
    const config = isObj(info) ? info : {};
    const key = canonJson(config.source);
    const list = marketplaces.get(name) ?? [];
    const same = list.find(x => x.key === key);
    if (same) {
      if (!same.comp.meta.sources.includes(source)) same.comp.meta.sources.push(source);
      return;
    }
    const comp = { id: `marketplace:${name}`, kind: 'marketplace', name, scope: 'user', root: null, config, meta: { sources: [source] } };
    list.push({ key, comp });
    marketplaces.set(name, list);
    add(comp, source);
  };

  // When the project's .claude directory IS the user's (Claude Code started from the home directory),
  // its settings and skills are already the user scope: listing them again would duplicate every item.
  const projectClaudeIsUser = !!projectDir && realDir(path.join(projectDir, '.claude')) === realDir(claudeHome);

  // --- Plugins ---
  // Self is compared by real path, so a symlinked/junctioned install or checkout still matches.
  const selfReal = selfRoot ? realDir(selfRoot) : null;
  const installed = read(path.join(claudeHome, 'plugins', 'installed_plugins.json'));
  // Every install entry is inventoried (user/project/local installs can differ); entries resolving to
  // the same real directory are one component. The first keeps `plugin:<key>`, later ones get `#n`.
  const installs = [];
  if (isObj(installed) && isObj(installed.plugins)) {
    for (const [key, entries] of Object.entries(installed.plugins)) {
      const seenRoots = new Set();
      for (const e of Array.isArray(entries) ? entries : [entries]) {
        if (!isObj(e) || typeof e.installPath !== 'string') continue;
        const root = path.resolve(claudeHome, 'plugins', e.installPath);
        const rk = realDir(root);
        if (seenRoots.has(rk)) continue;
        seenRoots.add(rk);
        installs.push({ key, e, root, rk });
      }
    }
  }
  for (const { key, e, root, rk } of installs) {
    const name = key.includes('@') ? key.slice(0, key.lastIndexOf('@')) : key;
    const comp = {
      id: `plugin:${key}`, kind: 'plugin', name: key, scope: 'user', root,
      meta: { version: e.version, installScope: e.scope },
    };
    if (selfReal && rk === selfReal) comp.self = true;
    add(comp);

    // Each JSON file is read once per plugin even if referenced several times.
    const readOnce = new Set();
    const readFileOnce = f => {
      const k = normalizePath(path.resolve(f));
      if (readOnce.has(k)) return null;
      readOnce.add(k);
      return read(f);
    };
    const relPath = p => path.resolve(root, String(p).replace(/^\$\{CLAUDE_PLUGIN_ROOT\}[\\/]?/, ''));
    const hookLabel = `plugin:${name}`;
    const hooksFrom = (v, src) => addHooks(isObj(v) && isObj(v.hooks) ? v.hooks : v, 'plugin', hookLabel, root, src);
    const mcpFrom = (v, src) => addMcp(isObj(v) && isObj(v.mcpServers) ? v.mcpServers : v, hookLabel, 'plugin', root, src);

    const hooksFile = path.join(root, 'hooks', 'hooks.json');
    const hj = readFileOnce(hooksFile);
    if (isObj(hj)) hooksFrom(hj, hooksFile);
    const mcpFile = path.join(root, '.mcp.json');
    const mj = readFileOnce(mcpFile);
    if (isObj(mj)) mcpFrom(mj, mcpFile);

    // Hooks / MCP servers declared in the plugin manifest (inline or by relative path).
    const manifestFile = path.join(root, '.claude-plugin', 'plugin.json');
    const manifest = read(manifestFile);
    if (isObj(manifest)) {
      const h = manifest.hooks;
      if (isObj(h)) hooksFrom(h, manifestFile);
      else for (const p of [].concat(typeof h === 'string' || Array.isArray(h) ? h : [])) {
        if (typeof p !== 'string') continue;
        const rp = relPath(p);
        const v = readFileOnce(rp);
        if (isObj(v)) hooksFrom(v, rp);
      }
      const m = manifest.mcpServers;
      if (isObj(m)) mcpFrom(m, manifestFile);
      else for (const p of [].concat(typeof m === 'string' || Array.isArray(m) ? m : [])) {
        if (typeof p !== 'string') continue;
        const rp = relPath(p);
        const v = readFileOnce(rp);
        if (isObj(v)) mcpFrom(v, rp);
      }
    }

    for (const mf of [path.join(root, 'monitors.json'), path.join(root, 'monitors', 'monitors.json')]) {
      const mon = read(mf);
      if (mon !== null) {
        add({ id: `monitor:${name}`, kind: 'monitor', name, scope: 'plugin', root, files: [mf], config: isObj(mon) ? mon : { monitors: mon }, meta: {} }, mf);
        break;
      }
    }
  }

  // --- Marketplaces ---
  const known = read(path.join(claudeHome, 'plugins', 'known_marketplaces.json'));
  if (isObj(known)) for (const [name, info] of Object.entries(known)) addMarketplace(name, info, path.join(claudeHome, 'plugins', 'known_marketplaces.json'));

  // --- Settings (user, then project) ---
  const settingsSources = [{ scope: 'user', dir: claudeHome }];
  if (projectDir && !projectClaudeIsUser) settingsSources.push({ scope: 'project', dir: path.join(projectDir, '.claude') });
  for (const { scope, dir } of settingsSources) {
    for (const f of ['settings.json', 'settings.local.json']) {
      const sFile = path.join(dir, f);
      const s = read(sFile);
      if (!isObj(s)) continue;
      addHooks(s.hooks, scope, scope, null, sFile);
      if (isObj(s.statusLine)) {
        add({ id: `statusline:${scope}`, kind: 'statusline', name: 'statusLine', scope, root: null, config: redactRaw(s.statusLine), meta: {} }, sFile);
      }
      if (isObj(s.extraKnownMarketplaces)) {
        for (const [name, info] of Object.entries(s.extraKnownMarketplaces)) addMarketplace(name, info, sFile);
      }
    }
  }

  // --- MCP servers: ~/.claude.json and project .mcp.json ---
  const cjFile = path.join(homeDir, '.claude.json');
  const cj = read(cjFile);
  if (isObj(cj)) {
    addMcp(cj.mcpServers, 'user', 'user', null, cjFile);
    if (projectDir && isObj(cj.projects)) {
      const want = normDir(projectDir);
      for (const [k, v] of Object.entries(cj.projects)) {
        if (isObj(v) && normDir(k) === want) addMcp(v.mcpServers, 'project', 'project', projectDir, cjFile);
      }
    }
  }
  if (projectDir) {
    const pmFile = path.join(projectDir, '.mcp.json');
    const pm = read(pmFile);
    if (isObj(pm)) addMcp(isObj(pm.mcpServers) ? pm.mcpServers : pm, 'project', 'project', projectDir, pmFile);
  }

  // --- Standalone skills ---
  const skillRoots = [{ scope: 'user', dir: path.join(claudeHome, 'skills') }];
  if (projectDir && !projectClaudeIsUser) skillRoots.push({ scope: 'project', dir: path.join(projectDir, '.claude', 'skills') });
  for (const { scope, dir } of skillRoots) {
    let entries = [];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { /* absent */ }
    for (const e of entries) {
      const root = path.join(dir, e.name);
      if (!e.isDirectory() && !e.isSymbolicLink()) continue;
      if (!fs.existsSync(path.join(root, 'SKILL.md'))) continue;
      const comp = { id: `skill:${scope}:${e.name}`, kind: 'skill', name: e.name, scope, root, meta: {} };
      // skillFiles: false leaves the walk to scanComponent (the guard scans only the attributed component).
      if (skillFiles) {
        const r = listFiles(root, limits, { deadline });
        comp.files = r.files;
        if (r.truncated) comp.meta.filesTruncated = true;
        if (r.timedOut) comp.meta.incomplete = true;
        if (r.outside.length) comp.meta.symlinksOutside = r.outside;
      }
      add(comp);
    }
  }

  // --- Project instruction files ---
  if (projectDir) {
    for (const f of ['CLAUDE.md', 'AGENTS.md']) {
      const file = path.join(projectDir, f);
      if (fs.existsSync(file)) {
        add({ id: `instructions:project:${f}`, kind: 'instructions', name: f, scope: 'project', root: projectDir, files: [file], meta: {} });
      }
    }
  }

  return { components, configFindings };
}
