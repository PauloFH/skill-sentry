import fs from 'node:fs';
import path from 'node:path';
import { readJsonSafe } from './jsonsafe.mjs';
import { normalizePath, truncate } from './text.mjs';

const isObj = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const normDir = p => normalizePath(path.resolve(p)).replace(/\/+$/, '');

const DEFAULT_LIMITS = { maxFiles: 2000, maxDepth: 6 };

/**
 * Recursively list files under dir, following symlinks (cycles guarded by realpath).
 * Skips node_modules and .git. Sets `truncated` when a cap cut the listing short.
 */
function listFiles(dir, limits) {
  const { maxFiles, maxDepth } = { ...DEFAULT_LIMITS, ...limits };
  const files = [];
  let truncated = false;
  const visited = new Set();
  const walk = (d, depth) => {
    let real;
    try { real = fs.realpathSync(d); } catch { return; }
    if (visited.has(real)) return;
    visited.add(real);
    if (depth > maxDepth) { truncated = true; return; }
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (e.name === 'node_modules' || e.name === '.git') continue;
      const full = path.join(d, e.name);
      let isDir = e.isDirectory();
      let isFile = e.isFile();
      if (e.isSymbolicLink()) {
        try { const st = fs.statSync(full); isDir = st.isDirectory(); isFile = !isDir; } catch { isFile = true; }
      }
      if (isDir) { walk(full, depth + 1); continue; }
      if (!isFile) continue;
      if (files.length >= maxFiles) { truncated = true; return; }
      files.push(full);
    }
  };
  walk(dir, 0);
  return { files, truncated };
}

/** Copy of a raw config entry with the VALUES of env/headers replaced by "<redacted>" (keys kept). */
function redactRaw(raw, extra = {}) {
  const out = { ...extra };
  if (isObj(raw)) for (const [k, v] of Object.entries(raw)) out[k] = v;
  for (const k of ['env', 'headers']) {
    if (isObj(out[k])) out[k] = Object.fromEntries(Object.keys(out[k]).map(key => [key, '<redacted>']));
  }
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
export function discover({ claudeHome, homeDir, projectDir, selfRoot, limits }) {
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

  const addMarketplace = (name, info, source) => {
    add({ id: `marketplace:${name}`, kind: 'marketplace', name, scope: 'user', root: null, config: isObj(info) ? info : {}, meta: {} }, source);
  };

  // --- Plugins ---
  const selfNorm = selfRoot ? normDir(selfRoot) : null;
  const installed = read(path.join(claudeHome, 'plugins', 'installed_plugins.json'));
  if (isObj(installed) && isObj(installed.plugins)) {
    for (const [key, entries] of Object.entries(installed.plugins)) {
      const e = Array.isArray(entries) ? entries[0] : entries;
      if (!isObj(e) || typeof e.installPath !== 'string') continue;
      const root = path.resolve(claudeHome, 'plugins', e.installPath);
      const name = key.includes('@') ? key.slice(0, key.lastIndexOf('@')) : key;
      const comp = {
        id: `plugin:${key}`, kind: 'plugin', name: key, scope: 'user', root,
        meta: { version: e.version, installScope: e.scope },
      };
      if (selfNorm && normDir(root) === selfNorm) comp.self = true;
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
  }

  // --- Marketplaces ---
  const known = read(path.join(claudeHome, 'plugins', 'known_marketplaces.json'));
  if (isObj(known)) for (const [name, info] of Object.entries(known)) addMarketplace(name, info, path.join(claudeHome, 'plugins', 'known_marketplaces.json'));

  // --- Settings (user, then project) ---
  const settingsSources = [{ scope: 'user', dir: claudeHome }];
  if (projectDir) settingsSources.push({ scope: 'project', dir: path.join(projectDir, '.claude') });
  for (const { scope, dir } of settingsSources) {
    for (const f of ['settings.json', 'settings.local.json']) {
      const sFile = path.join(dir, f);
      const s = read(sFile);
      if (!isObj(s)) continue;
      addHooks(s.hooks, scope, scope, null, sFile);
      if (isObj(s.statusLine)) {
        add({ id: `statusline:${scope}`, kind: 'statusline', name: 'statusLine', scope, root: null, config: s.statusLine, meta: {} }, sFile);
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
  if (projectDir) skillRoots.push({ scope: 'project', dir: path.join(projectDir, '.claude', 'skills') });
  for (const { scope, dir } of skillRoots) {
    let entries = [];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { /* absent */ }
    for (const e of entries) {
      const root = path.join(dir, e.name);
      if (!e.isDirectory() && !e.isSymbolicLink()) continue;
      if (!fs.existsSync(path.join(root, 'SKILL.md'))) continue;
      const { files, truncated } = listFiles(root, limits);
      add({ id: `skill:${scope}:${e.name}`, kind: 'skill', name: e.name, scope, root, files, meta: truncated ? { filesTruncated: true } : {} });
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
