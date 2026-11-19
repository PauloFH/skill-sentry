import fs from 'node:fs';
import path from 'node:path';
import { readJsonSafe } from './jsonsafe.mjs';
import { normalizePath, truncate } from './text.mjs';

const isObj = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const normDir = p => normalizePath(path.resolve(p)).replace(/\/+$/, '');

/** Recursively list files under dir (bounded depth/count; skips node_modules and .git). */
function listFiles(dir, depth = 0, out = []) {
  if (depth > 6 || out.length > 2000) return out;
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return out; }
  for (const e of entries) {
    if (e.name === 'node_modules' || e.name === '.git') continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) listFiles(full, depth + 1, out);
    else if (e.isFile()) out.push(full);
  }
  return out;
}

function redactMcp(raw) {
  const s = isObj(raw) ? raw : {};
  const env = {};
  if (isObj(s.env)) for (const k of Object.keys(s.env)) env[k] = '<redacted>';
  return { command: s.command, args: s.args, url: s.url, type: s.type, env };
}

/**
 * Discover every inspectable component.
 *
 * Conventions:
 * - A relative `installPath` in installed_plugins.json is resolved against `<claudeHome>/plugins`.
 * - Hook index `n` counts within one event across all matcher groups of one source; the user
 *   (or project) `settings.json` and `settings.local.json` form a single source, read in that order.
 */
export function discover({ claudeHome, homeDir, projectDir, selfRoot }) {
  const components = [];
  const configFindings = [];
  const seen = new Set();

  const add = c => {
    if (seen.has(c.id)) return;
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

  const addHooks = (hooksObj, scope, label, root) => {
    if (!isObj(hooksObj)) return;
    for (const [event, groups] of Object.entries(hooksObj)) {
      if (!Array.isArray(groups)) continue;
      let n = counters.get(`${label}:${event}`) || 0;
      for (const g of groups) {
        if (!isObj(g) || !Array.isArray(g.hooks)) continue;
        for (const h of g.hooks) {
          if (!isObj(h)) continue;
          const config = { event, matcher: g.matcher, type: h.type, command: h.command };
          if (h.args !== undefined) config.args = h.args;
          if (h.timeout !== undefined) config.timeout = h.timeout;
          add({ id: `hook:${label}:${event}:${n}`, kind: 'hook', name: `${event}[${n}]`, scope, root, config, meta: { event, source: label } });
          n++;
        }
      }
      counters.set(`${label}:${event}`, n);
    }
  };
  const counters = new Map();

  const addMcp = (servers, idScope, scope, root) => {
    if (!isObj(servers)) return;
    for (const [name, raw] of Object.entries(servers)) {
      add({ id: `mcp:${idScope}:${name}`, kind: 'mcp', name, scope, root, config: redactMcp(raw), meta: {} });
    }
  };

  const addMarketplace = (name, info) => {
    add({ id: `marketplace:${name}`, kind: 'marketplace', name, scope: 'user', root: null, config: isObj(info) ? info : {}, meta: {} });
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
      const hooksFrom = v => addHooks(isObj(v) && isObj(v.hooks) ? v.hooks : v, 'plugin', hookLabel, root);
      const mcpFrom = v => addMcp(isObj(v) && isObj(v.mcpServers) ? v.mcpServers : v, hookLabel, 'plugin', root);

      const hj = readFileOnce(path.join(root, 'hooks', 'hooks.json'));
      if (isObj(hj)) hooksFrom(hj);
      const mj = readFileOnce(path.join(root, '.mcp.json'));
      if (isObj(mj)) mcpFrom(mj);

      // Hooks / MCP servers declared in the plugin manifest (inline or by relative path).
      const manifest = read(path.join(root, '.claude-plugin', 'plugin.json'));
      if (isObj(manifest)) {
        const h = manifest.hooks;
        if (isObj(h)) hooksFrom(h);
        else for (const p of [].concat(typeof h === 'string' || Array.isArray(h) ? h : [])) {
          if (typeof p !== 'string') continue;
          const v = readFileOnce(relPath(p));
          if (isObj(v)) hooksFrom(v);
        }
        const m = manifest.mcpServers;
        if (isObj(m)) mcpFrom(m);
        else for (const p of [].concat(typeof m === 'string' || Array.isArray(m) ? m : [])) {
          if (typeof p !== 'string') continue;
          const v = readFileOnce(relPath(p));
          if (isObj(v)) mcpFrom(v);
        }
      }

      for (const mf of [path.join(root, 'monitors.json'), path.join(root, 'monitors', 'monitors.json')]) {
        const mon = read(mf);
        if (mon !== null) {
          add({ id: `monitor:${name}`, kind: 'monitor', name, scope: 'plugin', root, files: [mf], config: isObj(mon) ? mon : { monitors: mon }, meta: {} });
          break;
        }
      }
    }
  }

  // --- Marketplaces ---
  const known = read(path.join(claudeHome, 'plugins', 'known_marketplaces.json'));
  if (isObj(known)) for (const [name, info] of Object.entries(known)) addMarketplace(name, info);

  // --- Settings (user, then project) ---
  const settingsSources = [{ scope: 'user', dir: claudeHome }];
  if (projectDir) settingsSources.push({ scope: 'project', dir: path.join(projectDir, '.claude') });
  for (const { scope, dir } of settingsSources) {
    for (const f of ['settings.json', 'settings.local.json']) {
      const s = read(path.join(dir, f));
      if (!isObj(s)) continue;
      addHooks(s.hooks, scope, scope, null);
      if (isObj(s.statusLine)) {
        add({ id: `statusline:${scope}`, kind: 'statusline', name: 'statusLine', scope, root: null, config: s.statusLine, meta: {} });
      }
      if (isObj(s.extraKnownMarketplaces)) {
        for (const [name, info] of Object.entries(s.extraKnownMarketplaces)) addMarketplace(name, info);
      }
    }
  }

  // --- MCP servers: ~/.claude.json and project .mcp.json ---
  const cj = read(path.join(homeDir, '.claude.json'));
  if (isObj(cj)) {
    addMcp(cj.mcpServers, 'user', 'user', null);
    if (projectDir && isObj(cj.projects)) {
      const want = normDir(projectDir);
      for (const [k, v] of Object.entries(cj.projects)) {
        if (isObj(v) && normDir(k) === want) addMcp(v.mcpServers, 'project', 'project', projectDir);
      }
    }
  }
  if (projectDir) {
    const pm = read(path.join(projectDir, '.mcp.json'));
    if (isObj(pm)) addMcp(isObj(pm.mcpServers) ? pm.mcpServers : pm, 'project', 'project', projectDir);
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
      add({ id: `skill:${scope}:${e.name}`, kind: 'skill', name: e.name, scope, root, files: listFiles(root), meta: {} });
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
