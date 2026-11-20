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
export function realDir(p) {
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
 * Link text naming a network (UNC, `//host`) or device-namespace path. Such a link is never
 * realpath'd or stat'ed: resolving it would open an SMB connection. `\\?\X:\...` is a local path.
 */
export function isRemoteLinkText(text) {
  const t = String(text ?? '');
  return /^[\\/]{2}/.test(t) && !/^[\\/]{2}\?[\\/][a-z]:/i.test(t);
}

/** Link text of `p` when it is a symlink/junction to a remote path, else null (no I/O beyond lstat/readlink). */
export function remoteLinkTarget(p) {
  try {
    if (!fs.lstatSync(p).isSymbolicLink()) return null;
    const t = fs.readlinkSync(p);
    return isRemoteLinkText(t) ? t : null;
  } catch { return null; }
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
  const rootRemote = remoteLinkTarget(dir);
  if (rootRemote !== null) {
    outside.push({ path: dir, target: rootRemote });
    return { files, truncated, skipped, timedOut, outside };
  }
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
        const remote = remoteLinkTarget(full);
        if (remote !== null) { outside.push({ path: full, target: remote }); continue; }
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

/**
 * True when `rp` stays inside `root`: lexically first (no fs call on an outside or UNC path), then
 * with no remote link on the way, then by real path (a link may point out). A missing file that is
 * lexically inside counts as inside (the caller's read reports it).
 */
export function isInsideRoot(root, rp) {
  let inside = isInside(normDir(rp), normDir(root));
  if (inside) {
    const rel = path.relative(root, rp).split(/[\\/]/).filter(Boolean);
    for (let i = 1; inside && i <= rel.length; i++) if (remoteLinkTarget(path.join(root, ...rel.slice(0, i))) !== null) inside = false;
  }
  if (inside) {
    try { inside = isInside(realKey(rp), realDir(root)); } catch { /* missing */ }
  }
  return inside;
}

// Stored config -> unredacted copy, for the scanner's rules only (never serialized: a WeakMap entry
// survives `{ ...component }` copies and is invisible to JSON.stringify).
const RAW_CONFIG = new WeakMap();

/** Unredacted config of a discovered component (falls back to the stored config). */
export function rawConfigOf(config) {
  return (config && RAW_CONFIG.get(config)) ?? config;
}

/** Attach the unredacted `raw` copy to a stored (redacted) config object; returns `stored`. */
export function bindRawConfig(stored, raw) {
  RAW_CONFIG.set(stored, raw);
  return stored;
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
  if (Array.isArray(out.args)) out.args = redactArgs(out.args.map(String), rawCopy.command);
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
    c.agent = 'claude';
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
    // Manifest-referenced files must stay inside the plugin root: lexically first (no fs call on an
    // outside or UNC path), then no remote link on the way, then by real path (a link may point out).
    const readInside = rp => {
      if (!isInsideRoot(root, rp)) {
        configFindings.push({ ruleId: 'CONFIG_UNREADABLE', category: 'config', severity: 'info', line: 0, snippet: 'path outside plugin root', file: rp });
        return null;
      }
      return readFileOnce(rp);
    };
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
        const v = readInside(rp);
        if (isObj(v)) hooksFrom(v, rp);
      }
      const m = manifest.mcpServers;
      if (isObj(m)) mcpFrom(m, manifestFile);
      else for (const p of [].concat(typeof m === 'string' || Array.isArray(m) ? m : [])) {
        if (typeof p !== 'string') continue;
        const rp = relPath(p);
        const v = readInside(rp);
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
  // Entries of a skills root count against the directory cap; past the deadline a skill stays listed
  // (incomplete) but is not walked.
  const maxEntries = { ...DEFAULT_LIMITS, ...limits }.maxDirs;
  for (const { scope, dir } of skillRoots) {
    let entries = [];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { /* absent */ }
    let seenEntries = 0;
    for (const e of entries) {
      const root = path.join(dir, e.name);
      if (!e.isDirectory() && !e.isSymbolicLink()) continue;
      if (++seenEntries > maxEntries) {
        configFindings.push({
          ruleId: 'SCAN_TRUNCATED', category: 'config', severity: 'info', line: 0, file: dir,
          snippet: `skills directory has more than ${maxEntries} entries; the rest were not inspected`,
        });
        break;
      }
      const late = deadline !== undefined && Date.now() >= deadline;
      const remote = e.isSymbolicLink() ? remoteLinkTarget(root) : null;
      if (remote === null && !fs.existsSync(path.join(root, 'SKILL.md'))) continue;
      const comp = { id: `skill:${scope}:${e.name}`, kind: 'skill', name: e.name, scope, root, meta: {} };
      if (remote !== null) {
        // Linked to a network path: listed, never read (no SMB connection).
        comp.files = [];
        comp.meta.symlinksOutside = [{ path: root, target: remote }];
      } else if (late && skillFiles) {
        comp.files = [];
        comp.meta.filesTruncated = true;
        comp.meta.incomplete = true;
      } else if (skillFiles) {
        // skillFiles: false leaves the walk to scanComponent (the guard scans only the attributed component).
        const r = listFiles(root, limits, { deadline });
        comp.files = r.files;
        if (r.truncated || r.timedOut) comp.meta.filesTruncated = true;
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
