import path from 'node:path';
import crypto from 'node:crypto';
import { readJson, writeJsonAtomic, quarantine } from './datadir.mjs';

const FILE = 'baseline.json';
const CONFIG_PSEUDO_FILE = '<config>';

// All path/id maps are null-prototype: file names and ids are attacker-controlled.
const nullMap = () => Object.create(null);
const has = (o, k) => Object.hasOwn(o, k);

/** Map relPath -> sha256 for one scan result (config hashed as pseudo-file "<config>"). */
export function fileMap(result) {
  const files = nullMap();
  for (const f of result.files ?? []) files[f.path] = f.sha256;
  const cfg = result.component?.config;
  if (cfg !== undefined && cfg !== null && !has(files, CONFIG_PSEUDO_FILE)) {
    files[CONFIG_PSEUDO_FILE] = crypto.createHash('sha256').update(JSON.stringify(cfg)).digest('hex');
  }
  return files;
}

/** Validate parsed baseline JSON. Returns { baseline|null, dropped: string[] } with null-prototype maps. */
function sanitize(b) {
  if (!b || b.version !== 1 || !b.components || typeof b.components !== 'object' || Array.isArray(b.components)) {
    return { baseline: null, dropped: [], error: 'invalid baseline structure' };
  }
  const components = nullMap();
  const dropped = [];
  for (const id of Object.keys(b.components)) {
    const entry = b.components[id];
    const files = entry && typeof entry === 'object' ? entry.files : null;
    if (!files || typeof files !== 'object' || Array.isArray(files) || !Object.values(files).every(v => typeof v === 'string')) {
      dropped.push(id);
      continue;
    }
    const copy = nullMap();
    for (const p of Object.keys(files)) copy[p] = files[p];
    components[id] = { files: copy };
  }
  const error = dropped.length ? `invalid baseline component entries dropped: ${dropped.join(', ')}` : null;
  return { baseline: { version: 1, createdAt: b.createdAt, components }, dropped, error };
}

/**
 * Load the baseline. Missing or corrupt file -> null (treated as first run).
 * Invalid component entries are dropped. Use baselineLoadError(dir) to learn about problems.
 */
export function loadBaseline(dir) {
  const r = readJson(path.join(dir, FILE));
  return r.status === 'ok' ? sanitize(r.value).baseline : null;
}

/** Returns a description if baseline.json is unreadable/invalid or had entries dropped, else null. */
export function baselineLoadError(dir) {
  const r = readJson(path.join(dir, FILE));
  if (r.status === 'corrupt') return r.error;
  if (r.status === 'ok') return sanitize(r.value).error;
  return null;
}

export function saveBaseline(dir, results) {
  const file = path.join(dir, FILE);
  const err = baselineLoadError(dir);
  const prev = loadBaseline(dir);
  if (err) quarantine(file);
  const components = nullMap();
  for (const r of results) {
    const id = r.component.id;
    const files = fileMap(r);
    if (r.incomplete && prev && has(prev.components, id)) {
      // Truncated scan: never drop files that simply were not reached.
      components[id] = { files: Object.assign(nullMap(), prev.components[id].files, files) };
    } else {
      components[id] = { files };
    }
  }
  writeJsonAtomic(file, { version: 1, createdAt: new Date().toISOString(), components });
}

export function diffBaseline(prev, results) {
  const ids = results.map(r => r.component.id);
  if (!prev) return { firstRun: true, added: ids, removed: [], changed: [], incomplete: [] };
  const old = prev.components ?? nullMap();
  const seen = new Set(ids);
  const added = ids.filter(id => !has(old, id));
  const removed = Object.keys(old).filter(id => !seen.has(id));
  const changed = [];
  const incomplete = [];
  for (const r of results) {
    const id = r.component.id;
    if (r.incomplete) incomplete.push(id);
    if (!has(old, id)) continue;
    const before = old[id]?.files ?? nullMap();
    const after = fileMap(r);
    const files = [];
    for (const p of Object.keys(after)) if (!has(before, p) || before[p] !== after[p]) files.push(p);
    if (!r.incomplete) for (const p of Object.keys(before)) if (!has(after, p)) files.push(p);
    if (files.length) changed.push({ id, files });
  }
  return { firstRun: false, added, removed, changed, incomplete };
}
