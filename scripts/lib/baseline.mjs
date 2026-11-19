import path from 'node:path';
import crypto from 'node:crypto';
import { readJson, writeJsonAtomic, quarantine } from './datadir.mjs';

const FILE = 'baseline.json';
const CONFIG_PSEUDO_FILE = '<config>';

/** Map relPath -> sha256 for one scan result (config hashed as pseudo-file "<config>"). */
function fileMap(result) {
  const files = {};
  for (const f of result.files ?? []) files[f.path] = f.sha256;
  const cfg = result.component?.config;
  if (cfg !== undefined && cfg !== null && !(CONFIG_PSEUDO_FILE in files)) {
    files[CONFIG_PSEUDO_FILE] = crypto.createHash('sha256').update(JSON.stringify(cfg)).digest('hex');
  }
  return files;
}

function validBaseline(b) {
  return b && b.version === 1 && b.components && typeof b.components === 'object' && !Array.isArray(b.components);
}

/**
 * Load the baseline. Missing or corrupt file -> null (treated as first run).
 * Use baselineLoadError(dir) to tell "corrupt" apart from "missing".
 */
export function loadBaseline(dir) {
  const r = readJson(path.join(dir, FILE));
  return r.status === 'ok' && validBaseline(r.value) ? r.value : null;
}

/** Returns a description if baseline.json exists but is unreadable/invalid, else null. */
export function baselineLoadError(dir) {
  const r = readJson(path.join(dir, FILE));
  if (r.status === 'corrupt') return r.error;
  if (r.status === 'ok' && !validBaseline(r.value)) return 'invalid baseline structure';
  return null;
}

export function saveBaseline(dir, results) {
  const file = path.join(dir, FILE);
  if (baselineLoadError(dir)) quarantine(file);
  const components = {};
  for (const r of results) components[r.component.id] = { files: fileMap(r) };
  writeJsonAtomic(file, { version: 1, createdAt: new Date().toISOString(), components });
}

export function diffBaseline(prev, results) {
  const ids = results.map(r => r.component.id);
  if (!prev) return { firstRun: true, added: ids, removed: [], changed: [] };
  const old = prev.components ?? {};
  const seen = new Set(ids);
  const added = ids.filter(id => !Object.hasOwn(old, id));
  const removed = Object.keys(old).filter(id => !seen.has(id));
  const changed = [];
  for (const r of results) {
    const id = r.component.id;
    if (!Object.hasOwn(old, id)) continue;
    const before = old[id].files ?? {};
    const after = fileMap(r);
    const files = [];
    for (const p of Object.keys(after)) if (before[p] !== after[p]) files.push(p);
    for (const p of Object.keys(before)) if (!(p in after)) files.push(p);
    if (files.length) changed.push({ id, files });
  }
  return { firstRun: false, added, removed, changed };
}
