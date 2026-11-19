import path from 'node:path';
import { readJson, writeJsonAtomic, quarantine } from './datadir.mjs';

const FILE = 'allowlist.json';
const isStr = v => typeof v === 'string' && v.length > 0;

function validEntry(e) {
  if (!e || typeof e !== 'object') return false;
  if (e.type === 'finding') return isStr(e.componentId) && isStr(e.ruleId) && isStr(e.file) && isStr(e.sha256);
  if (e.type === 'command') return isStr(e.ruleId) && isStr(e.command);
  return false;
}

/** Load the allowlist. Missing/corrupt -> empty. Malformed entries are dropped. */
export function loadAllowlist(dir) {
  const r = readJson(path.join(dir, FILE));
  const entries = r.status === 'ok' && r.value && Array.isArray(r.value.entries) ? r.value.entries.filter(validEntry) : [];
  return { version: 1, entries };
}

/** Description if allowlist.json exists but is unreadable/not an object with `entries`, else null. */
export function allowlistLoadError(dir) {
  const r = readJson(path.join(dir, FILE));
  if (r.status === 'corrupt') return r.error;
  if (r.status === 'ok' && !(r.value && Array.isArray(r.value.entries))) return 'invalid allowlist structure';
  return null;
}

export function addAllowEntry(dir, entry) {
  if (!validEntry(entry)) throw new Error('invalid allowlist entry');
  const file = path.join(dir, FILE);
  if (allowlistLoadError(dir)) quarantine(file); // never overwrite a user-edited file we cannot parse
  const al = loadAllowlist(dir);
  al.entries.push({ addedAt: new Date().toISOString(), ...entry });
  writeJsonAtomic(file, al);
}

export function isFindingAllowed(al, { componentId, ruleId, file, sha256 }) {
  return al.entries.some(e => e.type === 'finding' && e.componentId === componentId && e.ruleId === ruleId && e.file === file && e.sha256 === sha256);
}

export function isCommandAllowed(al, { ruleId, command }) {
  return al.entries.some(e => e.type === 'command' && e.ruleId === ruleId && e.command === command);
}
