import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';

/** Data directory path (env SKILL_SENTRY_DATA_DIR or ~/.claude/skill-sentry), without touching the disk. */
export function dataDirPath() {
  return process.env.SKILL_SENTRY_DATA_DIR || path.join(os.homedir(), '.claude', 'skill-sentry');
}

/** Data directory: env SKILL_SENTRY_DATA_DIR or ~/.claude/skill-sentry. Created on demand. */
export function dataDir() {
  const dir = dataDirPath();
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

/** Atomic JSON write: tmp file in the same directory, then rename. Tmp is removed on failure. */
export function writeJsonAtomic(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.tmp-${process.pid}-${crypto.randomBytes(4).toString('hex')}`;
  try {
    fs.writeFileSync(tmp, JSON.stringify(value, null, 2) + '\n');
    fs.renameSync(tmp, file);
  } finally {
    try { fs.rmSync(tmp, { force: true }); } catch { /* best effort */ }
  }
}

/**
 * Read a JSON file without throwing.
 * @returns {{ status: 'missing'|'ok'|'corrupt', value?: any, error?: string }}
 */
export function readJson(file) {
  let text;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch (e) {
    if (e.code === 'ENOENT') return { status: 'missing' };
    return { status: 'corrupt', error: e.message };
  }
  try {
    return { status: 'ok', value: JSON.parse(text) };
  } catch (e) {
    return { status: 'corrupt', error: e.message };
  }
}

/** Move a corrupt file aside (`<file>.corrupt-<ts>`) so it is never silently overwritten. */
export function quarantine(file) {
  try { fs.renameSync(file, `${file}.corrupt-${Date.now()}`); } catch { /* best effort */ }
}
