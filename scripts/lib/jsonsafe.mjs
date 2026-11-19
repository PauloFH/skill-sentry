import fs from 'node:fs';

const MAX_JSON_BYTES = 5 * 1024 * 1024;

/**
 * Read and parse a JSON file without throwing. Strips a leading BOM. Only regular files up to 5 MB are
 * read: a device, FIFO or directory (`/dev/tty`, `\\.\CON`) never blocks or floods the caller.
 * @returns {{ ok: true, value: any } | { ok: false, error: string }}
 */
export function readJsonSafe(file) {
  let text;
  try {
    const st = fs.statSync(file);
    if (!st.isFile()) return { ok: false, error: 'not a regular file' };
    if (st.size > MAX_JSON_BYTES) return { ok: false, error: `too large (${st.size} bytes, limit ${MAX_JSON_BYTES})` };
    text = fs.readFileSync(file, 'utf8');
  } catch (e) {
    return { ok: false, error: e && e.code === 'ENOENT' ? 'missing' : String((e && e.message) || e) };
  }
  try {
    return { ok: true, value: JSON.parse(text.replace(/^﻿/, '')) };
  } catch (e) {
    return { ok: false, error: String((e && e.message) || e) };
  }
}
