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
  const src = text.replace(/^﻿/, '');
  try {
    return { ok: true, value: JSON.parse(src) };
  } catch (e) {
    return { ok: false, error: jsonErrorAt(src, e) };
  }
}

/**
 * Parse error as a position only. V8's message quotes the source near the error (on Node 20+ e.g.
 * `..."I_TOKEN": 'value... is not valid JSON`), which may be a credential: it is never returned.
 */
function jsonErrorAt(src, e) {
  const msg = String((e && e.message) || '');
  const lc = /\(line (\d+) column (\d+)\)/.exec(msg);
  if (lc) return `invalid JSON at line ${lc[1]} column ${lc[2]}`;
  const pos = /at position (\d+)/.exec(msg);
  if (pos) {
    const before = src.slice(0, Number(pos[1]));
    const line = before.split('\n').length;
    return `invalid JSON at line ${line} column ${before.length - before.lastIndexOf('\n')}`;
  }
  return 'invalid JSON';
}
