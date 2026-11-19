import fs from 'node:fs';

/**
 * Read and parse a JSON file without throwing. Strips a leading BOM.
 * @returns {{ ok: true, value: any } | { ok: false, error: string }}
 */
export function readJsonSafe(file) {
  let text;
  try {
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
