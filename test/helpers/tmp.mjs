import { after } from 'node:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

/**
 * Remove a test tmp dir. Every symlink/junction inside it is unlinked first, never followed (a junction
 * to a drive root must not be recursed into); when a link cannot be unlinked the dir is left alone.
 */
export function removeTree(dir) {
  try {
    if (fs.lstatSync(dir).isSymbolicLink()) { fs.unlinkSync(dir); return; }
  } catch { return; }
  const unlinkLinks = d => {
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return true; }
    let ok = true;
    for (const e of entries) {
      const p = path.join(d, e.name);
      if (e.isSymbolicLink()) {
        try { fs.unlinkSync(p); } catch { try { fs.rmdirSync(p); } catch { ok = false; } }
      } else if (e.isDirectory()) ok = unlinkLinks(p) && ok;
    }
    return ok;
  };
  if (unlinkLinks(dir)) {
    try { fs.rmSync(dir, { recursive: true, force: true, maxRetries: 2 }); } catch { /* best effort */ }
  }
}

/**
 * `tmp(name?)` creates `%TEMP%/<prefix><name>-XXXXXX`; every dir created is removed in an `after()` hook
 * of the calling test file. Call at module top level. The path is canonical (realpath): on a Windows runner whose
 * %TEMP% is an 8.3 alias (`C:\Users\RUNNER~1\…`), an absolute path built from it would otherwise be an unusual
 * form (Ruling K) in every test that writes one out. Tests of the 8.3 forms build them on purpose.
 */
export function tmpFactory(prefix) {
  const dirs = [];
  after(() => { for (const d of dirs) removeTree(d); });
  return (name = '') => {
    const d = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), `${prefix}${name ? `${name}-` : ''}`)));
    dirs.push(d);
    return d;
  };
}
