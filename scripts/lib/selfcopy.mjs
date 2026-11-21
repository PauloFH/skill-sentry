import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { normalizePath } from './text.mjs';
import { KNOWN_RELEASES, KNOWN_RELEASE_SIZES } from './releases.mjs';

// Other installed copies of skill-sentry (the Claude Code and Codex installs, or an older release next to a
// newer one). Their rules and tests quote the very patterns the scanner looks for, so scanning them as a
// third-party plugin reports skill-sentry itself as malicious. A copy is exempt only when the running scanner
// can vouch for every byte: a copy of itself, or a release whose hashes it carries (KNOWN_RELEASES). Nothing
// the copy says about itself (name, manifest, version) is trusted; the name only decides whether to look.

const normDir = p => normalizePath(path.resolve(p)).replace(/\/+$/, '');

/** Canonical directory key: realpath when it exists (symlinks/junctions resolved), case-insensitive on win32. */
export function realDir(p) {
  let r = path.resolve(p);
  try { r = fs.realpathSync.native(r); } catch { /* missing: compare the resolved form */ }
  return normDir(r);
}

const COPY_LIMITS = { maxFiles: 3000, maxDirs: 500, maxBytes: 64 * 1024 * 1024 };

/** LF-normalised bytes (CRLF -> LF only; every other byte kept): a git autocrlf checkout equals the LF bundle. */
export const lfBytes = buf => Buffer.from(buf.toString('latin1').replace(/\r\n/g, '\n'), 'latin1');
/** SHA-256 (hex) of the LF-normalised bytes: the hash stored in KNOWN_RELEASES. */
export const lfSha256 = buf => crypto.createHash('sha256').update(lfBytes(buf)).digest('hex');

// Claude Code writes `.in_use/<pid>` (a 48-byte JSON lock: pid and process start time) into every plugin
// cache dir it has loaded. Only that exact shape is ignored: a top-level `.in_use` dir, a digits-only name, a
// small regular file. Anything else there (another name, a subdir, a bigger file) is an unknown file.
const INSTALL_MARKER = /^\.in_use\/\d{1,10}$/;
const INSTALL_MARKER_MAX_BYTES = 256;
const isInstallMarker = (rel, size) => INSTALL_MARKER.test(rel) && size <= INSTALL_MARKER_MAX_BYTES;

// Never shipped: VCS and gitignored dev dirs of a checkout. Skipped on the running scanner's side only (it may
// run from a dev checkout); on the side of the copy under inspection they are files like any other.
const DEV_DIRS = new Set(['.git', 'node_modules', '.omc', '.superpowers', 'docs/superpowers']);

const late = deadline => deadline !== undefined && Date.now() >= deadline;
const abs = (root, rel) => path.join(root, ...rel.split('/'));

/**
 * Regular files under `root` as a Map of relpath (`/`-separated) -> size, without reading any file.
 * null when the tree cannot be vouched for: a link or special file, a read error, a limit or `deadline` hit,
 * or (with `allowed`) the first file whose relpath is not in `allowed`. Install markers are left out.
 * Directories in `skipDirs` (relpaths) are not entered. Never throws.
 */
export function shippedFiles(root, { allowed = null, skipDirs = null, limits = COPY_LIMITS, deadline } = {}) {
  const { maxFiles, maxDirs, maxBytes } = { ...COPY_LIMITS, ...limits };
  const out = new Map();
  let dirs = 0;
  let bytes = 0;
  const stack = [''];
  try {
    while (stack.length) {
      if (late(deadline) || ++dirs > maxDirs) return null;
      const rel = stack.pop();
      for (const e of fs.readdirSync(rel ? abs(root, rel) : root, { withFileTypes: true })) {
        const r = rel ? `${rel}/${e.name}` : e.name;
        if (e.isDirectory()) { if (!skipDirs?.has(r)) stack.push(r); continue; }
        if (!e.isFile()) return null; // symlink, junction, FIFO, socket, device
        const st = fs.lstatSync(abs(root, r));
        if (!st.isFile()) return null;
        if (isInstallMarker(r, st.size)) continue;
        if (allowed && !allowed.has(r)) return null;
        if (out.size >= maxFiles || (bytes += st.size) > maxBytes) return null;
        out.set(r, st.size);
      }
    }
  } catch {
    return null;
  }
  return out;
}

// A CRLF file is at most twice its LF size (every byte a newline); any wider gap cannot be the same file.
const sameUpToEol = (a, b) => Math.max(a, b) <= 2 * Math.min(a, b);

/**
 * Another installed copy of the running scanner: its set of regular files equals the running scanner's
 * shipped set (no extra, no missing; dev-only dirs of a checkout and install markers aside), every file with
 * identical bytes (CRLF and LF line ends count as equal), and it carries `scripts/guard.mjs` and
 * `.claude-plugin/plugin.json`. Links, special files, limits, `deadline` or read errors -> false (scanned as
 * usual). Never throws.
 */
export function isCopyOfSelf(root, selfRoot, { limits = COPY_LIMITS, deadline } = {}) {
  if (!root || !selfRoot) return false;
  try {
    if (realDir(root) === realDir(selfRoot)) return true;
    for (const must of ['scripts/guard.mjs', '.claude-plugin/plugin.json']) {
      if (!fs.lstatSync(abs(root, must)).isFile()) return false;
    }
    const mine = shippedFiles(selfRoot, { skipDirs: DEV_DIRS, limits, deadline });
    if (!mine || !mine.size) return false;
    const theirs = shippedFiles(root, { allowed: new Set(mine.keys()), limits, deadline });
    if (!theirs || theirs.size !== mine.size) return false;
    for (const [rel, size] of theirs) if (!sameUpToEol(size, mine.get(rel))) return false;
    for (const rel of theirs.keys()) {
      if (late(deadline)) return false;
      const x = fs.readFileSync(abs(root, rel));
      const y = fs.readFileSync(abs(selfRoot, rel));
      if (!x.equals(y) && !lfBytes(x).equals(lfBytes(y))) return false;
    }
    return true;
  } catch {
    return false;
  }
}

const isObj = v => v !== null && typeof v === 'object' && !Array.isArray(v);

/**
 * The release version whose table entry the tree at `root` equals exactly (same set of regular files, same
 * LF-normalised SHA-256 for each), else null. Cheap checks first: the walk stops at the first relpath no
 * release has, then file count and sizes (LF size up to twice it, for CRLF) are compared before any byte is
 * read, and hashing stops at the first mismatch. Links, special files, read errors, limits or `deadline` ->
 * null. `releases` ({ hashes, sizes }) defaults to the embedded table (tests inject their own). Never throws.
 */
export function knownRelease(root, { releases = { hashes: KNOWN_RELEASES, sizes: KNOWN_RELEASE_SIZES }, deadline } = {}) {
  try {
    const hashes = isObj(releases?.hashes) ? releases.hashes : {};
    const sizes = isObj(releases?.sizes) ? releases.sizes : {};
    const versions = Object.keys(hashes).filter(v => isObj(hashes[v]) && isObj(sizes[v]) && Object.keys(hashes[v]).length);
    if (!root || !versions.length) return null;
    const allowed = new Set(versions.flatMap(v => Object.keys(hashes[v])));
    const total = v => Object.values(sizes[v]).reduce((a, n) => a + (Number.isInteger(n) ? n : 0), 0);
    const limits = {
      maxFiles: Math.max(...versions.map(v => Object.keys(hashes[v]).length)),
      maxBytes: Math.max(...versions.map(v => 2 * total(v))),
    };
    const files = shippedFiles(root, { allowed, limits, deadline });
    if (!files) return null;
    candidates: for (const v of versions) {
      const names = Object.keys(hashes[v]);
      if (names.length !== files.size) continue;
      for (const n of names) {
        const lfSize = sizes[v][n];
        const size = files.get(n);
        if (size === undefined || !Number.isInteger(lfSize) || size < lfSize || size > 2 * lfSize) continue candidates;
      }
      for (const n of names) {
        if (late(deadline)) return null;
        const buf = fs.readFileSync(abs(root, n));
        if (buf.length > 2 * sizes[v][n] || lfSha256(buf) !== hashes[v][n]) continue candidates;
      }
      return v;
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Mark `comp` (a plugin dir named skill-sentry, not the running scanner's own dir) as self when the running
 * scanner can vouch for it: a copy of itself, or a known release (then `comp.meta.knownRelease` holds the
 * version taken from the table key, never from the copy). Otherwise `comp` is left as is and scanned.
 */
export function markSkillSentryCopy(comp, root, selfRoot, { releases, deadline } = {}) {
  if (isCopyOfSelf(root, selfRoot, { deadline })) { comp.self = true; return; }
  const version = knownRelease(root, { ...(releases ? { releases } : {}), deadline });
  if (version !== null) {
    comp.self = true;
    comp.meta = { ...comp.meta, knownRelease: version };
  }
}
