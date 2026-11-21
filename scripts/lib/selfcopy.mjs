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

// Claude Code writes `.in_use/<pid>` into every plugin cache dir it has loaded: a JSON lock of exactly the form
// {"pid":<pid>,"procStartFt":"<digits>"} (48 bytes as seen; the pid equals the file name). Only that exact shape
// is left out of a tree: a top-level `.in_use` dir, a digits-only name, content matching the form byte for byte
// (read with a bounded read), at most MAX_MARKERS files and MAX_MARKER_BYTES in total. Anything else (another
// name or content, a subdir, one marker too many) makes the tree unknown, so markers can never carry a payload.
const INSTALL_MARKER = /^\.in_use\/(\d{1,10})$/;
const MARKER_BODY = /^\{"pid":(\d{1,10}),"procStartFt":"\d{1,20}"\}$/;
const MARKER_MAX_SIZE = 64;
const MAX_MARKERS = 16;
const MAX_MARKER_BYTES = 4096;

// Never shipped: VCS and gitignored dev dirs of a checkout. Skipped on the running scanner's side only (it may
// run from a dev checkout); on the side of the copy under inspection they are files like any other.
const DEV_DIRS = new Set(['.git', 'node_modules', '.omc', '.superpowers', 'docs/superpowers']);

const late = deadline => deadline !== undefined && Date.now() >= deadline;
const abs = (root, rel) => path.join(root, ...rel.split('/'));

/**
 * Bytes of `file` when it is still a regular file of exactly `size` bytes (the size seen when listing), else
 * null. The descriptor is checked with fstat after opening (a file swapped or resized since the listing does
 * not match) and at most `size` bytes are read. Never throws.
 */
export function readListed(file, size) {
  if (!Number.isInteger(size) || size < 0) return null;
  let fd;
  try {
    fd = fs.openSync(file, 'r');
    const st = fs.fstatSync(fd);
    if (!st.isFile() || st.size !== size) return null;
    const buf = Buffer.alloc(size);
    for (let off = 0; off < size;) {
      const n = fs.readSync(fd, buf, off, size - off, off);
      if (n === 0) return null; // shrank while reading
      off += n;
    }
    return buf;
  } catch {
    return null;
  } finally {
    if (fd !== undefined) try { fs.closeSync(fd); } catch { /* already closed */ }
  }
}

/** True for a Claude Code in-use marker of exactly the expected shape (see INSTALL_MARKER). */
function isInstallMarker(root, rel, size) {
  const m = INSTALL_MARKER.exec(rel);
  if (!m || size > MARKER_MAX_SIZE) return false;
  const body = MARKER_BODY.exec(readListed(abs(root, rel), size)?.toString('latin1') ?? '');
  return body !== null && body[1] === m[1];
}

/**
 * Regular files under `root` as a Map of relpath (`/`-separated) -> size. Only install markers are read
 * (bounded); they are left out of the Map. null when the tree cannot be vouched for: a link or special file, a
 * read error, a limit (files, dirs, bytes, markers) or `deadline` hit (checked on every entry), or (with
 * `allowed`) the first file whose relpath is not in `allowed`. Directories in `skipDirs` (relpaths) are not
 * entered. Never throws.
 */
export function shippedFiles(root, { allowed = null, skipDirs = null, limits = COPY_LIMITS, deadline } = {}) {
  const { maxFiles, maxDirs, maxBytes } = { ...COPY_LIMITS, ...limits };
  const out = new Map();
  let dirs = 0;
  let bytes = 0;
  let markers = 0;
  let markerBytes = 0;
  const stack = [''];
  try {
    while (stack.length) {
      if (late(deadline) || ++dirs > maxDirs) return null;
      const rel = stack.pop();
      // Iterated entry by entry (not readdirSync): a huge directory is abandoned as soon as a check fails.
      const dir = fs.opendirSync(rel ? abs(root, rel) : root);
      try {
        for (let e = dir.readSync(); e !== null; e = dir.readSync()) {
          if (late(deadline)) return null;
          const r = rel ? `${rel}/${e.name}` : e.name;
          if (e.isDirectory()) { if (!skipDirs?.has(r)) stack.push(r); continue; }
          if (!e.isFile()) return null; // symlink, junction, FIFO, socket, device
          const st = fs.lstatSync(abs(root, r));
          if (!st.isFile()) return null;
          if (INSTALL_MARKER.test(r)) {
            if (++markers > MAX_MARKERS || (markerBytes += st.size) > MAX_MARKER_BYTES) return null;
            if (isInstallMarker(root, r, st.size)) continue;
          }
          if (allowed && !allowed.has(r)) return null;
          if (out.size >= maxFiles || (bytes += st.size) > maxBytes) return null;
          out.set(r, st.size);
        }
      } finally {
        dir.closeSync();
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
    for (const [rel, size] of theirs) {
      if (late(deadline)) return false;
      const x = readListed(abs(root, rel), size);
      const y = readListed(abs(selfRoot, rel), mine.get(rel));
      if (!x || !y || (!x.equals(y) && !lfBytes(x).equals(lfBytes(y)))) return false;
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
        const buf = readListed(abs(root, n), files.get(n)); // size already within [lfSize, 2*lfSize]
        if (!buf || lfSha256(buf) !== hashes[v][n]) continue candidates;
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
