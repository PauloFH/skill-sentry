import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
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

// Codex writes `.codex-marketplace-install.json` into the plugin root on the first start after `codex plugin add`
// from a git marketplace. Seen on the real installs (Windows and WSL): 185 bytes of 2-space pretty JSON with no
// trailing newline, exactly {"source_type": <word>, "source": <https URL with a short plain path>, "ref_name": null, "sparse_paths": [],
// "revision": <40-hex commit>} in that order. Only that exact shape at the top level is left out of a tree: the
// exact name, a regular file of at most CODEX_MARKER_MAX_SIZE bytes (bounded read), text equal byte for byte to
// the canonical pretty form of its own parse (no duplicate keys, comments or padding), every value pinned. Anything
// else (another key or type, a ref or sparse install, a directory of that name, a nested copy) is an ordinary
// file or dir, so the tree stays unknown and the marker can never carry a payload past the comparison.
const CODEX_MARKER = '.codex-marketplace-install.json';
const CODEX_MARKER_MAX_SIZE = 1024;
const CODEX_MARKER_KEYS = ['source_type', 'source', 'ref_name', 'sparse_paths', 'revision'];

/** True for a Codex install marker of exactly the expected shape (see CODEX_MARKER). Never throws. */
function isCodexMarker(root, rel, size) {
  if (rel !== CODEX_MARKER || size > CODEX_MARKER_MAX_SIZE) return false;
  try {
    const text = readListed(abs(root, rel), size)?.toString('utf8');
    if (!text) return false;
    const o = JSON.parse(text);
    if (o === null || typeof o !== 'object' || Array.isArray(o)) return false;
    if (Object.keys(o).join(',') !== CODEX_MARKER_KEYS.join(',')) return false;
    if (JSON.stringify(o, null, 2) !== text) return false;
    return typeof o.source_type === 'string' && /^[a-z]{1,16}$/.test(o.source_type)
      && typeof o.source === 'string' && /^https:\/\/[A-Za-z0-9.-]+\/[\w./-]{1,200}$/.test(o.source)
      && o.ref_name === null
      && Array.isArray(o.sparse_paths) && o.sparse_paths.length === 0
      && typeof o.revision === 'string' && /^[0-9a-f]{40}$/.test(o.revision);
  } catch {
    return false;
  }
}

// Never shipped: VCS and gitignored dev dirs of a checkout. Skipped on the running scanner's side only (it may
// run from a dev checkout); on the side of the copy under inspection they are files like any other.
const DEV_DIRS = new Set(['.git', 'node_modules', '.omc', '.superpowers', 'docs/superpowers']);
// Top-level dirs skipped in the copy being compared: only those the scanner also never reads (inventory SKIP_DIRS).
const OTHER_COPY_SKIP_DIRS = new Set(['.git', 'node_modules']);

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
 * Regular files under `root` as a Map of relpath (`/`-separated) -> size. Only install markers (Claude Code's
 * `.in_use/<pid>`, Codex's top-level CODEX_MARKER) are read (bounded); they are left out of the Map. null when the tree cannot be vouched for: a link or special file, a
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
          if (e.isDirectory()) {
            if (r === CODEX_MARKER) return null; // an (even empty) dir under the marker's name is never a marker
            if (!skipDirs?.has(r)) stack.push(r);
            continue;
          }
          if (!e.isFile()) return null; // symlink, junction, FIFO, socket, device
          const st = fs.lstatSync(abs(root, r));
          if (!st.isFile()) return null;
          if (INSTALL_MARKER.test(r)) {
            if (++markers > MAX_MARKERS || (markerBytes += st.size) > MAX_MARKER_BYTES) return null;
            if (isInstallMarker(root, r, st.size)) continue;
          }
          if (isCodexMarker(root, r, st.size)) continue; // top level only, at most one by construction
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
 * `root` holds exactly the regular files of `ref` (no extra, no missing; `refSkip` dirs of `ref` and install markers
 * aside, `rootSkip` dirs of `root` not entered), every file with identical bytes (CRLF and LF line ends count as
 * equal), and carries every relpath in `must`. Links, special files, limits, `deadline` or read errors -> false.
 */
function sameTree(root, ref, { must, refSkip, rootSkip, limits, deadline }) {
  for (const m of must) {
    if (!fs.lstatSync(abs(root, m)).isFile()) return false;
  }
  const mine = shippedFiles(ref, { skipDirs: refSkip, limits, deadline });
  if (!mine || !mine.size) return false;
  const theirs = shippedFiles(root, { allowed: new Set(mine.keys()), skipDirs: rootSkip, limits, deadline });
  if (!theirs || theirs.size !== mine.size) return false;
  for (const [rel, size] of theirs) if (!sameUpToEol(size, mine.get(rel))) return false;
  for (const [rel, size] of theirs) {
    if (late(deadline)) return false;
    const x = readListed(abs(root, rel), size);
    const y = readListed(abs(ref, rel), mine.get(rel));
    if (!x || !y || (!x.equals(y) && !lfBytes(x).equals(lfBytes(y)))) return false;
  }
  return true;
}

/**
 * Another installed copy of the running scanner: its set of regular files equals the running scanner's
 * shipped set (no extra, no missing; dev-only dirs of a checkout and install markers aside), every file with
 * identical bytes (CRLF and LF line ends count as equal), and it carries `skills/audit/scripts/guard.mjs` and
 * `.claude-plugin/plugin.json`. Links, special files, limits, `deadline` or read errors -> false (scanned as
 * usual). Never throws.
 */
export function isCopyOfSelf(root, selfRoot, { limits = COPY_LIMITS, deadline } = {}) {
  if (!root || !selfRoot) return false;
  try {
    if (realDir(root) === realDir(selfRoot)) return true;
    // m6: the other copy may carry a `.git` (or `node_modules`) dir too; nothing in either is ever executed and the
    // scanner never reads them. Every other extra file still makes the copy not-self.
    return sameTree(root, selfRoot, {
      must: ['skills/audit/scripts/guard.mjs', '.claude-plugin/plugin.json'], refSkip: DEV_DIRS, rootSkip: OTHER_COPY_SKIP_DIRS, limits, deadline,
    });
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
 * null. `releases` ({ hashes, sizes }) defaults to the embedded table (tests inject their own). `skipDirs`: top-level
 * dirs of `root` not entered (default `.git` and `node_modules`, see isCopyOfSelf). Never throws.
 */
export function knownRelease(root, { releases = { hashes: KNOWN_RELEASES, sizes: KNOWN_RELEASE_SIZES }, deadline, skipDirs = OTHER_COPY_SKIP_DIRS } = {}) {
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
    // A Codex install is a shallow git clone: its `.git` (and any `node_modules`) is skipped as in isCopyOfSelf (m6).
    const files = shippedFiles(root, { allowed, skipDirs, limits, deadline });
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

// ---- Self-manifest ----
// Every release writes skills/audit/scripts/lib/selfmanifest.json last in its prepare step (tools/ci/write-manifest.mjs):
// { "version": "x.y.z", "files": { "<relpath>": "<lfSha256>" } } over every file of the release tree except the manifest
// itself (and `.git`, install markers). The trust anchor is the manifest carried by the RUNNING scanner, next to this
// module; a copy's own selfmanifest.json is only one of its files, compared by hash with the running one, never read
// as a manifest. In a dev checkout the committed manifest is the last release's: the checkout itself differs from it,
// yet installed copies of that release still match it.

export const MANIFEST_REL = 'skills/audit/scripts/lib/selfmanifest.json';
const SKILL_PREFIX = 'skills/audit/';
const SKILL_MANIFEST_REL = MANIFEST_REL.slice(SKILL_PREFIX.length);
const DEFAULT_MANIFEST = fileURLToPath(new URL('./selfmanifest.json', import.meta.url));
const MANIFEST_MAX_BYTES = 1024 * 1024;
const VERSION_RE = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;
const HEX64 = /^[0-9a-f]{64}$/;
/** A relpath as the walk produces it: `/`-separated, relative, no empty, `.` or `..` segment, no control or `\`. */
const safeRel = r => typeof r === 'string' && r.length > 0 && r.length <= 1024 && !/[\\\x00-\x1f:]/.test(r)
  && r.split('/').every(s => s !== '' && s !== '.' && s !== '..');

/** The manifest text: `version`, then `files` with sorted keys; 2-space JSON, LF, trailing newline. */
export function serializeManifest({ version, files }) {
  const sorted = Object.fromEntries(Object.keys(files).sort().map(k => [k, files[k]]));
  return `${JSON.stringify({ version, files: sorted }, null, 2)}\n`;
}

let defaultManifest;
/**
 * `{ version, files, sha }` of a self-manifest file (`sha`: lfSha256 of its own bytes, what a copy's selfmanifest.json
 * must hash to), or null when it is missing, oversized, not a regular file or malformed. Never throws. The default
 * file (the running scanner's) is read once, lazily.
 */
export function loadSelfManifest(file = DEFAULT_MANIFEST) {
  const isDefault = file === DEFAULT_MANIFEST;
  if (isDefault && defaultManifest !== undefined) return defaultManifest;
  let out = null;
  try {
    const st = fs.lstatSync(file);
    const buf = st.isFile() && st.size <= MANIFEST_MAX_BYTES ? readListed(file, st.size) : null;
    const m = buf ? JSON.parse(buf.toString('utf8')) : null;
    if (isObj(m) && typeof m.version === 'string' && VERSION_RE.test(m.version) && isObj(m.files)
      && Object.entries(m.files).every(([k, v]) => safeRel(k) && k !== MANIFEST_REL && typeof v === 'string' && HEX64.test(v))) {
      out = { version: m.version, files: Object.fromEntries(Object.entries(m.files)), sha: lfSha256(buf) };
    }
  } catch {
    out = null;
  }
  if (isDefault) defaultManifest = out;
  return out;
}

/**
 * relpath -> lfSha256 a copy of `kind` must hold exactly: the whole manifest (plugin) or its skills/audit subset
 * re-rooted (skill), plus the manifest file itself hashed as the running one. null for a manifest that cannot vouch
 * for a skill-sentry tree (missing, empty, no scan.mjs).
 */
function manifestSet(manifest, kind) {
  if (!isObj(manifest?.files) || typeof manifest.sha !== 'string') return null;
  const out = new Map();
  for (const [rel, h] of Object.entries(manifest.files)) {
    if (kind === 'plugin') out.set(rel, h);
    else if (rel.startsWith(SKILL_PREFIX)) out.set(rel.slice(SKILL_PREFIX.length), h);
  }
  if (!out.has(kind === 'plugin' ? `${SKILL_PREFIX}scripts/scan.mjs` : 'scripts/scan.mjs')) return null;
  out.set(kind === 'plugin' ? MANIFEST_REL : SKILL_MANIFEST_REL, manifest.sha);
  return out;
}

/** `root` holds exactly the relpaths of `expected`, each with that LF-normalised SHA-256. Never throws. */
function matchesHashes(root, expected, { skipDirs, deadline }) {
  const files = shippedFiles(root, { allowed: new Set(expected.keys()), skipDirs, deadline });
  if (!files || files.size !== expected.size) return false;
  for (const [rel, size] of files) {
    if (late(deadline)) return false;
    const buf = readListed(abs(root, rel), size);
    if (!buf || lfSha256(buf) !== expected.get(rel)) return false;
  }
  return true;
}

/**
 * The skills/audit subset of a release table, re-rooted at the skill dir, for the releases that shipped a standalone
 * skill (their subset carries scripts/scan.mjs; a 0.1.x subset is a lone SKILL.md and is never a skill copy).
 */
function skillTables({ hashes, sizes } = {}) {
  const out = { hashes: {}, sizes: {} };
  for (const v of Object.keys(isObj(hashes) ? hashes : {})) {
    if (!isObj(hashes[v]) || !isObj(sizes?.[v]) || !Object.hasOwn(hashes[v], `${SKILL_PREFIX}scripts/scan.mjs`)) continue;
    out.hashes[v] = {};
    out.sizes[v] = {};
    for (const rel of Object.keys(hashes[v])) {
      if (!rel.startsWith(SKILL_PREFIX)) continue;
      out.hashes[v][rel.slice(SKILL_PREFIX.length)] = hashes[v][rel];
      out.sizes[v][rel.slice(SKILL_PREFIX.length)] = sizes[v][rel];
    }
  }
  return out;
}
let embeddedSkillTables;

/** The running scanner's skill dir: `<selfRoot>/skills/audit` in a plugin (or checkout) layout, else `selfRoot`. */
function selfSkillDir(selfRoot) {
  const inPlugin = path.join(selfRoot, 'skills', 'audit');
  try { if (fs.statSync(path.join(inPlugin, 'scripts', 'guard.mjs')).isFile()) return inPlugin; } catch { /* standalone */ }
  return selfRoot;
}

/**
 * Whether the running scanner can vouch for `dir` as a copy of skill-sentry. `kind` 'plugin' compares a whole plugin
 * tree, 'skill' a standalone skill dir (npx skills add). In order:
 *   path     - `dir` is the running scanner's own dir (its plugin root, or its skill dir), by real path;
 *   copy     - same files and bytes as the running tree (isCopyOfSelf, or the running skill dir for 'skill');
 *   manifest - exactly the running self-manifest's file set (plugin) or its skills/audit subset (skill);
 *   release  - exactly a KNOWN_RELEASES entry (or its skills/audit subset, from 0.2.0 on).
 * `version` is the release that matched (the running manifest's for path/copy/manifest, null without one). A plugin
 * copy may carry install markers and a `.git`/`node_modules` dir (a Codex git install); a skill copy only the
 * markers. `selfManifest` (default: the running scanner's) and `releases` (default: the embedded table) are seams
 * for tests. Never throws.
 */
export function matchSelf(dir, kind, { selfRoot = null, selfManifest, releases, deadline } = {}) {
  const no = { self: false, version: null, via: null };
  if (!dir || (kind !== 'plugin' && kind !== 'skill')) return no;
  try {
    const manifest = selfManifest === undefined ? loadSelfManifest() : selfManifest;
    const running = typeof manifest?.version === 'string' ? manifest.version : null;
    const plugin = kind === 'plugin';
    if (selfRoot) {
      const ref = plugin ? selfRoot : selfSkillDir(selfRoot);
      if (realDir(dir) === realDir(ref)) return { self: true, version: running, via: 'path' };
      const same = plugin ? isCopyOfSelf(dir, selfRoot, { deadline })
        : sameTree(dir, ref, { must: ['SKILL.md', 'scripts/guard.mjs'], refSkip: null, rootSkip: null, limits: COPY_LIMITS, deadline });
      if (same) return { self: true, version: running, via: 'copy' };
    }
    const skipDirs = plugin ? OTHER_COPY_SKIP_DIRS : null;
    const expected = manifestSet(manifest, kind);
    if (expected && matchesHashes(dir, expected, { skipDirs, deadline })) return { self: true, version: manifest.version, via: 'manifest' };
    let tables = releases ?? { hashes: KNOWN_RELEASES, sizes: KNOWN_RELEASE_SIZES };
    if (!plugin) tables = releases ? skillTables(releases) : (embeddedSkillTables ??= skillTables(tables));
    const version = knownRelease(dir, { releases: tables, deadline, skipDirs });
    return version === null ? no : { self: true, version, via: 'release' };
  } catch {
    return no;
  }
}

/** A standalone skill dir name that may hold skill-sentry: only this gates the (costly) copy check. */
export const isSkillSentryName = name => typeof name === 'string' && name.toLowerCase().includes('skill-sentry');

/**
 * Mark `comp` (a plugin or skill dir named after skill-sentry) as self when the running scanner can vouch for it
 * (matchSelf). A recorded older release also gets `comp.meta.knownRelease` (the version taken from the table key,
 * never from the copy), which the scanner reports as SKILL_SENTRY_OLD_VERSION. Otherwise `comp` is left as is and
 * scanned.
 */
export function markSkillSentryCopy(comp, root, selfRoot, { kind = 'plugin', releases, selfManifest, deadline } = {}) {
  const m = matchSelf(root, kind, { selfRoot, selfManifest, releases, deadline });
  if (!m.self) return;
  comp.self = true;
  if (m.via === 'release') comp.meta = { ...comp.meta, knownRelease: m.version };
}
