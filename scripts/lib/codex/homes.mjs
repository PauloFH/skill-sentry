// Codex homes to inventory. Never spawns a process: WSL homes are found through the `\\wsl.localhost\`
// filesystem. Every fs call is wrapped and deadline-checked; failures become problem lines, never throws.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { realDir } from '../inventory.mjs';

export const WSL_ROOT = '\\\\wsl.localhost\\';
const MAX_DISTROS = 32;
const MAX_USERS = 64;
const MAX_SETTINGS_BYTES = 2 * 1024 * 1024;
// Probed when nothing else names a distro: a missing one fails in ~1-2 ms (code UNKNOWN), silently.
export const COMMON_DISTROS = ['Ubuntu', 'Ubuntu-24.04', 'Ubuntu-22.04', 'Ubuntu-20.04', 'Debian', 'kali-linux', 'openSUSE-Tumbleweed', 'archlinux', 'FedoraLinux'];
// A distro name becomes a path segment: no separators, no `.`/`..`, no drive/stream colon.
const validDistro = n => typeof n === 'string' && n.trim() !== '' && !/[\\/:*?"<>|\0]/.test(n) && !/^\.+$/.test(n.trim());

const isDir = p => { try { return fs.statSync(p).isDirectory(); } catch { return false; } };

/**
 * Codex homes, in a stable order: the default home, then explicit homes, then WSL homes.
 *
 * Labels (component ids are `codex[<label>]:...`):
 * - `win`: the default home when it is `<homeDir>/.codex` (whatever the OS).
 * - `h<n>`: any other home: `$CODEX_HOME` pointing elsewhere (still the default home: it keeps the user
 *   home and system layer), `SKILL_SENTRY_CODEX_HOME` (replaces the default home) and `explicit` dirs.
 * - `wsl:<distro>:<user>`: `<wslRoot>\<distro>\home\<user>\.codex` (win32 + includeWsl only).
 *
 * WSL distro candidates (Ruling R7; the `\\wsl.localhost\` server root itself cannot be listed on
 * Windows, so names come from elsewhere), deduped case-insensitively, probed in this order:
 *   1. `SKILL_SENTRY_WSL_DISTROS` (comma list): a failing probe is a problem line;
 *   2. entries of `wslRoot` when it can be listed (`listRoot`; kept for systems where it works);
 *   3. Windows Terminal WSL profile names (`<localAppData>\Packages\Microsoft.WindowsTerminal*\LocalState\
 *      settings.json`, `<localAppData>\Microsoft\Windows Terminal\settings.json`);
 *   4. COMMON_DISTROS. Failing probes of 2-4 are skipped silently.
 *
 * Each entry: `{ label, root, userHome?, systemDir?, distroRoot? }`. `userHome` (where `~/.agents/skills`
 * lives) and `systemDir` (system config layer) are set for the default and WSL homes only: an explicit
 * home is read on its own, so a test or `--codex-home` dir never reaches into a real home.
 * Missing explicit homes and WSL listing failures are pushed onto `problems` (strings).
 */
export function codexHomes({
  env = process.env, homeDir = os.homedir(), platform = process.platform, deadline,
  includeWsl = true, explicit = [], wslRoot = WSL_ROOT, listRoot = true, localAppData = env.LOCALAPPDATA, problems = [],
} = {}) {
  const homes = [];
  const seen = new Set();
  let n = 0;
  const push = h => {
    const key = realDir(h.root);
    if (seen.has(key)) return;
    seen.add(key);
    homes.push(h);
  };
  const late = () => deadline !== undefined && Date.now() >= deadline;

  const override = env.SKILL_SENTRY_CODEX_HOME;
  const explicitDirs = [...(override ? [override] : []), ...explicit];
  if (!override) {
    const defaultRoot = path.resolve(env.CODEX_HOME || path.join(homeDir, '.codex'));
    if (isDir(defaultRoot)) {
      const isStd = realDir(defaultRoot) === realDir(path.join(homeDir, '.codex'));
      const h = { label: isStd ? 'win' : `h${n++}`, root: defaultRoot, userHome: path.resolve(homeDir) };
      if (platform !== 'win32') h.systemDir = '/etc/codex';
      else if (env.ProgramData) h.systemDir = path.join(env.ProgramData, 'OpenAI', 'Codex');
      push(h);
    }
  }
  for (const d of explicitDirs) {
    const root = path.resolve(d);
    if (!isDir(root)) { problems.push(`codex home not found: ${root}`); continue; }
    const before = homes.length;
    push({ label: `h${n}`, root });
    if (homes.length > before) n++;
  }

  if (platform === 'win32' && includeWsl) {
    for (const h of wslHomes({ env, wslRoot, listRoot, localAppData, late, problems })) push(h);
  }
  return homes;
}

/** Strip `//` and block comments and trailing commas outside strings (Windows Terminal JSONC). */
export function stripJsonc(text) {
  let out = '';
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"') {
      let j = i + 1;
      while (j < text.length && text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
      out += text.slice(i, j + 1);
      i = j;
    } else if (c === '/' && text[i + 1] === '/') {
      while (i < text.length && text[i] !== '\n') i++;
      out += '\n';
    } else if (c === '/' && text[i + 1] === '*') {
      const end = text.indexOf('*/', i + 2);
      i = end === -1 ? text.length : end + 1;
    } else out += c;
  }
  return out.replace(/,(\s*[}\]])/g, '$1');
}

/** WSL profile names from Windows Terminal settings files; anything unreadable is ignored. */
function terminalDistros(localAppData) {
  if (!localAppData) return [];
  const files = [path.join(localAppData, 'Microsoft', 'Windows Terminal', 'settings.json')];
  try {
    const pk = path.join(localAppData, 'Packages');
    for (const n of fs.readdirSync(pk)) {
      if (/^Microsoft\.WindowsTerminal/i.test(n)) files.push(path.join(pk, n, 'LocalState', 'settings.json'));
    }
  } catch { /* no Packages dir */ }
  const names = [];
  for (const f of files) {
    try {
      if (fs.statSync(f).size > MAX_SETTINGS_BYTES) continue;
      const s = JSON.parse(stripJsonc(fs.readFileSync(f, 'utf8').replace(/^﻿/, '')));
      const p = s?.profiles;
      const list = Array.isArray(p) ? p : Array.isArray(p?.list) ? p.list : [];
      for (const x of list) if (x && typeof x.source === 'string' && /WSL|Wsl/.test(x.source) && validDistro(x.name)) names.push(x.name.trim());
    } catch { /* missing or broken settings */ }
  }
  return names;
}

function wslHomes({ env, wslRoot, listRoot, localAppData, late, problems }) {
  const out = [];
  if (late()) { problems.push('WSL Codex homes not checked: scan time budget exhausted'); return out; }
  const candidates = new Map(); // lowercase name -> { name, strict }
  const addCandidate = (name, strict) => {
    const k = name.toLowerCase();
    if (!candidates.has(k)) candidates.set(k, { name, strict });
  };
  for (const n of String(env.SKILL_SENTRY_WSL_DISTROS ?? '').split(',').map(s => s.trim()).filter(Boolean)) {
    if (validDistro(n)) addCandidate(n, true);
    else problems.push(`invalid WSL distribution name in SKILL_SENTRY_WSL_DISTROS: ${n}`);
  }
  if (listRoot) {
    try {
      for (const d of fs.readdirSync(wslRoot, { withFileTypes: true })) if (validDistro(d.name)) addCandidate(d.name, false);
    } catch (e) {
      // ENOENT: the usual answer for the `\\wsl.localhost\` server root (it cannot be listed).
      if (e.code !== 'ENOENT') problems.push(`WSL distributions not listed (${e.code ?? 'error'}): ${wslRoot}`);
    }
  }
  if (!late()) for (const n of terminalDistros(localAppData)) addCandidate(n, false);
  for (const n of COMMON_DISTROS) addCandidate(n, false);

  for (const { name, strict } of [...candidates.values()].slice(0, MAX_DISTROS)) {
    if (late()) { problems.push('WSL Codex homes partly checked: scan time budget exhausted'); return out; }
    const distroRoot = path.join(wslRoot, name);
    const homeRoot = path.join(distroRoot, 'home');
    let users;
    try { users = fs.readdirSync(homeRoot, { withFileTypes: true }); } catch (e) {
      if (strict) problems.push(`WSL distribution ${name} not readable (${e.code ?? 'error'})`);
      continue;
    }
    for (const u of users.slice(0, MAX_USERS)) {
      if (late()) { problems.push('WSL Codex homes partly checked: scan time budget exhausted'); return out; }
      const userHome = path.join(homeRoot, u.name);
      const root = path.join(userHome, '.codex');
      if (!isDir(root)) continue;
      out.push({ label: `wsl:${name}:${u.name}`, root, userHome, systemDir: path.join(distroRoot, 'etc', 'codex'), distroRoot });
    }
  }
  return out;
}
