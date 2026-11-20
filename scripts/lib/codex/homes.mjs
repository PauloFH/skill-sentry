// Codex homes to inventory. Never spawns a process: WSL homes are found through the `\\wsl.localhost\`
// filesystem. Every fs call is wrapped and deadline-checked; failures become problem lines, never throws.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { realDir } from '../inventory.mjs';

export const WSL_ROOT = '\\\\wsl.localhost\\';
const MAX_DISTROS = 32;
const MAX_USERS = 64;

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
 * Each entry: `{ label, root, userHome?, systemDir?, distroRoot? }`. `userHome` (where `~/.agents/skills`
 * lives) and `systemDir` (system config layer) are set for the default and WSL homes only: an explicit
 * home is read on its own, so a test or `--codex-home` dir never reaches into a real home.
 * Missing explicit homes and WSL listing failures are pushed onto `problems` (strings).
 */
export function codexHomes({
  env = process.env, homeDir = os.homedir(), platform = process.platform, deadline,
  includeWsl = true, explicit = [], wslRoot = WSL_ROOT, problems = [],
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
    for (const h of wslHomes(wslRoot, late, problems)) push(h);
  }
  return homes;
}

function wslHomes(wslRoot, late, problems) {
  const out = [];
  if (late()) { problems.push('WSL Codex homes not checked: scan time budget exhausted'); return out; }
  let distros;
  try { distros = fs.readdirSync(wslRoot, { withFileTypes: true }); } catch (e) {
    if (e.code !== 'ENOENT') problems.push(`WSL distributions not listed (${e.code ?? 'error'}): ${wslRoot}`);
    return out;
  }
  for (const d of distros.slice(0, MAX_DISTROS)) {
    if (late()) { problems.push('WSL Codex homes partly checked: scan time budget exhausted'); return out; }
    const distroRoot = path.join(wslRoot, d.name);
    const homeRoot = path.join(distroRoot, 'home');
    let users;
    try { users = fs.readdirSync(homeRoot, { withFileTypes: true }); } catch (e) {
      if (e.code !== 'ENOENT' && e.code !== 'ENOTDIR') problems.push(`WSL distribution ${d.name} not listed (${e.code ?? 'error'})`);
      continue;
    }
    for (const u of users.slice(0, MAX_USERS)) {
      if (late()) { problems.push('WSL Codex homes partly checked: scan time budget exhausted'); return out; }
      const userHome = path.join(homeRoot, u.name);
      const root = path.join(userHome, '.codex');
      if (!isDir(root)) continue;
      out.push({ label: `wsl:${d.name}:${u.name}`, root, userHome, systemDir: path.join(distroRoot, 'etc', 'codex'), distroRoot });
    }
  }
  return out;
}
