// Helpers for the e2e install checks (test/e2e/install.test.mjs). No side effects at import time: Node's test
// runner may load this file as a test file. CI-only code: never imported by skills/audit/scripts/.
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline';

export const WIN = process.platform === 'win32';

/** Global npm root holding @anthropic-ai/claude-code and @openai/codex (override: SKILL_SENTRY_E2E_NPM_ROOT). */
export function npmRoot() {
  if (process.env.SKILL_SENTRY_E2E_NPM_ROOT) return process.env.SKILL_SENTRY_E2E_NPM_ROOT;
  const r = spawnSync('npm root -g', { shell: true, encoding: 'utf8' });
  if (r.status !== 0) throw new Error(`npm root -g failed: ${r.stderr}`);
  return r.stdout.trim();
}

/**
 * The CLIs as [file, ...prefixArgs], spawned without a shell. Claude Code's npm package puts its native binary at
 * bin/claude.exe (on every platform) once its postinstall ran; Codex's npm bin is a Node launcher.
 */
export function clis(root = npmRoot()) {
  return {
    claude: [path.join(root, '@anthropic-ai', 'claude-code', 'bin', 'claude.exe')],
    codex: [process.execPath, path.join(root, '@openai', 'codex', 'bin', 'codex.js')],
  };
}

/** Run a CLI to completion. Resolves { code, stdout, stderr }; never rejects on a non-zero exit. */
export function run([file, ...pre], args, { env, cwd, input, timeout = 180_000 } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(file, [...pre, ...args], { env, cwd, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => { child.kill(); reject(new Error(`timeout: ${path.basename(file)} ${args.join(' ')}`)); }, timeout);
    child.stdout.on('data', c => { stdout += c; });
    child.stderr.on('data', c => { stderr += c; });
    child.on('error', e => { clearTimeout(timer); reject(e); });
    child.on('close', code => { clearTimeout(timer); resolve({ code, stdout, stderr }); });
    child.stdin.end(input ?? '');
  });
}

/** Last JSON line of a CLI's stdout (both CLIs print one result object with --json; Codex pretty-prints it). */
export function lastJson(stdout) {
  const t = stdout.trim();
  try { return JSON.parse(t); } catch { /* not one document: take the last parseable line */ }
  const lines = t.split(/\r?\n/).reverse();
  for (const l of lines) { try { return JSON.parse(l); } catch { /* keep looking */ } }
  throw new Error(`no JSON in output: ${t.slice(0, 500)}`);
}

/**
 * Isolated environment: every home-like variable points inside `base`, the model API keys are dropped and
 * skill-sentry's own overrides are cleared, so the CLIs and the installed scripts only see the tmp homes.
 */
export function isolatedEnv(base) {
  const home = path.join(base, 'home');
  const env = { ...process.env };
  for (const k of Object.keys(env)) {
    // GIT_CONFIG_* covers GIT_CONFIG_GLOBAL, GIT_CONFIG_SYSTEM, GIT_CONFIG_NOSYSTEM and GIT_CONFIG_COUNT/KEY/VALUE:
    // git must read only the tmp home's ~/.gitconfig (the marketplace insteadOf lives there).
    if (/^(SKILL_SENTRY_|CLAUDE|CODEX_|ANTHROPIC_|OPENAI_|GIT_CONFIG)/i.test(k)) delete env[k];
  }
  Object.assign(env, {
    HOME: home, USERPROFILE: home, CODEX_HOME: path.join(home, '.codex'),
    XDG_CONFIG_HOME: path.join(home, '.config'), XDG_DATA_HOME: path.join(home, '.local', 'share'),
    XDG_STATE_HOME: path.join(home, '.local', 'state'), XDG_CACHE_HOME: path.join(home, '.cache'),
    SKILL_SENTRY_NO_WSL: '1', DISABLE_AUTOUPDATER: '1', CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: '1',
  });
  if (WIN) Object.assign(env, { APPDATA: path.join(home, 'AppData', 'Roaming'), LOCALAPPDATA: path.join(home, 'AppData', 'Local') });
  for (const d of [env.CODEX_HOME, env.XDG_CONFIG_HOME, env.XDG_DATA_HOME, env.XDG_STATE_HOME, env.XDG_CACHE_HOME, env.APPDATA, env.LOCALAPPDATA]) {
    if (d) fs.mkdirSync(d, { recursive: true });
  }
  return { env, home };
}

/** A clean export of HEAD (what a git or GitHub install ships): `git archive HEAD` unpacked into `dir`. */
export function exportHead(repo, dir) {
  fs.mkdirSync(dir, { recursive: true });
  const a = spawnSync('git', ['-C', repo, 'archive', '--format=tar', 'HEAD'], { maxBuffer: 256 * 1024 * 1024 });
  if (a.status !== 0) throw new Error(`git archive failed: ${a.stderr}`);
  const x = spawnSync('tar', ['-xf', '-'], { input: a.stdout, cwd: dir, encoding: 'utf8' });
  if (x.status !== 0) throw new Error(`tar failed: ${x.stderr}`);
}

/** Regular files under `root` as relpath (`/`) -> Buffer. */
export function readTree(root) {
  const out = new Map();
  const walk = rel => {
    for (const e of fs.readdirSync(path.join(root, rel), { withFileTypes: true })) {
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) walk(r);
      else if (e.isFile()) out.set(r, fs.readFileSync(path.join(root, r)));
    }
  };
  walk('');
  return out;
}

/**
 * Minimal `codex app-server` client over stdio (one JSON object per line, as codex-rs/tui talks to it).
 * Messages without a matching id (notifications, server requests) are collected in `notifications`.
 */
export async function appServer(codex, { env, cwd, args = [] }) {
  const [file, ...pre] = codex;
  const child = spawn(file, [...pre, 'app-server', ...args], { env, cwd, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
  let stderr = '';
  child.stderr.on('data', c => { stderr += c; });
  const pending = new Map();
  const notifications = [];
  let nextId = 1;
  let closed = false;
  const failAll = err => { for (const p of pending.values()) p.reject(err); pending.clear(); };
  child.on('error', failAll);
  child.on('close', code => { closed = true; failAll(new Error(`app-server exited ${code}: ${stderr.slice(-2000)}`)); });
  readline.createInterface({ input: child.stdout }).on('line', line => {
    let msg;
    try { msg = JSON.parse(line); } catch { return; }
    if (msg.id !== undefined && pending.has(msg.id) && msg.method === undefined) {
      const p = pending.get(msg.id);
      pending.delete(msg.id);
      if (msg.error) p.reject(new Error(`${p.method}: ${JSON.stringify(msg.error)}`));
      else p.resolve(msg.result);
    } else {
      notifications.push(msg);
      // A server request (approval, elicitation...): the e2e never grants anything, so every request is refused.
      if (msg.id !== undefined && typeof msg.method === 'string') {
        child.stdin.write(JSON.stringify({ id: msg.id, error: { code: -32601, message: 'refused by the skill-sentry e2e client' } }) + '\n');
      }
    }
    for (const w of waiters.splice(0)) if (!w(msg)) waiters.push(w);
  });
  const waiters = [];
  /** Resolves with the first later message for which `pred` is true (or rejects after `timeout` ms). */
  const waitFor = (pred, timeout = 120_000) => new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('app-server: timed out waiting for a message')), timeout);
    waiters.push(msg => { if (!pred(msg)) return false; clearTimeout(timer); resolve(msg); return true; });
  });
  const request = (method, params, timeout = 60_000) => new Promise((resolve, reject) => {
    if (closed) { reject(new Error('app-server is closed')); return; }
    const id = nextId++;
    const timer = setTimeout(() => { pending.delete(id); reject(new Error(`${method}: timeout`)); }, timeout);
    pending.set(id, {
      method,
      resolve: v => { clearTimeout(timer); resolve(v); },
      reject: e => { clearTimeout(timer); reject(e); },
    });
    child.stdin.write(JSON.stringify({ id, method, params }) + '\n');
  });
  const close = () => new Promise(resolve => {
    if (closed) { resolve(); return; }
    child.once('close', () => resolve());
    child.stdin.end();
    setTimeout(() => { if (!closed) child.kill(); }, 5000).unref();
  });
  const init = await request('initialize', { clientInfo: { name: 'skill-sentry-e2e', version: '0.0.0' } });
  child.stdin.write(JSON.stringify({ method: 'initialized' }) + '\n');
  return { init, request, waitFor, close, notifications, stderr: () => stderr };
}

/**
 * Run a Claude Code plugin hook command the way Claude Code 2.1.x does for a shell-form hook (no `args`, no
 * `shell`): the command string is not rewritten; it is spawned through a shell with CLAUDE_PLUGIN_ROOT and
 * CLAUDE_PROJECT_DIR in the environment. The shell is bash: /bin/sh via spawn's `shell: true` on POSIX, Git Bash
 * on Windows, where the root is forward-slashed and Git Bash's directory is prepended to PATH.
 */
export function runClaudeHook(command, { root, projectDir, env, input }) {
  const bash = WIN ? (process.env.CLAUDE_CODE_GIT_BASH_PATH || 'C:\\Program Files\\Git\\bin\\bash.exe') : true;
  const slash = p => (WIN ? p.replaceAll('\\', '/') : p);
  const hookEnv = { ...env, CLAUDE_PROJECT_DIR: slash(projectDir), CLAUDE_PLUGIN_ROOT: slash(root) };
  if (WIN) {
    const key = Object.keys(hookEnv).find(k => k.toUpperCase() === 'PATH') ?? 'PATH';
    hookEnv[key] = `${path.dirname(bash)}${path.delimiter}${hookEnv[key] ?? ''}`;
  }
  return spawnCollect(command, [], { shell: bash, env: hookEnv, cwd: projectDir }, input);
}

/**
 * Run a Codex plugin hook command the way codex-rs/hooks/src/engine/command_runner.rs does: the command is the
 * already-expanded string from `hooks/list`; Windows runs `%COMSPEC% /C "<command>"` verbatim, elsewhere
 * `$SHELL -lc <command>`; PLUGIN_ROOT and CLAUDE_PLUGIN_ROOT are set in the environment.
 */
export function runCodexHook(command, { root, projectDir, env, input }) {
  const hookEnv = { ...env, PLUGIN_ROOT: root, CLAUDE_PLUGIN_ROOT: root };
  if (WIN) {
    const comspec = Object.entries(env).find(([k]) => k.toUpperCase() === 'COMSPEC')?.[1] || 'cmd.exe';
    return spawnCollect(comspec, ['/C', `"${command}"`], { env: hookEnv, cwd: projectDir, windowsVerbatimArguments: true }, input);
  }
  return spawnCollect(env.SHELL || '/bin/sh', ['-lc', command], { env: hookEnv, cwd: projectDir }, input);
}

function spawnCollect(file, args, opts, input) {
  return new Promise((resolve, reject) => {
    const t0 = Date.now();
    const child = spawn(file, args, { ...opts, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => { child.kill(); reject(new Error('hook timeout')); }, 30_000);
    child.stdout.on('data', c => { stdout += c; });
    child.stderr.on('data', c => { stderr += c; });
    child.on('error', e => { clearTimeout(timer); reject(e); });
    child.on('close', code => { clearTimeout(timer); resolve({ code, stdout, stderr, ms: Date.now() - t0 }); });
    child.stdin.end(input + '\n');
  });
}

/** guard.log lines (parsed) in the default data dir of the isolated home. */
export function guardLog(home) {
  const f = path.join(home, '.claude', 'skill-sentry', 'guard.log');
  return fs.existsSync(f) ? fs.readFileSync(f, 'utf8').trim().split('\n').filter(Boolean).map(l => JSON.parse(l)) : [];
}

/**
 * Install `dist` as a local marketplace in both isolated homes and trust the Codex hook (start once, then
 * hooks/list + config/batchWrite). Returns { claudeRoot, codexRoot }. Throws on any failed step; install.test.mjs
 * asserts each step in detail, this is the short path for the model e2e.
 */
export async function installBoth(cli, { env, cwd, dist, id = 'skill-sentry@skill-sentry' }) {
  const ok = (r, what) => { if (r.code !== 0) throw new Error(`${what} failed (${r.code}): ${r.stdout}${r.stderr}`); return r; };
  ok(await run(cli.claude, ['plugin', 'marketplace', 'add', dist, '--json'], { env, cwd }), 'claude marketplace add');
  ok(await run(cli.claude, ['plugin', 'install', id, '--json'], { env, cwd }), 'claude plugin install');
  const list = JSON.parse(ok(await run(cli.claude, ['plugin', 'list', '--json'], { env, cwd }), 'claude plugin list').stdout);
  const claudeRoot = list.find(p => p.id === id)?.installPath;
  ok(await run(cli.codex, ['plugin', 'marketplace', 'add', dist, '--json'], { env, cwd }), 'codex marketplace add');
  const codexRoot = lastJson(ok(await run(cli.codex, ['plugin', 'add', id, '--json'], { env, cwd }), 'codex plugin add').stdout).installedPath;
  const first = await appServer(cli.codex, { env, cwd });
  await new Promise(r => setTimeout(r, 3000));
  await first.close();
  const s = await appServer(cli.codex, { env, cwd });
  try {
    const hooks = (await s.request('hooks/list', { cwds: [cwd] })).data.flatMap(d => d.hooks).filter(h => h.pluginId === id);
    if (hooks.length !== 1) throw new Error(`expected one skill-sentry hook, got ${hooks.length}`);
    const value = { [hooks[0].key]: { trusted_hash: hooks[0].currentHash } };
    await s.request('config/batchWrite', { edits: [{ keyPath: 'hooks.state', value, mergeStrategy: 'upsert' }], reloadUserConfig: true });
  } finally { await s.close(); }
  return { claudeRoot, codexRoot };
}

/**
 * A git marketplace without the network: commit `src` into a repo, clone it bare, and make `url` (a GitHub-style
 * https URL) resolve to that bare repo through `url.<file>.insteadOf` in the isolated home's ~/.gitconfig. A
 * global config, not GIT_CONFIG_* variables: Codex strips those from its background git commands
 * (codex-rs/core-plugins/src/git_policy.rs, PluginGitMode::Automatic). Returns the bare repo path.
 */
export function gitMarketplace(src, { base, home, url }) {
  const ident = { GIT_AUTHOR_NAME: 'e2e', GIT_AUTHOR_EMAIL: 'e2e@example.invalid', GIT_COMMITTER_NAME: 'e2e', GIT_COMMITTER_EMAIL: 'e2e@example.invalid' };
  const g = (args, cwd) => {
    const r = spawnSync('git', args, { cwd, encoding: 'utf8', env: { ...process.env, ...ident } });
    if (r.status !== 0) throw new Error(`git ${args.join(' ')}: ${r.stderr}`);
  };
  g(['init', '-q', '-b', 'main'], src);
  g(['add', '-A'], src);
  g(['commit', '-q', '-m', 'e2e marketplace'], src);
  const bare = path.join(base, 'remote.git');
  g(['clone', '-q', '--bare', src, bare], base);
  const fileUrl = `file:///${bare.replaceAll('\\', '/').replace(/^\/+/, '')}`;
  fs.writeFileSync(path.join(home, '.gitconfig'), `[url "${fileUrl}"]\n\tinsteadOf = ${url}\n[core]\n\tlongpaths = true\n`);
  return bare;
}

/** `codex app-server` arguments that route the model to the stub (Responses wire API, no retries, no auth). */
export const codexStubArgs = stubUrl => [
  '-c', 'model_provider="e2e"', '-c', 'model="gpt-5-codex"',
  '-c', `model_providers.e2e={ name = "skill-sentry e2e stub", base_url = "${stubUrl}/v1", wire_api = "responses", request_max_retries = 0, stream_max_retries = 0 }`,
];

/**
 * One `claude -p` turn against the stub model (ANTHROPIC_BASE_URL + a dummy key; the stub scripts one Bash call).
 * Returns the parsed stream-json events: the init message, the PreToolUse hook responses, the tool results and the
 * permission denials.
 */
export async function claudeTurn(cli, { env, cwd, stubUrl }) {
  const r = await run(cli.claude, ['-p', '--output-format', 'stream-json', '--verbose', '--include-hook-events', '--allowedTools', 'Bash'], {
    env: { ...env, ANTHROPIC_BASE_URL: stubUrl, ANTHROPIC_API_KEY: 'e2e-stub-placeholder' }, cwd, input: 'Run the probe command.', timeout: 180_000,
  });
  const events = r.stdout.split(/\r?\n/).filter(Boolean).map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
  const content = events.filter(e => e.type === 'user').flatMap(e => (Array.isArray(e.message?.content) ? e.message.content : []));
  return {
    code: r.code, stderr: r.stderr, events,
    init: events.find(e => e.type === 'system' && e.subtype === 'init'),
    hooks: events.filter(e => e.type === 'system' && e.subtype === 'hook_response' && e.hook_event === 'PreToolUse'),
    toolResults: content.filter(c => c?.type === 'tool_result'),
    denials: events.find(e => e.type === 'result')?.permission_denials ?? [],
  };
}

/**
 * One app-server turn against the stub model. Returns the PreToolUse hook runs reported for the turn
 * (hook/completed), the turn status and the command items.
 */
export async function codexTurn(server, threadId) {
  const before = server.notifications.length;
  const { turn } = await server.request('turn/start', { threadId, input: [{ type: 'text', text: 'Run the probe command.' }] });
  const completed = m => m.method === 'turn/completed' && m.params?.turn?.id === turn.id;
  // Checked and registered synchronously, so a completion that already arrived is not missed.
  if (!server.notifications.slice(before).some(completed)) await server.waitFor(completed, 180_000);
  const mine = server.notifications.slice(before).filter(m => m.params?.turnId === turn.id || m.params?.turn?.id === turn.id);
  return {
    turnId: turn.id,
    status: mine.find(m => m.method === 'turn/completed')?.params?.turn?.status,
    hooks: mine.filter(m => m.method === 'hook/completed' && m.params?.run?.eventName === 'preToolUse').map(m => m.params.run),
    commands: mine.filter(m => m.method === 'item/completed' && m.params?.item?.type === 'commandExecution').map(m => m.params.item),
  };
}

export const tmpBase = () => fs.mkdtempSync(path.join(process.env.RUNNER_TEMP || os.tmpdir(), 'ss-e2e-'));
