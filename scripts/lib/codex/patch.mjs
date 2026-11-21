// Write targets of a Codex `apply_patch` call. Only the file headers are read; patch content (the `+`/`-`
// lines) is never inspected, the same as Write/Edit content under Claude Code.
//
// Header matching follows codex-rs apply-patch (streaming_parser.rs): each line is trimmed (Rust `str::trim`,
// Unicode White_Space) before `*** Add File: ` / `*** Delete File: ` / `*** Update File: ` are stripped;
// `*** Move to: ` is matched the same way here (Codex only trims its end: a superset is safe). Lines are split
// on CR as well as LF (Codex splits on LF only; also a safe superset).
import { deobfuscate } from '../guardcore.mjs';

// Bounds. A patch past either cap is `truncated` and the guard denies it (fails closed): it could not be
// inspected. Paths seen before the cap are still returned. Headers are counted separately from body bytes.
export const PATCH_MAX_BYTES = 8 * 1024 * 1024;
export const PATCH_MAX_PATHS = 256;

// The path is everything to the end of the line: `[^\n]`, not `.`, which would stop at U+2028/U+2029 (N1).
const HEADER = /^\*\*\* (?:Add File|Update File|Delete File|Move to): ([^\n]+)$/;
// Rust White_Space = JS \s (minus U+FEFF) plus U+0085 (NEL).
const TRIM = /^[\s\u0085]+|[\s\u0085]+$/g;
const LINE_BREAK = /\r\n|\n|\r/;

/**
 * @param {unknown} patchText `tool_input.command` of an apply_patch call (or a shell-form patch body)
 * @returns {{ paths: string[], truncated: boolean }}
 */
export function scanPatch(patchText) {
  const paths = [];
  if (typeof patchText !== 'string' || !patchText) return { paths, truncated: false };
  const text = patchText.length > PATCH_MAX_BYTES ? patchText.slice(0, PATCH_MAX_BYTES) : patchText;
  let truncated = text.length < patchText.length;
  const lines = text.split(LINE_BREAK);
  // The last line of a cut-off text may itself be cut: skip it.
  if (truncated) lines.pop();
  for (const raw of lines) {
    if (raw.indexOf('*** ') === -1) continue;
    const m = HEADER.exec(raw.replace(TRIM, ''));
    if (!m) continue;
    const p = m[1].replace(TRIM, '');
    if (!p) continue;
    if (paths.length >= PATCH_MAX_PATHS) { truncated = true; break; }
    paths.push(p);
  }
  return { paths, truncated };
}

/** Header paths of an apply_patch text (see scanPatch for the bounds). */
export function patchPaths(patchText) {
  return scanPatch(patchText).paths;
}

// ---------------------------------------------------------------- shell-form apply_patch
//
// Codex intercepts `[cd <dir> &&] apply_patch|applypatch <<'EOF' … EOF` run through a shell (apply-patch
// invocation.rs) and applies it itself; the PreToolUse hook sees it as a `Bash` call. Codex also puts real
// `apply_patch`/`applypatch` executables (`.bat` alias on Windows) first on PATH (arg0), so any shell
// construct that runs one applies a patch. A small shell scanner finds invocations in command position:
//   - statements split at unquoted ; & | ( ) newline and at word-boundary { }, never inside quotes, comments or
//     heredoc bodies; $(…) and backticks (also inside double quotes) are scanned as nested scripts;
//   - leading keywords (if then do else elif while until ! { ( time), assignments, wrappers and their options
//     are skipped; the command word is unquoted / de-obfuscated (guardcore `deobfuscate`) and its basename
//     compared;
//   - for a shell command (bash, sh, cmd, pwsh, …) the script after -c / -lc / -Command / /c (quoted or not)
//     is scanned as a nested script.
// An invocation is inline (Ruling R18-b) only when nothing feeds its stdin (no `<` redirect, no pipe into it)
// and the patch directly follows it: a heredoc whose first line (trimmed) is `*** Begin Patch`, or a first
// argument starting with it. Flags-only `--help` / `--version` calls are not invocations.

const BEGIN = '*** Begin Patch';
const NAME_RE = /^(?:apply_patch|applypatch)(?:\.(?:exe|bat|cmd))?$/i;
const SHELLS = /^(?:bash|sh|zsh|dash|ksh|ash|fish|pwsh|powershell|cmd)(?:\.exe)?$/i;
const SCRIPT_FLAG = /^(?:-[a-z]*c|-command|\/c|\/k)$/i;
const KEYWORDS = new Set(['if', 'then', 'do', 'else', 'elif', 'while', 'until', '!', '{', '(', 'time']);
const WRAPPERS = new Set(['sudo', 'env', 'command', 'exec', 'nohup', 'xargs', 'doas', 'nice', 'stdbuf', 'timeout', 'busybox']);
const HELP = /^(?:--help|-h|--version|-V|-\?|\/\?)$/;
const HEREDOC = /^<<(-?)[ \t]*(?:'([^'\n]*)'|"([^"\n]*)"|\\?([^\s;&|<>()'"]+))/;
const REDIRECT = /^(?:<<<|<<-|<<|<&|<>|<|>>|>&|>\||>)/;
const MAX_DEPTH = 4;
// Bash words end at blanks and metacharacters only: U+2028 and friends stay inside the word (N1 audit).
const CD_PREFIX = /^[ \t\n]*cd[ \t]+(?:'([^']*)'|"([^"]*)"|([^ \t\n;&|()<>'"]+))[ \t]*(?:&&|;|\n)[ \t\n]*['"]?(?:apply_patch|applypatch)/;

/** Index of the parenthesis closing the one at `i` (quotes skipped), or s.length. */
function parenClose(s, i) {
  let depth = 0;
  let q = null;
  for (let k = i; k < s.length; k++) {
    const c = s[k];
    if (q) {
      if (c === '\\' && q === '"') k++;
      else if (c === q) q = null;
      continue;
    }
    if (c === '\\') { k++; continue; }
    if (c === "'" || c === '"') q = c;
    else if (c === '(') depth++;
    else if (c === ')' && --depth === 0) return k;
  }
  return s.length;
}

/** Index of the backtick closing the one at `i`, or s.length. */
function backtickClose(s, i) {
  for (let k = i + 1; k < s.length; k++) {
    if (s[k] === '\\') k++;
    else if (s[k] === '`') return k;
  }
  return s.length;
}

/** Quote-aware words of one simple command: `{ raw, value, start }` or `{ op }` for redirect operators. */
function words(text) {
  const out = [];
  const n = text.length;
  let i = 0;
  while (i < n) {
    while (i < n && /\s/.test(text[i])) i++;
    if (i >= n) break;
    if (text[i] === '<' || text[i] === '>') {
      const op = REDIRECT.exec(text.slice(i, i + 3))[0];
      out.push({ op });
      i += op.length;
      continue;
    }
    const start = i;
    let value = '';
    let q = null;
    let runFrom = i;
    const flush = to => { value += text.slice(runFrom, to); };
    for (; i < n; i++) {
      const c = text[i];
      if (q === "'") {
        if (c === "'") { flush(i); q = null; runFrom = i + 1; }
        continue;
      }
      if (q === '"') {
        if (c === '\\' && i + 1 < n && '"\\$`'.includes(text[i + 1])) { flush(i); runFrom = i + 1; i++; continue; }
        if (c === '"') { flush(i); q = null; runFrom = i + 1; }
        continue;
      }
      if (/\s/.test(c) || c === '<' || c === '>') break;
      if (c === "'" || c === '"') { flush(i); q = c; runFrom = i + 1; continue; }
      if (c === '\\' && i + 1 < n) { flush(i); runFrom = i + 1; i++; }
    }
    flush(i);
    out.push({ raw: text.slice(start, i), value, start });
  }
  return out;
}

const base = v => v.split(/[\\/]/).pop();

/** One simple command: record an apply_patch invocation, or scan a shell's -c / /c script. */
function analyze(text, seg, depth, calls) {
  const t = words(text);
  const items = [];
  let stdin = false;
  let heredocs = 0;
  for (let x = 0; x < t.length; x++) {
    const w = t[x];
    if (!w.op) { items.push(w); continue; }
    if (w.op === '<<' || w.op === '<<-') heredocs++;
    else if (w.op.startsWith('<')) stdin = true; // <, <&, <>, <<< (here-string)
    x++; // the operator's target word
  }
  let p = 0;
  while (items[p]) {
    const v = items[p].value;
    if (KEYWORDS.has(v.toLowerCase()) || /^[A-Za-z_]\w*=/.test(v)) { p++; continue; }
    if (WRAPPERS.has(v.toLowerCase())) {
      p++;
      while (items[p] && /^(?:-|\d|[A-Za-z_]\w*=)/.test(items[p].value)) p++;
      continue;
    }
    break;
  }
  const cmd = items[p];
  if (!cmd) return;
  const names = [base(cmd.value), base(deobfuscate(cmd.raw).replace(/["']/g, ''))];
  if (!names.some(nm => NAME_RE.test(nm))) {
    if (!names.some(nm => SHELLS.test(nm)) || depth >= MAX_DEPTH) return;
    for (let f = p + 1; f < items.length - 1; f++) {
      if (!SCRIPT_FLAG.test(items[f].value)) continue;
      const next = items[f + 1];
      const nested = /^['"]/.test(next.raw) && f + 2 === items.length ? next.value : text.slice(next.start);
      scan(nested, depth + 1, calls);
      return;
    }
    return;
  }
  const args = items.slice(p + 1);
  if (!stdin && !seg.piped && !heredocs && args.length && args.every(a => HELP.test(a.value))) return;
  let inline = false;
  if (!stdin && !seg.piped) {
    if (heredocs) inline = seg.heredocs.length > 0 && seg.heredocs[0].split('\n')[0].replace(TRIM, '') === BEGIN;
    else if (args[0]) inline = args[0].value.replace(TRIM, '').startsWith(BEGIN);
  }
  calls.push({ inline });
}

/** Split a script into simple commands (quotes, comments, heredoc bodies, substitutions aware) and analyze them. */
function scan(s, depth, calls) {
  const segs = [];
  let seg = { start: 0, piped: false, heredocs: [] };
  const pending = [];
  const next = (end, start, piped) => {
    seg.end = end;
    segs.push(seg);
    seg = { start, piped, heredocs: [] };
  };
  const sub = (from, to) => { if (depth < MAX_DEPTH) scan(s.slice(from, to), depth + 1, calls); };
  let q = null;
  let i = 0;
  while (i < s.length) {
    const c = s[i];
    if (q === "'") { if (c === "'") q = null; i++; continue; }
    if (q === '"') {
      if (c === '\\') { i += 2; continue; }
      if (c === '"') { q = null; i++; continue; }
      if (c === '`') { const e = backtickClose(s, i); sub(i + 1, e); i = e + 1; continue; }
      if (c === '$' && s[i + 1] === '(') { const e = parenClose(s, i + 1); sub(i + 2, e); i = e + 1; continue; }
      i++;
      continue;
    }
    if (c === '\\') { i += 2; continue; }
    if (c === "'" || c === '"') { q = c; i++; continue; }
    if (c === '`') { const e = backtickClose(s, i); sub(i + 1, e); i = e + 1; continue; }
    if (c === '$' && s[i + 1] === '(') { const e = parenClose(s, i + 1); sub(i + 2, e); i = e + 1; continue; }
    if (c === '#' && (i === 0 || /[\s;&|(]/.test(s[i - 1]))) {
      const nl = s.indexOf('\n', i);
      i = nl === -1 ? s.length : nl;
      continue;
    }
    if (c === '<' && s[i + 1] === '<' && s[i + 2] !== '<') {
      const m = HEREDOC.exec(s.slice(i, i + 512));
      if (m) { pending.push({ seg, delim: m[2] ?? m[3] ?? m[4], strip: m[1] === '-' }); i += m[0].length; continue; }
      i += 2;
      continue;
    }
    if (c === '\n') {
      let j = i + 1;
      for (const h of pending) {
        const lines = [];
        while (j < s.length) {
          let e = s.indexOf('\n', j);
          if (e === -1) e = s.length;
          let line = s.slice(j, e);
          if (line.endsWith('\r')) line = line.slice(0, -1);
          j = e + 1;
          if ((h.strip ? line.replace(/^\t+/, '') : line) === h.delim) break;
          lines.push(line);
        }
        h.seg.heredocs.push(lines.join('\n'));
      }
      pending.length = 0;
      j = Math.min(j, s.length);
      next(i, j, false);
      i = j;
      continue;
    }
    const prev = i === 0 ? ' ' : s[i - 1];
    const boundaryBrace = (c === '{' && /[\s;&|(]/.test(prev) && /\s/.test(s[i + 1] ?? ' ')) || (c === '}' && /[\s;]/.test(prev));
    if (c === ';' || c === '&' || c === '|' || c === '(' || c === ')' || boundaryBrace) {
      let len = 1;
      let piped = false;
      if ((c === '|' || c === '&') && s[i + 1] === c) len = 2;
      else if (c === '|') { piped = true; if (s[i + 1] === '&') len = 2; }
      next(i, i + len, piped);
      i += len;
      continue;
    }
    i++;
  }
  seg.end = s.length;
  segs.push(seg);
  for (const g of segs) if (g.end > g.start) analyze(s.slice(g.start, g.end), g, depth, calls);
}

const MAYBE = /apply_?patch/i;

/**
 * Shell-form apply_patch: `null` when the command does not invoke apply_patch in command position, else the
 * header paths (`truncated` as in scanPatch), the `cd` directory Codex applies the patch in (`workdir`, or
 * null), and `inline`: exactly one invocation and it is inline. A non-inline invocation (stdin, file, pipe,
 * substitution, a second invocation) cannot be inspected (Ruling R18).
 * @returns {{ paths: string[], truncated: boolean, workdir: string|null, inline: boolean } | null}
 */
export function shellPatch(command) {
  if (typeof command !== 'string' || !(MAYBE.test(command) || MAYBE.test(deobfuscate(command)))) return null;
  let calls = [];
  scan(command, 0, calls);
  // cmd `^` / PowerShell backtick escapes inside the command word (`ap^ply_patch`, ap`ply_patch): one more
  // pass over the text without them, only when the raw scan found nothing (quote structure is kept).
  if (!calls.length) {
    const unescaped = command.replace(/\^/g, '').replace(/`(?=[A-Za-z])/g, '');
    if (unescaped !== command) scan(unescaped, 0, calls = []);
  }
  if (!calls.length) return null;
  const cd = CD_PREFIX.exec(command);
  return { ...scanPatch(command), workdir: cd ? cd[1] ?? cd[2] ?? cd[3] : null, inline: calls.length === 1 && calls[0].inline };
}
