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
//   - statements split at unquoted ; & | ( ) newline and at word-boundary { }, never inside quotes ('…', "…",
//     $'…'), comments or heredoc bodies; $(…) is scanned in place as a nested script that ends at its own
//     unmatched `)`; a backtick substitution ends at the next unescaped backtick (quotes do not count, as in
//     bash) and its text is scanned as a nested script;
//   - leading keywords (if then do else elif while until ! { ( time), `time` options, assignments, wrappers
//     and their options are skipped (`command -v`/`-V` is a lookup, not a call); fd-numbered redirects (`2>x`)
//     are redirects; the command word is unquoted / de-obfuscated (guardcore `deobfuscate`) and its basename
//     compared;
//   - for a shell command (bash, sh, cmd, pwsh, …) the script after -c / -lc / -Command / /c (quoted or not)
//     is scanned as a nested script.
// An invocation is inline (Ruling R18-b) only when nothing feeds its stdin (no `<` redirect, no pipe into it)
// and the patch directly follows it: its only heredoc, whose first line (trimmed) is `*** Begin Patch`, or a
// first argument starting with it. Flags-only `--help` / `--version` calls are not invocations.
// R18-c: the patch must also be safe from shell expansion. A heredoc qualifies when any part of its delimiter
// is quoted, or when its body has no `$`, backtick or backslash; a first argument when it is made only of
// single-quoted parts and double-quoted parts with no `$`, backtick or backslash (unquoted text could glob).
// Calls inside a -c script that is not single-quoted and holds `$`, a backtick or a backslash-newline are not
// inline: the calling shell expands (or joins) that script first. A heredoc on an fd other than 0 is not stdin.
// R20.1: a scan that cannot finish (nesting past MAX_DEPTH, text ending inside a quote, substitution or
// heredoc body, or an internal error) fails closed: one non-inline call.

const BEGIN = '*** Begin Patch';
const NAME_RE = /^(?:apply_patch|applypatch)(?:\.(?:exe|bat|cmd))?$/i;
const SHELLS = /^(?:bash|sh|zsh|dash|ksh|ash|fish|pwsh|powershell|cmd)(?:\.exe)?$/i;
const SCRIPT_FLAG = /^(?:-[a-z]*c|-command|\/c|\/k)$/i;
const KEYWORDS = new Set(['if', 'then', 'do', 'else', 'elif', 'while', 'until', '!', '{', '(', 'time']);
const WRAPPERS = new Set(['sudo', 'env', 'command', 'exec', 'nohup', 'xargs', 'doas', 'nice', 'stdbuf', 'timeout', 'busybox']);
const LOOKUP = /^-[A-Za-z]*[vV]/; // command -v / -V / -pv: prints what the name resolves to
const HELP = /^(?:--help|-h|--version|-V|-\?|\/\?)$/;
const REDIRECT = /^(?:<<<|<<-|<<|<&|<>|<|>>|>&|>\||>)/;
const FD_REDIRECT = /^\d{0,9}[<>]/;
const EXPANDS = /[$`\\]/;
const LITERAL_WORD = /^(?:'[^']*'|"[^"$`\\]*")+$/;
const SINGLE_QUOTED = /^'[^']*'$/;
const MAX_DEPTH = 4;
// Bash words end at blanks and metacharacters only: U+2028 and friends stay inside the word (N1 audit).
const CD_PREFIX = /^[ \t\n]*cd[ \t]+(?:'([^']*)'|"([^"]*)"|([^ \t\n;&|()<>'"]+))[ \t]*(?:&&|;|\n)[ \t\n]*['"]?(?:apply_patch|applypatch)/;

/** Thrown when the scan cannot finish; shellPatch turns it into a non-inline call (R20.1). */
class Incomplete extends Error {}

/**
 * Heredoc operator at `i` (`<<` or `<<-`, then the delimiter word): the index after the word, the delimiter
 * after quote removal, and whether any part of the word was quoted (then bash does not expand the body).
 * `$'…'` / `$"…"` in the word end the delimiter differently in bash (`E`) and in shells without them (`$E`):
 * Incomplete. `$$` is two literal characters. Null when no word follows.
 */
function heredocAt(s, i) {
  let k = i + 2;
  const strip = s[k] === '-';
  if (strip) k++;
  while (s[k] === ' ' || s[k] === '\t') k++;
  const lim = Math.min(s.length, k + 512);
  let delim = '';
  let quoted = false;
  while (k < lim) {
    const c = s[k];
    if (c === '$' && s[k + 1] === '$') { delim += '$$'; k += 2; continue; }
    if (c === '$' && (s[k + 1] === "'" || s[k + 1] === '"')) throw new Incomplete('ambiguous heredoc delimiter');
    if (c === "'" || c === '"') {
      const e = s.indexOf(c, k + 1);
      if (e === -1 || e >= lim) return null;
      delim += s.slice(k + 1, e);
      quoted = true;
      k = e + 1;
      continue;
    }
    if (c === '\\' && k + 1 < s.length) { delim += s[k + 1]; quoted = true; k += 2; continue; }
    if (/[\s;&|<>()]/.test(c)) break;
    delim += c;
    k++;
  }
  return delim || quoted ? { end: k, delim, quoted, strip } : null;
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
    const fd = FD_REDIRECT.exec(text.slice(i, i + 10));
    if (fd) {
      // `<`, `>`, or an fd number written against one (`0<p.txt`, `2>/dev/null`): a redirect, not a word.
      const at = i + fd[0].length - 1;
      const op = REDIRECT.exec(text.slice(at, at + 3))[0];
      out.push({ op, fd: fd[0].slice(0, -1) });
      i = at + op.length;
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
      if (q === "$'") {
        // ANSI-C quoting: a backslash escapes the next character (`\'` does not close it).
        if (c === '\\' && i + 1 < n) { flush(i); runFrom = i + 1; i++; continue; }
        if (c === "'") { flush(i); q = null; runFrom = i + 1; }
        continue;
      }
      if (q === '"') {
        if (c === '\\' && i + 1 < n && '"\\$`'.includes(text[i + 1])) { flush(i); runFrom = i + 1; i++; continue; }
        if (c === '"') { flush(i); q = null; runFrom = i + 1; }
        continue;
      }
      if (/\s/.test(c) || c === '<' || c === '>') break;
      if (c === '$' && text[i + 1] === '$') { i++; continue; }
      if (c === '$' && text[i + 1] === "'") { flush(i); q = "$'"; i++; runFrom = i + 1; continue; }
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
    if (w.op === '<<' || w.op === '<<-') {
      heredocs++;
      if (Number(w.fd || 0) !== 0) stdin = true; // `3<<EOF` feeds fd 3: stdin is whatever the shell had
    } else if (w.op.startsWith('<')) stdin = true; // <, <&, <>, <<< (here-string)
    x++; // the operator's target word
  }
  let p = 0;
  while (items[p]) {
    const v = items[p].value.toLowerCase();
    if (KEYWORDS.has(v) || /^[A-Za-z_]\w*=/.test(v)) {
      p++;
      if (v === 'time') while (items[p] && items[p].value.startsWith('-')) p++;
      continue;
    }
    if (WRAPPERS.has(v)) {
      p++;
      while (items[p] && /^(?:-|\d|[A-Za-z_]\w*=)/.test(items[p].value)) {
        if (v === 'command' && LOOKUP.test(items[p].value)) return;
        p++;
      }
      continue;
    }
    break;
  }
  const cmd = items[p];
  if (!cmd) return;
  const names = [base(cmd.value), base(deobfuscate(cmd.raw).replace(/["']/g, ''))];
  if (!names.some(nm => NAME_RE.test(nm))) {
    if (!names.some(nm => SHELLS.test(nm))) return;
    for (let f = p + 1; f < items.length - 1; f++) {
      if (!SCRIPT_FLAG.test(items[f].value)) continue;
      if (depth >= MAX_DEPTH) throw new Incomplete('shell nesting');
      const next = items[f + 1];
      const whole = /^(?:['"]|\$')/.test(next.raw) && f + 2 === items.length;
      const nested = whole ? next.value : text.slice(next.start);
      const inner = [];
      scan(nested, 0, depth + 1, inner, false);
      const expanded = !SINGLE_QUOTED.test(next.raw) && /[$`]|\\\r?\n/.test(whole ? next.raw : nested);
      for (const c of inner) calls.push(expanded ? { inline: false } : c);
      return;
    }
    return;
  }
  const args = items.slice(p + 1);
  if (!stdin && !seg.piped && !heredocs && args.length && args.every(a => HELP.test(a.value))) return;
  let inline = false;
  if (!stdin && !seg.piped) {
    // The binary takes the patch from its first argument when there is one and reads stdin only otherwise
    // (codex-rs apply-patch standalone_executable.rs): with an argument, a heredoc is ignored.
    if (args[0]) {
      inline = LITERAL_WORD.test(args[0].raw) && args[0].value.replace(TRIM, '').startsWith(BEGIN);
    } else if (heredocs) {
      const h = heredocs === 1 && seg.heredocs.length === 1 ? seg.heredocs[0] : null;
      inline = !!h && h.body.split('\n')[0].replace(TRIM, '') === BEGIN && (h.quoted || !EXPANDS.test(h.body));
    }
  }
  calls.push({ inline });
}

/**
 * Split a script into simple commands (quotes, comments, heredoc bodies, substitutions aware) and analyze them.
 * Scans `s` from `from`; with `inSub` (the text after `$(`) it stops at the unmatched `)` and returns its
 * index, else it scans to the end. Throws Incomplete when the text ends inside a quote, substitution or
 * heredoc body, or nesting passes MAX_DEPTH.
 */
function scan(s, from, depth, calls, inSub) {
  const segs = [];
  let seg = { start: from, piped: false, heredocs: [] };
  const pending = [];
  const next = (end, start, piped) => {
    seg.end = end;
    segs.push(seg);
    seg = { start, piped, heredocs: [] };
  };
  const dollarParen = at => {
    if (depth >= MAX_DEPTH) throw new Incomplete('substitution nesting');
    return scan(s, at + 2, depth + 1, calls, true);
  };
  // Inside backticks bash first finds the closing backtick, then reads \\ \` \$ as escapes.
  const backtick = at => {
    const e = backtickClose(s, at);
    if (e >= s.length) throw new Incomplete('unclosed backtick');
    if (depth >= MAX_DEPTH) throw new Incomplete('substitution nesting');
    scan(s.slice(at + 1, e).replace(/\\([\\`$])/g, '$1'), 0, depth + 1, calls, false);
    return e;
  };
  let q = null;
  let parens = 0;
  let end = -1;
  let i = from;
  while (i < s.length) {
    const c = s[i];
    if (q === "'") { if (c === "'") q = null; i++; continue; }
    if (q === "$'") {
      if (c === '\\') { i += 2; continue; }
      if (c === "'") q = null;
      i++;
      continue;
    }
    // `$$` (the PID) is consumed as a pair: the `'` or `(` after it is not part of a `$'` / `$(`.
    if (q === '"') {
      if (c === '\\') { i += 2; continue; }
      if (c === '"') { q = null; i++; continue; }
      if (c === '`') { i = backtick(i) + 1; continue; }
      if (c === '$' && s[i + 1] === '$') { i += 2; continue; }
      if (c === '$' && s[i + 1] === '(') { i = dollarParen(i) + 1; continue; }
      i++;
      continue;
    }
    if (c === '\\') { i += 2; continue; }
    if (c === '$' && s[i + 1] === '$') { i += 2; continue; }
    if (c === '$' && s[i + 1] === "'") { q = "$'"; i += 2; continue; }
    if (c === "'" || c === '"') { q = c; i++; continue; }
    if (c === '`') { i = backtick(i) + 1; continue; }
    if (c === '$' && s[i + 1] === '(') { i = dollarParen(i) + 1; continue; }
    if (c === '#' && (i === 0 || /[\s;&|(]/.test(s[i - 1]))) {
      const nl = s.indexOf('\n', i);
      i = nl === -1 ? s.length : nl;
      continue;
    }
    if (c === '<' && s[i + 1] === '<' && s[i + 2] !== '<') {
      const h = heredocAt(s, i);
      if (h) { pending.push({ seg, ...h }); i = h.end; continue; }
      i += 2;
      continue;
    }
    if (c === '\n') {
      let j = i + 1;
      for (const h of pending) {
        const lines = [];
        let closed = false;
        while (j < s.length) {
          let e = s.indexOf('\n', j);
          if (e === -1) e = s.length;
          let line = s.slice(j, e);
          if (line.endsWith('\r')) line = line.slice(0, -1);
          j = e + 1;
          if ((h.strip ? line.replace(/^\t+/, '') : line) === h.delim) { closed = true; break; }
          lines.push(line);
        }
        if (!closed) throw new Incomplete('unterminated heredoc');
        h.seg.heredocs.push({ body: lines.join('\n'), quoted: h.quoted });
      }
      pending.length = 0;
      j = Math.min(j, s.length);
      next(i, j, false);
      i = j;
      continue;
    }
    if (c === ')' && inSub && parens === 0) { end = i; break; }
    if (c === '(') parens++;
    else if (c === ')' && parens > 0) parens--;
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
  if (q !== null) throw new Incomplete('unclosed quote');
  if (inSub && end === -1) throw new Incomplete('unclosed substitution');
  seg.end = end === -1 ? s.length : end;
  segs.push(seg);
  for (const g of segs) if (g.end > g.start) analyze(s.slice(g.start, g.end), g, depth, calls);
  return seg.end;
}

const MAYBE = /apply_?patch/i;

/**
 * Shell-form apply_patch: `null` when the command does not invoke apply_patch in command position, else the
 * header paths (`truncated` as in scanPatch), the `cd` directory Codex applies the patch in (`workdir`, or
 * null), and `inline`: exactly one invocation and it is inline. A non-inline invocation (stdin, file, pipe,
 * substitution, a second invocation, an expandable patch) cannot be inspected (Rulings R18, R18-c). Never
 * throws: once the pre-filter sees apply_patch, a scan that cannot finish is one non-inline call (R20.1).
 * @returns {{ paths: string[], truncated: boolean, workdir: string|null, inline: boolean } | null}
 */
export function shellPatch(command) {
  if (typeof command !== 'string') return null;
  // m3: a backslash-newline inside the command word (`apply\<newline>_patch`) is a line continuation; join it for
  // finding the invocation only (as guardcore does). Header paths are still read from the original text.
  const joined = command.replace(/\\\r?\n/g, '');
  let maybe = MAYBE.test(command) || MAYBE.test(joined);
  if (!maybe) try { maybe = MAYBE.test(deobfuscate(joined)); } catch { maybe = true; }
  if (!maybe) return null;
  const uninspectable = { paths: [], truncated: false, workdir: null, inline: false };
  try {
    let calls = [];
    try {
      scan(command, 0, 0, calls, false);
    } catch {
      return { ...uninspectable, ...scanPatch(command), inline: false };
    }
    // cmd `^` / PowerShell backtick escapes and backslash-newlines inside the command word (`ap^ply_patch`,
    // ap`ply_patch, apply\<newline>_patch): one more pass over the text without them, only when the raw scan found
    // nothing (quote structure is kept). This
    // text is a guess, not what a shell parses: when it cannot be scanned to the end it is ignored.
    if (!calls.length) {
      const unescaped = joined.replace(/\^/g, '').replace(/`(?=[A-Za-z])/g, '');
      if (unescaped !== command) {
        try { scan(unescaped, 0, 0, calls = [], false); } catch (e) { if (!(e instanceof Incomplete)) throw e; calls = []; }
      }
    }
    if (!calls.length) return null;
    const cd = CD_PREFIX.exec(command);
    return { ...scanPatch(command), workdir: cd ? cd[1] ?? cd[2] ?? cd[3] : null, inline: calls.length === 1 && calls[0].inline };
  } catch {
    return uninspectable;
  }
}
