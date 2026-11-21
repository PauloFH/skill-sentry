// Write targets of a Codex `apply_patch` call. Only the file headers are read; patch content (the `+`/`-`
// lines) is never inspected, the same as Write/Edit content under Claude Code.
//
// Header matching follows codex-rs apply-patch (streaming_parser.rs): each line is trimmed (Rust `str::trim`,
// Unicode White_Space) before `*** Add File: ` / `*** Delete File: ` / `*** Update File: ` are stripped;
// `*** Move to: ` is matched the same way here (Codex only trims its end: a superset is safe). Lines are split
// on CR as well as LF (Codex splits on LF only; also a safe superset).

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

// Codex intercepts `[cd <dir> &&] apply_patch|applypatch <<'EOF' … EOF` run through a shell (apply-patch
// invocation.rs) and applies it itself; the PreToolUse hook sees it as a `Bash` call. Codex also puts real
// `apply_patch`/`applypatch` executables first on PATH (arg0), so any shell construct that runs one applies a
// patch: the invocation is detected in command position (N2), not only at the start of the text.
//   statement starts: text start, newline, ; & | ( { ! backtick $(, or the quoted script of -c/-lc/-Command//c;
//   then assignments, common wrappers (with options) and a path prefix.
const NAME = String.raw`(?:apply_patch|applypatch)(?:\.exe)?`;
const START = String.raw`(?:^|[\n;&|({!\x60]|\$\(|(?:^|\s)(?:-[a-z]*c|-command|/c)\s+['"])`;
// Option alternatives are disjoint (start with `-`, a digit, or a letter/_) so the match cannot backtrack exponentially.
const WRAPPER = String.raw`(?:(?:sudo|env|command|exec|nohup|time|xargs|doas|nice|stdbuf|timeout|busybox)(?:[ \t]+(?:-\S+|\d\S*|[A-Za-z_]\w*=\S*))*[ \t]+)`;
const INVOCATION = new RegExp(String.raw`${START}[ \t]*(?:[A-Za-z_]\w*=\S*[ \t]+)*${WRAPPER}*(?:[^\s;&|()<>'"\x60]*[\\/])?${NAME}(?=$|[\s<>|;&)'"\x60])`, 'gi');
// Bash words end at blanks and metacharacters only: U+2028 and friends stay inside the word (N1 audit).
const CD_PREFIX = /^[ \t\n]*cd[ \t]+(?:'([^']*)'|"([^"]*)"|([^ \t\n;&|()<>'"]+))[ \t]*&&[ \t]*(?:apply_patch|applypatch)\b/;
const BEGIN = '*** Begin Patch';
const END = '*** End Patch';

/** [start, end) ranges of inline patch text, so a patch body line is never taken for an invocation. */
function patchRanges(text) {
  const out = [];
  let from = 0;
  for (;;) {
    const b = text.indexOf(BEGIN, from);
    if (b === -1) return out;
    const e = text.indexOf(END, b + BEGIN.length);
    out.push([b, e === -1 ? text.length : e + END.length]);
    if (e === -1) return out;
    from = e + END.length;
  }
}

/**
 * Shell-form apply_patch: `null` when the command does not invoke apply_patch in command position, else the
 * header paths (`truncated` as in scanPatch), the `cd` directory Codex applies the patch in (`workdir`, or
 * null), and `inline`: exactly one invocation, followed by an inline `*** Begin Patch`. A non-inline
 * invocation (stdin, file, substitution, a second invocation) cannot be inspected (Ruling R18).
 * @returns {{ paths: string[], truncated: boolean, workdir: string|null, inline: boolean } | null}
 */
export function shellPatch(command) {
  if (typeof command !== 'string' || !/apply_?patch/i.test(command)) return null;
  const ranges = patchRanges(command);
  const inPatch = i => ranges.some(([s, e]) => i >= s && i < e);
  const calls = [...command.matchAll(INVOCATION)].map(m => m.index + m[0].length).filter(end => !inPatch(end - 1));
  if (!calls.length) return null;
  const cd = CD_PREFIX.exec(command);
  const inline = calls.length === 1 && command.indexOf(BEGIN, calls[0]) !== -1;
  return { ...scanPatch(command), workdir: cd ? cd[1] ?? cd[2] ?? cd[3] : null, inline };
}
