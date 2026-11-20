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

const HEADER = /^\*\*\* (?:Add File|Update File|Delete File|Move to): (.+)$/;
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
// invocation.rs) and applies it itself; the PreToolUse hook sees it as a `Bash` call.
const SHELL_APPLY_PATCH = /(?:^|[\s;&|(){}])(?:apply_patch|applypatch)(?:\.exe)?(?=$|[\s<'"])/;
const CD_PREFIX = /^\s*cd\s+(?:'([^']*)'|"([^"]*)"|([^\s;&|'"]+))\s*&&\s*(?:apply_patch|applypatch)\b/;

/**
 * Shell-form apply_patch: `null` when the command does not invoke apply_patch, else the header paths
 * (`truncated` as in scanPatch) and the `cd` directory Codex applies the patch in (`workdir`, or null).
 * @returns {{ paths: string[], truncated: boolean, workdir: string|null } | null}
 */
export function shellPatch(command) {
  if (typeof command !== 'string' || !SHELL_APPLY_PATCH.test(command)) return null;
  const cd = CD_PREFIX.exec(command);
  return { ...scanPatch(command), workdir: cd ? cd[1] ?? cd[2] ?? cd[3] : null };
}
