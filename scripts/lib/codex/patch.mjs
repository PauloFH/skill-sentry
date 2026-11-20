// Write targets of a Codex `apply_patch` call. Only the file headers are read; patch content (the `+`/`-`
// lines) is never inspected, the same as Write/Edit content under Claude Code.

// Bounds: a patch past either cap is reported `truncated` (the caller treats the call as not fully
// inspected); paths seen before the cap are still returned.
export const PATCH_MAX_BYTES = 512 * 1024;
export const PATCH_MAX_PATHS = 256;

const HEADER = /^\*\*\* (?:Add File|Update File|Delete File|Move to): (.+)$/;

/**
 * @param {unknown} patchText `tool_input.command` of an apply_patch call
 * @returns {{ paths: string[], truncated: boolean }}
 */
export function scanPatch(patchText) {
  const paths = [];
  if (typeof patchText !== 'string' || !patchText) return { paths, truncated: false };
  const text = patchText.length > PATCH_MAX_BYTES ? patchText.slice(0, PATCH_MAX_BYTES) : patchText;
  let truncated = text.length < patchText.length;
  let start = 0;
  while (start < text.length) {
    let end = text.indexOf('\n', start);
    // The last line of a cut-off text may itself be cut: skip it.
    if (end === -1) { if (truncated) break; end = text.length; }
    const line = text.slice(start, end).replace(/\r$/, '');
    start = end + 1;
    if (!line.startsWith('*** ')) continue;
    const m = HEADER.exec(line);
    if (!m) continue;
    const p = m[1].trim();
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
