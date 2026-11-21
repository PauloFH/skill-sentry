import fs from 'node:fs';

// Claude Code built-in slash commands: invoking them does not make a skill the origin of later tool calls.
const BUILTIN_COMMANDS = new Set([
  'add-dir', 'agents', 'bashes', 'bug', 'clear', 'compact', 'config', 'context', 'cost', 'doctor', 'exit',
  'export', 'feedback', 'help', 'hooks', 'ide', 'init', 'install-github-app', 'login', 'logout', 'mcp',
  'memory', 'model', 'output-style', 'permissions', 'plugin', 'plugins', 'pr-comments', 'release-notes',
  'remote-control', 'resume', 'review', 'rewind', 'security-review', 'status', 'statusline',
  'terminal-setup', 'todos', 'upgrade', 'usage', 'vim',
]);

const COMMAND_NAME = /<command-name>\/?([^<\s]+)<\/command-name>/;

/** Read at most the last `maxBytes` of a file; drops the partial first line when starting mid-file. */
export function readTail(file, maxBytes) {
  const fd = fs.openSync(file, 'r');
  try {
    const size = fs.fstatSync(fd).size;
    const start = Math.max(0, size - maxBytes);
    const buf = Buffer.alloc(size - start);
    let off = 0;
    while (off < buf.length) {
      const n = fs.readSync(fd, buf, off, buf.length - off, start + off);
      if (n <= 0) break;
      off += n;
    }
    let text = buf.subarray(0, off).toString('utf8');
    if (start > 0) {
      const nl = text.indexOf('\n');
      text = nl === -1 ? '' : text.slice(nl + 1);
    }
    return text;
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * Text of a plain user message (typed by the user), or null for tool results, meta/injected
 * lines (skill bodies, caveats), compact summaries and non-user entries.
 */
function userText(o) {
  if (o.type !== 'user' || o.isMeta || o.sourceToolUseID || o.isCompactSummary || o.isVisibleInTranscriptOnly) return null;
  const m = o.message;
  if (!m || m.role !== 'user') return null;
  if (typeof m.content === 'string') return m.content;
  if (!Array.isArray(m.content)) return null;
  if (m.content.some(b => b && b.type === 'tool_result')) return null;
  const texts = m.content.filter(b => b && (b.type === 'text' || b.type === 'image'));
  if (!texts.length) return null;
  return texts.map(b => (typeof b.text === 'string' ? b.text : '')).join('\n');
}

/** Last Skill tool_use `input.skill` in an assistant entry, or null. */
function skillCall(o) {
  if (o.type !== 'assistant' || !o.message || !Array.isArray(o.message.content)) return null;
  for (let i = o.message.content.length - 1; i >= 0; i--) {
    const b = o.message.content[i];
    if (b && b.type === 'tool_use' && b.name === 'Skill' && b.input && typeof b.input.skill === 'string' && b.input.skill) {
      return b.input.skill;
    }
  }
  return null;
}

/**
 * Attribute the current tool call to a skill or plugin.
 * - `mcp__plugin_<plugin>_<server>__<tool>` -> `{ mcpPlugin, mcpQualified: '<plugin>_<server>' }` (no transcript read).
 * - Otherwise scan the transcript tail backwards to the most recent plain user message; the most recent
 *   Skill tool_use after it (or a `/plugin:skill` slash command in that message) is the origin.
 * @returns {{ skill: string } | { mcpPlugin: string, mcpQualified: string } | null}
 */
export function findOrigin(transcriptPath, maxBytes = 262144, toolName = null) {
  try {
    const mcp = typeof toolName === 'string' && /^mcp__plugin_(.+?)__/.exec(toolName);
    if (mcp) {
      const qualified = mcp[1];
      const us = qualified.indexOf('_');
      return { mcpPlugin: us > 0 ? qualified.slice(0, us) : qualified, mcpQualified: qualified };
    }
    if (typeof transcriptPath !== 'string' || !transcriptPath) return null;
    const lines = readTail(transcriptPath, maxBytes).split('\n');
    for (let i = lines.length - 1; i >= 0; i--) {
      const line = lines[i].trim();
      if (!line.startsWith('{')) continue;
      let o;
      try { o = JSON.parse(line); } catch { continue; }
      if (!o || typeof o !== 'object') continue;
      const skill = skillCall(o);
      if (skill) return { skill };
      const text = userText(o);
      if (text !== null) {
        const cmd = COMMAND_NAME.exec(text);
        if (cmd && !BUILTIN_COMMANDS.has(cmd[1].toLowerCase())) return { skill: cmd[1] };
        return null;
      }
    }
    return null;
  } catch {
    return null;
  }
}
