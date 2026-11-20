// Attribute a Codex tool call to a skill or MCP server from the session rollout (`transcript_path`).
//
// Rollout JSONL shape (learned from local rollouts, structure only; CLI 0.162-0.170 plus the legacy form):
//   { timestamp, type, payload, ordinal?, metadata? }, type in session_meta | event_msg | response_item |
//   turn_context | world_state | token_usage_record | compacted | ...
//   - user turn:  event_msg payload { type:"item_completed", item:{ type:"UserMessage", content:[
//                   {type:"text", text} | {type:"skill", name, path} ] } }   (legacy: event_msg {type:"user_message"})
//                 response_item payload { type:"message", role:"user", content:[{type:"input_text", text}] } also
//                 carries injected context ("# AGENTS.md ...", "<environment_context>", "<skill>...</skill>").
//   - commands:   event_msg item_completed item { type:"CommandExecution", command:[shell, flag, script], cwd,
//                   parsed_cmd:[{type:"read", cmd, name, path} | {type:"search"|"list_files"|"unknown", ...}] }
//                 response_item { type:"custom_tool_call", name:"exec", input:"<code-mode JS calling
//                   tools.exec_command({cmd})>" }; legacy response_item { type:"function_call", name:"shell",
//                   arguments:"{\"command\":[...]}" } / { type:"local_shell_call", action:{ command:[...] } }.
//   - hook additionalContext is recorded as a role:"developer" message (never a user turn).
import { readTail } from '../origin.mjs';

const DEFAULT_MAX_BYTES = 1024 * 1024;
// Raw-text reads: a read verb in command position-ish and a path ending in SKILL.md.
const READ_VERB = /(?:^|[\s;|&(`'"{])(?:cat|sed|head|tail|less|more|bat|nl|awk|type|get-content|gc)\s/i;
const SKILL_PATH = /([^\s'"`<>|;&(){}[\],=*?]*[\\/])?SKILL\.md(?![\w.])/gi;
const SKILL_FILE = /(?:^|[\\/])SKILL\.md$/i;
// Only lines that can matter are parsed (tool outputs can be large).
const INTERESTING = /"(?:UserMessage|user_message)"|skill\.md|"role"\s*:\s*"user"/i;
const MAX_TEXT = 256 * 1024;

const base = p => String(p).split(/[\\/]+/).filter(Boolean);

/** `{ skill }` for a SKILL.md path: the skill folder name, prefixed `<plugin>:` under plugins/cache/<mkt>/<plugin>/. */
function skillFromPath(p, cwd) {
  const parts = base(p);
  let name = parts.length >= 2 ? parts[parts.length - 2] : null;
  if (!name || name === '.') name = typeof cwd === 'string' ? base(cwd).pop() ?? null : null;
  if (!name || name === '..' || name === '.') return null;
  const lower = parts.map(s => s.toLowerCase());
  for (let i = 1; i + 2 < parts.length - 2; i++) {
    if (lower[i] === 'cache' && lower[i - 1] === 'plugins') return { skill: `${parts[i + 2]}:${name}` };
  }
  return { skill: name };
}

/** Last SKILL.md path read in a raw command/code text, or null. */
function fromText(text, cwd) {
  if (typeof text !== 'string' || text.length > MAX_TEXT || !READ_VERB.test(text)) return null;
  let last = null;
  for (const m of text.matchAll(SKILL_PATH)) last = m[0];
  return last ? skillFromPath(last, cwd) : null;
}

/** A CommandExecution item (or legacy exec_command_* event): parsed reads first, raw text when unparsed. */
function fromCommand(it) {
  const parsed = Array.isArray(it.parsed_cmd) ? it.parsed_cmd.filter(c => c && typeof c === 'object') : [];
  for (let i = parsed.length - 1; i >= 0; i--) {
    const c = parsed[i];
    if (c.type === 'read' && typeof c.path === 'string' && SKILL_FILE.test(c.path)) return skillFromPath(c.path, it.cwd);
  }
  if (parsed.length && parsed.every(c => c.type !== 'unknown')) return null;
  const cmd = it.command;
  const text = Array.isArray(cmd) ? cmd.filter(x => typeof x === 'string').join(' ') : cmd;
  return fromText(text, it.cwd);
}

/** Legacy function_call arguments (shell / shell_command / exec_command / read-like tools). */
function fromFunctionCall(p) {
  if (typeof p.arguments !== 'string' || p.arguments.length > MAX_TEXT) return null;
  let a;
  try { a = JSON.parse(p.arguments); } catch { return null; }
  if (!a || typeof a !== 'object') return null;
  for (const k of ['path', 'file_path']) {
    if (typeof a[k] === 'string' && SKILL_FILE.test(a[k]) && /read|view|open|cat/i.test(String(p.name))) return skillFromPath(a[k], a.workdir);
  }
  const cmd = a.command ?? a.cmd;
  return fromText(Array.isArray(cmd) ? cmd.filter(x => typeof x === 'string').join(' ') : cmd, a.workdir);
}

const joinText = content => (typeof content === 'string' ? content
  : Array.isArray(content) ? content.map(c => (c && typeof c.text === 'string' ? c.text : '')).join('\n') : '');

/** `<skill><name>..</name><path>..</path>..` injected as a user-role message. */
function injectedSkill(text) {
  if (!/^\s*<skill>/.test(text)) return null;
  const p = /<path>([^<\n]{1,4096})<\/path>/.exec(text);
  if (p && SKILL_FILE.test(p[1].trim())) return skillFromPath(p[1].trim());
  const n = /<name>([^<\n]{1,200})<\/name>/.exec(text);
  return n && n[1].trim() ? { skill: n[1].trim() } : null;
}

/** A user-role response_item that is the user's own text (not injected context). */
const isPlainUser = text => {
  const t = text.trimStart();
  return t.length > 0 && !/^<[A-Za-z_][\w-]*[\s>]/.test(t) && !/^# AGENTS\.md/.test(t);
};

/** Skill elements of a UserMessage item (explicit `$skill` invocation), or null. */
function userSkill(content) {
  if (!Array.isArray(content)) return null;
  for (let i = content.length - 1; i >= 0; i--) {
    const c = content[i];
    if (!c || c.type !== 'skill') continue;
    if (typeof c.path === 'string' && SKILL_FILE.test(c.path)) return skillFromPath(c.path);
    if (typeof c.name === 'string' && c.name) return { skill: c.name };
  }
  return null;
}

/**
 * Attribute the current Codex tool call.
 * - `mcp__<server>__<tool>` -> `{ mcpPlugin: server }` (no rollout read).
 * - Otherwise scan the rollout tail backwards to the last user turn: the most recent SKILL.md read (parsed
 *   `read` command, or a cat/sed/head/Get-Content/type/... command or code-mode text naming a .../SKILL.md),
 *   a `<skill>` injection, or a skill invoked in that user message, is the origin.
 * Bounded (last `maxBytes`), never throws; null when nothing is attributed.
 * @returns {{ skill: string } | { mcpPlugin: string } | null}
 */
export function findCodexOrigin(transcriptPath, maxBytes = DEFAULT_MAX_BYTES, toolName = null) {
  try {
    const mcp = typeof toolName === 'string' && /^mcp__(.+?)__./.exec(toolName);
    if (mcp) return { mcpPlugin: mcp[1] };
    if (typeof transcriptPath !== 'string' || !transcriptPath) return null;
    const lines = readTail(transcriptPath, maxBytes).split('\n');
    for (let i = lines.length - 1; i >= 0; i--) {
      const line = lines[i];
      if (!INTERESTING.test(line)) continue;
      let o;
      try { o = JSON.parse(line); } catch { continue; }
      const p = o && typeof o === 'object' ? o.payload : null;
      if (!p || typeof p !== 'object') continue;
      if (o.type === 'event_msg') {
        if (p.type === 'user_message') return null;
        const it = p.type === 'item_completed' && p.item && typeof p.item === 'object' ? p.item : null;
        if (it && it.type === 'UserMessage') return userSkill(it.content);
        const cmd = it && it.type === 'CommandExecution' ? it : /^exec_command_(?:begin|end)$/.test(p.type) ? p : null;
        const s = cmd && fromCommand(cmd);
        if (s) return s;
      } else if (o.type === 'response_item') {
        let s = null;
        if (p.type === 'message' && p.role === 'user') {
          const text = joinText(p.content);
          s = injectedSkill(text);
          if (!s && isPlainUser(text)) return null;
        } else if (p.type === 'custom_tool_call') s = fromText(p.input, null);
        else if (p.type === 'function_call') s = fromFunctionCall(p);
        else if (p.type === 'local_shell_call' && p.action && typeof p.action === 'object') s = fromCommand(p.action);
        if (s) return s;
      }
    }
    return null;
  } catch {
    return null;
  }
}
