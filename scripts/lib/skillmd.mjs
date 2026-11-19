import { matchCommand, matchText } from './rules.mjs';
import { truncate, escapeInvisible } from './text.mjs';

const RANK = { info: 0, medium: 1, high: 2, critical: 3 };
const mk = (ruleId, severity, line, snippet) =>
  ({ ruleId, category: 'skill', severity, line, snippet: truncate(escapeInvisible(String(snippet).trim())) });

/** Split a frontmatter block into [{ key, value, line }] (value keeps YAML list items as "a, b"). */
function parseFrontmatter(lines) {
  if (lines[0]?.replace(/^﻿/, '').trim() !== '---') return { entries: [], end: 0 };
  let end = -1;
  for (let i = 1; i < lines.length; i++) if (lines[i].trim() === '---') { end = i; break; }
  if (end < 0) return { entries: [], end: 0 };
  const entries = [];
  for (let i = 1; i < end; i++) {
    const m = /^([A-Za-z][\w-]*)\s*:\s*(.*)$/.exec(lines[i]);
    if (!m) continue;
    let value = m[2].trim();
    if (value === '' || /^[|>][+-]?$/.test(value)) {
      const parts = [];
      while (i + 1 < end && /^\s+\S|^\s*-\s/.test(lines[i + 1])) parts.push(lines[++i].replace(/^\s*-\s*/, '').trim());
      value = parts.join(value.startsWith('|') || value.startsWith('>') ? ' ' : ', ');
    }
    entries.push({ key: m[1].toLowerCase(), value: value.replace(/^(["'])(.*)\1$/, '$2'), line: i + 1 });
  }
  return { entries, end };
}

/** Split on commas that are outside parentheses. */
function splitTools(v) {
  const out = [];
  let depth = 0;
  let cur = '';
  for (const ch of v.replace(/^\[|\]$/g, '')) {
    if (ch === '(') depth++;
    else if (ch === ')') depth = Math.max(0, depth - 1);
    if ((ch === ',' || /\s/.test(ch)) && depth === 0) { out.push(cur); cur = ''; } else cur += ch;
  }
  out.push(cur);
  return out.map(s => s.trim().replace(/^(["'])(.*)\1$/, '$2')).filter(Boolean);
}

const isBroadTool = t =>
  t === '*' || t === 'WebFetch' || /^WebFetch\(\s*\*?\s*\)$/.test(t)
  || /^Bash$/i.test(t) || /^Bash\(\s*(?:\*(?::\*)?)?\s*\)$/i.test(t)
  || /^Bash\(\s*(?:curl|wget)\b/i.test(t);

const OVERBROAD = /\b(?:any|every|all)\s+(?:task|request|prompt|query|conversation)s?\b|\balways\s+use\b|\bqualquer\s+(?:tarefa|pedido)\b|\btoda\s+tarefa\b|\bcualquier\s+tarea\b/i;

/** @param {string} text @returns {import('./rules.mjs').Match[]} */
export function analyzeSkillMarkdown(text) {
  const lines = String(text).split(/\r?\n/);
  const out = [];
  const { entries, end } = parseFrontmatter(lines);

  for (const { key, value, line } of entries) {
    if (key === 'allowed-tools' || key === 'allowed_tools') {
      for (const tool of splitTools(value)) {
        out.push(isBroadTool(tool)
          ? mk('SKILL_ALLOWED_TOOLS_BROAD', 'high', line, `allowed-tools: ${tool}`)
          : mk('SKILL_ALLOWED_TOOLS', 'info', line, `allowed-tools: ${tool}`));
      }
    } else if (key === 'context' && /^fork\b/i.test(value)) {
      out.push(mk('SKILL_CONTEXT_FORK', 'medium', line, `context: ${value}`));
    } else if (key === 'description' && OVERBROAD.test(value)) {
      out.push(mk('SKILL_OVERBROAD_DESCRIPTION', 'medium', line, `description: ${value}`));
    }
  }

  // A document that references secrets and also runs an exfil-looking command is critical (spec combination rule).
  const docSecret = matchText(text, 'markdown').some(m => m.category === 'secret');
  const injected = (cmd, line) => {
    let severity = 'medium';
    const ms = matchCommand(cmd);
    for (const m of ms) if (RANK[m.severity] > RANK[severity]) severity = m.severity;
    if (ms.some(m => m.category === 'exfil') && (docSecret || ms.some(m => m.category === 'secret'))) severity = 'critical';
    out.push(mk('SKILL_INJECTED_SHELL', severity, line, cmd));
  };
  // Mirrors Claude Code's own substitution patterns (read from the shipped CLI, Claude Code 2.1.x):
  //   block  /```!\s*\n?([\s\S]*?)\n?```/  — anywhere, not only at line start
  //   inline /(?<=^|\s)!`([^`]+)`/        — `!` at body start or after whitespace; may span lines
  // Neither pattern skips ordinary ``` fences, so `!` commands inside documentation fences still count.
  const bodyStart = lines.slice(0, end).reduce((n, l) => n + l.length + 1, 0);
  const full = lines.join('\n');
  let body = full.slice(Math.min(bodyStart, full.length));
  const nl = [];
  for (let i = body.indexOf('\n'); i !== -1; i = body.indexOf('\n', i + 1)) nl.push(i);
  const lineAt = idx => { // binary search: number of newlines before idx
    let lo = 0;
    let hi = nl.length;
    while (lo < hi) { const mid = (lo + hi) >> 1; if (nl[mid] < idx) lo = mid + 1; else hi = mid; }
    return end + 1 + lo;
  };
  // Blocks are blanked (newlines kept) so their contents are not reported again as inline matches.
  const blankOut = s => s.replace(/[^\n]/g, ' ');
  body = body.replace(/```!\s*\n?([\s\S]*?)\n?```/g, (m0, cmd, idx) => { injected(cmd, lineAt(idx)); return blankOut(m0); });
  const open = body.indexOf('```!');
  if (open !== -1) { // unclosed block: Claude Code would not run it, but report it anyway
    injected(body.slice(open + 4).trim(), lineAt(open));
    body = body.slice(0, open) + blankOut(body.slice(open));
  }
  for (const m of body.matchAll(/(?<=^|\s)!`([^`]+)`/g)) injected(m[1], lineAt(m.index));
  return out;
}
