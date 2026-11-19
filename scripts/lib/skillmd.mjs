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
    if (ch === ',' && depth === 0) { out.push(cur); cur = ''; } else cur += ch;
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
  let inBang = false;
  let block = [];
  let blockStart = 0;
  for (let i = end; i < lines.length; i++) {
    const l = lines[i];
    if (inBang) {
      if (/^\s*```\s*$/.test(l)) { injected(block.join('\n'), blockStart); inBang = false; block = []; } else block.push(l);
      continue;
    }
    if (/^\s*```!/.test(l)) {
      inBang = true; blockStart = i + 1;
      const rest = l.replace(/^\s*```!\s*/, '');
      block = rest ? [rest] : [];
      continue;
    }
    for (const m of l.matchAll(/!`([^`\n]+)`/g)) injected(m[1], i + 1);
  }
  if (inBang) injected(block.join('\n'), blockStart);
  return out;
}
