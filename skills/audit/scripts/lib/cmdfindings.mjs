import { matchCommand } from './rules.mjs';
import { truncate, escapeInvisible, redactSecrets, redactArgs } from './text.mjs';

/** Pseudo-file of config-derived findings; baseline/allowlist hash the raw config under this name. */
export const CONFIG_FILE = '<config>';

export const finding = (ruleId, category, severity, file, snippet, line = 1) =>
  ({ ruleId, category, severity, line, snippet: truncate(escapeInvisible(String(snippet))), file });

/** Runner invoked without a pinned version, `npx -y`, `uvx` or `@latest`. */
export function unpinnedRuntime(cmd) {
  if (/@latest\b/i.test(cmd)) return true;
  const tokens = cmd.split(/\s+/).filter(Boolean);
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i].replace(/^.*[\\/]/, '').replace(/\.(?:cmd|exe)$/i, '').toLowerCase();
    const isDlx = t === 'pnpm' && tokens[i + 1] === 'dlx';
    const isPipx = t === 'pipx' && tokens[i + 1] === 'run';
    if (!['npx', 'uvx', 'bunx'].includes(t) && !isDlx && !isPipx) continue;
    const rest = tokens.slice(i + (isDlx || isPipx ? 2 : 1));
    if (t === 'npx' && rest.some(a => a === '-y' || a === '--yes')) return true;
    if (t === 'uvx') return true;
    const pkg = rest.find(a => !a.startsWith('-'));
    if (!pkg) return true;
    if (!/@\d|==\d|@[a-z]*\d/i.test(pkg.replace(/^@/, ''))) return true;
  }
  return false;
}

/**
 * Findings for one configured command (argv): command rules on the unredacted text (a payload after
 * `--token` must still match), snippets always redacted; plus SUPPLY_UNPINNED_RUNTIME.
 */
export function commandFindings(argv, file = CONFIG_FILE) {
  const out = [];
  const cmd = argv.join(' ');
  const shown = [argv[0], ...redactArgs(argv.slice(1), argv[0])].map(redactSecrets).join(' ');
  for (const m of matchCommand(cmd)) out.push({ ...m, snippet: redactSecrets(m.snippet), file });
  if (unpinnedRuntime(cmd)) out.push(finding('SUPPLY_UNPINNED_RUNTIME', 'supply', 'medium', file, shown));
  return out;
}

/** Findings for a remote MCP URL: SUPPLY_REMOTE_MCP (info) plus command rules on the URL. */
export function urlFindings(url, file = CONFIG_FILE) {
  const out = [finding('SUPPLY_REMOTE_MCP', 'supply', 'info', file, redactSecrets(url))];
  for (const m of matchCommand(url)) out.push({ ...m, snippet: redactSecrets(m.snippet), file });
  return out;
}
