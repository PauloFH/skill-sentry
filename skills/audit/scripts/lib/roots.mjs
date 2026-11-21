import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Install roots of an entry script at `<skill root>/scripts/<name>.mjs` (`metaUrl` is its import.meta.url).
 * `skillRoot` is the audit skill dir. `pluginRoot` is the skill-sentry plugin (or repository) root two levels above
 * it: only when the skill dir is exactly `<pluginRoot>/skills/audit` and `<pluginRoot>/.claude-plugin/plugin.json`
 * names `skill-sentry`. Otherwise null: a standalone skill install (npx skills add), even one placed inside some
 * other plugin's tree.
 */
export function roots(metaUrl) {
  const skillRoot = path.resolve(path.dirname(fileURLToPath(metaUrl)), '..');
  const candidate = path.resolve(skillRoot, '..', '..');
  let isPlugin = false;
  if (path.join(candidate, 'skills', 'audit') === skillRoot) {
    try {
      const m = JSON.parse(fs.readFileSync(path.join(candidate, '.claude-plugin', 'plugin.json'), 'utf8'));
      isPlugin = m !== null && typeof m === 'object' && m.name === 'skill-sentry';
    } catch { /* missing or unreadable: standalone */ }
  }
  return { skillRoot, pluginRoot: isPlugin ? candidate : null };
}
