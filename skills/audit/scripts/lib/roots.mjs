import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Install roots of an entry script at `<skill root>/scripts/<name>.mjs` (`metaUrl` is its import.meta.url).
 * `skillRoot` is the audit skill dir; `pluginRoot` is the plugin (or repository) root two levels above it when
 * `<pluginRoot>/.claude-plugin/plugin.json` exists, else null (a standalone skill install).
 */
export function roots(metaUrl) {
  const skillRoot = path.resolve(path.dirname(fileURLToPath(metaUrl)), '..');
  const pluginRoot = path.resolve(skillRoot, '..', '..');
  let isPlugin = false;
  try { isPlugin = fs.statSync(path.join(pluginRoot, '.claude-plugin', 'plugin.json')).isFile(); } catch { /* standalone */ }
  return { skillRoot, pluginRoot: isPlugin ? pluginRoot : null };
}
