// Dry-run configuration for the `release (dry run)` job of .github/workflows/release.yml: the same branch, tag
// format and commit analysis as release.config.cjs, but only the two plugins that compute the next version and its
// notes. Nothing here can write: no exec, changelog, git or github plugin, and the job holds no write token (it
// points semantic-release at a local bare clone; see the workflow).
const release = require('./release.config.cjs');

const keep = new Set(['@semantic-release/commit-analyzer', '@semantic-release/release-notes-generator']);
module.exports = {
  branches: release.branches,
  tagFormat: release.tagFormat,
  plugins: release.plugins.filter(p => keep.has(Array.isArray(p) ? p[0] : p)),
};
