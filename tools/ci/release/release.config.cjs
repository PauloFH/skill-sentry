// semantic-release configuration for the publish job of .github/workflows/release.yml. CI-only: the toolchain is
// locked in this directory (package.json + package-lock.json) and installed with
// `npm ci --ignore-scripts --prefix tools/ci/release`; semantic-release resolves the plugins of an --extends config
// from the config's own directory, which is why this file lives next to that node_modules. Never a dependency of
// the plugin. See docs/RELEASING.md.
//
// Conventional Commits since the last v* tag decide the version (conventionalcommits preset): fix -> patch,
// feat -> minor, a breaking change (`type!:` or a BREAKING CHANGE footer) -> major; docs, chore, ci, test,
// refactor, style, build -> no release.
//
// The npm plugin is not loaded at all, so nothing is ever published to npm (the package is private); the
// version in package.json is written by tools/ci/set-version.mjs together with the two plugin manifests.
module.exports = {
  branches: ['main'],
  tagFormat: 'v${version}',
  plugins: [
    ['@semantic-release/commit-analyzer', { preset: 'conventionalcommits' }],
    ['@semantic-release/release-notes-generator', { preset: 'conventionalcommits' }],
    ['@semantic-release/exec', {
      // Write the version, then check that the three version fields agree before anything is committed.
      prepareCmd: 'node tools/ci/set-version.mjs ${nextRelease.version} && node --test test/package.test.mjs',
    }],
    ['@semantic-release/changelog', { changelogFile: 'CHANGELOG.md', changelogTitle: '# Changelog' }],
    ['@semantic-release/git', {
      assets: ['.claude-plugin/plugin.json', '.claude-plugin/marketplace.json', 'package.json', 'CHANGELOG.md'],
      // One line, no body, no trailer (the project's commit format).
      message: 'chore: release ${nextRelease.version}',
    }],
    // No success comments or "released" labels on issues and PRs; a failed release still opens an issue.
    ['@semantic-release/github', { successComment: false, releasedLabels: false }],
  ],
};
