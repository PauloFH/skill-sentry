// semantic-release configuration, loaded by .github/workflows/release.yml with
// `semantic-release --extends ./tools/ci/release.config.cjs`. CI-only: the tooling is installed in the release
// job with pinned versions and is never a dependency of the plugin.
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
    ['@semantic-release/exec', { prepareCmd: 'node tools/ci/set-version.mjs ${nextRelease.version}' }],
    ['@semantic-release/changelog', { changelogFile: 'CHANGELOG.md', changelogTitle: '# Changelog' }],
    ['@semantic-release/git', {
      assets: ['.claude-plugin/plugin.json', '.claude-plugin/marketplace.json', 'package.json', 'CHANGELOG.md'],
      // One line, no body, no trailer (the project's commit format).
      message: 'chore: release ${nextRelease.version}',
    }],
    '@semantic-release/github',
  ],
};
