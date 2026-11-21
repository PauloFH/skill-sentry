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
    // Prepare runs in plugin order: version and KNOWN_RELEASES (exec), CHANGELOG.md (changelog), then the self-manifest
    // (a second exec), which must come LAST: it hashes every file of the release commit, these included.
    ['@semantic-release/exec', {
      // Write the version; record the previous release in KNOWN_RELEASES (a release cannot carry its own hashes,
      // so each release commit carries the one before it). `lastRelease.gitTag` is empty on a first release, and
      // record-release then does nothing.
      prepareCmd: 'node tools/ci/set-version.mjs ${nextRelease.version}'
        + ' && node tools/ci/record-release.mjs ${lastRelease.gitTag}',
    }],
    ['@semantic-release/changelog', { changelogFile: 'CHANGELOG.md', changelogTitle: '# Changelog' }],
    ['@semantic-release/exec', {
      // Write skills/audit/scripts/lib/selfmanifest.json over the release tree as it will be committed, then check the
      // manifests, the table and the self-recognition, and that the manifest matches the tree, before anything is
      // committed.
      prepareCmd: 'node tools/ci/write-manifest.mjs .'
        + ' && node --test test/package.test.mjs test/known-releases.test.mjs test/selfcopy.test.mjs'
        + ' && node tools/ci/write-manifest.mjs . --verify',
    }],
    ['@semantic-release/git', {
      assets: ['.claude-plugin/plugin.json', '.claude-plugin/marketplace.json', 'package.json', 'CHANGELOG.md', 'skills/audit/scripts/lib/releases.mjs',
        'skills/audit/scripts/lib/selfmanifest.json'],
      // One line, no body, no trailer (the project's commit format).
      message: 'chore: release ${nextRelease.version}',
    }],
    // No success comments or "released" labels on issues and PRs; a failed release still opens an issue.
    ['@semantic-release/github', { successComment: false, releasedLabels: false }],
  ],
};
