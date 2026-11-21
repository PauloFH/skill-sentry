# Releasing skill-sentry

Releases are automatic. Nobody bumps a version or pushes a tag by hand.

## How a release happens

1. Changes reach `main` only through pull requests whose checks passed (a ruleset on `main`). Each pull request
   runs `.github/workflows/release.yml`: the unit suite (`npm test`) on Linux, Windows and macOS with Node 18 and 22,
   the e2e install checks against the real Claude Code and Codex CLIs on Linux and Windows, and a release dry run
   whose summary says which version merging would release.
2. On every push to `main`, the same workflow runs the checks again, then the model e2e (only when the API key
   secrets exist), and only if everything passed, semantic-release (`tools/ci/release/`, a locked toolchain):
   - the version comes from the Conventional Commits since the last `v*` tag: `fix:` gives a patch, `feat:` a
     minor, `type!:` or a `BREAKING CHANGE:` footer a major; `docs:`, `chore:`, `ci:`, `test:`, `refactor:` give
     no release;
   - `tools/ci/set-version.mjs` writes the version into `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`
     and `package.json`, and `test/package.test.mjs` checks they agree;
   - `CHANGELOG.md` gets the release notes;
   - the commit `chore: release <version>` goes to `main`, tagged `v<version>`, and a GitHub Release is created.
3. The release push is made with a GitHub App token (repository variable `RELEASE_APP_CLIENT_ID` or
   `RELEASE_APP_ID`, secret `RELEASE_APP_PRIVATE_KEY`), the only actor allowed to bypass the ruleset. Without them
   the publish job fails with a clear error instead of releasing.
4. That push starts the workflow once more. It releases nothing: the last tag is on that very commit, so there are
   no new commits to analyse.

## After each release: add it to KNOWN_RELEASES

`scripts/lib/releases.mjs` holds the file hashes of every published release. A newer scanner uses it to recognise
an older skill-sentry copy (for example the one still installed for the other agent) instead of reporting it as
malicious. A release cannot carry its own hashes, so each release's entry ships with the next one.

`test/known-releases.test.mjs` enforces this: once a release is tagged, every pull request fails until its entry is
added. Do it right after the release:

```
mkdir <tmp>
git fetch --tags
git archive v<version> | tar -x -C <tmp>
node tools/release-hashes.mjs <tmp>
```

Add the printed `hashes` under `KNOWN_RELEASES["<version>"]` and `sizes` under `KNOWN_RELEASE_SIZES["<version>"]`,
keep every older entry, and merge it as a `chore:` pull request (for example `chore: add the 0.1.2 release
hashes`). A `chore:` commit releases nothing; the entry is published with the next `fix:` or `feat:` release.
