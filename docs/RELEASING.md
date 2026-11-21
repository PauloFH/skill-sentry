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
     and `package.json`;
   - `tools/ci/record-release.mjs` adds the previous release to `scripts/lib/releases.mjs` (see below);
   - `test/package.test.mjs` and `test/known-releases.test.mjs` check the result;
   - `CHANGELOG.md` gets the release notes;
   - the commit `chore: release <version>` (those files) goes to `main`, tagged `v<version>`, and a GitHub Release
     is created.
3. The release push is made with a GitHub App token (repository variable `RELEASE_APP_CLIENT_ID` or
   `RELEASE_APP_ID`, secret `RELEASE_APP_PRIVATE_KEY`), the only actor allowed to bypass the ruleset. Without them
   the publish job fails with a clear error instead of releasing.
4. That push starts the workflow once more. It releases nothing: the last tag is on that very commit, so there are
   no new commits to analyse.

No step is manual.

## KNOWN_RELEASES, one release behind

`scripts/lib/releases.mjs` holds the file hashes of every published release. A newer scanner uses it to recognise
an older skill-sentry copy (for example the one still installed for the other agent) instead of reporting it as
malicious.

A release cannot carry its own hashes: they are hashes of the files the release commit itself produces. So the
release step records the *previous* release: while preparing `v0.1.3`, `tools/ci/record-release.mjs` runs
`git archive v0.1.2`, computes its entry with `tools/release-hashes.mjs` and appends it to both tables (in the
file's own format; nothing happens when the entry is already there). The `chore: release 0.1.3` commit therefore
carries the 0.1.2 entry, the earliest point possible.

The table of a release is one release behind: `0.1.3` lists `0.1.2` and older, not itself. That costs nothing in
practice: a scanner recognises copies of itself byte for byte (`isCopyOfSelf`, install markers aside), and every
later release lists all earlier ones; no table can list a release newer than itself. `test/known-releases.test.mjs` checks
the rule on every pull request: every release tag reachable from `HEAD` except the newest must be in the table, and
every entry must match a clean `git archive` of its tag.

## Recovery

semantic-release pushes the release commit first, then the tag, then creates the GitHub Release; a failure in the
middle leaves one of these states. A failed release also opens a GitHub issue (`failComment`).

**The release commit is on `main`, its tag is not.** `main` then carries `chore: release X.Y.Z` with version X.Y.Z in
the manifests, but the last tag is still the previous release. Left alone, the next run analyses those same commits
again: it would release X.Y.Z a second time on a newer commit (two commits claiming one version, a duplicated
CHANGELOG section), or a different version while the manifests already said X.Y.Z. Fix it before anything else
merges, in one of two ways:
- tag the release commit by hand, then create its Release (next item):
  `git tag vX.Y.Z <sha of the chore: release X.Y.Z commit> && git push origin vX.Y.Z`
  (the ruleset must let you push the tag);
- or revert the release commit through a pull request (`git revert <sha>`); the next push to `main` releases X.Y.Z
  again, cleanly.

**The tag exists, the GitHub Release does not.** Create the Release from the tag:
`gh release create vX.Y.Z --verify-tag --title vX.Y.Z --notes-file <notes>`, with the notes being the release's
section of `CHANGELOG.md` (from its `## [X.Y.Z]` heading to the next `## `). `--notes-from-tag` is not enough here:
semantic-release creates lightweight tags, which carry no message.

**`record-release` cannot hash a released tree.** The prepare step fails and nothing is pushed. Causes and fixes:
- a symlink or special file in the tag: no scanner can vouch for such a tree (`shippedFiles` refuses links), so the
  release can never be recognised. Remove the link in a `fix:` commit, and list the old version in
  `tools/ci/release/unrecordable.json` (`{ "X.Y.Z": "contains a symlink" }`), which `record-release` and
  `test/known-releases.test.mjs` skip;
- a size limit (more than 3000 files, 500 directories or 64 MB): the runtime has the same limits
  (`scripts/lib/selfcopy.mjs` COPY_LIMITS), so raise both together in a `fix:` commit, or list the version as above;
- `export-ignore` in a `.gitattributes`: `git archive` then leaves files out that a git install still contains, so
  the recorded entry would never match an install. Do not use `export-ignore`; if one was added, remove it in a
  `fix:` commit and list the affected version as above.
