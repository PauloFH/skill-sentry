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
   - `tools/ci/record-release.mjs` adds the previous release to `skills/audit/scripts/lib/releases.mjs` (see below);
   - `CHANGELOG.md` gets the release notes;
   - last, `tools/ci/write-manifest.mjs .` writes the self-manifest `skills/audit/scripts/lib/selfmanifest.json`
     over the release tree as it will be committed (see below);
   - `test/package.test.mjs`, `test/known-releases.test.mjs` and `test/selfcopy.test.mjs` check the result, and
     `write-manifest.mjs . --verify` checks the manifest against the tree;
   - the commit `chore: release <version>` (those files) goes to `main`, tagged `v<version>`, and a GitHub Release
     is created.
3. The release push is made with a GitHub App token (repository variable `RELEASE_APP_CLIENT_ID` or
   `RELEASE_APP_ID`, secret `RELEASE_APP_PRIVATE_KEY`), the only actor allowed to bypass the ruleset. Without them
   the publish job fails with a clear error instead of releasing.
4. That push starts the workflow once more. It releases nothing: the last tag is on that very commit, so there are
   no new commits to analyse.

No step is manual.

## KNOWN_RELEASES, one release behind

`skills/audit/scripts/lib/releases.mjs` holds the file hashes of every published release. A newer scanner uses it to recognise
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

## The self-manifest, written last

`skills/audit/scripts/lib/selfmanifest.json` is `{ "version": "x.y.z", "files": { "<relpath>": "<sha256>" } }`: the
LF-normalised SHA-256 of every file of the release tree except the manifest itself (`.git` and install markers are
never part of a tree). The running scanner uses its own copy of that file to recognise other installs of the same
release, both whole plugin trees (the Claude Code and Codex installs) and standalone skills (`npx skills add`, which
copies only `skills/audit`; it is compared with the manifest's `skills/audit/` entries). A copy's own
`selfmanifest.json` is just one of its files: it must hash like the running one, and is never read as a manifest.

The manifest has to describe the release commit exactly, so it is written after every other file of that commit has
changed. semantic-release runs the prepare steps in plugin order, so `tools/ci/release/release.config.cjs` lists
`@semantic-release/exec` (set-version, record-release), then `@semantic-release/changelog`, then a second
`@semantic-release/exec` (write-manifest, the tests, `write-manifest --verify`), then `@semantic-release/git`, whose
assets include the manifest. In the release job's work tree `write-manifest` hashes the files git tracks, read from
the work tree; ignored ones such as `tools/ci/release/node_modules` are never part of a release. On a `git archive`
export it hashes every file. `test/known-releases.test.mjs` re-checks every released tag that carries a manifest:
`write-manifest <export> --verify` must pass.

Between releases the committed manifest is the last release's, so a dev checkout never matches its own manifest. A dev
checkout recognises itself by real path and copies of its own tree byte for byte. Through the manifest it recognises
installs of the manifest's release, and through `KNOWN_RELEASES` older recorded releases. Until 0.2.0 is released, the
committed manifest is an empty placeholder and `KNOWN_RELEASES` holds 0.1.0 and 0.1.1 only, so a dev checkout does not
recognise an installed 0.1.2. A standalone copy (`npx skills add`) has no plugin tree of its own, so between releases it
recognises a plugin copy only through the manifest; a dev or PR build's standalone scanner flags same-tree plugin copies
until a release writes the matching manifest.

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
  (`skills/audit/scripts/lib/selfcopy.mjs` COPY_LIMITS), so raise both together in a `fix:` commit, or list the version as above;
- `export-ignore` in a `.gitattributes`: `git archive` then leaves files out that a git install still contains, so
  the recorded entry would never match an install. Do not use `export-ignore`; if one was added, remove it in a
  `fix:` commit and list the affected version as above.
