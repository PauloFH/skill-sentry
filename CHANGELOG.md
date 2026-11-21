# Changelog

## [0.2.0](https://github.com/PauloFH/skill-sentry/compare/v0.1.2...v0.2.0) (2026-11-21)

### Features

* install the audit with npx skills add ([92eb4ae](https://github.com/PauloFH/skill-sentry/commit/92eb4aebac790fd2a2b3f75d645b9e8c8edaa6d4))
* recognise standalone skill-sentry copies ([4b14b02](https://github.com/PauloFH/skill-sentry/commit/4b14b02296a08f8c5094dc893386ad65a9746354))

### Bug Fixes

* exempt only verified standalone copies and protect skill-sentry-audit paths ([e5dd146](https://github.com/PauloFH/skill-sentry/commit/e5dd146b2c349f27a9a605c1b47002c7314f044c))

## [0.1.2](https://github.com/PauloFH/skill-sentry/compare/v0.1.1...v0.1.2) (2026-11-21)

### Bug Fixes

* accept the codex install marker in self copies ([dda63c8](https://github.com/PauloFH/skill-sentry/commit/dda63c8b969b1f65227c84f9a04a5bcd4089eb75))
* bound path lookups per guard decision ([3544daa](https://github.com/PauloFH/skill-sentry/commit/3544daac5a59314942196fe0fb4b78e1c0c04453))
* check both readings of a dot-dot path from a junction cwd ([57c65c4](https://github.com/PauloFH/skill-sentry/commit/57c65c4b9a02c71528e415667fe716b6303ceb00))
* count the codex taint ttl in whole milliseconds ([0c3ce02](https://github.com/PauloFH/skill-sentry/commit/0c3ce02a369440f2e5467ea69170a07c407f9d64))
* drop the relative exemption for any carriage return ([fb71ad7](https://github.com/PauloFH/skill-sentry/commit/fb71ad7cb348957a2d3c4d00785bb3c26154bf1a))
* fail closed on write paths left unresolved ([2fd6056](https://github.com/PauloFH/skill-sentry/commit/2fd60562c65fca4977d85e9a62e58cdcd5ab9ec1))
* keep relative cd targets and name searches asking ([57cb939](https://github.com/PauloFH/skill-sentry/commit/57cb939c04206f1b7f6bb5a9ef4ec6bf13539437))
* recognise skill-sentry 0.1.1 ([0e6264b](https://github.com/PauloFH/skill-sentry/commit/0e6264b3bc81aad30f154d386a35f82c5dea18b4))
* resolve codex patch paths from the canonical cwd ([d4d606b](https://github.com/PauloFH/skill-sentry/commit/d4d606bddc38813d99f102e6140334ba90aa38ce))
* skip costly rule patterns on lines that cannot match ([f44935f](https://github.com/PauloFH/skill-sentry/commit/f44935ff0126efc365a8681706faf3898c3b7e76))
* stop prompting for relative skill-sentry folders ([0282e4f](https://github.com/PauloFH/skill-sentry/commit/0282e4ff434f5abd5c583a79d9b3c723b8f23a61))
* tighten the codex marker source check ([b601d29](https://github.com/PauloFH/skill-sentry/commit/b601d29639ebac086a1e9c0971ae12ed7ac15b42))
* treat carriage returns as powershell statement breaks ([afc4553](https://github.com/PauloFH/skill-sentry/commit/afc45530a2a49641667bc8004f61a602067120a9))

## 0.1.1

### Added
- OpenAI Codex support:
  - Audit of Codex homes: `config.toml`, `rules/*.rules`, plugins, hooks with their trust state, MCP servers, skills (including `~/.agents/skills`), `AGENTS.md` and `notify`.
  - Tiered runtime guard for Codex tool calls. Codex has no "ask", so a call is allowed or denied.
  - Recommend-only harden for Codex: `harden.mjs check --agent codex`. skill-sentry never edits Codex files.
  - Flags `--agent claude|codex|all`, `--codex-home <dir>` and `--no-wsl`.
- Windows and WSL Codex home detection.
- Known-release recognition: a newer scanner recognises older skill-sentry copies and shows an "update both installs" note when Claude Code and Codex run different versions.

### Changed
- The default audit (`--agent all`) now also reads the Codex home (`~/.codex` or `$CODEX_HOME`) and, on Windows, probes WSL distros for Codex homes. Use `--agent claude` or `--no-wsl` to skip them.
- New Claude Code prompts:
  - a move, link or rename verb (`mv`, `ln`, `mklink`, `Rename-Item`, `Move-Item`, `New-Item -ItemType Junction`, ...) whose operand names a `.claude` directory;
  - PowerShell commands that create or remove a drive (`New-PSDrive`, `Remove-PSDrive`, and `ndr`, `mount` or `rdr` used as a command);
  - shell commands and writes that touch any installed skill-sentry copy, including the one installed for Codex;
  - writes to Codex control files (`config.toml`, `hooks.json`, `requirements.toml`, `rules/`) when a skill or plugin is the likely origin.

### Fixed
- Self-protect no longer prompts for unrelated folders that happen to be named skill-sentry.

### Security
- `apply_patch` patches are inspected by the Codex guard.
- A patch that comes from a file, a pipe or shell expansion is denied (fail closed).
- Hardened secret redaction in audit output.

## 0.1.0

First release: audit, harden and runtime guard for Claude Code.
