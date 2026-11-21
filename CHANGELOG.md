# Changelog

## 0.1.2

### Fixed
- The scanner no longer reports a skill-sentry copy installed by Codex as malicious (score 100) when it sees it from Claude Code, or the other way round. Codex writes an install file (`.codex-marketplace-install.json`) into the plugin folder on its first start, and the copy check now accepts that file in its exact shape, on both sides.
- A relative `skill-sentry` folder in a shell command (`cd /c/Users/me/vault && ls skill-sentry`) no longer asks in Claude Code when the folder it resolves to is outside the Claude and Codex homes, plugin caches and skill-sentry's own folders. Codex gets this only after a literal `cd <absolute path> &&`.
- skill-sentry 0.1.2 recognises 0.1.1 copies (Claude Code or Codex) and shows the "update both installs" note instead of scanning them as a third-party plugin.

### Docs
- The Codex install from GitHub is verified. Start Codex once after installing, then trust the hook in `/hooks`: the install file Codex writes on its first start changes the hook's fingerprint, and until you trust it again the hook does not run.

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
