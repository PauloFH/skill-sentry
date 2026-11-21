# Changelog

## 0.1.1

### Added
- OpenAI Codex support:
  - Audit of Codex homes: `config.toml`, `rules/*.rules`, plugins, hooks with their trust state, MCP servers, skills (including `~/.agents/skills`), `AGENTS.md` and `notify`.
  - Tiered runtime guard for Codex tool calls. Codex has no "ask", so a call is allowed or denied.
  - Recommend-only harden for Codex: `harden.mjs check --agent codex`. skill-sentry never edits Codex files.
  - Flags `--agent claude|codex|all`, `--codex-home <dir>` and `--no-wsl`.
- Windows and WSL Codex home detection.
- Known-release recognition: a newer scanner recognises older skill-sentry copies and shows an "update both installs" note when Claude Code and Codex run different versions.

### Fixed
- Self-protect no longer prompts for unrelated folders that happen to be named skill-sentry.

### Security
- `apply_patch` patches are inspected by the Codex guard.
- A patch the guard cannot read is denied (fail closed).
- Hardened secret redaction in audit output.

## 0.1.0

First release: audit, harden and runtime guard for Claude Code.
