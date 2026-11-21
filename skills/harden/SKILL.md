---
name: harden
description: Review and tighten the user's Claude Code and OpenAI Codex settings against supply-chain risks from third-party plugins and skills. For Claude Code it can apply settings such as asking before curl or wget, denying reads of SSH and cloud credentials, and disabling shell execution inside skills. For Codex it only recommends changes. Use when the user asks to harden or lock down their Claude Code or Codex setup.
---

# skill-sentry harden

Check the user's Claude Code settings and apply only the hardening items the user approves. For Codex, show recommendations only: skill-sentry never edits Codex files.

## Steps

1. Locate the helper. The helper is at `<skill dir>/../../scripts/harden.mjs`, where `<skill dir>` is the directory containing this SKILL.md. Run:

   `node "<skill dir>/../../scripts/harden.mjs" check`

   With the Bash tool, write the path with forward slashes (`C:/Users/...`), since a backslash makes the runtime guard ask for confirmation. With the PowerShell tool, backslashes in the script path are fine.

   It prints a JSON array. Each item has `id`, `title`, `why`, `applicable` and `present`. Codex items also have a `snippet`.

   To check Codex, add `--agent codex`. Use `--agent all` for both. Add `--codex-home <dir>` (repeatable) for an extra Codex home and `--no-wsl` to skip Codex homes inside WSL. Without `--agent` only Claude Code is checked.

2. Explain each item with `applicable: true` and `present: false` in plain language: what the setting does and why it reduces risk. For `disable-skill-shell`, state clearly the trade-off in its `why` text: it also turns off the shell lines that official plugins use to gather context.

3. Report items that are already present as done. Show items with `applicable: false` (third-party marketplaces and managed settings) as information only. The helper never changes them.

4. Ask the user about each missing Claude Code item one by one. Apply an item only after an explicit yes for that item:

   `node "<skill dir>/../../scripts/harden.mjs" apply <id>`

   Several approved ids can be passed in one call. The helper merges only the requested ids, keeps every other setting, and never duplicates a rule.

   `apply` changes settings through skill-sentry's own script, so the runtime guard shows a confirmation prompt for it. That prompt is expected: the user approves it for the items they already agreed to. The read-only `check` runs without a prompt.

5. After applying, tell the user the backup path the helper printed. The backup is a copy of the previous `settings.json` and can be restored by copying it back.

## Codex items

Every Codex item has an id starting with `codex-` and `applicable: false`. They are recommendations only.

- For each item with `present: false`, explain what it does and why it reduces risk, then show its `snippet` exactly as printed. The user pastes it into `config.toml` (or the rules file the snippet names) themselves.
- Never edit `config.toml`, a rules file or anything else under the Codex home yourself, and do not offer to. `apply` refuses `codex-` ids and exits with code 2.
- Snippets are fixed recommended text and never contain the user's own values. Where a snippet lists key names, the values stay in the user's file.
- `codex-trust-guard-hook` is not a TOML change: the user opens `/hooks` in Codex and trusts the skill-sentry hook there.

6. Answer in the language the user is writing in.
