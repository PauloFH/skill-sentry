---
name: harden
description: Review and tighten the user's Claude Code settings against supply-chain risks from third-party plugins and skills, such as asking before curl or wget, denying reads of SSH and cloud credentials, and disabling shell execution inside skills. Use when the user asks to harden or lock down their Claude Code setup.
---

# skill-sentry harden

Check the user's Claude Code settings and apply only the hardening items the user approves.

## Steps

1. Locate the helper. This skill's base directory is shown to you when the skill loads. The helper is at `<base directory>/../../scripts/harden.mjs`. Run:

   `node "<base directory>/../../scripts/harden.mjs" check`

   With the Bash tool, write the path with forward slashes (`C:/Users/...`), since a backslash makes the runtime guard ask for confirmation. With the PowerShell tool, backslashes in the quoted script path are fine.

   It prints a JSON array. Each item has `id`, `title`, `why`, `applicable` and `present`.

2. Explain each item with `applicable: true` and `present: false` in plain language: what the setting does and why it reduces risk. For `disable-skill-shell`, state clearly the trade-off in its `why` text: it also turns off the shell lines that official plugins use to gather context.

3. Report items that are already present as done. Show items with `applicable: false` (third-party marketplaces and managed settings) as information only. The helper never changes them.

4. Ask the user about each missing item one by one. Apply an item only after an explicit yes for that item:

   `node "<base directory>/../../scripts/harden.mjs" apply <id>`

   Several approved ids can be passed in one call. The helper merges only the requested ids, keeps every other setting, and never duplicates a rule.

   `apply` changes settings through skill-sentry's own script, so the runtime guard shows a confirmation prompt for it. That prompt is expected: the user approves it for the items they already agreed to. The read-only `check` runs without a prompt.

5. After applying, tell the user the backup path the helper printed. The backup is a copy of the previous `settings.json` and can be restored by copying it back.

6. Answer in the language the user is writing in.
