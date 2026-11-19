**English** | [Português](README.pt.md) | [Español](README.es.md) | [中文](README.zh.md)

# skill-sentry

A zero-dependency Claude Code plugin that audits the plugins, skills, hooks and MCP servers installed on your machine for malicious behavior, hardens your Claude Code settings, and guards risky tool calls at runtime.

Third-party skills and plugins are code and instructions that run with your privileges. A malicious one can steal credentials, install a crypto miner, open a backdoor, or quietly instruct the model to do those things for it. skill-sentry gives you a fast, local, readable second look.

- **Audit** (`/skill-sentry:audit`): a static scanner reads every installed plugin, skill, hook and MCP server config, scores each component and reports findings by category: miner, rce, secret, exfil, persistence, permissions, destructive, obfuscation, injection, supply, skill, config.
- **Harden** (`/skill-sentry:harden`): reviews your `settings.json` and applies only the tightening steps you approve one by one.
- **Guard** (PreToolUse hook): inspects tool calls as they happen and blocks or asks before the dangerous ones.

Requires Node 18 or newer. No npm dependencies.

## Threat model and honest limits

skill-sentry is a second pair of eyes, not a shield. Read this before trusting it.

- It is **not an antivirus and not a sandbox**. It does not isolate anything and cannot undo damage.
- The scanner is **static analysis only**. It reads files with pattern rules and never executes them. Sufficiently creative code can evade pattern rules.
- It **cannot see other plugins' hooks while they execute**. It only reads their configuration and scripts.
- It **cannot inspect code that is fetched at runtime** (for example a package launched with a floating version tag, or a script downloaded and then run). It can only flag that this happens.
- The guard is a best-effort filter. **Sufficiently obfuscated shell can bypass it.** It inspects commands, paths and URLs; for Write and Edit it looks at the target path only, never the content.
- A clean report is not proof of safety. A bad report is a reason to look closer.

Mitigations worth doing regardless: pin plugin versions, avoid auto-update for third-party marketplaces, read what you install, and apply the settings from `/skill-sentry:harden`.

## Install

```
/plugin marketplace add OWNER/skill-sentry
/plugin install skill-sentry@skill-sentry
```

This repository is both the plugin and its own marketplace.

## Usage

### Audit installed components

```
/skill-sentry:audit
```

Claude runs the scanner, then presents a summary (components per verdict, what changed since the baseline), every problem found while reading configs, and a table for each component that is not `ok`. The scanner's verdict is never lowered: if Claude disagrees it adds its own opinion in a separate "Claude assessment" column, so you always see both. Text copied from scanned files is treated as untrusted data and never followed as instructions.

Verdicts come from a score: critical findings weigh 40, high 15, medium 5. Each rule counts once per component, at its highest severity, and the score is capped at 100.

| Score | Verdict |
| --- | --- |
| below 10 | ok |
| 10 to 29 | review |
| 30 to 59 | suspicious |
| 60 and above | malicious |

Any critical finding raises the verdict to at least `suspicious`. Combinations escalate within a file: exfiltration next to secret access becomes critical, and obfuscation next to rce, exfil or secret findings becomes high.

Useful options (you can ask Claude for them, or run the script yourself):

```
node scripts/scan.mjs --json
node scripts/scan.mjs --path <dir>
node scripts/scan.mjs --component <id>
node scripts/scan.mjs --diff-only
node scripts/scan.mjs --update-baseline
```

- `--path <dir>` vets a single folder, so you can check a skill or plugin **before installing it**. It does not read or write the baseline.
- `--component <id>` scans one installed component.
- `--diff-only` shows only components added or changed since the baseline. The first full scan creates the baseline automatically.
- `--update-baseline` accepts the current state as the new baseline (Claude asks first).

### Harden your settings

```
/skill-sentry:harden
```

Claude lists each recommendation, explains why it matters, and applies one only after your explicit yes for that item. A timestamped backup of `settings.json` is made before any change, and the helper merges only what you approved.

| Id | What it does |
| --- | --- |
| `ask-curl` | Ask before running curl |
| `ask-wget` | Ask before running wget |
| `deny-ssh-read` | Deny reading `~/.ssh` |
| `deny-aws-read` | Deny reading `~/.aws` |
| `ask-env-read` | Ask before reading `.env` files |
| `disable-skill-shell` | Turn off inline shell execution inside skills (trade-off: official plugins that gather context that way will stop doing so) |

Two more items are shown for information only and never applied: reviewing third-party marketplaces (`third-party-autoupdate`) and restricting marketplaces and hooks through managed settings (`managed-settings`).

### Runtime guard

The guard is a PreToolUse hook installed with the plugin. It watches Bash, PowerShell, Read, Write, Edit, NotebookEdit, Grep, Glob, WebFetch and MCP tool calls.

| Decision | When |
| --- | --- |
| deny | A critical rule matches (for example download-and-execute pipes, reverse shells, crypto-miner launches, disk or home-directory wipes). Always blocked unless you allowlisted that exact command. |
| ask | A high-risk rule matches and a skill or plugin is the likely origin of the call. Also always for writes to skill-sentry's own data or install directory, shell commands that mention those directories, and writes through unusual Windows path forms (device paths, UNC paths, 8.3 short names, NTFS streams, trailing dot or space). |
| log | A high-risk rule matches but no skill or plugin is the likely origin (you typed it yourself). Recorded in `guard.log`, not interrupted. |

If the guard itself fails, it fails open: it writes a line to `guard.log` and lets the call proceed rather than breaking your session.

### Allowlist

If a finding is a known false positive, allow it one finding at a time:

```
node scripts/scan.mjs --allow <componentId> <ruleId> <file> --reason "why"
```

An entry is tied to the sha256 of that file, so it **stops applying as soon as the file changes**. Entries that let a blocked command through are exact-string matches. Claude only runs this after you say yes.

If the `skillspector` command is installed, the audit can offer a second opinion with it. skill-sentry never installs it.

## Data and privacy

- **No network calls and no telemetry.** Everything runs locally.
- It writes only to `~/.claude/skill-sentry/`: `baseline.json`, `allowlist.json`, `guard.log` and `reports/`. The one exception is `harden`, which edits your `settings.json` after approval, with a backup.
- Environment variables (mainly for testing): `SKILL_SENTRY_DATA_DIR` (data directory), `SKILL_SENTRY_CLAUDE_HOME` (default `~/.claude`), `SKILL_SENTRY_HOME_DIR` (where `~/.claude.json` is read from).

## Validation

Tested against a real Windows 11 installation with 11 plugins (65 components); the official Anthropic plugins score ok or review. The project has 197 automated tests.

## Credits and inspiration

- CybeDefend, ["Are Claude Code skills safe?"](https://www.cybedefend.com/blog/are-claude-code-skills-safe)
- The "Agent Skills in the Wild" study (January 2026)
- NVIDIA SkillSpector, a complementary scanner (`skillspector scan <dir> --no-llm`). Use it alongside skill-sentry for a second opinion.

## License

MIT. See [LICENSE](LICENSE).
