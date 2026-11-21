**English** | [Português](README.pt.md) | [Español](README.es.md) | [中文](README.zh.md)

🌐 https://paulofh.github.io/skill-sentry/

# skill-sentry

A zero-dependency Claude Code plugin that audits the plugins, skills, hooks and MCP servers installed on your machine for malicious behavior, hardens your Claude Code settings, and guards risky tool calls at runtime.

Third-party skills and plugins are code and instructions that run with your privileges. A malicious one can steal credentials, install a crypto miner, open a backdoor, or quietly instruct the model to do those things for it. skill-sentry gives you a fast, local, readable second look.

- **Audit** (`/skill-sentry:audit`): a static scanner reads every installed plugin, skill, hook and MCP server config, scores each component and reports findings by category: miner, rce, secret, exfil, persistence, permissions, destructive, obfuscation, injection, supply, skill, config.
- **Harden** (`/skill-sentry:harden`): reviews your `settings.json` and applies only the tightening steps you approve one by one.
- **Guard** (PreToolUse hook): inspects tool calls as they happen and blocks or asks before the dangerous ones.

Requires Node 18 or newer. No npm dependencies.

Since 0.1.1 it also works in OpenAI Codex: see [Codex support](#codex-support).

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
/plugin marketplace add PauloFH/skill-sentry
/plugin install skill-sentry@skill-sentry
```

This repository is both the plugin and its own marketplace.

## Usage

### Audit installed components

```
/skill-sentry:audit
```

Claude runs the scanner, then presents a summary (components per verdict, what changed since the baseline), every problem found while reading configs, and a table for each component that is not `ok`. The scanner's verdict is never lowered: if Claude disagrees it adds its own opinion in a separate "Agent assessment" column, so you always see both. Text copied from scanned files is treated as untrusted data and never followed as instructions.

Verdicts come from a score: critical findings weigh 40, high 15, medium 5. Each rule counts once per component, at its highest severity, and the score is capped at 100.

| Score | Verdict |
| --- | --- |
| below 10 | ok |
| 10 to 29 | review |
| 30 to 59 | suspicious |
| 60 and above | malicious |

Any critical finding raises the verdict to at least `suspicious`. Combinations escalate within a file: exfiltration next to secret access becomes critical, and obfuscation next to rce, exfil or secret findings becomes high.

`/skill-sentry:audit` is the normal entry point. To run the script yourself, note that for an installed plugin the scripts live under the plugin install directory, `~/.claude/plugins/cache/skill-sentry/skill-sentry/<version>/scripts/`; the paths below are relative to that directory (or to a clone of this repository).

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
| ask | A high-risk rule matches and a skill or plugin is the likely origin of the call. Also always for writes to skill-sentry's own data or install directory (or to any other installed skill-sentry copy, such as the one installed for Codex), shell commands that mention those directories, and writes through unusual Windows path forms (device paths, UNC paths, 8.3 short names, NTFS streams, trailing dot or space). |
| log | A high-risk rule matches but no skill or plugin is attributed as the likely origin. Recorded in `guard.log`, not interrupted. |

If the guard itself fails, it fails open: it writes a line to `guard.log` and lets the call proceed rather than breaking your session.

The default audit (`scan.mjs` with only `--json` and/or `--diff-only`) and `harden.mjs check` run without a prompt. Audits with `--path` or `--component`, baseline updates (`--update-baseline`), allowlisting (`--allow`) and `harden.mjs apply` show a confirmation prompt by design: approve it for the action you already agreed to. Under the Bash tool, write the script path with forward slashes (`C:/Users/...`).

### Allowlist

If a finding is a known false positive, allow it one finding at a time:

```
node scripts/scan.mjs --allow <componentId> <ruleId> <file> --reason "why"
```

An entry is tied to the sha256 of that file, so it **stops applying as soon as the file changes**. Entries that let a blocked command through are exact-string matches. Claude only runs this after you say yes.

If the `skillspector` command is installed, the audit can offer a second opinion with it. skill-sentry never installs it.

## Codex support

skill-sentry 0.1.1 brings the same audit and guard to OpenAI Codex, plus a recommend-only harden.

### What the audit covers in Codex

- `config.toml`: approval and sandbox settings, MCP servers, literal secrets, trusted projects, the shell environment policy
- `rules/*.rules` execution policy files
- plugins, and the hooks they ship together with each hook's trust state
- MCP servers
- skills, including `~/.agents/skills`
- `AGENTS.md` instruction files
- the `notify` program

Windows and WSL Codex homes are detected automatically. Pick what to audit with `--agent claude|codex|all` (default `all`), add a home with `--codex-home <dir>` (repeatable) and skip WSL with `--no-wsl`:

```
node scripts/scan.mjs --agent codex
node scripts/scan.mjs --agent all --codex-home <dir> --no-wsl
```

### Install in Codex

```
codex plugin marketplace add PauloFH/skill-sentry
codex plugin add skill-sentry@skill-sentry
```

This install from the public GitHub repository is verified on Windows and WSL Codex.

Then **start Codex once, then trust the guard hook**. Codex does not run a hook until you trust it, and enabling a plugin does not trust its hooks. On its first start after the install, Codex writes an install file into the plugin folder, which changes the hook's fingerprint. So trust the hook after that first start: open `/hooks` in Codex (or "Review hooks" in the desktop app), review the skill-sentry hook and trust it. Until you do, the guard does not run.

Then ask Codex to run the skill-sentry audit for your first report. This is verified on WSL Codex only. On Windows Codex it may need your approval for the shell commands it runs.

### Guard under Codex

The guard is a PreToolUse hook here too. Codex has no "ask", so it can only allow or deny, and the tiers are:

| Tier | When | Codex behaviour |
| --- | --- | --- |
| 1 | A critical rule matches | deny |
| 2 | A high rule for rce, exfil, miner or destructive; a secret and network egress in one command; a network-capable call after an attributed (skill or plugin) call that read a secret was allowed on retry earlier in the session | deny. If you really meant it, run it yourself in a terminal. |
| 3 | Any other high rule with an attributed origin (a skill or plugin) | denied the first time, with the reason. An identical retry in the same session within 10 minutes is allowed once. |
| 4 | A high rule with no skill or plugin attributed | logged only |
| 5 | Writes to skill-sentry's own files (any installed copy), or unusual path forms | deny |

`apply_patch` patches are inspected too. Most patches the guard cannot read are denied: one that comes from a file or a pipe, or that uses shell expansion. A patch command hidden behind dynamic or obfuscated shell (see the limits below) is not detected.

### Codex limits

- Codex has no "ask": the guard can only allow or deny.
- It fails open: if the hook errors or exceeds Codex's timeout (about 5 seconds), the call runs.
- Hooks need trust (`/hooks`). The `dangerously-bypass-hook-trust` flag of Codex turns that protection off.
- After a plugin update Codex marks the hook `modified` and stops running it until you trust it again in `/hooks`. It does not warn you: the guard is simply off until then.
- The tier 3 retry is confirmed by the model, not by you.
- Interactive input sent to a running shell (`write_stdin`) is not hooked.
- Commands that build names or paths at run time are not analysed: `eval`, variables, globs, interpreter one-liners such as `python -c`, or a script written in one call and run in a later one.
- Origin attribution is lost when more than about 1 MiB of output follows the skill read in the session; the call then counts as tier 4.
- Under WSL, if the session starts under `/mnt/c` and your node toolchain (for example mise) refuses to start there, the guard fails open. Start the session under `/home/...`.
- WSL Codex and Windows Codex keep separate skill-sentry data (taint, baseline, allowlist).
- Under the `workspace-write` sandbox the audit needs your approval to write its report to `~/.claude/skill-sentry`.
- Reading skill-sentry's own `SKILL.md` through a chained shell command (`cd ... && cat ...`) may be denied. The plain read works.
- Mentioning a bare `skill-sentry` path in a shell command can still prompt in Claude Code (self-protect).

### Harden under Codex

```
node scripts/harden.mjs check --agent codex
```

Plain `check` stays Claude-only. Codex hardening is **recommend-only**: skill-sentry never edits Codex files. Each recommendation comes with a snippet for you to apply yourself:

| Id | What it recommends |
| --- | --- |
| `approval-sandbox` | Keep `approval_policy` and `sandbox_mode` on the sandboxed, ask-on-request defaults |
| `broad-allow-rules` | Replace execution policy allow rules that end at a shell or interpreter with prompt rules |
| `secrets-in-config` | Move literal secrets out of `config.toml` and reference an environment variable |
| `env-excludes` | Keep the default environment excludes so secret-looking variables are not passed to commands |
| `mcp-auto-approve` | Do not auto-approve MCP servers or tools |
| `approvals-reviewer` | Keep `approvals_reviewer` on `user` |
| `trusted-tmp-projects` | Do not trust projects that live in temp directories |
| `hooks-enabled` | Keep Codex hooks enabled, so the guard can run |
| `trust-guard-hook` | Trust the skill-sentry hook in `/hooks` |

### Two installs, one version

If Claude Code and Codex run different skill-sentry versions, a newer scanner recognises older releases and shows an "update both installs" note. An older scanner may report the newer copy as suspicious or malicious (a false positive) until both installs are updated. **Update both installs** after each release.

### skills.sh

Not supported yet (planned): skills.sh copies only the skill folder, so it cannot install the guard hook.

## Data and privacy

- **No network calls and no telemetry.** Everything runs locally.
- It writes only to `~/.claude/skill-sentry/`: `baseline.json`, `allowlist.json`, `guard.log` and `reports/`. The one exception is `harden`, which edits your `settings.json` after approval, with a backup.
- Environment variables (mainly for testing): `SKILL_SENTRY_DATA_DIR` (data directory), `SKILL_SENTRY_CLAUDE_HOME` (default `~/.claude`), `SKILL_SENTRY_HOME_DIR` (where `~/.claude.json` is read from), `SKILL_SENTRY_CODEX_HOME` (replaces the default Codex home) and `SKILL_SENTRY_NO_WSL=1` (do not look for Codex homes inside WSL).

## Validation

Tested against a real Windows 11 installation (68 components): 2 flagged. One was rated malicious: a third-party orchestration plugin that launches agents with permission prompts disabled and auto-approves commands, powerful by design rather than malware. One was rated review: test scripts that use the skip-permissions flag. Everything else came back ok. The project has 240+ automated tests.

## Credits and inspiration

- CybeDefend, ["Are Claude Code skills safe?"](https://www.cybedefend.com/blog/are-claude-code-skills-safe)
- The "Agent Skills in the Wild" study (January 2026)
- NVIDIA SkillSpector, a complementary scanner (`skillspector scan <dir> --no-llm`). Use it alongside skill-sentry for a second opinion.

## License

MIT. See [LICENSE](LICENSE).
