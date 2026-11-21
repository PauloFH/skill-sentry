[English](README.md) | [Português](README.pt.md) | [Español](README.es.md) | **中文**

🌐 https://paulofh.github.io/skill-sentry/

# skill-sentry

一个零依赖的 Claude Code 插件：审计你机器上已安装的插件、skill、hook 和 MCP 服务器是否存在恶意行为，加固 Claude Code 设置，并在运行时守护有风险的工具调用。

第三方 skill 和插件是以你的权限运行的代码和指令。恶意的 skill 或插件可能窃取凭据、安装加密货币挖矿程序、开启后门，或悄悄指示模型替它做这些事。skill-sentry 为你提供一次快速、本地、可读的二次检查。

- **审计**（`/skill-sentry:audit`）：静态扫描器读取每个已安装插件、skill、hook 和 MCP 服务器的配置，为每个组件打分，并按类别报告发现：miner、rce、secret、exfil、persistence、permissions、destructive、obfuscation、injection、supply、skill、config。
- **加固**（`/skill-sentry:harden`）：检查你的 `settings.json`，只应用你逐项批准的加固步骤。
- **守卫**（PreToolUse hook）：在工具调用发生时进行检查，对危险调用先拦截或先询问。

需要 Node 18 或更高版本。没有 npm 依赖。

从 0.1.1 起，它也支持 OpenAI Codex：见 [Codex 支持](#codex-支持)。

## 威胁模型与坦诚的局限

skill-sentry 是一双额外的眼睛，而不是一面盾牌。在信任它之前请先阅读本节。

- 它**不是杀毒软件，也不是沙箱**。它不隔离任何东西，也无法撤销损害。
- 扫描器**只做静态分析**。它用模式规则读取文件，从不执行它们。足够巧妙的代码可以绕过模式规则。
- 它**无法看到其他插件的 hook 在运行时的行为**，只能读取它们的配置和脚本。
- 它**无法检查运行时才获取的代码**（例如以浮动版本标签启动的软件包，或先下载再执行的脚本），只能标记出这种情况的存在。
- 守卫是尽力而为的过滤器。**足够混淆的 shell 命令可以绕过它。** 它检查命令、路径和 URL；对于 Write 和 Edit，只看目标路径，从不看内容。
- 干净的报告不能证明安全。糟糕的报告则是仔细查看的理由。

无论如何都值得做的缓解措施：固定插件版本，避免第三方 marketplace 自动更新，阅读你安装的内容，并应用 `/skill-sentry:harden` 提供的设置。

## 安装

```
/plugin marketplace add PauloFH/skill-sentry
/plugin install skill-sentry@skill-sentry
```

本仓库既是插件，也是它自己的 marketplace。

## 使用

### 审计已安装的组件

```
/skill-sentry:audit
```

Claude 运行扫描器，然后给出摘要（各结论的组件数量、自基线以来的变化）、读取配置时发现的每个问题，以及每个非 `ok` 组件的表格。扫描器的结论永远不会被调低：如果 Claude 不同意，会在单独的 "Agent assessment" 列中加入自己的意见，让你始终能同时看到两者。从被扫描文件复制来的文本一律视为不可信数据，绝不会当作指令执行。

结论来自评分：critical 发现计 40 分，high 计 15 分，medium 计 5 分。每条规则在每个组件中只计一次，取其最高严重级别，总分上限为 100。

| 分数 | 结论 |
| --- | --- |
| 低于 10 | ok |
| 10 至 29 | review |
| 30 至 59 | suspicious |
| 60 及以上 | malicious |

任何 critical 发现都会把结论至少提升到 `suspicious`。同一文件内的组合会升级：外泄行为与访问机密同时出现时升为 critical，混淆与 rce、exfil 或 secret 发现同时出现时升为 high。

`/skill-sentry:audit` 是常规入口。如果要自己运行脚本，请注意：对于已安装的插件，脚本位于插件安装目录 `~/.claude/plugins/cache/skill-sentry/skill-sentry/<版本>/scripts/` 下；下面的路径都相对于该目录（或本仓库的克隆）。

常用选项（可以让 Claude 使用，也可以自己运行脚本）：

```
node scripts/scan.mjs --json
node scripts/scan.mjs --path <dir>
node scripts/scan.mjs --component <id>
node scripts/scan.mjs --diff-only
node scripts/scan.mjs --update-baseline
```

- `--path <dir>` 检查单个文件夹，便于你在**安装之前**审查某个 skill 或插件。它不会读取或写入基线。
- `--component <id>` 扫描一个已安装的组件。
- `--diff-only` 只显示自基线以来新增或变更的组件。第一次完整扫描会自动创建基线。
- `--update-baseline` 把当前状态接受为新的基线（Claude 会先询问）。

### 加固你的设置

```
/skill-sentry:harden
```

Claude 列出每条建议，解释其重要性，只有在你对该项明确回答"是"之后才会应用。任何更改之前都会为 `settings.json` 生成带时间戳的备份，辅助程序只合并你批准的内容。

| Id | 作用 |
| --- | --- |
| `ask-curl` | 运行 curl 之前先询问 |
| `ask-wget` | 运行 wget 之前先询问 |
| `deny-ssh-read` | 禁止读取 `~/.ssh` |
| `deny-aws-read` | 禁止读取 `~/.aws` |
| `ask-env-read` | 读取 `.env` 文件之前先询问 |
| `disable-skill-shell` | 关闭 skill 内的内联 shell 执行（代价：以这种方式收集上下文的官方插件将不再这样做） |

另有两项仅供参考，永远不会被应用：审查第三方 marketplace（`third-party-autoupdate`），以及通过托管设置限制 marketplace 和 hook（`managed-settings`）。

### 运行时守卫

守卫是随插件安装的 PreToolUse hook。它监视 Bash、PowerShell、Read、Write、Edit、NotebookEdit、Grep、Glob、WebFetch 和 MCP 工具调用。

| 决定 | 条件 |
| --- | --- |
| deny | 命中 critical 规则（例如下载并执行的管道、反向 shell、启动加密货币挖矿程序、清除磁盘或主目录）。始终拦截，除非你已把这条完全相同的命令加入白名单。 |
| ask | 命中 high 风险规则，且调用很可能来自某个 skill 或插件。此外，写入 skill-sentry 自己的数据目录或安装目录（或任何其他已安装的 skill-sentry 副本，例如为 Codex 安装的那份）、提及这些目录的 shell 命令，以及使用不寻常的 Windows 路径形式（设备路径、UNC 路径、8.3 短文件名、NTFS 数据流、末尾的点或空格）进行写入，也始终询问。 |
| log | 命中 high 风险规则，但没有把任何 skill 或插件认定为可能的来源。记录到 `guard.log`，不打断你。 |

如果守卫自身出错，它会以放行方式失败：向 `guard.log` 写入一行，并让调用继续，而不是破坏你的会话。

默认审计（只带 `--json` 和/或 `--diff-only` 的 `scan.mjs`）和 `harden.mjs check` 运行时不会弹出确认。带 `--path` 或 `--component` 的审计、基线更新（`--update-baseline`）、加入白名单（`--allow`）以及 `harden.mjs apply` 按设计会弹出确认：对你已经同意的操作批准即可。使用 Bash 工具时，脚本路径请用正斜杠书写（`C:/Users/...`）。

### 白名单

如果某个发现是已知的误报，可以逐条放行：

```
node scripts/scan.mjs --allow <componentId> <ruleId> <file> --reason "why"
```

条目与该文件的 sha256 绑定，因此**文件一旦改变，条目立即失效**。放行被拦截命令的条目采用完整字符串精确匹配。Claude 只会在你同意之后才运行此命令。

如果安装了 `skillspector` 命令，审计可以用它提供第二意见。skill-sentry 从不安装它。

## Codex 支持

skill-sentry 0.1.1 把同样的审计和守卫带到了 OpenAI Codex，并提供只给建议的加固。

### 审计在 Codex 中覆盖什么

- `config.toml`：审批与沙箱设置、MCP 服务器、明文密钥、受信任的项目、shell 环境策略
- `rules/*.rules` 执行策略文件
- 插件及其自带的 hook，连同每个 hook 的信任状态
- MCP 服务器
- skill，包括 `~/.agents/skills`
- `AGENTS.md` 指令文件
- `notify` 程序

Windows 和 WSL 中的 Codex 目录会被自动检测。用 `--agent claude|codex|all`（默认 `all`）选择审计对象，用 `--codex-home <dir>`（可重复）添加目录，用 `--no-wsl` 跳过 WSL：

```
node scripts/scan.mjs --agent codex
node scripts/scan.mjs --agent all --codex-home <dir> --no-wsl
```

### 在 Codex 中安装

```
codex plugin marketplace add PauloFH/skill-sentry
codex plugin add skill-sentry@skill-sentry
```

从公开的 GitHub 仓库安装的流程已在 Windows 和 WSL 的 Codex 上验证。

然后**先启动一次 Codex，再信任守卫 hook**。在你信任之前，Codex 不会运行 hook，而启用插件并不会自动信任它的 hook。安装后首次启动时，Codex 会在插件目录中写入一个安装文件，这会改变 hook 的指纹。所以要在首次启动之后再信任 hook：在 Codex 中打开 `/hooks`（桌面应用中是 "Review hooks"），检查 skill-sentry 的 hook 并信任它。在此之前守卫不会运行。

接着让 Codex 运行 skill-sentry 的审计，查看你的第一份报告。这仅在 WSL 中的 Codex 上验证过。在 Windows 的 Codex 上，它运行的 shell 命令可能需要你批准。

### Codex 下的守卫

这里的守卫同样是 PreToolUse hook。Codex 没有 "ask"，所以它只能放行或拒绝。分级如下：

| 级别 | 条件 | 在 Codex 中的行为 |
| --- | --- | --- |
| 1 | 命中严重（critical）规则 | deny |
| 2 | 命中 rce、exfil、miner 或 destructive 的高危（high）规则；同一条命令里既有密钥又有对外网络访问；会话中先前有一个归属于 skill 或插件、读取了密钥的调用在重试时被放行，随后又出现能联网的调用 | deny。如果你确实想执行，请自己在终端里运行。 |
| 3 | 其他有明确来源（skill 或插件）的高危规则 | 第一次被拒绝并给出原因。同一会话内 10 分钟之内完全相同的重试会被放行一次。 |
| 4 | 没有归属到任何 skill 或插件的高危规则 | 仅记录日志 |
| 5 | 写入 skill-sentry 自身文件（任何已安装的副本），或使用不寻常的路径形式 | deny |

`apply_patch` 的补丁也会被检查。守卫无法读取的补丁大多会被拒绝：来自文件或管道的补丁，或带有 shell 展开的补丁。藏在动态或混淆的 shell 写法背后的补丁命令（见下方局限）不会被发现。

### Codex 下的局限

- Codex 没有 "ask"：守卫只能放行或拒绝。
- 它是失败即放行：如果 hook 出错或超过 Codex 的超时（约 5 秒），调用照常执行。
- hook 需要信任（`/hooks`）。Codex 的 `dangerously-bypass-hook-trust` 选项会关闭这层保护。
- 每次插件更新后，Codex 可能会要求你在 `/hooks` 中重新信任 hook（它会显示为 `modified`）。在此之前守卫不会运行。
- 第 3 级的重试由模型确认，而不是由你确认。
- 发给正在运行的 shell 的交互式输入（`write_stdin`）不经过 hook。
- 在运行时才拼出名称或路径的命令不会被分析：`eval`、变量、通配符（glob）、`python -c` 这类解释器单行命令，或在一次调用里写入、在之后的调用里运行的脚本。
- 如果会话中在读取 skill 之后又出现了超过约 1 MiB 的输出，来源归属就会丢失，该调用会按第 4 级处理。
- 在 WSL 下，如果会话从 `/mnt/c` 开始，而你的 node 工具链（例如 mise）在那里拒绝启动，守卫就会失败即放行。请在 `/home/...` 下开始会话。
- WSL 中的 Codex 与 Windows 中的 Codex 各自保存独立的 skill-sentry 数据（taint、baseline、allowlist）。
- 在 `workspace-write` 沙箱下，审计需要你批准才能把报告写入 `~/.claude/skill-sentry`。
- 通过串联的 shell 命令（`cd ... && cat ...`）读取 skill-sentry 自己的 `SKILL.md` 可能被拒绝，直接读取则可以。
- 在 shell 命令里单独提到 `skill-sentry` 路径，在 Claude Code 中仍可能弹出确认（自我保护）。

### Codex 下的加固

```
node scripts/harden.mjs check --agent codex
```

不带选项的 `check` 仍然只针对 Claude。Codex 的加固**只给建议**：skill-sentry 绝不会修改 Codex 的文件。每条建议都附带一段代码片段，由你自己应用：

| Id | 建议内容 |
| --- | --- |
| `approval-sandbox` | 让 `approval_policy` 和 `sandbox_mode` 保持带沙箱、按需询问的默认值 |
| `broad-allow-rules` | 把以 shell 或解释器结尾的执行策略 allow 规则改成 prompt 规则 |
| `secrets-in-config` | 把明文密钥移出 `config.toml`，改为引用环境变量 |
| `env-excludes` | 保留默认的环境变量排除，避免把看起来像密钥的变量传给命令 |
| `mcp-auto-approve` | 不要自动批准 MCP 服务器或工具 |
| `approvals-reviewer` | 让 `approvals_reviewer` 保持为 `user` |
| `trusted-tmp-projects` | 不要信任位于临时目录中的项目 |
| `hooks-enabled` | 保持 Codex 的 hook 开启，守卫才能运行 |
| `trust-guard-hook` | 在 `/hooks` 中信任 skill-sentry 的 hook |

### 两套安装，同一个版本

如果 Claude Code 和 Codex 运行的 skill-sentry 版本不同，较新的扫描器能识别旧版本，并显示"请更新两处安装"的提示。较旧的扫描器可能会把较新的副本报告为 suspicious 或 malicious（误报），直到两处安装都更新。每次发布后请**更新两处安装**。

### skills.sh

暂不支持（已列入计划）：skills.sh 只复制 skill 文件夹，因此无法安装守卫 hook。

## 数据与隐私

- **没有网络调用，没有遥测。** 一切都在本地运行。
- 它只写入 `~/.claude/skill-sentry/`：`baseline.json`、`allowlist.json`、`guard.log` 和 `reports/`。唯一的例外是 `harden`，它会在你批准后编辑你的 `settings.json`，并附带备份。
- 环境变量（主要用于测试）：`SKILL_SENTRY_DATA_DIR`（数据目录）、`SKILL_SENTRY_CLAUDE_HOME`（默认 `~/.claude`）、`SKILL_SENTRY_HOME_DIR`（读取 `~/.claude.json` 的位置）、`SKILL_SENTRY_CODEX_HOME`（替换默认的 Codex 目录）和 `SKILL_SENTRY_NO_WSL=1`（不在 WSL 中查找 Codex 目录）。

## 验证

已在一台真实的 Windows 11 安装环境上测试（68 个组件）：2 个被标记。一个被评为 malicious：一个第三方编排插件，它在禁用权限提示的情况下启动代理并自动批准命令，功能强大是设计使然，并非恶意软件。另一个被评为 review：使用跳过权限标志的测试脚本。其余均为 ok。项目有 240 多个自动化测试。

## 致谢与灵感

- CybeDefend，["Are Claude Code skills safe?"](https://www.cybedefend.com/blog/are-claude-code-skills-safe)
- "Agent Skills in the Wild" 研究（2026 年 1 月）
- NVIDIA SkillSpector，一个互补的扫描器（`skillspector scan <dir> --no-llm`）。可与 skill-sentry 搭配使用以获得第二意见。

## 许可证

MIT。参见 [LICENSE](LICENSE)。
