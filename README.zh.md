[English](README.md) | [Português](README.pt.md) | [Español](README.es.md) | **中文**

# skill-sentry

一个零依赖的 Claude Code 插件：审计你机器上已安装的插件、skill、hook 和 MCP 服务器是否存在恶意行为，加固 Claude Code 设置，并在运行时守护有风险的工具调用。

第三方 skill 和插件是以你的权限运行的代码和指令。恶意的 skill 或插件可能窃取凭据、安装加密货币挖矿程序、开启后门，或悄悄指示模型替它做这些事。skill-sentry 为你提供一次快速、本地、可读的二次检查。

- **审计**（`/skill-sentry:audit`）：静态扫描器读取每个已安装插件、skill、hook 和 MCP 服务器的配置，为每个组件打分，并按类别报告发现：miner、rce、secret、exfil、persistence、permissions、destructive、obfuscation、injection、supply、skill、config。
- **加固**（`/skill-sentry:harden`）：检查你的 `settings.json`，只应用你逐项批准的加固步骤。
- **守卫**（PreToolUse hook）：在工具调用发生时进行检查，对危险调用先拦截或先询问。

需要 Node 18 或更高版本。没有 npm 依赖。

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

Claude 运行扫描器，然后给出摘要（各结论的组件数量、自基线以来的变化）、读取配置时发现的每个问题，以及每个非 `ok` 组件的表格。扫描器的结论永远不会被调低：如果 Claude 不同意，会在单独的 "Claude assessment" 列中加入自己的意见，让你始终能同时看到两者。从被扫描文件复制来的文本一律视为不可信数据，绝不会当作指令执行。

结论来自评分：critical 发现计 40 分，high 计 15 分，medium 计 5 分。每条规则在每个组件中只计一次，取其最高严重级别，总分上限为 100。

| 分数 | 结论 |
| --- | --- |
| 低于 10 | ok |
| 10 至 29 | review |
| 30 至 59 | suspicious |
| 60 及以上 | malicious |

任何 critical 发现都会把结论至少提升到 `suspicious`。同一文件内的组合会升级：外泄行为与访问机密同时出现时升为 critical，混淆与 rce、exfil 或 secret 发现同时出现时升为 high。

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
| ask | 命中 high 风险规则，且调用很可能来自某个 skill 或插件。此外，写入 skill-sentry 自己的数据目录或安装目录、提及这些目录的 shell 命令，以及使用不寻常的 Windows 路径形式（设备路径、UNC 路径、8.3 短文件名、NTFS 数据流、末尾的点或空格）进行写入，也始终询问。 |
| log | 命中 high 风险规则，但调用不太可能来自 skill 或插件（是你自己输入的）。记录到 `guard.log`，不打断你。 |

如果守卫自身出错，它会以放行方式失败：向 `guard.log` 写入一行，并让调用继续，而不是破坏你的会话。

对 skill-sentry 自身脚本的只读运行（只带 `--json`、`--path`、`--component`、`--diff-only`、`--claude-home` 或 `--project` 的 `scan.mjs`，以及 `harden.mjs check`）不会弹出确认。会修改其数据或你的设置的步骤（`--update-baseline`、`--allow` 和 `harden.mjs apply`）按设计会弹出确认：对你已经同意的操作批准即可。

### 白名单

如果某个发现是已知的误报，可以逐条放行：

```
node scripts/scan.mjs --allow <componentId> <ruleId> <file> --reason "why"
```

条目与该文件的 sha256 绑定，因此**文件一旦改变，条目立即失效**。放行被拦截命令的条目采用完整字符串精确匹配。Claude 只会在你同意之后才运行此命令。

如果安装了 `skillspector` 命令，审计可以用它提供第二意见。skill-sentry 从不安装它。

## 数据与隐私

- **没有网络调用，没有遥测。** 一切都在本地运行。
- 它只写入 `~/.claude/skill-sentry/`：`baseline.json`、`allowlist.json`、`guard.log` 和 `reports/`。唯一的例外是 `harden`，它会在你批准后编辑你的 `settings.json`，并附带备份。
- 环境变量（主要用于测试）：`SKILL_SENTRY_DATA_DIR`（数据目录）、`SKILL_SENTRY_CLAUDE_HOME`（默认 `~/.claude`）、`SKILL_SENTRY_HOME_DIR`（读取 `~/.claude.json` 的位置）。

## 验证

已在一台真实的 Windows 11 安装环境上测试，共 11 个插件（65 个组件）；Anthropic 官方插件的结论为 ok 或 review。项目有 197 个自动化测试。

## 致谢与灵感

- CybeDefend，["Are Claude Code skills safe?"](https://www.cybedefend.com/blog/are-claude-code-skills-safe)
- "Agent Skills in the Wild" 研究（2026 年 1 月）
- NVIDIA SkillSpector，一个互补的扫描器（`skillspector scan <dir> --no-llm`）。可与 skill-sentry 搭配使用以获得第二意见。

## 许可证

MIT。参见 [LICENSE](LICENSE)。
