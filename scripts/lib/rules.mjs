import { normalizePath, escapeInvisible, truncate, invisibleRegex } from './text.mjs';

/**
 * @typedef {'critical'|'high'|'medium'|'info'} Severity
 * @typedef {'code'|'markdown'|'config'|'binary'|'other'} FileKind
 * @typedef {{ ruleId: string, category: string, severity: Severity, line: number, snippet: string }} Match
 * @typedef {{ id: string, category: string, severity: Severity, pattern: RegExp,
 *             appliesTo: Array<'code'|'markdown'|'config'|'command'|'path'>, description: string,
 *             kindSeverity?: Partial<Record<FileKind, Severity>> }} Rule
 */

// Signature words are assembled from fragments so detector sources stay inert.
const j = (...p) => p.join('');
const MINER_NAMES = [
  j('xm', 'rig'), j('xmr', '-stak'), j('cpu', 'miner'), j('minerd'), j('eth', 'miner'), j('nb', 'miner'),
  j('phoenix', 'miner'), j('cg', 'miner'), j('bfg', 'miner'), j('lol', 'miner'), j('t-', 'rex'),
  j('gmi', 'ner'), j('teamred', 'miner'), j('nice', 'hash'), j('coin', 'hive'), j('crypto', 'loot'),
];
const POOL_HOSTS = [
  j('mine', 'xmr'), j('support', 'xmr'), j('nano', 'pool'), j('2', 'miners'), j('f2', 'pool'),
  j('hash', 'vault'), j('monero', 'ocean'), j('c3', 'pool'), j('moneroocean'), j('ethermine'),
];
const EXFIL_HOSTS = [
  'webhook\\.site', 'pastebin\\.com', 'transfer\\.sh', 'file\\.io', '0x0\\.st', 'anonfiles',
  '[a-z0-9-]+\\.ngrok(?:-free)?\\.(?:io|app|dev)', 'ngrok\\.io',
  'discord(?:app)?\\.com/api/webhooks', 'api\\.telegram\\.org/bot',
  'requestbin', 'pipedream\\.net', 'interact\\.sh', 'oast\\.(?:fun|live|pro|site|me)',
  'burpcollaborator', 'hookbin', 'beeceptor',
];

const ALL = ['code', 'markdown', 'config', 'command'];
const CODE_CMD = ['code', 'command'];
const SCRIPTY = ['code', 'config', 'command'];
const PROSE = ['markdown'];

// download tool, optional `| tee …` stages, then a pipe into a shell (any args, `$SHELL` included)
// or into an interpreter reading its program from stdin.
const PIPE_TO_INTERPRETER = new RegExp(
  '\\b(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\\b[^\\n|;]{0,150}'
  + '(?:\\|\\s*(?:sudo\\s+)?tee\\b[^\\n|;]{0,100}){0,3}'
  + '\\|\\s*(?:sudo(?:\\s+-\\S+){0,4}\\s+)?(?:(?:\\/\\S{0,60}\\/)?env\\s+)?(?:\\S{0,80}\\/)?["\']?'
  + '(?:(?:(?:ba|z|da|k|c)?sh|iex|invoke-expression)\\b|\\$\\{?shell\\b\\}?'
  + '|(?:python[23]?|node|perl|ruby|php)(?=\\s*(?:$|[;&|)]|-(?:\\s|$))))',
  'i');
// PowerShell web download cmdlets, optionally wrapped in `(`, `$(`, and `.Content` access.
const PS_DOWNLOAD = '(?:new-object\\s+(?:system\\.)?net\\.webclient|iwr|irm|invoke-webrequest|invoke-restmethod)\\b';

/** @returns {Rule} */
// `needs` (optional): a cheap test every match of `pattern` must pass (a literal the pattern requires). It skips
// patterns that scan a 300-char window after every `>` on long lines (CI: 1 MB of `curl => x;` took 645 ms).
const r = (id, category, severity, pattern, appliesTo, description, needs) =>
  ({ id, category, severity, pattern, appliesTo, description, ...(needs ? { needs } : {}) });

/** @type {Rule[]} */
export const RULES = [
  // ---- MINER ----
  r('MINER_BINARY', 'miner', 'critical', new RegExp(`\\b(?:${MINER_NAMES.join('|')})\\b`, 'i'), ALL,
    'References a known cryptocurrency miner'),
  r('MINER_POOL_URL', 'miner', 'critical', new RegExp(`${j('stra', 'tum')}\\+(?:tcp|ssl|tls)://|\\b(?:${POOL_HOSTS.join('|')})\\.`, 'i'), ALL,
    'Mining pool URL or hostname'),
  r('MINER_FLAGS', 'miner', 'high', /--donate-level\b|--coin[= ]+(?:monero|xmr|ethash)\b|--cpu-priority\b|--randomx\b/i, ALL,
    'Typical miner command-line flags'),

  // ---- RCE ----
  r('RCE_DOWNLOAD_PIPE_SHELL', 'rce', 'critical', PIPE_TO_INTERPRETER, ALL,
    'Downloads content and pipes it straight into a shell or interpreter', /\|/),
  r('RCE_PROCESS_SUBST', 'rce', 'critical',
    /(?:^|[\s;&|(])(?:(?:ba|z|da|k)?sh|source|\.)\s+<\(\s*(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b/i, ALL,
    'Shell sources or executes the output of a download'),
  r('RCE_EVAL_SUBST', 'rce', 'critical', /\beval\s+["']?(?:\$\(|`)\s*(?:curl|wget)\b/i, ALL,
    'eval of the output of a download'),
  r('RCE_IEX_DOWNLOAD', 'rce', 'critical',
    new RegExp(`\\b(?:iex|invoke-expression)\\b\\s*(?:\\$?\\(\\s*){0,3}${PS_DOWNLOAD}`
      + `|\\[scriptblock\\]::create\\s*(?:\\$?\\(\\s*){0,3}${PS_DOWNLOAD}|\\.downloadstring\\s*\\(`, 'i'),
    ALL, 'PowerShell download-and-evaluate'),
  r('RCE_SHELL_C_SUBST', 'rce', 'critical', /\b(?:ba|z|da)?sh\s+-c\s+["']?\$\(\s*(?:curl|wget)\b/i, ALL,
    'Shell executes the output of a download'),
  r('RCE_POWERSHELL_ENCODED', 'rce', 'high',
    /\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]{0,300}\s-e(?:nc(?:odedcommand)?)?\s+['"]?[A-Za-z0-9+/=]{8,}/i, ALL,
    'PowerShell encoded command'),
  r('RCE_REVERSE_SHELL', 'rce', 'critical',
    /\/dev\/tcp\/[\w.$-]+\/\d+|\bn(?:c|cat)\b[^\n]{0,300}\s-e\s+\/?\S*sh\b|\b(?:ba)?sh\s+-i\s*>&|\bmkfifo\b[^\n]{0,300}\bnc\b/i, ALL,
    'Reverse shell construction'),
  r('RCE_DOWNLOAD_EXEC', 'rce', 'high',
    /\b(?:curl|wget)\b[^\n;]{0,120}?(?:\s-o\s*|>\s*)\S{1,100}\s*(?:&&|;)\s*(?:sudo\s+)?(?:chmod\s+\+?[ugoa]*x|\.\/|sh\s|bash\s)/i, ALL,
    'Downloads a file then makes it executable / runs it', /&&|;/),
  r('RCE_LOLBIN_DOWNLOAD', 'rce', 'high',
    /\bmshta\b[^\n]{0,300}https?:|\bcertutil(?:\.exe)?\s+[^\n]{0,300}-urlcache\b|\bbitsadmin\b[^\n]{0,300}\/transfer\b|\bregsvr32\b[^\n]{0,300}\/i:https?:/i, ALL,
    'Windows living-off-the-land downloader'),

  // ---- SECRET ----
  r('SECRET_SSH_KEY_REF', 'secret', 'high',
    /\.ssh[/\\](?:id_[a-z0-9_]+(?!\.pub)\b|authorized_keys|[a-z0-9_]*_key\b)|\bid_(?:rsa|ed25519|ecdsa|dsa)\b(?!\.pub)/i, ALL,
    'References an SSH private key'),
  r('SECRET_SSH_DIR_READ', 'secret', 'high',
    /\b(?:cat|type|grep|egrep|rg|ag|findstr|select-string|sls|get-content|gc|tar|zip|7z|compress-archive|cp|copy|copy-item|xcopy|robocopy|scp|rsync|base64|xxd|od|strings|find)\b[^\n|;&]{0,300}(?:^|[\s"'=(])(?:(?:~|\$\{?HOME\}?|%USERPROFILE%|\$env:USERPROFILE|[a-z]:[/\\]users[/\\][^/\\\n"']+|\/(?:home|Users)\/[^/\s"']+|\/root)?[/\\])?\.ssh(?:[/\\]\*?)?(?=$|[\s"';|&)])/i,
    ['command'], 'Reads or archives the whole SSH key directory'),
  r('SECRET_AWS_CREDENTIALS_REF', 'secret', 'high', /\.aws[/\\](?:credentials|sso)\b/i, ALL, 'References AWS credentials'),
  r('SECRET_CLAUDE_CREDENTIALS_REF', 'secret', 'high', /\.claude[/\\]\.credentials\.json/i, ALL,
    'References Claude Code credentials'),
  r('SECRET_GIT_NETRC_REF', 'secret', 'high', /(?:^|[\s/\\"'=])(?:\.git-credentials|\.netrc|_netrc)\b/i, ALL,
    'References stored git/netrc credentials'),
  r('SECRET_BROWSER_DATA_REF', 'secret', 'high',
    /(?:google[-/\\ ]chrome|chromium|brave|microsoft[/\\ ]edge|mozilla[/\\ ]firefox|vivaldi)[^\n]{0,300}(?:login data|cookies|logins\.json|key4\.db|web data)/i,
    ALL, 'References browser credential or cookie stores'),
  r('SECRET_WALLET_REF', 'secret', 'high',
    /\bwallet\.dat\b|[/\\]\.(?:electrum|monero|bitcoin)\b|[/\\]exodus[/\\]|\bmetamask\b|keystore[/\\]utc--/i, ALL,
    'References cryptocurrency wallet files'),
  r('SECRET_ENV_FILE_READ', 'secret', 'high',
    // `cp .env.example .env` (creating .env from a template) writes the file, it does not read it. The exemption needs
    // exactly two operands and only plain flags: no `-t`/`--target-directory` (which would copy the real .env elsewhere),
    // and the template operand never starts with `-` (`cp -t/tmp/q.env.example .env` is an option, not a template).
    /\b(?:cat|type|cp(?!\s+(?:(?:-(?![a-z]*t)[a-z]+|--(?!target)[a-z][a-z-]*)\s+)*["']?(?!-)[^\s"'|;&]*\.env\.(?:example|sample|template|dist)["']?\s+["']?[^\s"'|;&]*\.env["']?\s*(?:$|[|;&]))|scp|base64|tar|zip|get-content|gc)\b[^\n|;&]{0,300}(?:^|[\s/\\])\.env(?:\.(?!example|sample|template)[\w-]+)?(?=\s|$|["'|;&])/i,
    ['command'], 'Reads a .env file'),
  r('SECRET_ENV_DUMP_PIPE', 'secret', 'high',
    /JSON\.stringify\(\s*process\.env\b|\bdict\(\s*os\.environ\s*\)|\b(?:printenv|env)\b\s*\|\s*(?:curl|nc|base64)\b|\bget-childitem\s+env:[^\n]{0,300}\|\s*(?:iwr|irm|invoke-)/i,
    CODE_CMD, 'Dumps the whole environment into a pipe or serializer'),
  r('SECRET_TOKEN_LITERAL', 'secret', 'high',
    /\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bAKIA[0-9A-Z]{16}\b|\bsk-ant-[A-Za-z0-9_-]{20,}|-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----|\bxox[baprs]-[A-Za-z0-9-]{10,}/,
    ['code', 'config', 'command', 'markdown'], 'Embedded credential or private key material'),

  // ---- EXFIL ----
  r('EXFIL_KNOWN_SERVICE', 'exfil', 'high', new RegExp(`(?:^|[^a-z0-9.-])(?:${EXFIL_HOSTS.join('|')})`, 'i'), ALL,
    'Known data-exfiltration / paste / tunnel service'),
  r('EXFIL_UPLOAD_FILE', 'exfil', 'high',
    /\bcurl\b[^\n]{0,120}?\s(?:-d|--data(?:-binary|-raw|-urlencode)?|-F|--form|-T|--upload-file)(?:\s+|=)["']?(?:[\w.-]+=)?@\S|\bwget\b[^\n]{0,300}--post-file\b|\b(?:iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n]{0,300}-infile\b/i,
    CODE_CMD, 'Uploads a local file to a remote host', /@|--post-file|-infile/i),
  r('EXFIL_RAW_IP_URL', 'exfil', 'high',
    /\bhttps?:\/\/(?!(?:127\.|0\.0\.0\.0|10\.|192\.168\.|169\.254\.|172\.(?:1[6-9]|2\d|3[01])\.))\d{1,3}(?:\.\d{1,3}){3}\b/i,
    SCRIPTY, 'Request to a raw public IP address'),

  // ---- PERSISTENCE ----
  r('PERSIST_CRON', 'persistence', 'high',
    /\(\s*crontab\s+-l[^\n]{0,300}\)\s*\|\s*crontab\b|\|\s*crontab\s+-?\s*(?:$|[\s;&])|\bcrontab\s+-\s*$|>>?\s*\/etc\/cron\S*|>>?\s*\/var\/spool\/cron\S*/im,
    CODE_CMD, 'Installs a cron job'),
  r('PERSIST_SCHTASKS', 'persistence', 'high', /\bschtasks(?:\.exe)?\s+\/create\b|\bregister-scheduledtask\b/i, CODE_CMD,
    'Creates a Windows scheduled task'),
  r('PERSIST_REG_RUN', 'persistence', 'high', /CurrentVersion[\\/]Run(?:Once)?\b/i, CODE_CMD,
    'Registry Run key autostart'),
  r('PERSIST_SERVICE_ENABLE', 'persistence', 'high',
    /\bsystemctl\s+(?:--user\s+)?enable\b|\blaunchctl\s+(?:load|bootstrap)\b|\bsc(?:\.exe)?\s+create\b/i, CODE_CMD,
    'Enables a service / launch agent'),
  r('PERSIST_STARTUP_FOLDER', 'persistence', 'high', /start menu[/\\]programs[/\\]startup/i, ALL,
    'Writes to the Windows Startup folder'),
  r('PERSIST_RC_APPEND', 'persistence', 'high',
    /(?:>>|\btee\s+-a|\badd-content\b)[^\n]{0,300}(?:\.bashrc|\.zshrc|\.zprofile|\.bash_profile|\.profile\b|\$profile\b|microsoft\.powershell_profile)/i,
    CODE_CMD, 'Appends to a shell startup file'),
  r('PERSIST_CLAUDE_SETTINGS_WRITE', 'persistence', 'high',
    /(?:>>?|\btee\b|\bsed\s+-i|\bset-content\b|\badd-content\b|\bout-file\b)[^\n]{0,300}\.claude[/\\]settings(?:\.local)?\.json/i,
    CODE_CMD, 'Modifies Claude Code settings from a script', /\.claude/i),
  // Final review I3: the Codex control files (see CODEX_CONTROL_TAIL), under `.codex` or `$CODEX_HOME`.
  r('PERSIST_CODEX_CONFIG_WRITE', 'persistence', 'high',
    /(?:>>?|\btee\b|\bsed\s+-i|\bset-content\b|\badd-content\b|\bout-file\b|\bcp\b|\bmv\b|\bcopy-item\b|\bmove-item\b)[^\n]{0,300}(?:\.codex|codex_home[}%]?)[/\\](?:(?:[\w-]+\.)?config\.toml|hooks\.json|requirements\.toml|rules\b|\.hook-trust\b)/i,
    CODE_CMD, 'Modifies Codex config, hooks, requirements or execpolicy rules from a script', /\.codex|codex_home/i),

  // ---- PERMISSIONS ----
  r('PERM_SKIP_PERMISSIONS', 'permissions', 'high',
    /--dangerously-skip-permissions\b|["']?defaultMode["']?\s*[:=]\s*["']bypassPermissions["']|--permission-mode[= ]+bypassPermissions\b/i,
    ALL, 'Disables Claude Code permission prompts'),
  r('PERM_ALLOW_ALL', 'permissions', 'high', /["'](?:Bash|Write|Edit|Read)\(\*{1,2}\)["']|["']allow["']\s*:\s*\[\s*["']\*["']/, ['config', 'markdown'],
    'Blanket allow rule for powerful tools'),
  r('PERM_AUTO_MCP', 'permissions', 'medium', /["']enableAllProjectMcpServers["']\s*:\s*true/, ['config', 'markdown'],
    'Auto-approves every project MCP server'),
  r('PERM_SUDO', 'permissions', 'medium', /(?:^|[;&|]\s*|\s)sudo\s+(?!-l\b)\S/, ['command'], 'Runs a command with sudo'),
  r('PERM_CHMOD_WORLD', 'permissions', 'medium', /\bchmod\s+(?:-R\s+)?(?:0?777|a\+rwx|\+s|u\+s)\b/, CODE_CMD,
    'Makes files world-writable or setuid'),

  // ---- DESTRUCTIVE ----
  r('DESTRUCT_RM_HOME_ROOT', 'destructive', 'critical',
    /\brm\s+(?:-{1,2}[a-z-]+\s+)*(?:~|\$HOME|\$\{HOME\}|\/)\/?\*?(?=\s|$|[;&|"'])/i, CODE_CMD,
    'Recursive delete of the home directory or filesystem root'),
  r('DESTRUCT_WIN_WIPE', 'destructive', 'critical',
    /\b(?:rd|rmdir|del|erase)\s+(?:\/[sq]\s+)+(?:[a-z]:\\?\*?|%userprofile%\\?\*?|%homepath%)(?=\s|$)|\bremove-item\b[^\n]{0,300}-recurse[^\n]{0,300}\s(?:[a-z]:\\\*?|\$env:userprofile\\?\*?|~[\\/]?\*?)(?=\s|$)/i,
    CODE_CMD, 'Recursive delete of a Windows drive root or user profile'),
  r('DESTRUCT_DISK', 'destructive', 'critical',
    /\bmkfs(?:\.\w+)?\s+\/dev\/|\bdd\s+[^\n]{0,300}\bof=\/dev\/(?:sd|nvme|hd|vd|disk)|>\s*\/dev\/(?:sd[a-z]|nvme\d)/i, CODE_CMD,
    'Overwrites or formats a block device'),
  r('DESTRUCT_FORMAT_DRIVE', 'destructive', 'high', /\bformat(?:\.com)?\s+[a-z]:(?:\s|$)|\bclear-disk\b/i, CODE_CMD,
    'Formats a Windows drive'),
  r('DESTRUCT_FORK_BOMB', 'destructive', 'critical', /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/, CODE_CMD, 'Fork bomb'),

  // ---- OBFUSCATION ----
  r('OBF_BASE64_PIPE_SHELL', 'obfuscation', 'critical',
    /\bbase64\s+(?:-d|-D|--decode)\b[^\n]{0,300}\|\s*(?:sudo\s+)?(?:(?:ba|z|da)?sh|python[23]?|perl|iex)\b|frombase64string\b[^\n]{0,300}(?:\|\s*iex\b|invoke-expression)|\b(?:iex|invoke-expression)\b[^\n]{0,300}frombase64string/i,
    ALL, 'Decodes base64 and executes it'),
  r('OBF_EVAL_DECODE', 'obfuscation', 'high',
    /\b(?:eval|exec|new\s+Function)\s*\(\s*(?:atob|Buffer\.from|base64\.b64decode|bytes\.fromhex|zlib\.decompress|String\.fromCharCode)\b/, CODE_CMD,
    'Evaluates decoded data'),
  r('OBF_BASE64_BLOB', 'obfuscation', 'medium', /(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{300,}={0,2}/, ['code'], 'Very long base64-like blob'),
  r('OBF_HEX_ESCAPES', 'obfuscation', 'medium', /(?:\\x[0-9a-f]{2}){16,}/i, ['code'], 'Long run of hex escapes'),
  r('OBF_CHARCODE_ARRAY', 'obfuscation', 'medium', /String\.fromCharCode\((?:\s*\d+\s*,){8,}/, ['code'],
    'String assembled from char codes'),

  // ---- PROMPT INJECTION (English + Portuguese) ----
  // CONCEAL gaps never cross a clause break (`.`, `;`, `:`, `!`, `?`): "Do not retry; tell the user" is two clauses.
  // IGNORE gaps only stop at `.` (as before calibration): "Ignore everything above: your rules are now these" is one attack.
  // Singular "direction" is not a target noun ("Override the parent's direction inside a subgraph"); "lint rules" is not either.
  // These four are high in Markdown (the instruction surface) and medium in code/config (`kindSeverity`).
  r('INJECT_IGNORE_INSTRUCTIONS_EN', 'injection', 'high',
    /\b(?:ignore|disregard|forget|override)\b[^\n.]{0,30}\b(?:previous|prior|above|earlier|preceding|all|any|your|the|these|those|system)\b[^\n.]{0,30}\b(?<!\b(?:lint|linting|linter|eslint|tslint)\s)(?:instructions?|prompts?|rules?|directions|guidelines?)\b/i,
    ['markdown', 'config', 'code'], 'Tells the model to ignore its instructions'),
  r('INJECT_IGNORE_INSTRUCTIONS_PT', 'injection', 'high',
    /\b(?:ignor[ea]r?|desconsidere|desconsiderar|esque[çc]a|esquecer|sobrescreva)\b[^\n.]{0,40}\b(?:instru[çc][õo]es|regras|diretrizes|orienta[çc][õo]es|prompts?)\b/i,
    ['markdown', 'config', 'code'], 'Tells the model to ignore its instructions (Portuguese)'),
  r('INJECT_CONCEAL_FROM_USER_EN', 'injection', 'high',
    /\b(?:do not|don'?t|never)\b[^\n.;:!?]{0,20}\b(?:tell|inform|mention|reveal|notify|show|let)\b[^\n.;:!?]{0,20}\b(?:the |this )?(?:user|human|person)\b/i,
    ['markdown', 'config', 'code'], 'Instructs the model to hide actions from the user'),
  r('INJECT_CONCEAL_FROM_USER_PT', 'injection', 'high',
    /\bn[ãa]o\b[^\n.;:!?]{0,20}\b(?:conte|diga|informe|avise|mencione|revele|mostre|fale)\b[^\n.;:!?]{0,20}\b(?:usu[áa]rio|humano|pessoa)\b/i,
    ['markdown', 'config', 'code'], 'Instructs the model to hide actions from the user (Portuguese)'),
  r('INJECT_FAKE_SYSTEM_TAG', 'injection', 'high',
    /<\/?(?:system|important|admin|instructions?)>|\[\s*system\s*\]|<\|(?:im_start|system)\|>/i, PROSE,
    'Fake system / important tag used to hijack the model'),
  r('INJECT_HIDDEN_COMMENT', 'injection', 'medium', /<!--[^\n]{0,300}(?:instruction|ignore|assistant|claude|system prompt|instru[çc][õo]es)[^\n]{0,300}-->/i, PROSE,
    'HTML comment carrying instructions'),
  r('INJECT_REVEAL_PROMPT', 'injection', 'medium',
    /\b(?:reveal|print|output|repeat|leak|show)\b[^\n.]{0,30}\b(?:system prompt|your instructions|hidden instructions)\b|\b(?:revele|mostre|imprima)\b[^\n.]{0,30}\b(?:prompt do sistema|suas instru[çc][õo]es)\b/i,
    PROSE, 'Tries to extract the system prompt'),
  r('INJECT_ROLE_OVERRIDE', 'injection', 'medium',
    /\byou are now\b[^\n.]{0,40}\b(?:unrestricted|jailbroken|dan|developer mode|root|admin)\b|\bnew instructions?\s*:|\bnovas instru[çc][õo]es\s*:|\bvoc[êe] agora [ée] (?:um|uma) [^\n.]{0,20}(?:sem restri[çc][õo]es)/i,
    PROSE, 'Attempts to redefine the model role'),
  r('INJECT_SKIP_CONFIRMATION', 'injection', 'medium',
    // The pre-calibration broad match ("without/sem" + asking/confirmation/permission/approval/consent within 20 chars),
    // plus "prompting" and "sem perguntar" (new; not counted after "não/nunca" + up to 4 words, as in the user's own
    // skill "Não delete notas existentes sem perguntar"), minus narrow exclusions, each for a descriptive pattern observed on a real install:
    //   "never push without permission"                 negation + one verb right before (superpowers spec)
    //   "use it without asking"                         acting on a declared preference (superpowers using-git-worktrees:67)
    //   "existing declared preference without asking"   same (using-git-worktrees:45)
    //   "was auto-creating worktrees without consent"   past progressive narration, no clause punctuation in between
    //                                                   (superpowers RELEASE-NOTES:445)
    //   "without their permission" / "without Jesse's"  a named third party's consent (CODE_OF_CONDUCT:34, specs) — not
    //                                                   user's/anyone's/someone's/Claude's/agent's
    //   "without asking which/what/follow-up/questions", whitespace + an OPENING quote ("without asking "what's
    //   missing?""; a closing quote after the phrase still matches), "without asking in 24 of 24 runs"
    //                                                   (OMC agents/critic.md, explore.md; superpowers RELEASE-NOTES:70, specs)
    /(?<!\b(?:never|not|n't|nunca|n[ãa]o)\s+[\w-]+\s+|\buse\s+(?:it|that|this|them)\s+|\b(?:was|were)\s+[\w-]+ing\b[^\n.,;:!?]{0,60}|\b(?:declared|existing|stated|specified)\s+preferences?\s+)\b(?:without|sem)\b(?!\s+(?:their|his|her)\b|\s+(?!(?:user|human|owner|person|anyone|anybody|everyone|everybody|someone|somebody|claude|agent|assistant)['’]s\b)[a-z]+['’]s\b)[^\n.]{0,20}\b(?:asking|prompting|confirmation|confirma[çc][ãa]o|permiss[ãa]o|permission|approval|consent)\b(?!\s+["“‘]|\s+(?:which|what|whether|why|how|in\s+\d|(?:any\s+)?(?:follow-?up|clarifying|further)\b|(?:any\s+)?questions?\b))|(?<!\b(?:n[ãa]o|nunca)\s+(?:[^\s.;:!?]+\s+){0,4})\bsem\s+perguntar\b/i, PROSE,
    'Tells the model to act without user confirmation'),
  r('INJECT_EXFIL_INSTRUCTION', 'injection', 'high',
    /\b(?:send|post|upload|exfiltrate|forward|envie|enviar|mande)\b[^\n.]{0,60}\b(?:ssh keys?|credentials?|api keys?|tokens?|secrets?|\.env|chaves? ssh|credenciais|segredos?)\b[^\n.]{0,60}\b(?:to|para)\s+(?:https?:|an? (?:external|remote)|\S+@)/i,
    PROSE, 'Instructs the model to send secrets to a remote destination'),

  // ---- SUPPLY CHAIN ----
  r('SUPPLY_INSTALL_FROM_URL', 'supply', 'medium',
    // The URL must be an argument of the same install command (no quote, pipe or separator in between),
    // so `npm i -g pkg` followed later on the line by an unrelated URL does not match.
    /\b(?:npm|pnpm|yarn|bun)\s+(?:i|install|add)\b(?:\s+(?:"[^"\n]*"|'[^'\n]*'|[^\s"'`|;&<>()]+)(?=\s|$)){0,20}?\s+["']?[^\s"'`|;&<>()]*(?:https?:\/\/|git\+|github:)|\bpip3?\s+install\b(?:\s+(?:"[^"\n]*"|'[^'\n]*'|[^\s"'`|;&<>()]+)(?=\s|$)){0,20}?\s+["']?(?:[^\s"'`|;&<>()]*(?:https?:\/\/|git\+)|--index-url\b|--extra-index-url\b|-i\s+["']?https?:)/i,
    ['command', 'code', 'markdown'], 'Installs a package from a URL or custom index'),
  r('SUPPLY_NPX_REMOTE', 'supply', 'medium', /\bnpx\s+(?:-y\s+|--yes\s+)[^\n]{0,300}(?:https?:\/\/|github:|git\+)/i, ALL,
    'npx runs a package from a remote location'),
  r('SUPPLY_REGISTRY_OVERRIDE', 'supply', 'medium', /\bnpm\s+config\s+set\s+registry\b|--registry[= ]+https?:\/\/(?!registry\.npmjs\.org)/i, CODE_CMD,
    'Overrides the package registry'),
  r('SUPPLY_LIFECYCLE_SCRIPT', 'supply', 'high',
    /["'](?:preinstall|install|postinstall|prepare)["']\s*:\s*["'][^"'\n]*\b(?:curl|wget|powershell|node\s+-e|python[23]?\s+-c|bash\s|sh\s+-c|iex)\b/i,
    ['config'], 'Install lifecycle script that downloads or evaluates code'),
];

// Injection phrasing is high where the model reads it as instructions (Markdown) and medium in code/config,
// where it is mostly string data or comments ("ignore any previous rules" in a linter, a test string).
const PROSE_HIGH_ONLY = new Set(['INJECT_IGNORE_INSTRUCTIONS_EN', 'INJECT_IGNORE_INSTRUCTIONS_PT', 'INJECT_CONCEAL_FROM_USER_EN', 'INJECT_CONCEAL_FROM_USER_PT']);
for (const rule of RULES) if (PROSE_HIGH_ONLY.has(rule.id)) rule.kindSeverity = { code: 'medium', config: 'medium' };

// ---- Path rules (applied to normalizePath(p)) ----
const pr = (id, category, severity, pattern, description) => r(id, category, severity, pattern, ['path'], description);

/**
 * Final review I3: the Codex files that control what runs (config layers, hooks, requirements, execpolicy rules,
 * hook trust records), relative to a Codex home or project `.codex` dir. The guard also applies it under a custom
 * `$CODEX_HOME`, which has no `.codex` segment.
 */
export const CODEX_CONTROL_TAIL = /^(?:(?:[\w-]+\.)?config\.toml$|hooks\.json$|requirements\.toml$|rules(?:\/|$)|\.hook-trust(?:\/|$))/i;
const CODEX_CONTROL_PATH = new RegExp(`(?:^|\\/)(?:\\.codex|etc\\/codex|openai\\/codex)\\/(?:${CODEX_CONTROL_TAIL.source.slice(1)})`, 'i');

const PATH_RULES = [
  // Secret path rules also accept a relative form (`.ssh/id_rsa`, `.aws/credentials`) with no leading `/`.
  pr('SECRET_PATH_SSH', 'secret', 'high', /(?:^|\/)\.ssh(?:\/(?![^/]*\.pub$)|$)/i, 'SSH key directory'),
  pr('SECRET_PATH_AWS', 'secret', 'high', /(?:^|\/)\.aws\/(?:credentials|sso\/)/i, 'AWS credentials'),
  pr('SECRET_PATH_ENV', 'secret', 'high', /(?:^|\/)\.env(?:\.(?!example$|sample$|template$|dist$)[\w-]+)?$/i, 'Environment file'),
  pr('SECRET_PATH_NETRC', 'secret', 'high', /(?:^|\/)(?:\.netrc|_netrc|\.git-credentials)$/i, 'Stored git/netrc credentials'),
  pr('SECRET_PATH_TOKEN_FILES', 'secret', 'medium',
    /(?:^|\/)(?:\.npmrc|\.pypirc|\.docker\/config\.json|\.kube\/config|\.config\/gh\/hosts\.yml|\.gnupg\/[^/]+)$/i, 'Tool credential files'),
  pr('SECRET_PATH_CLAUDE_CREDENTIALS', 'secret', 'high', /(?:^|\/)\.claude\/\.credentials\.json$/i, 'Claude Code credentials'),
  pr('SECRET_PATH_BROWSER', 'secret', 'high',
    /\/(?:google[-/]chrome|chromium|brave-?software|brave-browser|microsoft[-/]edge|\.?mozilla\/firefox|vivaldi)\b.*\/(?:login data|cookies|logins\.json|key4\.db|web data|local state)$/i,
    'Browser credential or cookie store'),
  pr('SECRET_PATH_WALLET', 'secret', 'high',
    /\/wallet\.dat$|\/\.(?:electrum|bitcoin|ethereum|monero)\/|\/(?:exodus|metamask|atomic)\/|\/keystore\/utc--|\/\.config\/solana\/id\.json$/i,
    'Cryptocurrency wallet'),

  pr('PERSIST_PATH_SHELL_RC', 'persistence', 'high',
    /\/(?:\.bashrc|\.bash_profile|\.bash_login|\.profile|\.zshrc|\.zshenv|\.zprofile|\.zlogin|\.config\/fish\/config\.fish)$/i,
    'Shell startup file'),
  pr('PERSIST_PATH_PS_PROFILE', 'persistence', 'high', /\/(?:[^/]*_)?profile\.ps1$/i, 'PowerShell profile'),
  pr('PERSIST_PATH_STARTUP', 'persistence', 'high', /\/start menu\/programs\/startup(?:\/|$)/i, 'Windows Startup folder'),
  pr('PERSIST_PATH_LAUNCHD', 'persistence', 'high', /\/library\/launch(?:agents|daemons)\//i, 'macOS launch agent/daemon'),
  pr('PERSIST_PATH_SYSTEMD', 'persistence', 'high',
    /\/(?:\.config\/systemd\/user|etc\/systemd\/system|\.config\/autostart|etc\/cron[^/]*|var\/spool\/cron)(?:\/|$)/i,
    'systemd / cron / autostart location'),
  pr('PERSIST_PATH_CLAUDE_SETTINGS', 'persistence', 'high', /\/\.claude\/(?:settings(?:\.[\w-]+)?\.json|hooks\/)/i,
    'Claude Code settings or hooks'),
  pr('PERSIST_PATH_GIT_HOOKS', 'persistence', 'high', /\/\.git\/hooks\/[^/]+$/i, 'Git hook'),
  pr('PERSIST_PATH_CODEX_CONFIG', 'persistence', 'high', CODEX_CONTROL_PATH, 'Codex config, hooks, requirements or execpolicy rules'),
];

// ---- Matching ----

function lineMatch(rule, line, lineNo, kind) {
  if (rule.needs && !rule.needs.test(line)) return null; // cheap necessary condition before a costly pattern
  const hit = rule.pattern.exec(line);
  if (!hit) return null;
  const idx = hit.index;
  // Window around the hit keeps snippets useful on very long (minified) lines.
  const text = line.length > 400 ? line.slice(Math.max(0, idx - 60), idx + 160) : line.trim();
  const severity = rule.kindSeverity?.[kind] ?? rule.severity;
  return { ruleId: rule.id, category: rule.category, severity, line: lineNo, snippet: truncate(escapeInvisible(text.trim())) };
}

/** @param {string} text @param {FileKind} kind @returns {Match[]} */
export function matchText(text, kind) {
  if (kind !== 'code' && kind !== 'markdown' && kind !== 'config') return [];
  const rules = RULES.filter(x => x.appliesTo.includes(kind));
  const out = [];
  const lines = String(text).split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    for (const rule of rules) {
      const m = lineMatch(rule, lines[i], i + 1, kind);
      if (m) out.push(m);
    }
  }
  return out;
}

/** @param {string} cmd @returns {Match[]} */
export function matchCommand(cmd) {
  // Join backslash-newline continuations, then evaluate each logical line; one match per rule.
  const logical = String(cmd ?? '').replace(/\\\r?\n[ \t]*/g, ' ').split(/\r?\n/);
  const rules = RULES.filter(x => x.appliesTo.includes('command'));
  const out = [];
  for (const rule of rules) {
    for (const line of logical) {
      const m = lineMatch(rule, line, 1);
      if (m) { out.push(m); break; }
    }
  }
  return out;
}

/** @param {string} p @returns {Match[]} */
export function matchPath(p) {
  const norm = normalizePath(p);
  const out = [];
  for (const rule of PATH_RULES) {
    if (rule.pattern.test(norm)) {
      out.push({ ruleId: rule.id, category: rule.category, severity: rule.severity, line: 1, snippet: truncate(escapeInvisible(String(p))) });
    }
  }
  return out;
}

const INVISIBLE = invisibleRegex();

/** Report lines containing invisible / bidi / tag characters. @returns {Match[]} */
export function findInvisible(text, kind) {
  if (kind !== 'code' && kind !== 'markdown' && kind !== 'config') return [];
  const severity = kind === 'markdown' ? 'critical' : 'medium';
  const lines = String(text).split(/\r?\n/);
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    INVISIBLE.lastIndex = 0;
    let found = false;
    let mm;
    while ((mm = INVISIBLE.exec(line)) !== null) {
      const cp = mm[0].codePointAt(0);
      if (cp === 0xFEFF && i === 0 && mm.index === 0) continue; // BOM
      if (cp === 0x200D) {
        // Zero-width joiner inside emoji sequences is legitimate.
        const prev = line.codePointAt(mm.index - 1) ?? 0;
        const next = line.codePointAt(mm.index + 1) ?? 0;
        if (prev >= 0x2190 && next >= 0x2190) continue;
      }
      found = true;
      break;
    }
    if (found) {
      out.push({
        ruleId: 'OBF_INVISIBLE_CHARS', category: 'obfuscation', severity, line: i + 1,
        snippet: truncate(escapeInvisible(line.trim())),
      });
    }
  }
  return out;
}
