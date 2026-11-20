import fs from 'node:fs';
import path from 'node:path';

// Synthetic Codex homes, generated at runtime in a tmp dir (never committed, never the real homes).
// Every credential is the SENTINEL string: tests assert it never reaches a serialized component.
export const SENTINEL = 'SENTINELs3cretValue9f2c';

const write = (root, rel, content) => {
  const file = path.join(root, ...rel.split('/'));
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content);
  return file;
};
const skill = (dir, name) => write(dir, `${name}/SKILL.md`, `---\nname: ${name}\ndescription: ${name} helper\n---\n# ${name}\nSummarize notes.\n`);
// TOML literal string: backslashes kept as-is.
const lit = p => `'${p}'`;

/**
 * Build a fake Windows-style Codex setup under `base`:
 *   home/.codex (Codex home), home/.agents/skills, system/ (system layer), project/ (git root) with
 *   project/sub as the scanned project dir.
 */
export function buildCodexFixture(base) {
  const userHome = path.join(base, 'home');
  const codexHome = path.join(userHome, '.codex');
  const systemDir = path.join(base, 'system');
  const project = path.join(base, 'project');
  const projectDir = path.join(project, 'sub');
  const instrFile = write(userHome, 'instr.md', '# Model instructions\nBe careful.\n');

  write(codexHome, 'config.toml', [
    'model = "gpt-5"',
    'approval_policy = "never"',
    'sandbox_mode = "danger-full-access"',
    `notify = ["node", "C:/tools/notify.js", "--api-key=${SENTINEL}"]`,
    'developer_instructions = "Be terse."',
    `model_instructions_file = ${lit(instrFile)}`,
    '',
    '[shell_environment_policy.set]',
    `ANTHROPIC_AUTH_TOKEN = "${SENTINEL}"`,
    '',
    '[mcp_servers.pad]',
    'command = "npx"',
    `args = ["-y", "pad-mcp@1.0.0", "--token", "${SENTINEL}"]`,
    'default_tools_approval_mode = "approve"',
    '',
    '[mcp_servers.pad.env]',
    `PAD_KEY = "${SENTINEL}"`,
    '',
    '[mcp_servers.remote]',
    `url = "https://user:${SENTINEL}@mcp.example.com/x?key=${SENTINEL}"`,
    `oauth = { client_id = "abc", client_secret = "${SENTINEL}" }`,
    '',
    '[mcp_servers.remote.http_headers]',
    `Authorization = "Bearer ${SENTINEL}"`,
    '',
    '[marketplaces.mkt]',
    'source_type = "git"',
    'source = "https://github.com/example/mkt.git"',
    '',
    '[plugins."p@mkt"]',
    'enabled = true',
    '',
    '[plugins."p@mkt".mcp_servers.pm]',
    'default_tools_approval_mode = "approve"',
    '',
    `[projects.${lit(project)}]`,
    'trust_level = "trusted"',
    '',
    `[projects.${lit(path.join(base, 'other'))}]`,
    'trust_level = "trusted"',
    '',
    `[projects.${lit(path.join(base, 'untrusted'))}]`,
    'trust_level = "untrusted"',
    '',
    `[projects.${lit(path.join(base, 'gone'))}]`,
    'trust_level = "trusted"',
    '',
    `[projects.${lit(userHome)}]`,
    'trust_level = "trusted"',
    '',
    '[apps.github]',
    'enabled = true',
    '',
    '[[skills.config]]',
    'name = "home-skill"',
    'enabled = false',
    '',
    '[hooks.state."p@mkt:hooks/hooks.json:pre_tool_use:0:0"]',
    'trusted_hash = "sha256:aaa"',
    'trusted_content_hash = "sha256:bbb"',
    'enabled = true',
    '',
    '[hooks.state."p@mkt:hooks/hooks.json:session_start:0:0"]',
    'enabled = false',
    '',
    '[[hooks.PreToolUse]]',
    'matcher = "Bash"',
    '',
    '[[hooks.PreToolUse.hooks]]',
    'type = "command"',
    'command = "node C:/guard/guard.js"',
    'timeout = 5',
    '',
  ].join('\n'));
  write(codexHome, 'work.config.toml', 'model = "gpt-5-mini"\n[mcp_servers.w]\ncommand = "node"\nargs = ["w.js"]\n');
  write(codexHome, 'hooks.json', JSON.stringify({
    hooks: {
      SessionStart: [{ hooks: [{ type: 'command', command: 'node C:/omx/codex-native-hook.js' }] }],
      PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: 'echo a' }, { type: 'command', command: 'echo b' }] }],
    },
  }, null, 2));
  write(codexHome, 'AGENTS.md', '# Global agents\nUse tabs.\n');
  write(codexHome, 'rules/default.rules', [
    'prefix_rule(pattern=["pwsh", "-NoProfile", "-Command"], decision="allow")',
    'prefix_rule(pattern=["git", "status"], decision="prompt")',
    '',
  ].join('\n'));
  skill(path.join(codexHome, 'skills'), 'home-skill');
  skill(path.join(codexHome, 'skills', '.system'), 'sys-bundled');
  write(codexHome, 'agents/reviewer.toml', 'name = "reviewer"\ndeveloper_instructions = "Review code."\n');
  write(codexHome, 'prompts/fix.md', '# Fix\nFix the bug.\n');
  write(codexHome, 'auth.json', JSON.stringify({ OPENAI_API_KEY: SENTINEL }));
  write(codexHome, 'sessions/rollout.jsonl', `{"secret":"${SENTINEL}"}\n`);

  const plug = path.join(codexHome, 'plugins', 'cache', 'mkt', 'p', '1.0.0');
  write(plug, '.claude-plugin/plugin.json', JSON.stringify({ name: 'p', version: '1.0.0', description: 'Test plugin', apps: './custom.app.json' }));
  write(plug, '.app.json', JSON.stringify({ apps: { gh: { id: 'gh', token: SENTINEL } } }));
  write(plug, 'custom.app.json', JSON.stringify({ apps: { docs: { id: 'docs', url: 'https://apps.example.com/docs' } } }));
  write(plug, 'hooks/hooks.json', JSON.stringify({
    hooks: {
      PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: `node \${PLUGIN_ROOT}/scripts/h.js --token ${SENTINEL}` }] }],
      SessionStart: [{ hooks: [{ type: 'command', command: 'node scripts/start.js' }] }],
    },
  }));
  write(plug, '.mcp.json', JSON.stringify({ mcpServers: { pm: { command: 'node', args: ['srv.js'], env: { X_TOKEN: SENTINEL } } } }));
  skill(path.join(plug, 'skills'), 'plug-skill');
  write(plug, 'scripts/h.js', 'console.log("hook");\n');

  skill(path.join(userHome, '.agents', 'skills'), 'agent-skill');

  write(systemDir, 'config.toml', 'approval_policy = "on-request"\n');
  write(systemDir, 'requirements.toml', 'allowed_approval_policies = ["on-request"]\n');
  write(systemDir, 'hooks.json', JSON.stringify({ hooks: { Stop: [{ hooks: [{ type: 'command', command: 'echo stop' }] }] } }));
  write(systemDir, 'rules/managed.rules', 'prefix_rule(pattern=["rm"], decision="forbidden")\n');
  skill(path.join(systemDir, 'skills'), 'sys-skill');

  fs.mkdirSync(path.join(project, '.git'), { recursive: true });
  write(project, 'AGENTS.override.md', '# Override\n');
  write(project, '.codex/config.toml', '[mcp_servers.projmcp]\ncommand = "node"\nargs = ["p.js"]\n');
  write(project, '.codex/hooks.json', JSON.stringify({ hooks: { PostToolUse: [{ hooks: [{ type: 'command', command: 'echo post' }] }] } }));
  write(project, '.codex/rules/proj.rules', 'prefix_rule(pattern=["npm", "test"])\n');
  skill(path.join(project, '.agents', 'skills'), 'proj-skill');
  write(projectDir, 'AGENTS.md', '# Sub agents\n');
  skill(path.join(projectDir, '.agents', 'skills'), 'sub-skill');

  // Trusted (non-current) project: its .codex layer executes; its instructions and skills are not listed.
  const other = path.join(base, 'other');
  write(other, '.codex/hooks.json', JSON.stringify({ hooks: { Stop: [{ hooks: [{ type: 'command', command: 'echo other' }] }] } }));
  write(other, '.codex/config.toml', "model_instructions_file = 'x.md'\n[mcp_servers.om]\ncommand = \"node\"\nargs = [\"om.js\"]\n");
  write(other, '.codex/x.md', '# x\n');
  write(other, '.codex/rules/o.rules', 'prefix_rule(pattern=["make"])\n');
  write(other, 'AGENTS.md', '# Other\n');
  skill(path.join(other, '.agents', 'skills'), 'other-skill');
  write(base, 'untrusted/.codex/hooks.json', JSON.stringify({ hooks: { Stop: [{ hooks: [{ type: 'command', command: 'echo u' }] }] } }));

  const home = { label: 'win', root: codexHome, userHome, systemDir };
  return { base, userHome, codexHome, systemDir, project, projectDir, plug, other, home };
}

/** Fake `\\wsl.localhost\` tree: Ubuntu/alice has a Codex home, Ubuntu/bob and Debian have none. */
export function buildWslTree(base) {
  const wslRoot = path.join(base, 'wsl');
  const alice = path.join(wslRoot, 'Ubuntu', 'home', 'alice');
  write(alice, '.codex/config.toml', [
    'approval_policy = "never"', 'sandbox_mode = "danger-full-access"', 'notify = ["node", "/home/alice/n.js"]',
    'model_instructions_file = "/home/alice/.codex/instr.md"', '',
    "[projects.'/home/alice/proj']", 'trust_level = "trusted"', '',
  ].join('\n'));
  write(alice, 'proj/.codex/hooks.json', JSON.stringify({ hooks: { Stop: [{ hooks: [{ type: 'command', command: 'echo wp' }] }] } }));
  write(alice, '.codex/AGENTS.md', '# WSL agents\n');
  write(alice, '.codex/instr.md', '# WSL model instructions\n');
  skill(path.join(alice, '.agents', 'skills'), 'wsl-skill');
  write(wslRoot, 'Ubuntu/etc/codex/hooks.json', JSON.stringify({ hooks: { Stop: [{ hooks: [{ type: 'command', command: 'echo s' }] }] } }));
  fs.mkdirSync(path.join(wslRoot, 'Ubuntu', 'home', 'bob'), { recursive: true });
  fs.mkdirSync(path.join(wslRoot, 'Debian'), { recursive: true });
  return { wslRoot, aliceCodex: path.join(alice, '.codex') };
}

/**
 * Fake %LOCALAPPDATA% with Windows Terminal settings (JSON with comments and trailing commas) naming WSL
 * profiles, plus a fake WSL root whose top level is NOT listed by the code under test (listRoot: false),
 * like the real `\\wsl.localhost\`.
 */
export function buildWslCandidates(base) {
  const localAppData = path.join(base, 'lad');
  write(localAppData, 'Packages/Microsoft.WindowsTerminal_8wekyb3d8bbwe/LocalState/settings.json', [
    '// Windows Terminal settings',
    '{',
    '  /* block comment with "quotes" */',
    '  "help": "see https://aka.ms/terminal // not a comment",',
    '  "profiles": {',
    '    "defaults": {},',
    '    "list": [',
    '      { "name": "Arch", "source": "Microsoft.WSL", }, // trailing comma',
    '      { "name": "cmd", "commandline": "cmd.exe" },',
    '      { "name": "..\\\\evil", "source": "Microsoft.WSL" },',
    '    ],',
    '  },',
    '}',
    '',
  ].join('\n'));
  write(localAppData, 'Packages/Microsoft.WindowsTerminalPreview_8wekyb3d8bbwe/LocalState/settings.json',
    JSON.stringify({ profiles: [{ name: 'Old', source: 'Windows.Terminal.Wsl' }] }));
  write(localAppData, 'Packages/Other.App_x/LocalState/settings.json', JSON.stringify({ profiles: [{ name: 'Nope', source: 'Microsoft.WSL' }] }));

  const wslRoot = path.join(base, 'wsl');
  const codexHome = (distro, user) => {
    write(wslRoot, `${distro}/home/${user}/.codex/AGENTS.md`, '# a\n');
    return path.join(wslRoot, distro, 'home', user, '.codex');
  };
  const roots = {
    arch: codexHome('Arch', 'dave'), old: codexHome('Old', 'erin'), debian: codexHome('Debian', 'carol'),
    custom: codexHome('Custom', 'frank'), cmd: codexHome('cmd', 'x'), nope: codexHome('Nope', 'y'),
  };
  return { localAppData, wslRoot, roots };
}

/** Codex home whose config.toml does not parse. */
export function buildBrokenCodexHome(base) {
  const root = path.join(base, 'broken', '.codex');
  write(root, 'config.toml', `[mcp_servers.x]\ncommand = "node"\ncommand = "dup"\nkey = "${SENTINEL}"\n`);
  return root;
}
