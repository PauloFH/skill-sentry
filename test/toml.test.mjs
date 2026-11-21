import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseToml } from '../skills/audit/scripts/lib/toml.mjs';

const ok = (text) => {
  const r = parseToml(text);
  assert.equal(r.ok, true, JSON.stringify(r));
  return r.value;
};

test('tables, dotted tables and quoted keys', () => {
  const v = ok('[a.b]\nx = 1\n[a."b.c"]\ny = "z"\n[plugins."omc@mkt"]\nenabled = true\n');
  assert.equal(v.a.b.x, 1);
  assert.equal(v.a['b.c'].y, 'z');
  assert.equal(v.plugins['omc@mkt'].enabled, true);
});

test('literal-quoted key with Windows path', () => {
  const v = ok("[projects.'C:\\Users\\x\\proj']\ntrust_level = \"trusted\"\n");
  assert.equal(v.projects['C:\\Users\\x\\proj'].trust_level, 'trusted');
});

test('dotted keys', () => {
  const v = ok('a.b = 1\na.c.d = "x"\n');
  assert.deepEqual(v, { a: { b: 1, c: { d: 'x' } } });
});

test('hooks arrays of tables with nested array of tables', () => {
  const v = ok(
    '[[hooks.PreToolUse]]\nmatcher = "Bash"\n[[hooks.PreToolUse.hooks]]\ntype = "command"\ncommand = "a"\n' +
      '[[hooks.PreToolUse.hooks]]\ncommand = "b"\n' +
      '[[hooks.PreToolUse]]\nmatcher = "x"\n[[hooks.PreToolUse.hooks]]\ncommand = "c"\n'
  );
  assert.equal(v.hooks.PreToolUse.length, 2);
  assert.equal(v.hooks.PreToolUse[0].matcher, 'Bash');
  assert.deepEqual(v.hooks.PreToolUse[0].hooks.map((h) => h.command), ['a', 'b']);
  assert.deepEqual(v.hooks.PreToolUse[1].hooks.map((h) => h.command), ['c']);
});

test('strings: basic escapes, literal, multiline', () => {
  const v = ok(
    'a = "l1\\nl2\\t\\"q\\" \\\\ \\u0041 \\U0001F600"\n' +
      "b = 'C:\\raw\\path'\n" +
      'c = """\nfirst\nsecond \\\n   joined"""\n' +
      "d = '''\nraw \\n line\nnext'''\n"
  );
  assert.equal(v.a, 'l1\nl2\t"q" \\ A \u{1F600}');
  assert.equal(v.b, 'C:\\raw\\path');
  assert.equal(v.c, 'first\nsecond joined');
  assert.equal(v.d, 'raw \\n line\nnext');
});

test('numbers, bools, dates', () => {
  const v = ok('i = 1_000\nn = -5\nf = 3.14\ne = 1e3\nh = 0xFF\no = 0o17\nb = 0b101\nt = true\nz = false\nd = 2024-01-02\ndt = 2024-01-02T03:04:05Z\n');
  assert.equal(v.i, 1000);
  assert.equal(v.n, -5);
  assert.equal(v.f, 3.14);
  assert.equal(v.e, 1000);
  assert.equal(v.h, 255);
  assert.equal(v.o, 15);
  assert.equal(v.b, 5);
  assert.equal(v.t, true);
  assert.equal(v.z, false);
  assert.equal(v.d, '2024-01-02');
  assert.equal(v.dt, '2024-01-02T03:04:05Z');
});

test('arrays: multi-line, trailing comma, comments, nested', () => {
  const v = ok('a = [\n  "x", # c1\n  "y",\n  # c2\n]\nb = [[1, 2], [3]]\nc = []\n');
  assert.deepEqual(v.a, ['x', 'y']);
  assert.deepEqual(v.b, [[1, 2], [3]]);
  assert.deepEqual(v.c, []);
});

test('inline tables, nested and dotted', () => {
  const v = ok('a = { x = 1, y = "two", z = { k = [1, 2] }, "q.r" = true }\nb = {}\n');
  assert.deepEqual(v.a, { x: 1, y: 'two', z: { k: [1, 2] }, 'q.r': true });
  assert.deepEqual(v.b, {});
});

test('comments after values, # inside strings preserved', () => {
  const v = ok('a = 1 # comment\nb = "has # hash" # c\n');
  assert.equal(v.a, 1);
  assert.equal(v.b, 'has # hash');
});

test('CRLF and BOM tolerated', () => {
  const v = ok('\uFEFF[a]\r\nx = 1\r\ny = """\r\nm1\r\nm2"""\r\n');
  assert.equal(v.a.x, 1);
  assert.equal(v.a.y, 'm1\nm2');
});

test('real Codex config shapes (synthetic)', () => {
  const v = ok(
    'approval_policy = "never"\nsandbox_mode = "danger-full-access"\nnotify = ["node", "C:\\\\x\\\\notify.js"]\n' +
      '[features]\nhooks = true\n' +
      '[marketplaces.omc]\nsource_type = "git"\nsource = "https://example.invalid/r.git"\nlast_revision = "abc"\n' +
      '[plugins."omc@omc"]\nenabled = true\n' +
      '[mcp_servers.pad]\ncommand = "npx"\nargs = ["-y", "pad"]\ndefault_tools_approval_mode = "approve"\n' +
      '[mcp_servers.pad.env]\nK = "v"\n' +
      '[shell_environment_policy.set]\nSOME_TOKEN = "REDACTED"\n' +
      '[hooks.state."omc@omc:hooks/hooks.json:pre_tool_use:0:0"]\ntrusted_hash = "sha256:aa"\nenabled = true\n'
  );
  assert.equal(v.approval_policy, 'never');
  assert.equal(v.notify[1], 'C:\\x\\notify.js');
  assert.equal(v.mcp_servers.pad.env.K, 'v');
  assert.equal(v.shell_environment_policy.set.SOME_TOKEN, 'REDACTED');
  assert.equal(v.hooks.state['omc@omc:hooks/hooks.json:pre_tool_use:0:0'].enabled, true);
});

test('duplicate key and redefined table fail with line', () => {
  let r = parseToml('a = 1\nb = 2\na = 3\n');
  assert.equal(r.ok, false);
  assert.equal(r.line, 3);
  assert.equal(typeof r.error, 'string');
  r = parseToml('[a]\nx = 1\n[b]\n[a]\ny = 2\n');
  assert.equal(r.ok, false);
  assert.equal(r.line, 4);
});

test('garbage yields ok:false with a line', () => {
  for (const bad of ['a = ', '= 1', '[unclosed\nx=1', 'a = "unterminated', 'a = [1, 2', 'a = {x=1', 'a b = 1', 'a = 1 2', '[[x]\n', 'a = @@@']) {
    const r = parseToml(bad);
    assert.equal(r.ok, false, bad);
    assert.equal(typeof r.line, 'number', bad);
  }
});

test('non-string input does not throw', () => {
  for (const x of [undefined, null, 42, {}]) {
    assert.equal(parseToml(x).ok, false);
  }
  assert.deepEqual(parseToml('').value, {});
});

test('prototype pollution keys are inert', () => {
  const r = parseToml('[__proto__]\npolluted = 1\n');
  assert.equal({}.polluted, undefined);
  assert.equal(typeof r.ok, 'boolean');
});

test('fuzz: truncated and garbled prefixes never throw', () => {
  const doc =
    "# c\nmodel = \"x\"\n[a.\"b.c\"]\nk = [1, 2,\n 3] # t\ni = { a = 1, b = [\"q\"] }\ns = \"\"\"\nml\\\n x\"\"\"\nl = '''\nraw'''\n[[hooks.PreToolUse]]\nm = \"Bash\"\n[[hooks.PreToolUse.hooks]]\nc = \"z\"\n[projects.'C:\\p']\nt = 2024-01-02T03:04:05Z\n";
  for (let i = 0; i <= doc.length; i++) {
    const r = parseToml(doc.slice(0, i));
    assert.equal(typeof r.ok, 'boolean');
    const g = doc.slice(0, i) + '\u0000"[{=\\' + doc.slice(i, i + 5);
    assert.equal(typeof parseToml(g).ok, 'boolean');
  }
});
