import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseRules } from '../skills/audit/scripts/lib/codexrules.mjs';

test('pwsh allow rule', () => {
  const r = parseRules('prefix_rule(pattern=["pwsh", "-NoProfile", "-Command"], decision="allow")\n');
  assert.deepEqual(r.rules, [{ pattern: ['pwsh', '-NoProfile', '-Command'], decision: 'allow', line: 1 }]);
  assert.deepEqual(r.unparsed, []);
});

test('Windows path pattern element', () => {
  const r = parseRules('prefix_rule(pattern=["C:\\\\Program Files\\\\PowerShell\\\\7\\\\pwsh.exe", "-NoProfile"], decision="allow")');
  assert.equal(r.rules[0].pattern[0], 'C:\\Program Files\\PowerShell\\7\\pwsh.exe');
});

test('decision defaults to allow; prompt/forbidden kept; justification', () => {
  const r = parseRules(
    'prefix_rule(pattern=["git"])\nprefix_rule(pattern=["rm"], decision="forbidden", justification="no \\"rm\\"")\nprefix_rule(pattern=["curl"], decision="prompt")\n'
  );
  assert.deepEqual(r.rules.map((x) => x.decision), ['allow', 'forbidden', 'prompt']);
  assert.equal(r.rules[1].justification, 'no "rm"');
  assert.equal('justification' in r.rules[0], false);
  assert.deepEqual(r.rules.map((x) => x.line), [1, 2, 3]);
});

test('multi-line call, comments, match/not_match ignored, line = call start', () => {
  const text = [
    '# header (prefix_rule(pattern=["fake"]) in a comment)',
    '',
    'prefix_rule(',
    '    pattern = ["git", "status"],  # trailing # comment',
    '    decision = "allow",',
    '    match = [["git", "status"], "git status -s"],',
    '    not_match = ["git push"],',
    ')',
  ].join('\r\n');
  const r = parseRules(text);
  assert.equal(r.rules.length, 1);
  assert.equal(r.rules[0].line, 3);
  assert.deepEqual(r.rules[0].pattern, ['git', 'status']);
  assert.deepEqual(r.unparsed, []);
});

test('nested alternatives flatten to string or array element', () => {
  const r = parseRules('prefix_rule(pattern=["git", ["push", "pull"]], decision="prompt")');
  assert.deepEqual(r.rules[0].pattern, ['git', ['push', 'pull']]);
});

test('malformed calls go to unparsed, valid ones still parsed', () => {
  const text = [
    'prefix_rule(pattern=["a"], decision="allow")',
    'prefix_rule(pattern=["b"',
    'prefix_rule(decision="allow")',
    'prefix_rule(pattern=[x + y])',
    'prefix_rule(pattern=["c"], decision="bogus")',
    'prefix_rule(pattern=["d"], decision="forbidden")',
  ].join('\n');
  const r = parseRules(text);
  assert.deepEqual(r.rules.map((x) => x.pattern[0]), ['a', 'd']);
  assert.deepEqual(r.unparsed, [2, 3, 4, 5]);
});

test('prefix_rule inside a string is not a call; garbage and non-strings never throw', () => {
  assert.deepEqual(parseRules('x = "prefix_rule(pattern=[\\"a\\"])"').rules, []);
  for (const x of [undefined, null, 3, '\u0000(((', 'prefix_rule(', 'prefix_rule("']) {
    const r = parseRules(x);
    assert.ok(Array.isArray(r.rules) && Array.isArray(r.unparsed));
  }
  assert.deepEqual(parseRules('prefix_rule(').unparsed, [1]);
});

test('BOM tolerated', () => {
  assert.equal(parseRules('\uFEFFprefix_rule(pattern=["a"])').rules.length, 1);
});
