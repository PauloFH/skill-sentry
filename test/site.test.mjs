import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Invariants of the static landing page in docs/ (served by GitHub Pages from /docs).
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DOCS = path.join(ROOT, 'docs');
const read = rel => fs.readFileSync(path.join(DOCS, rel), 'utf8');
const exists = rel => fs.existsSync(path.join(DOCS, rel));

const html = () => read('index.html');
const css = () => read('assets/site.css');
const js = () => read('assets/site.js');

/** Keys used in the markup: data-i18n="key" (inner HTML) and data-i18n-attr="attr:key[,attr:key]". */
function markupKeys(src) {
  const keys = [...src.matchAll(/\sdata-i18n="([^"]+)"/g)].map(m => m[1]);
  for (const m of src.matchAll(/\sdata-i18n-attr="([^"]+)"/g)) {
    for (const pair of m[1].split(',')) keys.push(pair.split(':')[1].trim());
  }
  return keys;
}

function dictionary(src) {
  const m = /<script type="application\/json" id="i18n">([\s\S]*?)<\/script>/.exec(src);
  assert.ok(m, 'index.html carries the translations in <script type="application/json" id="i18n">');
  return JSON.parse(m[1]);
}

test('page exists with title, viewport and English as the document language', () => {
  assert.ok(exists('index.html'), 'docs/index.html');
  const src = html();
  assert.match(src, /^<!doctype html>/i);
  assert.match(src, /<html lang="en"[\s>]/);
  assert.match(src, /<title[^>]*>[^<]{10,}<\/title>/);
  assert.match(src, /<meta name="viewport" content="width=device-width, initial-scale=1"/);
  assert.match(src, /<meta name="description" content="[^"]{40,}"/);
  assert.ok(exists('.nojekyll'), 'docs/.nojekyll keeps GitHub Pages from running Jekyll');
});

test('no third-party resource is loaded by the page, its CSS or its JS', () => {
  const external = /(?:https?:)?\/\//.source;
  const htmlRules = [
    new RegExp(`<script[^>]*\\ssrc=["']?${external}`, 'i'),
    new RegExp(`<link[^>]*\\shref=["']?${external}`, 'i'),
    new RegExp(`<(?:img|source|video|audio|embed|object|track)[^>]*\\s(?:src|srcset|data)=["']?${external}`, 'i'),
    /<iframe/i,
    /<form/i,
  ];
  const cssRules = [/@import/i, new RegExp(`url\\(\\s*["']?${external}`, 'i')];
  const src = html();
  for (const r of htmlRules) assert.doesNotMatch(src, r, `index.html: ${r}`);
  for (const r of cssRules) assert.doesNotMatch(src, r, `index.html inline style: ${r}`);
  for (const r of cssRules) assert.doesNotMatch(css(), r, `site.css: ${r}`);
  const script = js();
  assert.doesNotMatch(script, /https?:\/\//, 'site.js contains no URL');
  assert.doesNotMatch(script, /\bfetch\s*\(|XMLHttpRequest|WebSocket|sendBeacon|EventSource|\bimport\s*\(/, 'site.js makes no request');
  assert.doesNotMatch(src, /<script(?![^>]*type="application\/json")(?![^>]*src="assets\/site\.js")[^>]*>/i, 'only site.js and the JSON block are scripts');
});

test('asset paths are relative and point to files that exist', () => {
  const src = html();
  assert.doesNotMatch(src, /\s(?:src|href)=["']\/(?!\/)/, 'no root-absolute src/href (breaks the /skill-sentry/ subpath and file://)');
  assert.doesNotMatch(css(), /url\(\s*["']?\//, 'no root-absolute url() in site.css');
  const refs = [...src.matchAll(/\s(?:src|href)="([^"#][^"]*)"/g)].map(m => m[1])
    .filter(u => !/^(?:[a-z]+:|\/\/)/i.test(u));
  assert.ok(refs.includes('assets/site.css') && refs.includes('assets/site.js'), `local refs: ${refs.join(', ')}`);
  for (const r of refs) assert.ok(exists(r), `referenced file exists: ${r}`);
  for (const m of css().matchAll(/url\(\s*["']?([^"')]+)/g)) {
    assert.ok(fs.existsSync(path.join(DOCS, 'assets', m[1])), `site.css url exists: ${m[1]}`);
  }
  for (const m of src.matchAll(/\shref="#([^"]+)"/g)) {
    assert.match(src, new RegExp(`\\sid="${m[1]}"`), `in-page link target exists: #${m[1]}`);
  }
});

test('install commands appear verbatim', () => {
  const src = html();
  assert.ok(src.includes('/plugin marketplace add PauloFH/skill-sentry'));
  assert.ok(src.includes('/plugin install skill-sentry@skill-sentry'));
});

test('the nine sections exist', () => {
  const src = html();
  for (const id of ['hero', 'why', 'what', 'how', 'codex', 'tested', 'limits', 'install', 'footer']) {
    assert.match(src, new RegExp(`\\sid="${id}"`), `section #${id}`);
  }
});

test('the Codex section documents install, the hook trust step, the tiers and the main limits', () => {
  const src = html();
  const m = /<section id="codex"[\s\S]*?<\/section>/.exec(src);
  assert.ok(m, 'a real #codex section, not just a mention');
  const sec = m[0];
  assert.ok(sec.includes('codex plugin marketplace add PauloFH/skill-sentry'));
  assert.ok(sec.includes('codex plugin add skill-sentry@skill-sentry'));
  assert.match(sec, /<code>\/hooks<\/code>/, 'the /hooks trust step');
  assert.equal((sec.match(/class="pill-sub"/g) ?? []).length, 5, 'one table row per guard tier');
  assert.match(sec, /No “ask”/);
  assert.match(sec, /fails open/i);
  assert.match(sec, /recommend-only/);
  assert.match(sec, /apply_patch/);
  // The trust-bypass flag is never written with its leading dashes: skill-sentry's own audit flags that form.
  assert.doesNotMatch(src, new RegExp(['-', '-dangerously-bypass-hook-trust'].join('')));
  assert.match(src, /<a href="#codex"/, 'the nav links to the Codex section');
  assert.match(dictionary(src).pt['codex.title'], /Codex/);
});

test('English copy lives in the markup, not in JavaScript', () => {
  const src = html();
  assert.ok(src.includes('Your plugins run with your privileges.'), 'hero headline in the HTML');
  // Every translatable element ships non-empty English content, so the page reads fine without JS.
  for (const m of src.matchAll(/<(\w+)[^>]*\sdata-i18n="([^"]+)"[^>]*>([\s\S]*?)<\/\1>/g)) {
    assert.ok(m[3].replace(/<[^>]*>/g, '').trim().length > 0, `English content for ${m[2]}`);
  }
  for (const m of src.matchAll(/<[^>]*\sdata-i18n-attr="([^"]+)"[^>]*>/g)) {
    for (const pair of m[1].split(',')) {
      const attr = pair.split(':')[0].trim();
      assert.match(m[0], new RegExp(`\\s${attr}="[^"]+"`), `English ${attr} for ${pair}`);
    }
  }
});

test('every translatable key has a Portuguese entry and there are no orphans', () => {
  const src = html();
  const dict = dictionary(src);
  assert.deepEqual(Object.keys(dict), ['pt'], 'English comes from the markup; the dictionary holds Portuguese only');
  const keys = markupKeys(src);
  const unique = [...new Set(keys)];
  assert.ok(unique.length > 50, `found ${unique.length} keys`);
  const pt = Object.keys(dict.pt);
  assert.deepEqual([...pt].sort(), unique.sort(), 'Portuguese key set equals the English (markup) key set');
  for (const [k, v] of Object.entries(dict.pt)) {
    assert.equal(typeof v, 'string', k);
    assert.ok(v.trim().length > 0, `non-empty pt: ${k}`);
  }
  assert.ok(dict.pt['hero.title'].includes('privilégios'), 'pt hero headline');
  assert.ok(js().includes('ss-lang'), 'language choice stored under ss-lang');
});

test('page files carry no malware-signature literals', () => {
  // Built from fragments so this test file itself carries no signature strings.
  const words = [['xm', 'rig'], ['cpu', 'miner'], ['nice', 'hash'], ['strat', 'um+tcp'], ['strat', 'um+ssl'], ['Download', 'String'], ['coin', 'hive']]
    .map(p => p.join('').toLowerCase());
  const pipeToShell = new RegExp(['(?:cu', 'rl|wg', 'et)\\b[^\\n|]*\\|\\s*(?:sudo\\s+)?(?:ba|z)?sh\\b'].join(''), 'i');
  const iexDownload = new RegExp(['i', 'ex\\s*\\(?\\s*\\(?\\s*new-object'].join(''), 'i');
  for (const [name, text] of [['index.html', html()], ['site.css', css()], ['site.js', js()]]) {
    const lower = text.toLowerCase();
    for (const w of words) assert.ok(!lower.includes(w), `${name} contains a forbidden literal (${w.length} chars)`);
    assert.doesNotMatch(text, pipeToShell, `${name}: download piped to a shell`);
    assert.doesNotMatch(text, iexDownload, `${name}: PowerShell download-and-run`);
  }
});

test('links opening a new tab use rel=noopener', () => {
  for (const m of html().matchAll(/<a\b[^>]*>/g)) {
    if (!/\starget="_blank"/.test(m[0])) continue;
    assert.match(m[0], /\srel="[^"]*\bnoopener\b[^"]*"/, m[0]);
  }
});

test('self-hosted Inter font and its license are present', () => {
  const font = path.join(DOCS, 'assets', 'fonts', 'inter-latin-wght-normal.woff2');
  assert.ok(fs.statSync(font).size > 20 * 1024, 'font larger than 20 KB');
  assert.equal(fs.readFileSync(font).subarray(0, 4).toString('latin1'), 'wOF2');
  assert.match(fs.readFileSync(path.join(DOCS, 'assets', 'fonts', 'OFL.txt'), 'utf8'), /SIL Open Font License/);
  assert.match(css(), /url\(["']?fonts\/inter-latin-wght-normal\.woff2/);
});
