#!/usr/bin/env node
// skill-sentry harden helper.
//   node harden.mjs check                 -> JSON array of recommendations
//   node harden.mjs apply <id> [<id>...]  -> back up settings.json, merge the requested ids, print the backup path
// Env: SKILL_SENTRY_CLAUDE_HOME (default ~/.claude).
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { writeJsonAtomic } from './lib/datadir.mjs';

const RULES = {
  'ask-curl': { list: 'ask', rule: 'Bash(curl *)', title: 'Ask before running curl', why: 'curl can send local data to any server. A permission prompt makes every download or upload visible.' },
  'ask-wget': { list: 'ask', rule: 'Bash(wget *)', title: 'Ask before running wget', why: 'wget can fetch and save arbitrary remote content. A permission prompt makes every download visible.' },
  'deny-ssh-read': { list: 'deny', rule: 'Read(~/.ssh/**)', title: 'Deny reading SSH keys', why: 'Private keys in ~/.ssh are a prime target for credential theft by a malicious skill or hook.' },
  'deny-aws-read': { list: 'deny', rule: 'Read(~/.aws/**)', title: 'Deny reading AWS credentials', why: 'Cloud credentials in ~/.aws are a prime target for credential theft by a malicious skill or hook.' },
  'ask-env-read': { list: 'ask', rule: 'Read(**/.env)', title: 'Ask before reading .env files', why: '.env files usually hold API keys and tokens. A prompt makes any read of them visible.' },
};

const SKILL_SHELL = {
  id: 'disable-skill-shell',
  title: 'Disable shell execution inside skills',
  why: 'Sets disableSkillShellExecution so skills and custom commands cannot run inline shell lines. Warning: it also disables !`git status`-style lines in official and trusted plugins, which may then stop working as designed.',
};

const OFFICIAL_REPO = /^anthropics\//i;

function has(settings, list, rule) {
  const arr = settings?.permissions?.[list];
  return Array.isArray(arr) && arr.includes(rule);
}

function thirdParty(known) {
  if (!known || typeof known !== 'object') return [];
  return Object.keys(known).filter(name => {
    const src = known[name]?.source ?? {};
    const repo = src.repo ?? '';
    return !(src.source === 'github' && OFFICIAL_REPO.test(repo));
  });
}

/** @returns {{id:string,title:string,why:string,applicable:boolean,present:boolean}[]} */
export function checkHardening(settings, knownMarketplaces) {
  const s = settings && typeof settings === 'object' ? settings : {};
  const recs = [];
  for (const [id, r] of Object.entries(RULES)) {
    recs.push({ id, title: r.title, why: `${r.why} Adds "${r.rule}" to permissions.${r.list}.`, applicable: true, present: has(s, r.list, r.rule) });
  }
  recs.push({ ...SKILL_SHELL, applicable: true, present: s.disableSkillShellExecution === true });
  const tp = thirdParty(knownMarketplaces);
  recs.push({
    id: 'third-party-autoupdate',
    title: 'Review third-party marketplaces',
    why: tp.length
      ? `Third-party marketplaces can ship updated plugin code that you never reviewed: ${tp.join(', ')}. Disable auto-update for them in /plugin and re-audit after each update. Info only, nothing to apply.`
      : 'No third-party marketplaces found. Info only, nothing to apply.',
    applicable: false,
    present: tp.length === 0,
  });
  recs.push({
    id: 'managed-settings',
    title: 'Restrict marketplaces and hooks with managed settings',
    why: 'Organizations can set strictKnownMarketplaces and allowManagedHooksOnly in managed settings to block unknown marketplaces and user-defined hooks. These keys are only honored from managed settings, so skill-sentry does not apply them. Info only.',
    applicable: false,
    present: s.strictKnownMarketplaces !== undefined && s.allowManagedHooksOnly === true,
  });
  return recs;
}

/** Merge one recommendation id into settings (mutates). */
function applyOne(settings, id) {
  if (id === 'disable-skill-shell') { settings.disableSkillShellExecution = true; return; }
  const { list, rule } = RULES[id];
  if (!settings.permissions || typeof settings.permissions !== 'object' || Array.isArray(settings.permissions)) settings.permissions = {};
  if (!Array.isArray(settings.permissions[list])) settings.permissions[list] = [];
  if (!settings.permissions[list].includes(rule)) settings.permissions[list].push(rule);
}

function readSettings(file) {
  let text;
  try { text = fs.readFileSync(file, 'utf8'); } catch (e) {
    if (e.code === 'ENOENT') return { settings: {}, exists: false };
    throw new Error(`cannot read ${file}: ${e.message}`);
  }
  try {
    const v = JSON.parse(text.replace(/^﻿/, ''));
    if (!v || typeof v !== 'object' || Array.isArray(v)) throw new Error('not a JSON object');
    return { settings: v, exists: true };
  } catch (e) {
    throw new Error(`${file} is not valid JSON (${e.message}); fix it manually, nothing was changed`);
  }
}

function readKnownMarketplaces(claudeHome) {
  try {
    return JSON.parse(fs.readFileSync(path.join(claudeHome, 'plugins', 'known_marketplaces.json'), 'utf8').replace(/^﻿/, ''));
  } catch { return {}; }
}

function main(argv) {
  const claudeHome = path.resolve(process.env.SKILL_SENTRY_CLAUDE_HOME || path.join(os.homedir(), '.claude'));
  const file = path.join(claudeHome, 'settings.json');
  const [cmd, ...ids] = argv;
  const fail = msg => { process.stderr.write(`${msg}\nusage: node harden.mjs check | apply <id> [<id>...]\n`); process.exitCode = 2; };
  try {
    if (cmd === 'check') {
      const { settings } = readSettings(file);
      process.stdout.write(JSON.stringify(checkHardening(settings, readKnownMarketplaces(claudeHome)), null, 2) + '\n');
    } else if (cmd === 'apply') {
      if (!ids.length) return fail('apply needs at least one id');
      const applicable = new Set(Object.keys(RULES).concat(SKILL_SHELL.id));
      const bad = ids.filter(i => !applicable.has(i));
      if (bad.length) return fail(`unknown or non-applicable id: ${bad.join(', ')}`);
      const { settings, exists } = readSettings(file);
      let backup = null;
      if (exists) {
        backup = `${file}.skill-sentry-${new Date().toISOString().replace(/[:.]/g, '-')}.bak`;
        fs.copyFileSync(file, backup);
      }
      for (const id of ids) applyOne(settings, id);
      writeJsonAtomic(file, settings);
      process.stdout.write(`${backup ?? '(no previous settings.json, no backup needed)'}\n`);
    } else {
      fail(cmd ? `unknown command: ${cmd}` : 'missing command');
    }
  } catch (e) {
    fail(e.message);
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main(process.argv.slice(2));
