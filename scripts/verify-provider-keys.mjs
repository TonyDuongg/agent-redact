#!/usr/bin/env node
/**
 * Check REAL AI provider keys against the built patterns in dist/, without ever printing them.
 *
 * Keys are read from environment variables only (never from arguments, files or stdin), so they
 * do not end up in shell history, process listings or the repository. The output is one line per
 * provider, "<provider>: PASS | FAIL | SKIPPED". Nothing derived from a key's content is printed.
 *
 *   npm run build
 *
 *   # PowerShell: read the key from the clipboard so it is never typed into history
 *   $env:GROQ_KEY = Get-Clipboard; node scripts/verify-provider-keys.mjs; Remove-Item Env:GROQ_KEY
 *
 *   # bash / zsh: read the key without echo
 *   read -rs GROQ_KEY && export GROQ_KEY && node scripts/verify-provider-keys.mjs; unset GROQ_KEY
 *
 * Options:
 *   --explain   add non-secret hints to FAIL lines: the reason, whether the prefix is the expected
 *               one, the length, and which character classes occur (A-Z a-z 0-9 _ - other).
 *
 * Exit code: 0 when nothing failed (PASS or SKIPPED), 1 when any provider failed, 2 on usage errors.
 */

import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

/** First variable that is set wins; the later names are the providers' usual SDK variables. */
const PROVIDERS = [
  { name: 'openrouter', patternId: 'openrouter-api-key', prefix: 'sk-or-v1-', env: ['OPENROUTER_KEY', 'OPENROUTER_API_KEY'] },
  { name: 'groq', patternId: 'groq-api-key', prefix: 'gsk_', env: ['GROQ_KEY', 'GROQ_API_KEY'] },
  { name: 'xai', patternId: 'xai-api-key', prefix: 'xai-', env: ['XAI_KEY', 'XAI_API_KEY'] },
  { name: 'perplexity', patternId: 'perplexity-api-key', prefix: 'pplx-', env: ['PERPLEXITY_KEY', 'PERPLEXITY_API_KEY'] },
  { name: 'replicate', patternId: 'replicate-api-token', prefix: 'r8_', env: ['REPLICATE_KEY', 'REPLICATE_API_TOKEN'] },
  // HF_TOKEN is usually a user token (hf_...), not an organization token, so it is not an alias here
  { name: 'huggingface-org', patternId: 'huggingface-org-token', prefix: 'api_org_', env: ['HF_ORG_KEY'] },
  { name: 'langsmith', patternId: 'langsmith-api-key', prefix: 'lsv2_', env: ['LANGSMITH_KEY', 'LANGSMITH_API_KEY', 'LANGCHAIN_API_KEY'] }
];

/** The key must be found, with its full span and the right pattern, in each of these settings. */
const CONTEXTS = [
  (k) => `API_KEY=${k}\n`, // .env line
  (k) => `{"apiKey": "${k}"}`, // JSON / config
  (k) => `Use ${k} for the request.`, // prose / logs
  (k) => `Authorization: Bearer ${k}` // HTTP header
];

const CLASSES = [
  ['A-Z', /[A-Z]/],
  ['a-z', /[a-z]/],
  ['0-9', /[0-9]/],
  ['_', /_/],
  ['-', /-/],
  ['other', /[^A-Za-z0-9_-]/]
];

const args = process.argv.slice(2);
const unknown = args.filter((a) => a !== '--explain');
if (unknown.length > 0) {
  console.error('Usage: node scripts/verify-provider-keys.mjs [--explain]   (keys come from environment variables)');
  process.exit(2);
}
const explain = args.includes('--explain');

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const entry = join(root, 'dist', 'index.js');
if (!existsSync(entry)) {
  console.error('dist/index.js not found: run `npm run build` first.');
  process.exit(2);
}
const { redact } = await import(pathToFileURL(entry).href);

/** Non-secret description of a key: prefix match, length and character classes only. */
function shape(key, prefix) {
  const prefixOk = key.startsWith(prefix);
  const body = prefixOk ? key.slice(prefix.length) : key;
  const classes = CLASSES.filter(([, re]) => re.test(body)).map(([label]) => label).join(' ');
  return prefixOk
    ? `prefix ok, ${body.length} chars after prefix, characters: ${classes}`
    : `unexpected prefix, ${body.length} chars, characters: ${classes}`;
}

/** Returns null on success, otherwise a reason that never contains key material. */
function check(key, patternId) {
  if (/\s/.test(key)) return 'contains whitespace';
  for (const context of CONTEXTS) {
    const text = context(key);
    const start = text.indexOf(key);
    const end = start + key.length;
    let res;
    try {
      res = redact(text);
    } catch {
      return 'redact() threw';
    }
    const overlapping = res.matches.filter((m) => m.startIndex < end && m.endIndex > start);
    const own = overlapping.find((m) => m.patternId === patternId);
    if (!own) {
      if (overlapping.length === 0) return 'not detected';
      return `detected as ${[...new Set(overlapping.map((m) => m.patternId))].join(', ')}`;
    }
    if (own.startIndex !== start || own.endIndex !== end || res.text.includes(key)) return 'partial match';
  }
  return null;
}

let found = 0;
let failed = 0;
for (const provider of PROVIDERS) {
  const variable = provider.env.find((name) => (process.env[name] ?? '').trim() !== '');
  if (!variable) {
    console.log(`${provider.name}: SKIPPED`);
    continue;
  }
  found++;
  const key = process.env[variable].trim();
  const reason = check(key, provider.patternId);
  if (reason === null) {
    console.log(`${provider.name}: PASS`);
  } else {
    failed++;
    console.log(explain ? `${provider.name}: FAIL (${reason}; ${shape(key, provider.prefix)})` : `${provider.name}: FAIL`);
  }
}

if (found === 0) {
  console.error(`No keys found in the environment. Set one of: ${PROVIDERS.map((p) => p.env[0]).join(', ')}`);
}
process.exitCode = failed > 0 ? 1 : 0;
