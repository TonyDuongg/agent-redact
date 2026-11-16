#!/usr/bin/env node
/*
 * Accuracy benchmark on SYNTHETIC, labelled data.
 *
 *   npm run bench:accuracy                 # print the Markdown table
 *   npm run bench:accuracy -- --write-readme  # also update the table in README.md
 *
 * Every token is generated at run time from a fixed seed, placed in env, JSON, YAML, code and
 * log contexts, and labelled with its exact span. Decoy documents hold realistic non-secrets
 * (hashes, ids, versions, placeholders, near-miss tokens). Precision and recall are computed
 * per pattern: a finding counts as correct only with the expected pattern id and the exact span.
 * Real-world text is messier, so treat the numbers as a regression baseline, not a promise.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const SEED = 20261116;
const REPS = 3; // values per template

/** Small deterministic PRNG (mulberry32) */
export function rng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const LOWER = 'abcdefghijklmnopqrstuvwxyz';
const DIGIT = '0123456789';
const ALNUM = UPPER + LOWER + DIGIT;
const HEX = '0123456789abcdef';
const URLSAFE = ALNUM + '-_';
const B64 = ALNUM + '+/';

function makeGen(r) {
  const pick = (abc) => abc[Math.floor(r() * abc.length)];
  const str = (n, abc = ALNUM) => Array.from({ length: n }, () => pick(abc)).join('');
  const int = (lo, hi) => lo + Math.floor(r() * (hi - lo + 1));
  const b64 = (s) => Buffer.from(s, 'utf-8').toString('base64');
  // A password-like value: letters, digits and a symbol, so every context pattern accepts it
  const password = () => str(int(4, 8), LOWER) + str(int(2, 4), DIGIT) + pick('!#%+') + str(int(3, 6), UPPER + LOWER);
  const luhnCard = () => {
    const d = [4, ...Array.from({ length: 14 }, () => int(0, 9))];
    let sum = 0;
    for (let i = 0; i < 15; i++) {
      let x = d[14 - i];
      if (i % 2 === 0) x = x * 2 > 9 ? x * 2 - 9 : x * 2;
      sum += x;
    }
    d.push((10 - (sum % 10)) % 10);
    const s = d.join('');
    return `${s.slice(0, 4)} ${s.slice(4, 8)} ${s.slice(8, 12)} ${s.slice(12)}`;
  };
  return { pick, str, int, b64, password, luhnCard };
}

/*
 * Templates: `S` marks the secret. Vendor tokens appear in all five contexts with a realistic key
 * name; context-aware patterns appear in the contexts they are designed for.
 */
const vendor = (key, make) => ({
  make,
  templates: [
    { format: 'env', t: `${key.toUpperCase()}=S` },
    { format: 'json', t: `{"service": "billing", "${key}": "S", "retries": 3}` },
    { format: 'yaml', t: `service: billing\n${key}: S\nretries: 3` },
    { format: 'code', t: `client = Client(${key}="S", timeout=30)` },
    { format: 'log', t: `2026-11-16T10:00:00Z DEBUG request authorized with S (attempt 1)` }
  ]
});

function specs(g) {
  const { str, int, b64, password, luhnCard, pick } = g;
  return {
    'anthropic-api-key': vendor('anthropic_api_key', () => ['sk', 'ant', 'api03', str(93, URLSAFE) + 'AA'].join('-')),
    'openai-api-key': vendor('openai_api_key', () => ['sk', 'proj', str(64, URLSAFE)].join('-')),
    'aws-access-key-id': vendor('aws_access_key_id', () => 'AKIA' + str(16, UPPER + DIGIT)),
    'aws-secret-access-key': {
      make: () => str(40, B64),
      templates: [
        { format: 'env', t: 'AWS_SECRET_ACCESS_KEY=S' },
        { format: 'json', t: '{"aws_secret_access_key": "S"}' },
        { format: 'yaml', t: 'aws_secret_access_key: S' },
        { format: 'code', t: 'aws_secret_access_key = "S"' },
        { format: 'log', t: 'config loaded aws_secret_access_key=S region=eu-west-1' }
      ]
    },
    'github-token': vendor('github_token', () => 'ghp_' + str(36)),
    'stripe-api-key': vendor('stripe_key', () => pick(['sk', 'rk']) + '_' + pick(['live', 'test']) + '_' + str(int(24, 99))),
    'jwt-token': vendor('id_token', () => ['eyJ' + str(20, URLSAFE), 'eyJ' + str(40, URLSAFE), str(43, URLSAFE)].join('.')),
    'private-key': {
      make: () => ['-----BEGIN ', 'PRIVATE KEY-----\n', str(64, B64), '\n', str(64, B64), '\n-----END ', 'PRIVATE KEY-----'].join(''),
      templates: [
        { format: 'code', t: 'KEY = """S"""' },
        { format: 'yaml', t: 'tls:\n  key: |\nS' },
        { format: 'log', t: 'loaded key material:\nS\nend' }
      ]
    },
    'google-api-key': vendor('google_api_key', () => 'AIza' + str(35, URLSAFE)),
    'slack-token': vendor('slack_token', () => ['xoxb', str(12, DIGIT), str(13, DIGIT), str(24)].join('-')),
    'database-url': {
      make: () => `${pick(['postgres', 'mysql', 'mongodb+srv', 'redis'])}://${str(6, LOWER)}:${str(12)}@db-${str(5, LOWER)}.internal:${int(1000, 9999)}/${str(5, LOWER)}`,
      templates: [
        { format: 'env', t: 'DATABASE_URL=S' },
        { format: 'json', t: '{"database": "S"}' },
        { format: 'yaml', t: 'database:\n  url: S' },
        { format: 'code', t: 'engine = create_engine("S")' },
        { format: 'log', t: 'connecting to S ...' }
      ]
    },
    'basic-auth-url': vendor('webhook_url', () => `https://${str(6, LOWER)}:${str(14)}@ci.${str(6, LOWER)}.example/hook`),
    'huggingface-token': vendor('hf_token', () => 'hf_' + str(34)),
    'gitlab-token': vendor('gitlab_token', () => 'glpat-' + str(20, URLSAFE)),
    'discord-token': vendor('discord_bot_token', () => [pick('MNO') + str(23, URLSAFE), str(6, URLSAFE), str(27, URLSAFE)].join('.')),
    'npm-token': vendor('npm_token', () => 'npm_' + str(36)),
    'sendgrid-api-key': vendor('sendgrid_api_key', () => ['SG', str(22, URLSAFE), str(43, URLSAFE)].join('.')),
    'twilio-account-sid': vendor('twilio_account_sid', () => 'AC' + str(32, HEX)),
    'supabase-key': vendor('supabase_key', () => 'sbp_' + str(40)),
    'telegram-bot-token': vendor('telegram_bot_token', () => str(9, DIGIT).replace(/^0/, '1') + ':' + str(35, URLSAFE)),
    'twilio-api-key': vendor('twilio_api_key', () => 'SK' + str(32, HEX)),
    'azure-storage-key': {
      make: () => 'AccountKey=' + str(86, B64) + '==',
      templates: [
        { format: 'env', t: 'AZURE_STORAGE_CONNECTION_STRING=DefaultEndpointsProtocol=https;AccountName=acct;S;EndpointSuffix=core.windows.net' },
        { format: 'json', t: '{"storage": "DefaultEndpointsProtocol=https;AccountName=acct;S"}' },
        { format: 'log', t: 'using connection string S' }
      ]
    },
    'gcp-oauth-client-secret': vendor('client_secret', () => 'GOCSPX-' + str(28, URLSAFE)),
    'digitalocean-token': vendor('do_token', () => 'dop_v1_' + str(64, HEX)),
    'mailgun-api-key': vendor('mailgun_api_key', () => 'key-' + str(32)),
    'openrouter-api-key': vendor('openrouter_api_key', () => ['sk', 'or', 'v1', str(64, HEX)].join('-')),
    'groq-api-key': vendor('groq_api_key', () => 'gsk_' + str(52)),
    'xai-api-key': vendor('xai_api_key', () => 'xai-' + str(80, ALNUM + '_')),
    'perplexity-api-key': vendor('perplexity_api_key', () => 'pplx-' + str(48)),
    'replicate-api-token': vendor('replicate_api_token', () => 'r8_' + str(37, URLSAFE).replace(/-$/, 'x')),
    'huggingface-org-token': vendor('hf_org_token', () => 'api_org_' + str(34)),
    'langsmith-api-key': vendor('langsmith_api_key', () => ['lsv2', 'pt', str(32, HEX), str(10, HEX)].join('_')),
    'npmrc-auth': {
      make: () => str(40, URLSAFE).replace(/^npm_/, 'tok_'),
      templates: [
        { format: 'npmrc', t: '//registry.npmjs.org/:_authToken=S\nalways-auth=true' },
        { format: 'npmrc', t: '@corp:registry=https://npm.corp.example/\n//npm.corp.example/:_authToken="S"' }
      ]
    },
    'netrc-password': {
      make: password,
      templates: [
        { format: 'netrc', t: 'machine api.example.com login deploy password S' },
        { format: 'netrc', t: 'machine git.example.com\n  login ci-bot\n  password S\n' }
      ]
    },
    'docker-config-auth': {
      make: () => b64(`${str(6, LOWER)}:${password()}`),
      templates: [{ format: 'json', t: '{\n  "auths": {\n    "ghcr.io": {\n      "auth": "S"\n    }\n  }\n}' }]
    },
    // Templates marked `limitation` are documented misses; they are kept so recall stays honest
    'dotenv-secret': {
      make: password,
      templates: [
        { format: 'env', t: 'DB_HOST=db\nDB_PASSWORD=S\nDB_PORT=5432' },
        { format: 'env', t: 'export JWT_SECRET="S"' },
        { format: 'yaml', t: 'environment:\n  - POSTGRES_PASSWORD=S' },
        { format: 'env', t: 'db_host=db\ndb_password=S', limitation: 'lowercase .env key' }
      ]
    },
    'quoted-secret-assignment': {
      make: password,
      templates: [
        { format: 'json', t: '{"client_id": "web", "client_secret": "S"}' },
        { format: 'yaml', t: 'smtp:\n  password: "S"' },
        { format: 'code', t: 'conn = connect(host="db", user="app", password="S")' },
        { format: 'code', t: "const cfg = { apiKey: 'S', region: 'eu' };" },
        {
          format: 'json',
          t: '{"passphrase": "S"}',
          make: () => [str(5, LOWER), str(6, LOWER), str(4, LOWER), str(7, LOWER)].join(' '),
          limitation: 'value with spaces'
        },
        { format: 'code', t: 'token = "S"', make: () => str(28, UPPER + LOWER), limitation: 'letters-only value' }
      ]
    },
    'kubernetes-secret': {
      make: () => b64(password()),
      templates: [
        { format: 'yaml', t: 'apiVersion: v1\nkind: Secret\nmetadata:\n  name: db\ntype: Opaque\ndata:\n  password: S\n' },
        { format: 'yaml', t: 'apiVersion: v1\ndata:\n  token: S\nkind: Secret\nmetadata:\n  name: api\n' },
        { format: 'json', t: '{"apiVersion": "v1", "data": {"tls.key": "S"}, "kind": "Secret"}', limitation: 'kubectl -o json' }
      ]
    },
    'email-address': {
      make: () => `${str(5, LOWER)}.${str(6, LOWER)}@${str(7, LOWER)}.${pick(['com', 'io', 'org'])}`,
      templates: [
        { format: 'log', t: 'INFO password reset sent to S' },
        { format: 'json', t: '{"user": {"email": "S", "role": "admin"}}' }
      ]
    },
    'ipv4-address': {
      make: () => [int(11, 223), int(0, 255), int(0, 255), int(1, 254)].join('.'),
      templates: [{ format: 'log', t: 'GET /health from S 200 3ms' }, { format: 'yaml', t: 'upstream:\n  host: S\n  port: 8080' }]
    },
    'ipv6-address': {
      make: () => Array.from({ length: 8 }, () => str(4, HEX)).join(':'),
      templates: [{ format: 'log', t: 'accepted connection from S port 443' }]
    },
    'phone-number': {
      make: () => pick([`+1 ${int(201, 989)} ${int(200, 999)} ${int(1000, 9999)}`, `09${int(1, 9)}${int(1, 9)} ${int(100, 999)} ${int(100, 999)}`]),
      templates: [{ format: 'log', t: 'SMS queued for S' }, { format: 'json', t: '{"contact": {"phone": "S"}}' }]
    },
    'us-ssn': {
      make: () => `${int(100, 665)}-${int(10, 99)}-${int(1000, 9999)}`,
      templates: [{ format: 'json', t: '{"applicant": {"ssn": "S"}}' }]
    },
    'credit-card': {
      make: luhnCard,
      templates: [{ format: 'log', t: 'charge attempt card=S amount=42.00' }, { format: 'json', t: '{"payment": {"card": "S"}}' }]
    }
  };
}

/** Realistic non-secret lines, generated with the same seed */
function decoys(g) {
  const { str, int } = g;
  const uuid = () => [str(8, HEX), str(4, HEX), '4' + str(3, HEX), '8' + str(3, HEX), str(12, HEX)].join('-');
  const lines = [];
  for (let i = 0; i < 20; i++) {
    lines.push(
      `commit ${str(40, HEX)}`,
      `"integrity": "sha512-${str(86, B64)}=="`,
      `image: ghcr.io/acme/app@sha256:${str(64, HEX)}`,
      `request_id=${uuid()} duration_ms=${int(1, 900)} status=200`,
      `2026-11-${String(int(1, 28)).padStart(2, '0')}T${String(int(0, 23)).padStart(2, '0')}:${String(int(0, 59)).padStart(2, '0')}:00Z INFO job ${int(1000, 99999)} done in ${int(1, 999)}ms`,
      `"version": "${int(0, 20)}.${int(0, 30)}.${int(0, 50)}", "build": ${int(1000, 9999)}`,
      `stripe request req_${str(14)} customer cus_${str(14)}`,
      `md5 ${str(32, HEX)}  dist/app.js`,
      `order ORD-${int(2020, 2026)}-${String(int(1, 999999)).padStart(6, '0')} total ${int(1, 999)}.${String(int(0, 99)).padStart(2, '0')} EUR`,
      // near misses: right prefix, wrong length or alphabet
      `token prefix ghp_${str(12)} is truncated`,
      `AKIA${str(8, UPPER)} (redacted in console)`,
      `sk-${str(8)} is not a full key`
    );
  }
  lines.push(
    'OPENAI_API_KEY=${OPENAI_API_KEY}',
    'DB_PASSWORD=<your-database-password>',
    'password: "{{ vault_db_password }}"',
    'api_key = os.environ["API_KEY"]',
    'const token = process.env.GITHUB_TOKEN;',
    'GITHUB_TOKEN=${{ secrets.GITHUB_TOKEN }}',
    '//registry.npmjs.org/:_authToken=${NPM_TOKEN}',
    'Use sk-ant-... or ghp_xxx as placeholders in docs.',
    'node v24.18.0 ; python 3.12.4 ; version 10.0.19045.1',
    'margin: 0 auto; color: #ff00aa; ratio 16:9; time 10:45:30',
    'kind: ConfigMap\ndata:\n  log_level: debug-verbose'
  );
  return lines;
}

/** Builds the labelled corpus: [{ format, text, labels: [{ id, start, end }] }] plus decoy documents */
export function buildCorpus(seed = SEED) {
  const r = rng(seed);
  const g = makeGen(r);
  const docs = [];
  const sp = specs(g);
  for (const [id, spec] of Object.entries(sp)) {
    for (const { format, t, make } of spec.templates) {
      for (let k = 0; k < REPS; k++) {
        const value = (make ?? spec.make)();
        // The marker is a lone uppercase S (never inside a word such as DB_HOST or Secret)
        const marker = /(?<![A-Za-z_])S(?![A-Za-z_])/.exec(t);
        if (!marker) throw new Error(`template for ${id} has no S marker: ${t}`);
        const at = marker.index;
        const text = t.slice(0, at) + value + t.slice(at + 1);
        docs.push({ format, text, labels: [{ id, start: at, end: at + value.length }] });
      }
    }
  }
  const decoyLines = decoys(g);
  for (let i = 0; i < decoyLines.length; i += 25) {
    docs.push({ format: 'decoy', text: decoyLines.slice(i, i + 25).join('\n'), labels: [] });
  }
  const limitations = Object.values(sp).flatMap((s) => s.templates.map((t) => t.limitation).filter(Boolean));
  return { docs, ids: Object.keys(sp), decoyLines: decoyLines.length, limitations };
}

/** Scores `redact` on the corpus. Returns per-pattern counts and totals. */
export function evaluate(redact, corpus) {
  const per = new Map(corpus.ids.map((id) => [id, { samples: 0, tp: 0, fp: 0, fn: 0, masked: 0 }]));
  const row = (id) => {
    if (!per.has(id)) per.set(id, { samples: 0, tp: 0, fp: 0, fn: 0, masked: 0 });
    return per.get(id);
  };
  let leaked = 0;
  for (const doc of corpus.docs) {
    const matches = redact(doc.text).matches;
    const found = new Set();
    for (const m of matches) {
      const i = doc.labels.findIndex((l) => l.id === m.patternId && l.start === m.startIndex && l.end === m.endIndex);
      if (i === -1) row(m.patternId).fp++;
      else {
        row(m.patternId).tp++;
        found.add(i);
      }
    }
    doc.labels.forEach((l, i) => {
      const r = row(l.id);
      r.samples++;
      if (!found.has(i)) r.fn++;
      const covered = new Uint8Array(l.end - l.start);
      for (const m of matches) {
        for (let p = Math.max(m.startIndex, l.start); p < Math.min(m.endIndex, l.end); p++) covered[p - l.start] = 1;
      }
      if (covered.every((c) => c === 1)) r.masked++;
      else leaked++;
    });
  }
  const totals = [...per.values()].reduce(
    (a, r) => ({ samples: a.samples + r.samples, tp: a.tp + r.tp, fp: a.fp + r.fp, fn: a.fn + r.fn }),
    { samples: 0, tp: 0, fp: 0, fn: 0 }
  );
  return { per, totals, leaked, docs: corpus.docs.length, decoyLines: corpus.decoyLines, limitations: corpus.limitations ?? [] };
}

const ratio = (a, b) => (b === 0 ? '—' : (a / b).toFixed(3));

export function toMarkdown(result) {
  const { per, totals, leaked, docs, decoyLines, limitations } = result;
  const lines = [
    `> **Synthetic data.** ${totals.samples} generated secrets in env, JSON, YAML, code and log contexts, plus ${decoyLines} decoy lines (hashes, ids, versions, placeholders, near-miss tokens), ${docs} documents in all, seed ${SEED}. A finding is correct only with the expected pattern id and the exact span. Real-world text is messier: use these numbers as a regression baseline, not a promise. Reproduce with \`npm run bench:accuracy\`.`,
    '',
    `The corpus deliberately includes documented limitations (${limitations.join(', ')}), so recall below 1 is expected there.`,
    '',
    `Overall: precision **${ratio(totals.tp, totals.tp + totals.fp)}**, recall **${ratio(totals.tp, totals.tp + totals.fn)}**, secrets left partly or fully visible: **${leaked}**.`,
    '',
    '| Pattern | Samples | TP | FP | FN | Precision | Recall |',
    '| :--- | ---: | ---: | ---: | ---: | ---: | ---: |'
  ];
  for (const [id, r] of per) {
    lines.push(`| \`${id}\` | ${r.samples} | ${r.tp} | ${r.fp} | ${r.fn} | ${ratio(r.tp, r.tp + r.fp)} | ${ratio(r.tp, r.tp + r.fn)} |`);
  }
  return lines.join('\n');
}

export const README_START = '<!-- accuracy:start -->';
export const README_END = '<!-- accuracy:end -->';

/** Replaces the block between the README markers; throws if they are missing */
export function replaceReadmeBlock(readme, table) {
  const a = readme.indexOf(README_START);
  const b = readme.indexOf(README_END);
  if (a === -1 || b === -1 || b < a) throw new Error('README accuracy markers not found');
  return `${readme.slice(0, a + README_START.length)}\n${table}\n${readme.slice(b)}`;
}

async function main(argv) {
  const root = join(dirname(fileURLToPath(import.meta.url)), '..');
  const { redact } = await import(pathToFileURL(join(root, 'dist', 'index.js')).href);
  const table = toMarkdown(evaluate((t) => redact(t), buildCorpus()));
  console.log(table);
  if (argv.includes('--write-readme')) {
    const path = join(root, 'README.md');
    writeFileSync(path, replaceReadmeBlock(readFileSync(path, 'utf-8'), table));
    console.error('README.md updated');
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main(process.argv.slice(2));
}
