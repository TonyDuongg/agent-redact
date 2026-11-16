#!/usr/bin/env node
/*
 * Coverage report: which credential formats known to gitleaks and trufflehog agent-redact detects.
 *
 *   node scripts/coverage-report.mjs [--out benchmarks/coverage.md]
 *   node scripts/coverage-report.mjs --gitleaks gitleaks.toml --trufflehog detector_type.proto
 *
 * Inputs are pinned in benchmarks/coverage-map.json (repository, commit and sha256). They are
 * downloaded as text and parsed with regular expressions; nothing downloaded is executed.
 * A mismatching sha256, an unknown rule or detector name in the map, or a pattern missing from
 * the map is an error (exit 2), so the mapping cannot drift silently.
 */
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

/**
 * Rule ids of a gitleaks config: the `id` of every [[rules]] table. Ids are plain names
 * ([A-Za-z0-9._-]); anything else is skipped so it cannot inject Markdown into the report.
 */
export function parseGitleaksRules(toml) {
  const ids = [];
  let inRule = false;
  for (const line of toml.split(/\r?\n/)) {
    if (/^[ \t]*\[/.test(line)) {
      inRule = line.trim() === '[[rules]]';
      continue;
    }
    const id = inRule && /^[ \t]*id[ \t]*=[ \t]*"([A-Za-z0-9._-]+)"[ \t]*$/.exec(line);
    if (id) {
      ids.push(id[1]);
      inRule = false;
    }
  }
  return ids;
}

/** Members of trufflehog's `enum DetectorType`, with their deprecated flag */
export function parseTrufflehogTypes(proto) {
  const start = proto.search(/enum\s+DetectorType\s*\{/);
  if (start === -1) return [];
  const body = proto.slice(proto.indexOf('{', start) + 1, proto.indexOf('}', start));
  const out = [];
  // [ \t]* rather than \s*: with the m flag, \s* would rescan runs of blank lines from every line start
  for (const m of body.matchAll(/^[ \t]*([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*\d+[ \t]*(\[[^\]\n]*\])?[ \t]*;/gm)) {
    out.push({ name: m[1], deprecated: /deprecated\s*=\s*true/.test(m[2] ?? '') });
  }
  return out;
}

const norm = (s) => s.toLowerCase().replace(/[^a-z0-9]/g, '');
const pct = (a, b) => (b === 0 ? '0' : ((100 * a) / b).toFixed(1));

/**
 * Provider of a gitleaks rule id, matched against trufflehog names: the shortest run of leading
 * id segments that equals a trufflehog type or prefixes one (4+ characters), so that
 * "cloudflare-api-key" and "cloudflare-global-api-key" both group under "cloudflare" and
 * "new-relic-…" under "newrelic". Falls back to the first segment. Heuristic.
 */
export function gitleaksProvider(ruleId, truffleNorms, aliases = {}) {
  const seg = ruleId.split('-');
  seg[0] = aliases[seg[0]] ?? seg[0];
  for (let i = 1; i <= seg.length; i++) {
    const key = norm(seg.slice(0, i).join(''));
    if (truffleNorms.some((t) => t === key || (key.length >= 4 && t.startsWith(key)))) return key;
  }
  return norm(seg[0]);
}

const trufflehogOf = (provider, types) =>
  types.filter((t) => norm(t.name) === provider || (provider.length >= 4 && norm(t.name).startsWith(provider)));

/**
 * Builds the Markdown report. `patterns` is [{ id, name }] for every default and preset pattern.
 * Returns { markdown, errors, stats }.
 */
export function buildReport({ map, gitleaksRules, trufflehogTypes, patterns }) {
  const errors = [];
  const ruleSet = new Set(gitleaksRules);
  const typeByName = new Map(trufflehogTypes.map((t) => [t.name, t]));
  const active = trufflehogTypes.filter((t) => !t.deprecated);
  const activeNorms = active.map((t) => norm(t.name));
  const patternIds = new Set(patterns.map((p) => p.id));

  for (const id of patternIds) if (!map.patterns[id]) errors.push(`pattern "${id}" has no entry in coverage-map.json`);
  for (const [id, entry] of Object.entries(map.patterns)) {
    if (!patternIds.has(id)) errors.push(`coverage-map.json maps unknown pattern "${id}"`);
    for (const r of entry.gitleaks ?? []) if (!ruleSet.has(r)) errors.push(`${id}: gitleaks rule "${r}" does not exist`);
    for (const t of entry.trufflehog ?? []) {
      const type = typeByName.get(t);
      if (!type) errors.push(`${id}: trufflehog detector "${t}" does not exist`);
      else if (type.deprecated) errors.push(`${id}: trufflehog detector "${t}" is deprecated`);
    }
  }

  const coveredRules = new Set(Object.values(map.patterns).flatMap((e) => e.gitleaks ?? []));
  const coveredTypes = new Set(Object.values(map.patterns).flatMap((e) => e.trufflehog ?? []));
  const coveredRuleCount = gitleaksRules.filter((r) => coveredRules.has(r)).length;
  const coveredTypeCount = active.filter((t) => coveredTypes.has(t.name)).length;

  // Group gitleaks rules by provider
  const providers = new Map();
  for (const r of gitleaksRules) {
    const p = gitleaksProvider(r, activeNorms, map.providerAliases);
    if (!providers.has(p)) providers.set(p, []);
    providers.get(p).push(r);
  }
  const matchedTypes = new Set();
  const missingBoth = [];
  const missingGitleaksOnly = [];
  const partly = [];
  for (const [p, rules] of [...providers].sort((a, b) => a[0].localeCompare(b[0]))) {
    const types = trufflehogOf(p, active);
    types.forEach((t) => matchedTypes.add(t.name));
    const covered = rules.filter((r) => coveredRules.has(r));
    const anyType = types.some((t) => coveredTypes.has(t.name));
    if (covered.length === 0 && !anyType) {
      if (types.length > 0) missingBoth.push({ p, rules, types });
      else missingGitleaksOnly.push(...rules);
    } else if (covered.length < rules.length) {
      partly.push({ p, covered, missing: rules.filter((r) => !coveredRules.has(r)) });
    }
  }
  const truffleOnly = active
    .filter((t) => !matchedTypes.has(t.name) && !coveredTypes.has(t.name))
    .map((t) => t.name)
    .sort((a, b) => a.localeCompare(b));

  const code = (xs) => (xs.length ? xs.map((x) => `\`${x}\``).join(', ') : '—');
  const gl = map.sources.gitleaks;
  const th = map.sources.trufflehog;
  const lines = [
    '# Coverage against gitleaks and trufflehog',
    '',
    '<!-- Generated by `node scripts/coverage-report.mjs --out benchmarks/coverage.md`. Do not edit by hand. -->',
    '',
    `Compared with **gitleaks ${gl.version}** (\`${gl.path}\` at \`${gl.commit.slice(0, 7)}\`) and **trufflehog ${th.version}** (\`${th.path}\` at \`${th.commit.slice(0, 7)}\`). Both files were downloaded as text and parsed; nothing was executed. The mapping is maintained by hand in [\`coverage-map.json\`](coverage-map.json).`,
    '',
    'A rule or detector counts as covered when an agent-redact pattern detects the same credential format. Coverage says nothing about verification: trufflehog can check keys against live APIs, agent-redact never contacts a provider.',
    '',
    '## Summary',
    '',
    '| Source | Total | Covered by agent-redact |',
    '| :--- | ---: | ---: |',
    `| gitleaks rules | ${gitleaksRules.length} | ${coveredRuleCount} (${pct(coveredRuleCount, gitleaksRules.length)}%) |`,
    `| trufflehog detector types (excluding ${trufflehogTypes.length - active.length} deprecated) | ${active.length} | ${coveredTypeCount} (${pct(coveredTypeCount, active.length)}%) |`,
    '',
    '## agent-redact patterns and their counterparts',
    '',
    '| agent-redact pattern | gitleaks rules | trufflehog detectors |',
    '| :--- | :--- | :--- |'
  ];
  for (const p of patterns) {
    const e = map.patterns[p.id] ?? {};
    lines.push(`| \`${p.id}\` | ${code(e.gitleaks ?? [])} | ${code(e.trufflehog ?? [])} |`);
  }
  lines.push(
    '',
    '## Missing providers known to both scanners',
    '',
    `${missingBoth.length} providers. Provider names are matched heuristically (leading segments of the gitleaks rule id against trufflehog type names), so a few pairings may be loose.`,
    '',
    '| Provider | gitleaks rules | trufflehog detectors |',
    '| :--- | :--- | :--- |',
    ...missingBoth.map(({ p, rules, types }) => `| ${p} | ${code(rules)} | ${code(types.map((t) => t.name))} |`),
    '',
    '## Partly covered providers',
    '',
    '| Provider | Covered gitleaks rules | Missing gitleaks rules |',
    '| :--- | :--- | :--- |',
    ...partly.map(({ p, covered, missing }) => `| ${p} | ${code(covered)} | ${code(missing)} |`),
    '',
    '## Missing, gitleaks only',
    '',
    `${missingGitleaksOnly.length} rules: ${code(missingGitleaksOnly)}`,
    '',
    '## Missing, trufflehog only',
    '',
    `${truffleOnly.length} detector types without a gitleaks counterpart.`,
    '',
    '<details><summary>List</summary>',
    '',
    truffleOnly.join(', '),
    '',
    '</details>',
    ''
  );
  return {
    markdown: lines.join('\n'),
    errors,
    stats: {
      gitleaksRules: gitleaksRules.length,
      gitleaksCovered: coveredRuleCount,
      trufflehogTypes: active.length,
      trufflehogCovered: coveredTypeCount,
      missingBoth: missingBoth.length
    }
  };
}

async function loadSource(source, localPath) {
  let text;
  if (localPath) {
    text = readFileSync(localPath, 'utf-8');
  } else {
    const url = `https://raw.githubusercontent.com/${source.repo}/${source.commit}/${source.path}`;
    const res = await fetch(url, { signal: AbortSignal.timeout(30_000) });
    if (!res.ok) throw new Error(`GET ${url}: HTTP ${res.status}`);
    text = await res.text();
  }
  const sha = createHash('sha256').update(text, 'utf-8').digest('hex');
  if (sha !== source.sha256) {
    throw new Error(`${source.repo} ${source.path}: sha256 ${sha} does not match the pinned ${source.sha256}`);
  }
  return text;
}

async function main(argv) {
  const opt = { gitleaks: undefined, trufflehog: undefined, out: undefined };
  for (let i = 0; i < argv.length; i++) {
    const key = argv[i]?.replace(/^--/, '');
    if (!(key in opt) || argv[i + 1] === undefined) {
      console.error('Usage: node scripts/coverage-report.mjs [--gitleaks <file>] [--trufflehog <file>] [--out <file>]');
      return 2;
    }
    opt[key] = argv[++i];
  }
  const root = join(dirname(fileURLToPath(import.meta.url)), '..');
  const entry = join(root, 'dist', 'index.js');
  if (!existsSync(entry)) {
    console.error('dist/index.js not found: run `npm run build` first.');
    return 2;
  }
  const { DEFAULT_PATTERNS, PATTERN_PRESETS } = await import(pathToFileURL(entry).href);
  const patterns = [...DEFAULT_PATTERNS, ...Object.values(PATTERN_PRESETS).flat()].map((p) => ({ id: p.id, name: p.name }));
  const map = JSON.parse(readFileSync(join(root, 'benchmarks', 'coverage-map.json'), 'utf-8'));

  let gitleaksText;
  let trufflehogText;
  try {
    gitleaksText = await loadSource(map.sources.gitleaks, opt.gitleaks);
    trufflehogText = await loadSource(map.sources.trufflehog, opt.trufflehog);
  } catch (err) {
    console.error(String(err instanceof Error ? err.message : err));
    return 2;
  }
  const report = buildReport({
    map,
    gitleaksRules: parseGitleaksRules(gitleaksText),
    trufflehogTypes: parseTrufflehogTypes(trufflehogText),
    patterns
  });
  if (report.errors.length > 0) {
    for (const e of report.errors) console.error(`error: ${e}`);
    return 2;
  }
  if (opt.out) {
    writeFileSync(opt.out, report.markdown);
    const s = report.stats;
    console.log(
      `Wrote ${opt.out}: gitleaks ${s.gitleaksCovered}/${s.gitleaksRules} rules, trufflehog ${s.trufflehogCovered}/${s.trufflehogTypes} detector types, ${s.missingBoth} providers missing from both.`
    );
  } else {
    process.stdout.write(report.markdown);
  }
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = await main(process.argv.slice(2));
}
