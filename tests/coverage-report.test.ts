import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
// @ts-expect-error -- plain .mjs script without type declarations
import { parseGitleaksRules, parseTrufflehogTypes, gitleaksProvider, buildReport } from '../scripts/coverage-report.mjs';
import { DEFAULT_PATTERNS, PATTERN_PRESETS } from '../src/index.js';

const root = process.cwd();
const map = JSON.parse(readFileSync(join(root, 'benchmarks', 'coverage-map.json'), 'utf-8'));
const allPatterns = [...DEFAULT_PATTERNS, ...Object.values(PATTERN_PRESETS).flat()].map((p) => ({ id: p.id, name: p.name }));

const TOML = [
  'title = "gitleaks config"',
  '[extend]',
  'useDefault = false',
  '[[rules]]',
  'id = "acme-api-key"',
  'regex = \'\'\'acme_[a-z]{20}\'\'\'',
  '[[rules.allowlists]]',
  'regexes = [\'\'\'id = "not-a-rule"\'\'\']',
  '[[rules]]',
  'id = "acme-cloud-token"',
  '[[rules]]',
  'id = "new-relic-user-api-key"',
  '[[rules]]',
  'id = "zeta-token"'
].join('\n');

const PROTO = [
  'syntax = "proto3";',
  'enum DecoderType {',
  '  PLAIN = 1;',
  '}',
  'enum DetectorType {',
  '  Acme = 0;',
  '  AcmeCloudToken = 1; // comment',
  '  NewRelicUserKey = 2;',
  '  OldThing = 3 [deprecated = true];',
  '  Omega = 4;',
  '}'
].join('\n');

describe('scripts/coverage-report.mjs', () => {
  it('parses gitleaks rule ids (only [[rules]] tables)', () => {
    expect(parseGitleaksRules(TOML)).toEqual(['acme-api-key', 'acme-cloud-token', 'new-relic-user-api-key', 'zeta-token']);
  });

  it('parses trufflehog DetectorType members with the deprecated flag', () => {
    expect(parseTrufflehogTypes(PROTO)).toEqual([
      { name: 'Acme', deprecated: false },
      { name: 'AcmeCloudToken', deprecated: false },
      { name: 'NewRelicUserKey', deprecated: false },
      { name: 'OldThing', deprecated: true },
      { name: 'Omega', deprecated: false }
    ]);
  });

  it('parses in linear time and ignores ids that are not plain names (no Markdown injection)', () => {
    const t0 = performance.now();
    // Blank lines that lead to no match: a multi-line \s* rescanned them from every line start
    parseTrufflehogTypes(`enum DetectorType {\n  Acme = 0;\n${'\n'.repeat(40_000)}}`);
    parseGitleaksRules(`[[rules]]\n${'   \n'.repeat(40_000)}id = "acme-api-key"`);
    expect(performance.now() - t0).toBeLessThan(300);
    expect(parseGitleaksRules('[[rules]]\nid = "evil|<img src=x>"\n[[rules]]\nid = "ok-rule"')).toEqual(['ok-rule']);
  });

  it('groups gitleaks rules by the shortest id prefix that names a trufflehog provider', () => {
    const norms = ['acme', 'acmecloudtoken', 'newrelicuserkey', 'cloudflareapitoken', 'cloudflareglobalapikey'];
    expect(gitleaksProvider('acme-cloud-token', norms)).toBe('acme');
    expect(gitleaksProvider('new-relic-user-api-key', norms)).toBe('newrelic');
    expect(gitleaksProvider('cloudflare-global-api-key', norms)).toBe('cloudflare');
    expect(gitleaksProvider('zeta-token', norms)).toBe('zeta');
    expect(gitleaksProvider('1password-secret-key', ['onepasswordx'], { '1password': 'onepassword' })).toBe('onepassword');
  });

  it('builds the report and reports drift in the mapping as errors', () => {
    const fixtureMap = {
      sources: map.sources,
      providerAliases: {},
      patterns: { 'acme-key': { gitleaks: ['acme-api-key', 'no-such-rule'], trufflehog: ['Acme', 'OldThing', 'Nope'] } }
    };
    const report = buildReport({
      map: fixtureMap,
      gitleaksRules: parseGitleaksRules(TOML),
      trufflehogTypes: parseTrufflehogTypes(PROTO),
      patterns: [{ id: 'acme-key', name: 'Acme' }, { id: 'unmapped', name: 'U' }]
    });
    expect(report.errors).toEqual([
      'pattern "unmapped" has no entry in coverage-map.json',
      'acme-key: gitleaks rule "no-such-rule" does not exist',
      'acme-key: trufflehog detector "OldThing" is deprecated',
      'acme-key: trufflehog detector "Nope" does not exist'
    ]);
    expect(report.stats).toMatchObject({ gitleaksRules: 4, gitleaksCovered: 1, trufflehogTypes: 4, trufflehogCovered: 1 });
    expect(report.markdown).toContain('| acme | `acme-api-key` | `acme-cloud-token` |'); // partly covered
    expect(report.markdown).toContain('| newrelic | `new-relic-user-api-key` | `NewRelicUserKey` |'); // missing in both
    expect(report.markdown).toMatch(/1 rules: `zeta-token`/);
    expect(report.markdown).toMatch(/1 detector types without a gitleaks counterpart[\s\S]*Omega/);
  });

  it('maps every default and preset pattern, and nothing else', () => {
    const ids = allPatterns.map((p) => p.id).sort();
    expect(Object.keys(map.patterns).sort()).toEqual(ids);
  });

  it('pins both sources by commit and sha256', () => {
    for (const s of Object.values(map.sources) as Array<Record<string, string>>) {
      expect(s.commit).toMatch(/^[0-9a-f]{40}$/);
      expect(s.sha256).toMatch(/^[0-9a-f]{64}$/);
      expect(s.repo).toMatch(/^[\w.-]+\/[\w.-]+$/);
    }
  });

  it('the committed report lists every mapped pattern', () => {
    const md = readFileSync(join(root, 'benchmarks', 'coverage.md'), 'utf-8');
    for (const p of allPatterns) expect(md).toContain(`| \`${p.id}\` |`);
  });
});
