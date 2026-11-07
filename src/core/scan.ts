import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { redact } from './engine.js';
import { DEFAULT_PATTERNS } from '../patterns/index.js';
import type { RedactOptions, SecretCategory, Severity } from './types.js';

/** A detected secret, without its value: safe to print, log, or upload as SARIF */
export interface Finding {
  /** Path relative to the scan root, with forward slashes */
  file: string;
  line: number;
  column: number;
  patternId: string;
  patternName: string;
  severity: Severity;
  category: SecretCategory;
  /** Stable id: sha256(patternId, file, value). The value itself is never stored */
  fingerprint: string;
}

export interface ScanContentOptions extends Omit<RedactOptions, 'reversible' | 'includeMatchedText'> {
  /** Honour `agent-redact-ignore` / `agent-redact-ignore-next-line` comments (default false) */
  respectInlineIgnore?: boolean;
  /** Fingerprints to suppress (from a baseline file) */
  baseline?: ReadonlySet<string>;
}

export interface ScanContentResult {
  findings: Finding[];
  suppressed: { inline: number; baseline: number };
}

const IGNORE_LINE_RE = /agent-redact-ignore(?!-next-line)/;
const IGNORE_NEXT_LINE_RE = /agent-redact-ignore-next-line/;

/** Offsets at which each line starts; used for O(log n) offset → line/column lookups */
export function lineStarts(text: string): number[] {
  const starts = [0];
  for (let i = text.indexOf('\n'); i !== -1; i = text.indexOf('\n', i + 1)) starts.push(i + 1);
  return starts;
}

/** 1-based line and column of `offset` */
export function positionAt(starts: readonly number[], offset: number): { line: number; column: number } {
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (starts[mid]! <= offset) lo = mid;
    else hi = mid - 1;
  }
  return { line: lo + 1, column: offset - starts[lo]! + 1 };
}

export function fingerprintOf(patternId: string, file: string, secret: string): string {
  return createHash('sha256').update(`${patternId}\0${file}\0${secret}`).digest('hex').slice(0, 32);
}

/**
 * Scans text and returns findings without secret values. Inline ignore comments are only
 * honoured when explicitly enabled: they are meant for audits of a repository you own,
 * never for redacting prompts (a prompt could otherwise opt itself out of redaction).
 */
export function scanContent(content: string, file: string, options: ScanContentOptions = {}): ScanContentResult {
  const { respectInlineIgnore = false, baseline, ...redactOptions } = options;
  const result = redact(content, { ...redactOptions, reversible: false, includeMatchedText: true });
  const starts = lineStarts(content);
  const lineText = (line: number) => content.slice(starts[line - 1], (starts[line] ?? content.length + 1) - 1);

  const findings: Finding[] = [];
  const suppressed = { inline: 0, baseline: 0 };
  for (const m of result.matches) {
    const { line, column } = positionAt(starts, m.startIndex);
    if (
      respectInlineIgnore &&
      (IGNORE_LINE_RE.test(lineText(line)) || (line > 1 && IGNORE_NEXT_LINE_RE.test(lineText(line - 1))))
    ) {
      suppressed.inline++;
      continue;
    }
    const fingerprint = fingerprintOf(m.patternId, file, m.matchedText ?? '');
    if (baseline?.has(fingerprint)) {
      suppressed.baseline++;
      continue;
    }
    findings.push({
      file,
      line,
      column,
      patternId: m.patternId,
      patternName: m.patternName,
      severity: m.severity,
      category: m.category,
      fingerprint
    });
  }
  return { findings, suppressed };
}

interface BaselineFile {
  tool: 'agent-redact';
  version: 1;
  findings: Array<Pick<Finding, 'fingerprint' | 'patternId' | 'file' | 'line'>>;
}

/** Writes accepted findings so later scans only report new ones. Contains no secret values. */
export function writeBaseline(path: string, findings: readonly Finding[]): void {
  const data: BaselineFile = {
    tool: 'agent-redact',
    version: 1,
    findings: findings.map(({ fingerprint, patternId, file, line }) => ({ fingerprint, patternId, file, line }))
  };
  writeFileSync(path, JSON.stringify(data, null, 2) + '\n', 'utf-8');
}

export function loadBaseline(path: string): Set<string> {
  const data = JSON.parse(readFileSync(path, 'utf-8')) as Partial<BaselineFile>;
  if (data?.tool !== 'agent-redact' || data.version !== 1 || !Array.isArray(data.findings)) {
    throw new Error(`Invalid baseline file: ${path}`);
  }
  return new Set(data.findings.map((f) => String(f.fingerprint)));
}

const SECURITY_SEVERITY: Record<Severity, string> = { critical: '9.5', high: '8.0', medium: '5.5', low: '3.0' };
const SARIF_LEVEL: Record<Severity, 'error' | 'warning' | 'note'> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note'
};

/** SARIF 2.1.0 report for GitHub code scanning and other SARIF consumers */
export function toSarif(findings: readonly Finding[], toolVersion: string): Record<string, unknown> {
  const descriptions = new Map(DEFAULT_PATTERNS.map((p) => [p.id, p.description]));
  const rules = new Map<string, Record<string, unknown>>();
  for (const f of findings) {
    if (rules.has(f.patternId)) continue;
    rules.set(f.patternId, {
      id: f.patternId,
      name: f.patternName.replace(/[^A-Za-z0-9]+/g, ''),
      shortDescription: { text: f.patternName },
      fullDescription: { text: descriptions.get(f.patternId) ?? f.patternName },
      defaultConfiguration: { level: SARIF_LEVEL[f.severity] },
      properties: { 'security-severity': SECURITY_SEVERITY[f.severity], tags: ['security', 'secret', f.category] }
    });
  }
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'agent-redact',
            version: toolVersion,
            informationUri: 'https://github.com/TonyDuongg/agent-redact',
            rules: [...rules.values()]
          }
        },
        results: findings.map((f) => ({
          ruleId: f.patternId,
          level: SARIF_LEVEL[f.severity],
          message: { text: `${f.patternName} detected (${f.severity}). The secret value is not included in this report.` },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: f.file, uriBaseId: '%SRCROOT%' },
                region: { startLine: f.line, startColumn: f.column }
              }
            }
          ],
          partialFingerprints: { 'agentRedact/v1': f.fingerprint }
        }))
      }
    ]
  };
}
