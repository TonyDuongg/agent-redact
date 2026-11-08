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
    suppressed: {
        inline: number;
        baseline: number;
    };
}
/** Offsets at which each line starts; used for O(log n) offset → line/column lookups */
export declare function lineStarts(text: string): number[];
/** 1-based line and column of `offset` */
export declare function positionAt(starts: readonly number[], offset: number): {
    line: number;
    column: number;
};
export declare function fingerprintOf(patternId: string, file: string, secret: string): string;
/**
 * Scans text and returns findings without secret values. Inline ignore comments are only
 * honoured when explicitly enabled: they are meant for audits of a repository you own,
 * never for redacting prompts (a prompt could otherwise opt itself out of redaction).
 */
export declare function scanContent(content: string, file: string, options?: ScanContentOptions): ScanContentResult;
/** Writes accepted findings so later scans only report new ones. Contains no secret values. */
export declare function writeBaseline(path: string, findings: readonly Finding[]): void;
export declare function loadBaseline(path: string): Set<string>;
/** SARIF 2.1.0 report for GitHub code scanning and other SARIF consumers */
export declare function toSarif(findings: readonly Finding[], toolVersion: string): Record<string, unknown>;
