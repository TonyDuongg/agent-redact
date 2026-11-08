import { type Finding, type ScanContentOptions } from '../core/scan.js';
export type ScanFormat = 'text' | 'json' | 'sarif';
export interface ScanRequest {
    /** Files and/or directories, relative to `cwd` */
    targets: string[];
    /** Scan the git index (what is about to be committed) instead of `targets` */
    staged: boolean;
    baselineFile?: string;
    maxBytes?: number;
    cwd: string;
    options: Omit<ScanContentOptions, 'baseline' | 'respectInlineIgnore'>;
}
export interface ScanOutcome {
    findings: Finding[];
    filesScanned: number;
    skipped: {
        binary: number;
        'too-large': number;
        unreadable: number;
    };
    suppressed: {
        inline: number;
        baseline: number;
    };
}
/**
 * Expands directories into files. Inside a git work tree this uses `git ls-files`, so
 * .gitignore is honoured exactly as git does; elsewhere common build/dependency
 * directories are skipped. Throws `Cannot read file: <target>` for missing targets.
 */
/** Thrown when part of a target could not be enumerated; callers must fail closed */
export declare class UnverifiableTargetError extends Error {
}
export interface ExpandOptions {
    /** Directory names skipped outside git work trees (default: common build/dependency dirs) */
    excludeDirs?: ReadonlySet<string>;
    /** Keep files with binary-looking extensions (callers that sniff content themselves) */
    includeBinaryExtensions?: boolean;
}
export declare function expandTargets(targets: string[], cwd: string, options?: ExpandOptions): string[];
export declare function runScan(req: ScanRequest): ScanOutcome;
export declare function writeScanBaseline(path: string, outcome: ScanOutcome): void;
export declare function formatReport(outcome: ScanOutcome, format: Exclude<ScanFormat, 'text'>): string;
interface Colors {
    reset: string;
    red: string;
    green: string;
    yellow: string;
    gray: string;
}
/** Human-readable summary (written to stderr by the CLI). Never contains secret values. */
export declare function formatText(outcome: ScanOutcome, c: Colors): string;
export {};
