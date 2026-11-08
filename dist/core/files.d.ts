/** Default upper bound for a single file read by scanners (5 MB) */
export declare const DEFAULT_MAX_SCAN_BYTES: number;
export declare function hasKnownBinaryExtension(path: string): boolean;
/** Treats a file as binary when its first `sampleSize` bytes contain a NUL byte (as git does) */
export declare function isBinaryFile(path: string, sampleSize?: number): boolean;
export type ScanReadResult = {
    ok: true;
    content: string;
} | {
    ok: false;
    reason: 'binary' | 'too-large' | 'unreadable';
    size?: number;
};
/**
 * Reads a file for scanning, refusing binary files and files above `maxBytes`
 * so scanners never load huge blobs into memory or report noise from binary data.
 */
export declare function readTextForScan(path: string, maxBytes?: number): ScanReadResult;
/**
 * Recursively lists regular files below `dir`, skipping excluded directory names and .git.
 * Files with a known binary extension are skipped unless `includeBinaryExtensions` is set.
 */
export declare function walkFiles(dir: string, excludeDirs: ReadonlySet<string>, result?: string[], includeBinaryExtensions?: boolean): string[];
