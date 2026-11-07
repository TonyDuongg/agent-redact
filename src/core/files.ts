import { readdirSync, openSync, readSync, closeSync, statSync, readFileSync } from 'node:fs';
import { join, extname } from 'node:path';

/** Default upper bound for a single file read by scanners (5 MB) */
export const DEFAULT_MAX_SCAN_BYTES = 5 * 1024 * 1024;

/** Extensions skipped without opening the file (fast path; content sniffing covers the rest) */
const KNOWN_BINARY_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.ico', '.webp', '.svg', '.bmp', '.tif', '.tiff', '.avif', '.psd',
  '.wasm', '.zip', '.tar', '.gz', '.tgz', '.bz2', '.xz', '.7z', '.rar', '.zst',
  '.exe', '.dll', '.so', '.dylib', '.node', '.o', '.a', '.lib', '.class', '.jar', '.pyc', '.whl',
  '.pdf', '.docx', '.xlsx', '.pptx', '.bin', '.dat', '.db', '.sqlite',
  '.woff', '.woff2', '.ttf', '.otf', '.eot',
  '.mp3', '.mp4', '.mov', '.avi', '.mkv', '.webm', '.wav', '.flac', '.ogg'
]);

export function hasKnownBinaryExtension(path: string): boolean {
  return KNOWN_BINARY_EXTENSIONS.has(extname(path).toLowerCase());
}

/** Treats a file as binary when its first `sampleSize` bytes contain a NUL byte (as git does) */
export function isBinaryFile(path: string, sampleSize = 8192): boolean {
  const fd = openSync(path, 'r');
  try {
    const buf = Buffer.alloc(sampleSize);
    const read = readSync(fd, buf, 0, sampleSize, 0);
    return buf.subarray(0, read).includes(0);
  } finally {
    closeSync(fd);
  }
}

export type ScanReadResult =
  | { ok: true; content: string }
  | { ok: false; reason: 'binary' | 'too-large' | 'unreadable'; size?: number };

/**
 * Reads a file for scanning, refusing binary files and files above `maxBytes`
 * so scanners never load huge blobs into memory or report noise from binary data.
 */
export function readTextForScan(path: string, maxBytes = DEFAULT_MAX_SCAN_BYTES): ScanReadResult {
  try {
    const { size } = statSync(path);
    if (size > maxBytes) return { ok: false, reason: 'too-large', size };
    if (hasKnownBinaryExtension(path) || (size > 0 && isBinaryFile(path))) {
      return { ok: false, reason: 'binary', size };
    }
    return { ok: true, content: readFileSync(path, 'utf-8') };
  } catch {
    return { ok: false, reason: 'unreadable' };
  }
}

/**
 * Recursively lists regular files below `dir`, skipping excluded directory names and .git.
 * Files with a known binary extension are skipped unless `includeBinaryExtensions` is set.
 */
export function walkFiles(
  dir: string,
  excludeDirs: ReadonlySet<string>,
  result: string[] = [],
  includeBinaryExtensions = false
): string[] {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return result; // unreadable directory
  }
  for (const entry of entries) {
    const fullPath = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name !== '.git' && !excludeDirs.has(entry.name)) {
        walkFiles(fullPath, excludeDirs, result, includeBinaryExtensions);
      }
    } else if (entry.isFile() && (includeBinaryExtensions || !hasKnownBinaryExtension(entry.name))) {
      result.push(fullPath);
    }
  }
  return result;
}
