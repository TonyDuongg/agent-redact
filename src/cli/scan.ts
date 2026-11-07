import { statSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { walkFiles, readTextForScan, DEFAULT_MAX_SCAN_BYTES } from '../core/files.js';
import { isGitWorkTree, gitListFiles, gitStagedFiles, gitRoot, gitStagedContent } from '../core/git.js';
import {
  scanContent,
  toSarif,
  loadBaseline,
  writeBaseline,
  type Finding,
  type ScanContentOptions
} from '../core/scan.js';
import { VERSION } from '../version.js';

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
  skipped: { binary: number; 'too-large': number; unreadable: number };
  suppressed: { inline: number; baseline: number };
}

/** Directories skipped when a target is not inside a git work tree */
const DEFAULT_EXCLUDES = new Set([
  'node_modules', 'dist', 'build', 'coverage', '.turbo', '.next', '.nuxt', 'vendor', '.venv', 'venv', '__pycache__'
]);

const toPosix = (p: string) => p.split('\\').join('/');

/**
 * Expands directories into files. Inside a git work tree this uses `git ls-files`, so
 * .gitignore is honoured exactly as git does; elsewhere common build/dependency
 * directories are skipped. Throws `Cannot read file: <target>` for missing targets.
 */
/** Thrown when part of a target could not be enumerated; callers must fail closed */
export class UnverifiableTargetError extends Error {}

export interface ExpandOptions {
  /** Directory names skipped outside git work trees (default: common build/dependency dirs) */
  excludeDirs?: ReadonlySet<string>;
  /** Keep files with binary-looking extensions (callers that sniff content themselves) */
  includeBinaryExtensions?: boolean;
}

export function expandTargets(targets: string[], cwd: string, options: ExpandOptions = {}): string[] {
  const excludeDirs = options.excludeDirs ?? DEFAULT_EXCLUDES;
  const out = new Set<string>();
  const visit = (abs: string, label: string, depth: number) => {
    let isDir: boolean;
    try {
      isDir = statSync(abs).isDirectory();
    } catch {
      throw new Error(`Cannot read file: ${label}`);
    }
    if (!isDir) {
      out.add(abs);
    } else if (isGitWorkTree(abs)) {
      for (const p of gitListFiles('.', abs)) {
        const child = join(abs, p);
        // Submodules / nested repositories are listed as directories: descend into them
        // so their files are not silently skipped
        let childIsDir = false;
        try {
          childIsDir = statSync(child).isDirectory();
        } catch {
          continue; // deleted in the working tree
        }
        if (childIsDir) {
          // Fail closed: never silently skip a nested repository we cannot descend into
          if (depth >= 8) throw new UnverifiableTargetError(`Submodules nested too deeply to verify: ${p}`);
          visit(child, p, depth + 1);
        } else out.add(child);
      }
    } else {
      for (const p of walkFiles(abs, excludeDirs, [], options.includeBinaryExtensions)) out.add(p);
    }
  };
  for (const target of targets) visit(resolve(cwd, target), target, 0);
  return [...out];
}

export function runScan(req: ScanRequest): ScanOutcome {
  const maxBytes = req.maxBytes ?? DEFAULT_MAX_SCAN_BYTES;
  const baseline = req.baselineFile ? loadBaseline(resolve(req.cwd, req.baselineFile)) : undefined;
  // Scan mode audits a repository you control, so inline ignore comments are honoured here
  const scanOptions: ScanContentOptions = { ...req.options, respectInlineIgnore: true, baseline };
  const outcome: ScanOutcome = {
    findings: [],
    filesScanned: 0,
    skipped: { binary: 0, 'too-large': 0, unreadable: 0 },
    suppressed: { inline: 0, baseline: 0 }
  };

  const record = (content: string, file: string) => {
    const res = scanContent(content, file, scanOptions);
    outcome.filesScanned++;
    outcome.findings.push(...res.findings);
    outcome.suppressed.inline += res.suppressed.inline;
    outcome.suppressed.baseline += res.suppressed.baseline;
  };

  if (req.staged) {
    const root = gitRoot(req.cwd);
    for (const path of gitStagedFiles(root)) {
      let blob: Buffer;
      try {
        blob = gitStagedContent(path, root);
      } catch {
        outcome.skipped.unreadable++;
        continue;
      }
      if (blob.length > maxBytes) outcome.skipped['too-large']++;
      else if (blob.subarray(0, 8192).includes(0)) outcome.skipped.binary++;
      // Report paths relative to the caller's cwd, like every other mode
      else record(blob.toString('utf8'), toPosix(relative(req.cwd, join(root, path))));
    }
    return outcome;
  }

  for (const abs of expandTargets(req.targets, req.cwd)) {
    const read = readTextForScan(abs, maxBytes);
    if (!read.ok) {
      outcome.skipped[read.reason]++;
      continue;
    }
    record(read.content, toPosix(relative(req.cwd, abs)));
  }
  return outcome;
}

export function writeScanBaseline(path: string, outcome: ScanOutcome): void {
  writeBaseline(path, outcome.findings);
}

export function formatReport(outcome: ScanOutcome, format: Exclude<ScanFormat, 'text'>): string {
  if (format === 'sarif') return JSON.stringify(toSarif(outcome.findings, VERSION), null, 2) + '\n';
  return JSON.stringify(outcome, null, 2) + '\n';
}

interface Colors {
  reset: string;
  red: string;
  green: string;
  yellow: string;
  gray: string;
}

/** Human-readable summary (written to stderr by the CLI). Never contains secret values. */
export function formatText(outcome: ScanOutcome, c: Colors): string {
  const lines: string[] = [];
  for (const f of outcome.findings) {
    lines.push(
      `${c.yellow}✖ [LEAK]${c.reset} ${f.file}:${f.line}:${f.column}  ${f.patternName} (${f.severity.toUpperCase()})`
    );
  }
  const notes: string[] = [];
  const skipped = outcome.skipped.binary + outcome.skipped['too-large'] + outcome.skipped.unreadable;
  if (skipped > 0) notes.push(`${skipped} skipped (binary/too large/unreadable)`);
  if (outcome.suppressed.inline > 0) notes.push(`${outcome.suppressed.inline} ignored inline`);
  if (outcome.suppressed.baseline > 0) notes.push(`${outcome.suppressed.baseline} in baseline`);
  const suffix = notes.length > 0 ? ` ${c.gray}(${notes.join(', ')})${c.reset}` : '';

  const filesWithFindings = new Set(outcome.findings.map((f) => f.file)).size;
  lines.push(
    outcome.findings.length > 0
      ? `\n${c.red}[agent-redact] Audit failed: detected ${outcome.findings.length} secret(s) across ${filesWithFindings} of ${outcome.filesScanned} files.${c.reset}${suffix}`
      : `\n${c.green}[agent-redact] All ${outcome.filesScanned} files are clean.${c.reset}${suffix}`
  );
  return lines.join('\n');
}
