import { execFileSync } from 'node:child_process';

/**
 * Hardening for repositories we do not trust: a scanned directory may carry its own
 * .git/config, and `core.fsmonitor` there is executed by commands such as `ls-files`
 * (verified by tests/scan-cli.test.ts). Disable every config-driven helper we could trigger.
 */
const HARDENING = [
  '-c', 'core.fsmonitor=false',
  '-c', 'core.untrackedCache=false',
  '-c', 'core.pager=cat',
  // A repo-local core.excludesFile (writable by an agent) must not hide files from scans;
  // .gitignore and .git/info/exclude still apply, as they do for ripgrep
  '-c', 'core.excludesFile='
];

// Arguments are passed as an array (no shell), so paths can never inject commands.
const run = (args: string[], cwd: string): Buffer =>
  execFileSync('git', [...HARDENING, ...args], {
    cwd,
    stdio: ['ignore', 'pipe', 'ignore'],
    maxBuffer: 256 * 1024 * 1024,
    env: { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_OPTIONAL_LOCKS: '0' }
  });

const splitNul = (buf: Buffer): string[] => buf.toString('utf8').split('\0').filter(Boolean);

/** True when `cwd` is inside a git work tree (and git is installed) */
export function isGitWorkTree(cwd: string): boolean {
  try {
    return run(['rev-parse', '--is-inside-work-tree'], cwd).toString('utf8').trim() === 'true';
  } catch {
    return false;
  }
}

/**
 * Files under `pathspec` that git would consider part of the project: tracked files plus
 * untracked files that are not ignored. This honours .gitignore, .git/info/exclude and the
 * global excludes file exactly as git does. Paths are relative to `cwd`.
 */
export function gitListFiles(pathspec: string, cwd: string): string[] {
  return splitNul(run(['ls-files', '-z', '--cached', '--others', '--exclude-standard', '--', pathspec], cwd));
}

/** Paths staged for commit (added, copied, modified, renamed), relative to the repo root */
export function gitStagedFiles(cwd: string): string[] {
  return splitNul(run(['diff', '--cached', '--name-only', '-z', '--diff-filter=ACMR'], cwd));
}

/** Repository root of `cwd` */
export function gitRoot(cwd: string): string {
  return run(['rev-parse', '--show-toplevel'], cwd).toString('utf8').trim();
}

/**
 * Raw content of `path` as staged in the index (what will actually be committed).
 * `cat-file blob` never applies textconv or other content filters, unlike `show`.
 */
export function gitStagedContent(path: string, repoRoot: string): Buffer {
  return run(['cat-file', 'blob', `:${path}`], repoRoot);
}
