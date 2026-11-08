/** True when `cwd` is inside a git work tree (and git is installed) */
export declare function isGitWorkTree(cwd: string): boolean;
/**
 * Files under `pathspec` that git would consider part of the project: tracked files plus
 * untracked files that are not ignored. This honours .gitignore, .git/info/exclude and the
 * global excludes file exactly as git does. Paths are relative to `cwd`.
 */
export declare function gitListFiles(pathspec: string, cwd: string): string[];
/** Paths staged for commit (added, copied, modified, renamed), relative to the repo root */
export declare function gitStagedFiles(cwd: string): string[];
/** Repository root of `cwd` */
export declare function gitRoot(cwd: string): string;
/**
 * Raw content of `path` as staged in the index (what will actually be committed).
 * `cat-file blob` never applies textconv or other content filters, unlike `show`.
 */
export declare function gitStagedContent(path: string, repoRoot: string): Buffer;
