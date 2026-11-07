import { readFileSync, statSync } from 'node:fs';
import { isAbsolute, relative, resolve } from 'node:path';
import { redact } from '../core/engine.js';
import { loadConfig } from '../core/config.js';
import type { RedactOptions } from '../core/types.js';
import { expandTargets } from './scan.js';

/**
 * Claude Code hook integration (`agent-redact hook`).
 *
 * Reads the hook event JSON on stdin and exits with code 2 to block the action: for
 * UserPromptSubmit the prompt is rejected and the message is shown to the user; for
 * PreToolUse the tool call is refused and the message is shown to Claude. Messages name
 * secret *types*, never values.
 *
 * Fail-closed design, because the agent is the party being constrained:
 * - inline `agent-redact-ignore` comments are NOT honoured (an agent could add them);
 * - from the project config, which the agent can edit, only settings that ADD detection are
 *   used (custom patterns, entropy). allowlist/include/exclude are ignored unless the user
 *   passes `--config <path>` explicitly;
 * - large files are scanned in full (up to 64 MB; beyond that the read is refused), UTF-16
 *   files are decoded, and printable strings inside binary files are scanned.
 */
export interface HookInput {
  hook_event_name?: string;
  tool_name?: string;
  tool_input?: Record<string, unknown>;
  prompt?: string;
  cwd?: string;
}

export interface HookOptions {
  /** Also block Write/Edit/MultiEdit/NotebookEdit calls whose content contains secrets */
  blockWrites?: boolean;
  /** Explicit, user-controlled config file; applied in full (allowlist/exclude included) */
  configPath?: string;
}

export interface HookDecision {
  block: boolean;
  message?: string;
}

interface Summary {
  count: number;
  types: string;
}

/** Commands that print file contents; their file arguments are checked for secrets */
const READER_RE =
  /(?:^|[\s;&|(`$])(?:cat|tac|head|tail|less|more|bat|nl|grep|egrep|fgrep|rg|ag|awk|gawk|sed|cut|sort|uniq|strings|xxd|od|hexdump|base64|jq|yq|type|Get-Content|gc|Select-String|findstr)(?=\s)/i;
const WRITE_TOOLS = new Set(['Write', 'Edit', 'MultiEdit', 'NotebookEdit']);
/** Tools that only list paths and never return file contents */
const PATH_ONLY_TOOLS = new Set(['Glob', 'LS', 'TodoWrite']);
/** agent-redact's own MCP tools are the safe way to read secrets-bearing files */
const TRUSTED_TOOLS = new Set([
  'mcp__agent-redact__scan_file',
  'mcp__agent-redact__redact_text',
  'mcp__agent-redact__unmask_text',
  'mcp__agent-redact__get_vault_status',
  'mcp__agent-redact__clear_vault',
  'mcp__agent-redact__list_supported_patterns'
]);
const PATH_KEYS = ['file_path', 'filePath', 'path', 'paths', 'notebook_path', 'file', 'filename', 'uri'];
const MAX_BASH_FILE_ARGS = 50;
const HOOK_MAX_FILE_BYTES = 64 * 1024 * 1024;
const GREP_MAX_FILES = 5000;
const GREP_MAX_TOTAL_BYTES = 128 * 1024 * 1024;

const str = (v: unknown): string => (typeof v === 'string' ? v : '');

function summarize(text: string, options: RedactOptions): Summary {
  const res = redact(text, { ...options, reversible: false });
  return { count: res.totalLeaks, types: [...new Set(res.matches.map((m) => m.patternName))].join(', ') };
}

function redactOptionsFor(cwd: string, configPath?: string): RedactOptions {
  if (configPath) {
    // The user pointed at a config explicitly: trust all of it
    const c = loadConfig(configPath, cwd);
    return {
      include: c?.include,
      exclude: c?.exclude,
      allowlist: c?.allowlist,
      customPatterns: c?.customPatterns,
      detectHighEntropy: c?.detectHighEntropy ?? false,
      entropy: c?.entropy
    };
  }
  let c = null;
  try {
    c = loadConfig(undefined, cwd);
  } catch {
    // An invalid project config must not disable the hook; fall back to defaults
  }
  // Only settings that can ADD detections; never ones that remove them
  return {
    customPatterns: c?.customPatterns,
    detectHighEntropy: c?.detectHighEntropy === true,
    entropy: c?.detectHighEntropy === true ? c.entropy : undefined
  };
}

/** Decodes file bytes into scannable text without letting binary/UTF-16 framing hide secrets */
function decodeForScan(buf: Buffer): string {
  if (buf[0] === 0xff && buf[1] === 0xfe) return buf.subarray(2).toString('utf16le');
  if (buf[0] === 0xfe && buf[1] === 0xff) return Buffer.from(buf.subarray(2)).swap16().toString('utf16le');
  const sample = buf.subarray(0, 8192);
  if (!sample.includes(0)) return buf.toString('utf8');
  // BOM-less UTF-16: most odd (LE) or even (BE) bytes are NUL in ASCII-heavy text
  let oddZeros = 0;
  let evenZeros = 0;
  for (let i = 0; i < sample.length; i++) if (sample[i] === 0) (i % 2 ? oddZeros++ : evenZeros++);
  const half = sample.length / 2;
  if (oddZeros > half * 0.3 && evenZeros < half * 0.05) return buf.toString('utf16le');
  if (evenZeros > half * 0.3 && oddZeros < half * 0.05) {
    return Buffer.from(buf.subarray(0, buf.length - (buf.length % 2))).swap16().toString('utf16le');
  }
  // Other binaries: scan printable ASCII runs, like `strings`
  return (buf.toString('latin1').match(/[\x20-\x7e\t]{6,}/g) ?? []).join('\n');
}

type FileCheck = { kind: 'secrets'; summary: Summary; text: string } | { kind: 'too-large' } | null;

function checkFile(path: string, cwd: string, options: RedactOptions): FileCheck {
  const abs = isAbsolute(path) ? path : resolve(cwd, path);
  let size: number;
  try {
    const st = statSync(abs);
    if (!st.isFile()) return null;
    size = st.size;
  } catch {
    return null; // missing or unreadable: the tool itself will fail
  }
  if (size > HOOK_MAX_FILE_BYTES) return { kind: 'too-large' };
  let text: string;
  try {
    text = decodeForScan(readFileSync(abs));
  } catch {
    return null;
  }
  const summary = summarize(text, options);
  return summary.count > 0 ? { kind: 'secrets', summary, text } : null;
}

function fileBlockMessage(what: string, path: string, check: Exclude<FileCheck, null>): string {
  if (check.kind === 'too-large') {
    return `agent-redact blocked ${what} ${path}: the file is larger than 64 MB and cannot be verified to be free of secrets. Ask the user first.`;
  }
  return (
    `agent-redact blocked ${what} ${path}: it contains ${check.summary.count} secret(s) (${check.summary.types}). ` +
    'Ask the user first, or use the agent-redact MCP tool scan_file to read a redacted copy.'
  );
}

/**
 * Glob → RegExp for the conservative subset whose meaning is unambiguous (`*`, `**`, `?`,
 * `{a,b}` over plain characters). Anything else (character classes, negation, escapes,
 * nested braces) returns null and the glob is ignored: a glob may only narrow the check,
 * never skip a file that ripgrep would search. Patterns without '/' match the basename.
 */
function simpleGlobToRegExp(glob: string): RegExp | null {
  if (!/^[A-Za-z0-9._\-/*?{},@ ]+$/.test(glob)) return null;
  let re = '';
  let braceDepth = 0;
  for (let i = 0; i < glob.length; i++) {
    const ch = glob[i]!;
    if (ch === '*') {
      if (glob[i + 1] === '*') {
        re += '.*';
        i++;
        if (glob[i + 1] === '/') i++;
      } else re += '[^/]*';
    } else if (ch === '?') re += '[^/]';
    else if (ch === '{') {
      if (++braceDepth > 1) return null;
      re += '(?:';
    } else if (ch === '}') {
      if (--braceDepth < 0) return null;
      re += ')';
    } else if (ch === ',') {
      if (braceDepth === 0) return null;
      re += '|';
    } else re += ch.replace(/[.]/g, '\\.');
  }
  return braceDepth === 0 ? new RegExp(`^${re}$`) : null;
}

/**
 * Grep is blocked when any file it could search contains a secret, in EVERY output mode:
 * content/context lines print secrets directly, and files_with_matches/count act as an
 * oracle (a guessed pattern reveals whether it matches). The agent-supplied regex is never
 * evaluated, so ripgrep/JS regex differences and ReDoS cannot weaken the check.
 *
 * Files are enumerated like ripgrep (inside git: tracked + untracked-not-ignored, honouring
 * .gitignore but not an agent-settable core.excludesFile; outside git: everything except
 * .git). Hidden files and binary extensions are included.
 */
function checkGrep(input: Record<string, unknown>, cwd: string, options: RedactOptions): HookDecision {
  const target = str(input['path']) || cwd;
  const glob = str(input['glob']);
  const globRe = glob ? simpleGlobToRegExp(glob) : null;

  let files: string[];
  try {
    files = expandTargets([target], cwd, { excludeDirs: new Set(), includeBinaryExtensions: true });
  } catch {
    return { block: false }; // path does not exist: grep itself will fail
  }
  if (globRe) {
    files = files.filter((f) => {
      const rel = relative(cwd, f).split('\\').join('/');
      return globRe.test(glob.includes('/') ? rel : rel.split('/').pop()!);
    });
  }
  if (files.length > GREP_MAX_FILES) {
    return { block: true, message: `agent-redact blocked Grep: ${files.length} files are too many to verify. Narrow the path or glob.` };
  }
  let total = 0;
  for (const file of files) {
    try {
      total += statSync(file).size;
    } catch {
      continue;
    }
    if (total > GREP_MAX_TOTAL_BYTES) {
      return { block: true, message: 'agent-redact blocked Grep: the search covers too much data to verify. Narrow the path or glob.' };
    }
    const check = checkFile(file, cwd, options);
    if (!check) continue;
    const rel = relative(cwd, file) || file;
    if (check.kind === 'too-large') return { block: true, message: fileBlockMessage('searching', rel, check) };
    return {
      block: true,
      message:
        `agent-redact blocked Grep: the search includes ${rel}, which contains ${check.summary.count} secret(s) ` +
        `(${check.summary.types}). Narrow the path or glob to files without secrets, or ask the user.`
    };
  }
  return { block: false };
}

export function evaluateHook(input: HookInput, options: HookOptions = {}): HookDecision {
  const cwd = input.cwd || process.cwd();
  const redactOptions = redactOptionsFor(cwd, options.configPath);
  const event = input.hook_event_name;

  if (event === 'UserPromptSubmit') {
    const s = summarize(str(input.prompt), redactOptions);
    return s.count > 0
      ? {
          block: true,
          message:
            `agent-redact blocked this prompt: it contains ${s.count} secret(s) (${s.types}). ` +
            'Remove them, or refer to them indirectly (for example "the key in .env") instead of pasting them.'
        }
      : { block: false };
  }

  if (event !== 'PreToolUse') return { block: false };

  const tool = input.tool_name ?? '';
  const toolInput = input.tool_input ?? {};

  if (TRUSTED_TOOLS.has(tool) || PATH_ONLY_TOOLS.has(tool)) return { block: false };

  if (tool === 'Read') {
    const path = str(toolInput['file_path']);
    const check = path ? checkFile(path, cwd, redactOptions) : null;
    return check ? { block: true, message: fileBlockMessage('reading', path, check) } : { block: false };
  }

  if (tool === 'Grep') return checkGrep(toolInput, cwd, redactOptions);

  if (tool === 'Bash') {
    const command = str(toolInput['command']);
    const inline = summarize(command, redactOptions);
    if (inline.count > 0) {
      return {
        block: true,
        message: `agent-redact blocked this command: it contains ${inline.count} secret(s) (${inline.types}). Use an environment variable instead of the literal value.`
      };
    }
    if (READER_RE.test(command)) {
      const candidates = command
        .split(/[\s;&|()<>'"`=]+/)
        .filter((t) => t && !t.startsWith('-'))
        .slice(0, MAX_BASH_FILE_ARGS);
      for (const token of candidates) {
        const check = checkFile(token, cwd, redactOptions);
        if (check) return { block: true, message: fileBlockMessage('printing', token, check) };
      }
    }
    return { block: false };
  }

  if (WRITE_TOOLS.has(tool)) {
    if (!options.blockWrites) return { block: false };
    const s = summarize(JSON.stringify(toolInput), redactOptions);
    return s.count > 0
      ? { block: true, message: `agent-redact blocked ${tool}: the new content contains ${s.count} secret(s) (${s.types}).` }
      : { block: false };
  }

  // Any other tool (WebFetch, WebSearch, MCP tools, sub-agents…): it may read files given by
  // path (e.g. a filesystem MCP server) or send its input elsewhere. Check both.
  for (const key of PATH_KEYS) {
    const value = toolInput[key];
    const paths = Array.isArray(value) ? value : [value];
    for (const p of paths) {
      if (typeof p !== 'string' || !p) continue;
      const check = checkFile(p, cwd, redactOptions);
      if (check) return { block: true, message: fileBlockMessage(`${tool} on`, p, check) };
    }
  }
  const s = summarize(JSON.stringify(toolInput), redactOptions);
  return s.count > 0
    ? { block: true, message: `agent-redact blocked the ${tool} call: its input contains ${s.count} secret(s) (${s.types}).` }
    : { block: false };
}

async function readAll(stream: NodeJS.ReadableStream): Promise<string> {
  let data = '';
  stream.setEncoding('utf8');
  for await (const chunk of stream) data += chunk;
  return data;
}

/** Entry point for `agent-redact hook [--block-writes] [--config <path>]`; returns the exit code */
export async function runHook(args: string[]): Promise<number> {
  const raw = await readAll(process.stdin);
  let input: HookInput;
  try {
    input = JSON.parse(raw) as HookInput;
  } catch {
    // Non-blocking error: Claude Code shows it to the user but continues
    process.stderr.write('agent-redact hook: could not parse hook input JSON from stdin\n');
    return 1;
  }
  const configIdx = args.indexOf('--config');
  const configPath = configIdx !== -1 ? args[configIdx + 1] : undefined;
  let decision: HookDecision;
  try {
    decision = evaluateHook(input, { blockWrites: args.includes('--block-writes'), configPath });
  } catch (err: unknown) {
    // Fail closed on unexpected errors (e.g. an unreadable explicit --config)
    const msg = err instanceof Error ? err.message : String(err);
    process.stderr.write(`agent-redact hook: refusing because the check failed: ${msg}\n`);
    return 2;
  }
  if (decision.block) {
    process.stderr.write(`${decision.message}\n`);
    return 2;
  }
  return 0;
}
