import { statSync } from 'node:fs';
import { isAbsolute, resolve } from 'node:path';
import { redact } from '../core/engine.js';
import { loadConfig } from '../core/config.js';
import { readTextForScan } from '../core/files.js';
import type { RedactOptions } from '../core/types.js';

/**
 * Claude Code hook integration (`agent-redact hook`).
 *
 * Reads the hook event JSON from stdin. Exit code 2 blocks the action: for UserPromptSubmit
 * the prompt is rejected and the message is shown to the user; for PreToolUse the tool call
 * is refused and the message is shown to Claude. Messages name secret *types*, never values.
 * Inline `agent-redact-ignore` comments are deliberately NOT honoured here: an agent must not
 * be able to unlock a file for itself by editing a comment into it.
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
}

export interface HookDecision {
  block: boolean;
  message?: string;
}

/** Commands that print file contents; their file arguments are checked for secrets */
const READER_RE =
  /(?:^|[\s;&|(`$])(?:cat|tac|head|tail|less|more|bat|nl|grep|egrep|fgrep|rg|ag|awk|gawk|sed|cut|sort|uniq|strings|xxd|od|hexdump|base64|jq|yq|type|Get-Content|gc|Select-String|findstr)(?=\s)/i;
const WRITE_TOOLS = new Set(['Write', 'Edit', 'MultiEdit', 'NotebookEdit']);
const MAX_BASH_FILE_ARGS = 50;

function summarize(text: string, options: RedactOptions): { count: number; types: string } {
  const res = redact(text, { ...options, reversible: false });
  const types = [...new Set(res.matches.map((m) => m.patternName))].join(', ');
  return { count: res.totalLeaks, types };
}

function redactOptionsFor(cwd: string): RedactOptions {
  let config = null;
  try {
    config = loadConfig(undefined, cwd);
  } catch {
    // An invalid config must not disable the hook; fall back to defaults
  }
  return {
    include: config?.include,
    exclude: config?.exclude,
    allowlist: config?.allowlist,
    customPatterns: config?.customPatterns,
    detectHighEntropy: config?.detectHighEntropy ?? false,
    entropy: config?.entropy
  };
}

function fileSecrets(path: string, cwd: string, options: RedactOptions): { count: number; types: string } | null {
  const abs = isAbsolute(path) ? path : resolve(cwd, path);
  try {
    if (!statSync(abs).isFile()) return null;
  } catch {
    return null;
  }
  const read = readTextForScan(abs);
  if (!read.ok) return null;
  const s = summarize(read.content, options);
  return s.count > 0 ? s : null;
}

const str = (v: unknown): string => (typeof v === 'string' ? v : '');

export function evaluateHook(input: HookInput, options: HookOptions = {}): HookDecision {
  const cwd = input.cwd || process.cwd();
  const redactOptions = redactOptionsFor(cwd);
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

  if (tool === 'Read') {
    const path = str(toolInput['file_path']);
    const s = path ? fileSecrets(path, cwd, redactOptions) : null;
    return s
      ? {
          block: true,
          message:
            `agent-redact blocked reading ${path}: it contains ${s.count} secret(s) (${s.types}). ` +
            'Ask the user first, or use the agent-redact MCP tool scan_file to read a redacted copy.'
        }
      : { block: false };
  }

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
        const s = fileSecrets(token, cwd, redactOptions);
        if (s) {
          return {
            block: true,
            message:
              `agent-redact blocked this command: it would print ${token}, which contains ${s.count} secret(s) (${s.types}). ` +
              'Ask the user first, or use the agent-redact MCP tool scan_file to read a redacted copy.'
          };
        }
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

  // Everything else may send its input somewhere else (WebFetch, WebSearch, MCP tools, sub-agents…)
  const s = summarize(JSON.stringify(toolInput), redactOptions);
  return s.count > 0
    ? {
        block: true,
        message: `agent-redact blocked the ${tool} call: its input contains ${s.count} secret(s) (${s.types}).`
      }
    : { block: false };
}

async function readAll(stream: NodeJS.ReadableStream): Promise<string> {
  let data = '';
  stream.setEncoding('utf8');
  for await (const chunk of stream) data += chunk;
  return data;
}

/** Entry point for `agent-redact hook [--block-writes]`; returns the process exit code */
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
  const decision = evaluateHook(input, { blockWrites: args.includes('--block-writes') });
  if (decision.block) {
    process.stderr.write(`${decision.message}\n`);
    return 2;
  }
  return 0;
}
