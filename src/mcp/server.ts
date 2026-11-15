import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import {
  readFileSync,
  writeFileSync,
  existsSync,
  realpathSync,
  openSync,
  closeSync,
  fchmodSync,
  chmodSync,
  renameSync,
  unlinkSync,
  statSync,
  constants as fsConstants
} from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';
import { resolve, relative, isAbsolute, dirname, basename, join, sep } from 'node:path';
import { tmpdir, homedir } from 'node:os';
import { redact, unmask } from '../core/engine.js';
import { Vault } from '../core/vault.js';
import { isBinaryFile, DEFAULT_MAX_SCAN_BYTES } from '../core/files.js';
import { VERSION } from '../version.js';
import { DEFAULT_PATTERNS } from '../patterns/index.js';

export interface McpServerOptions {
  /**
   * Directories the file tools may read from / write to.
   * Defaults to the process cwd, the OS temp dir and AGENT_REDACT_ALLOWED_DIR (if set).
   */
  allowedRoots?: string[];
  /** Maximum number of distinct secrets kept in the session vault (default 10,000) */
  vaultMaxEntries?: number;
  /**
   * Enable `unmask_text`, which writes restored secrets into any file inside the allowed
   * roots. Off by default since 0.5: a prompt-injected model could copy a secret into a file
   * that is later published. Prefer `edit_file_redacted`, which only restores a file's own
   * secrets into that same file.
   */
  allowUnmaskText?: boolean;
}

/** Options from `agent-redact mcp` / `agent-redact-mcp` arguments and the environment */
export function mcpOptionsFromArgs(args: string[], env: NodeJS.ProcessEnv = process.env): McpServerOptions {
  for (const arg of args) {
    if (arg !== '--allow-unmask-text') throw new Error(`Unknown option for the MCP server: ${arg}`);
  }
  return { allowUnmaskText: args.includes('--allow-unmask-text') || env.AGENT_REDACT_ALLOW_UNMASK_TEXT === '1' };
}

const sha256 = (text: string): string => createHash('sha256').update(text, 'utf8').digest('hex');

/** Placeholder-shaped tokens, e.g. [AWS_ACCESS_KEY_ID_1] */
const PLACEHOLDER_TOKEN_RE = /\[[A-Z][A-Z0-9_]*_\d+\]/g;

/**
 * Atomic write: a temp file in the same directory, given the original file's mode, renamed
 * over the target. Readers never see a half-written file, and no backup with plaintext
 * secrets is left behind.
 */
function atomicReplaceFile(path: string, content: string, mode: number): void {
  const temp = join(dirname(path), `.${basename(path)}.agent-redact-${randomBytes(6).toString('hex')}.tmp`);
  writeFileSync(temp, content, { encoding: 'utf-8', mode: mode & 0o777, flag: 'wx' });
  try {
    try {
      chmodSync(temp, mode & 0o777); // umask may have narrowed the creation mode
    } catch {
      // chmod is best effort on Windows
    }
    renameSync(temp, path);
  } catch (err) {
    try {
      unlinkSync(temp);
    } catch {
      // already gone
    }
    throw err;
  }
}

/**
 * Resolves symlinks/junctions for the deepest existing ancestor of `p`
 * and re-appends the not-yet-existing tail, so new files are checked
 * against their real destination directory.
 */
function realpathOrNearest(p: string): string {
  let current = resolve(p);
  const tail: string[] = [];
  for (;;) {
    try {
      return join(realpathSync.native(current), ...tail.reverse());
    } catch {
      const parent = dirname(current);
      if (parent === current) {
        return resolve(p);
      }
      tail.push(basename(current));
      current = parent;
    }
  }
}

function defaultAllowedRoots(): string[] {
  const roots: string[] = [];
  if (process.env.AGENT_REDACT_ALLOWED_DIR) {
    roots.push(process.env.AGENT_REDACT_ALLOWED_DIR);
  }
  const cwd = process.cwd();
  const rootDir = resolve(sep);
  const home = homedir();
  // Avoid defaulting to filesystem root or user home directory without explicit AGENT_REDACT_ALLOWED_DIR
  if (cwd !== rootDir && cwd !== home) {
    roots.push(cwd);
  }
  roots.push(tmpdir());
  return roots;
}

type PathCheck = { ok: true; realPath: string } | { ok: false; reason: string };

function checkPath(targetPath: string, roots: string[], mode: 'read' | 'write'): PathCheck {
  const realTarget = realpathOrNearest(targetPath);

  for (const root of roots) {
    const rel = relative(root, realTarget);
    const inside = rel === '' || (!isAbsolute(rel) && rel !== '..' && !rel.startsWith(`..${sep}`));
    if (!inside) continue;

    if (mode === 'write') {
      const segments = rel.split(sep);
      // Fail closed on NTFS alternate data streams ("name:stream") anywhere below the root
      if (segments.some((segment) => segment.includes(':'))) {
        return { ok: false, reason: 'not a plain file path' };
      }
      // Writing into VCS metadata (e.g. .git/hooks) would allow code execution.
      // Windows ignores trailing dots/spaces, so ".git." and ".git " also mean ".git".
      if (segments.some((segment) => segment.replace(/[. ]+$/, '').toLowerCase() === '.git')) {
        return { ok: false, reason: 'writing inside a .git directory is not allowed' };
      }
    }
    return { ok: true, realPath: realTarget };
  }

  return { ok: false, reason: 'outside the allowed directories (workspace or temp)' };
}

/**
 * Write flags that refuse to follow a symlink planted at the final path component
 * after the sandbox check (POSIX only; O_NOFOLLOW is unavailable on Windows).
 */
const SAFE_WRITE_FLAGS =
  fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_TRUNC | (fsConstants.O_NOFOLLOW ?? 0);

/**
 * Writes through a no-follow descriptor. `enforceMode` is applied even to existing files
 * (used for files that contain restored plaintext secrets); without it, an existing file
 * keeps its permissions (e.g. an executable script stays executable) and new files get 0644.
 */
function safeWriteFile(path: string, content: string, enforceMode?: number): void {
  const fd = openSync(path, SAFE_WRITE_FLAGS, enforceMode ?? 0o644);
  try {
    writeFileSync(fd, content, 'utf-8');
    if (enforceMode !== undefined) {
      try {
        fchmodSync(fd, enforceMode);
      } catch {
        // fchmod may be unavailable or fail on Windows / non-POSIX
      }
    }
  } finally {
    closeSync(fd);
  }
}

/** Writes a backup without ever overwriting an existing one: file.bak, file.bak.1, ... */
function writeUniqueBackup(file: string, content: string): string {
  for (let i = 0; i < 1000; i++) {
    const candidate = i === 0 ? `${file}.bak` : `${file}.bak.${i}`;
    try {
      writeFileSync(candidate, content, { encoding: 'utf-8', mode: 0o600, flag: 'wx' });
      return candidate;
    } catch (err: unknown) {
      if ((err as NodeJS.ErrnoException).code !== 'EEXIST') throw err;
    }
  }
  throw new Error(`Unable to allocate a backup file name for ${file}`);
}

function securityError(field: string, value: string, reason: string) {
  return {
    isError: true,
    content: [{ type: 'text' as const, text: `Security error: ${field} "${value}" is ${reason}.` }]
  };
}

export function createMcpServer(options: McpServerOptions = {}): McpServer {
  const vaultMaxEntries = options.vaultMaxEntries ?? 10_000;
  const sessionVault = new Vault({ maxEntries: vaultMaxEntries });
  const allowedRoots = (options.allowedRoots ?? defaultAllowedRoots()).map(realpathOrNearest);

  const server = new McpServer({
    name: 'agent-redact',
    version: VERSION
  });

  // Tool 1: redact_text
  server.tool(
    'redact_text',
    'Scans and redacts sensitive credentials (Anthropic keys, OpenAI keys, AWS tokens, GitHub PATs, JWTs, Stripe keys, SSH keys, database URIs) and PII from a given prompt or text payload.',
    {
      text: z.string().describe('The raw text/prompt to scan and sanitize'),
      reversible: z
        .boolean()
        .default(true)
        .describe(
          'If true, replaces secrets with reversible placeholders like [ANTHROPIC_API_KEY_1]. If false, uses one-way redaction [REDACTED_ANTHROPIC_API_KEY].'
        )
    },
    async ({ text, reversible }) => {
      const result = redact(text, {
        reversible,
        vault: sessionVault
      });

      const summary = {
        sanitizedText: result.text,
        hasLeaks: result.hasLeaks,
        totalLeaks: result.totalLeaks,
        stats: result.stats,
        durationMs: result.durationMs,
        detectedPatterns: result.matches.map((m) => ({
          pattern: m.patternName,
          category: m.category,
          severity: m.severity,
          placeholder: m.replacement
        }))
      };

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(summary, null, 2)
          }
        ]
      };
    }
  );

  // Tool 2: unmask_text
  server.tool(
    'unmask_text',
    'Restores masked session placeholders (e.g. [ANTHROPIC_API_KEY_1]) in agent response back to original secret values using the secure in-memory vault. Writes content directly to disk at outputFilePath to prevent exposing plaintext secrets in context.',
    {
      text: z.string().describe('The text containing session placeholders to restore'),
      outputFilePath: z
        .string()
        .describe(
          'Target file path where restored content will be written. Required: plaintext secrets are never exposed in model context.'
        )
    },
    async ({ text, outputFilePath }) => {
      if (!options.allowUnmaskText) {
        return {
          isError: true,
          content: [
            {
              type: 'text',
              text:
                'Error: unmask_text is disabled. It can write any secret of this session into any file, so a ' +
                'prompt-injected model could copy secrets into files that get published. To change a file that ' +
                'contains secrets, use read_file_redacted and edit_file_redacted instead. If you really need ' +
                'unmask_text, ask the user to start the server with --allow-unmask-text (or AGENT_REDACT_ALLOW_UNMASK_TEXT=1).'
            }
          ]
        };
      }
      if (!outputFilePath || outputFilePath.trim().length === 0) {
        return {
          isError: true,
          content: [
            {
              type: 'text',
              text: 'Error: outputFilePath is required. For security, unmasked secrets cannot be returned to the conversation context.'
            }
          ]
        };
      }

      const outCheck = checkPath(outputFilePath, allowedRoots, 'write');
      if (!outCheck.ok) {
        return securityError('outputFilePath', outputFilePath, outCheck.reason);
      }

      try {
        const restored = unmask(text, sessionVault);
        safeWriteFile(outCheck.realPath, restored, 0o600);
        // Placeholder names are not secret; report them so a capped vault never fails silently.
        // Inspect the caller's input, never `restored`: the result must not depend on plaintext
        // secret values (which could otherwise act as an oracle on their contents).
        const evicted = sessionVault.findEvictedPlaceholders(text);
        const evictionNote =
          evicted.length > 0
            ? ` WARNING: ${evicted.length} placeholder(s) could not be restored because they were evicted from the session vault (limit ${vaultMaxEntries} entries): ${evicted.join(', ')}. Re-run redact_text on the original source to regenerate them.`
            : '';
        return {
          content: [
            {
              type: 'text',
              text: `Successfully restored content to ${outputFilePath}. Plaintext secrets were safely written to disk and remain isolated from model context.${evictionNote}`
            }
          ]
        };
      } catch (err: unknown) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        return {
          isError: true,
          content: [{ type: 'text', text: `Failed writing to ${outputFilePath}: ${errorMsg}` }]
        };
      }
    }
  );

  // Tool 3: scan_file
  server.tool(
    'scan_file',
    'Scans a local file (.env, config, logs) for credentials before importing into agent context window.',
    {
      filePath: z.string().describe('Relative or absolute file path to inspect'),
      reversible: z
        .boolean()
        .default(false)
        .describe('Whether to generate reversible placeholders (default: false for one-way safe scan)'),
      inPlace: z
        .boolean()
        .default(false)
        .describe('If true, sanitizes the file directly in-place on disk after creating a .bak backup'),
      outputFilePath: z
        .string()
        .optional()
        .describe('Optional destination path within workspace to write sanitized content')
    },
    async ({ filePath, reversible, inPlace, outputFilePath }) => {
      const fileCheck = checkPath(filePath, allowedRoots, inPlace ? 'write' : 'read');
      if (!fileCheck.ok) {
        return securityError('filePath', filePath, fileCheck.reason);
      }

      let resolvedOut: string | undefined;
      if (outputFilePath) {
        const outCheck = checkPath(outputFilePath, allowedRoots, 'write');
        if (!outCheck.ok) {
          return securityError('outputFilePath', outputFilePath, outCheck.reason);
        }
        resolvedOut = outCheck.realPath;
      }

      const resolvedFile = fileCheck.realPath;
      if (!existsSync(resolvedFile)) {
        return {
          isError: true,
          content: [
            {
              type: 'text',
              text: `File not found: ${filePath}`
            }
          ]
        };
      }

      const fileStat = statSync(resolvedFile);
      if (fileStat.size > DEFAULT_MAX_SCAN_BYTES) {
        return {
          isError: true,
          content: [
            {
              type: 'text',
              text: `File size (${(fileStat.size / (1024 * 1024)).toFixed(2)} MB) exceeds maximum allowed limit of 5 MB.`
            }
          ]
        };
      }

      // Skip binary files to prevent corrupting non-text data and leaking raw bytes
      if (fileStat.size > 0) {
        if (isBinaryFile(resolvedFile)) {
          return {
            isError: true,
            content: [
              {
                type: 'text',
                text: `Cannot scan binary file: ${filePath}`
              }
            ]
          };
        }
      }

      try {
        const rawContent = readFileSync(resolvedFile, 'utf-8');
        const result = redact(rawContent, { reversible, vault: sessionVault });

        let backupPath: string | null = null;
        let writtenTo: string | null = null;
        if (inPlace) {
          // Only touch the file when there is something to sanitize, and never
          // overwrite an earlier backup (it may hold the only copy of the original secrets).
          if (result.hasLeaks) {
            const realBackup = writeUniqueBackup(resolvedFile, rawContent);
            // Report the backup next to the path the caller used (realpath may differ,
            // e.g. /var -> /private/var on macOS or 8.3 short names on Windows)
            backupPath = filePath + realBackup.slice(resolvedFile.length);
            safeWriteFile(resolvedFile, result.text);
            writtenTo = filePath;
          }
        } else if (resolvedOut) {
          safeWriteFile(resolvedOut, result.text);
          writtenTo = outputFilePath ?? null;
        }

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  filePath,
                  sanitizedContent: result.text,
                  hasLeaks: result.hasLeaks,
                  totalLeaks: result.totalLeaks,
                  stats: result.stats,
                  durationMs: result.durationMs,
                  backupCreated: backupPath,
                  backupWarning: backupPath
                    ? 'Backup contains the ORIGINAL plaintext secrets. Keep it out of version control and delete it when no longer needed.'
                    : undefined,
                  writtenTo
                },
                null,
                2
              )
            }
          ]
        };
      } catch (err: unknown) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        return {
          isError: true,
          content: [{ type: 'text', text: `Failed reading/writing file ${filePath}: ${errorMsg}` }]
        };
      }
    }
  );

  // Tools 7 & 8: read_file_redacted / edit_file_redacted. Each file gets its own vault, so
  // placeholders are numbered per file and an edit can only restore that file's own secrets.
  const fileVaults = new Map<string, Vault>();
  const errorResult = (text: string) => ({ isError: true, content: [{ type: 'text' as const, text }] });
  const jsonResult = (value: unknown) => ({ content: [{ type: 'text' as const, text: JSON.stringify(value, null, 2) }] });

  type Loaded = { realPath: string; content: string; mode: number };
  const loadTextFile = (filePath: string, mode: 'read' | 'write'): Loaded | ReturnType<typeof errorResult> => {
    const check = checkPath(filePath, allowedRoots, mode);
    if (!check.ok) return securityError('filePath', filePath, check.reason);
    if (!existsSync(check.realPath)) return errorResult(`File not found: ${filePath}`);
    const stat = statSync(check.realPath);
    if (!stat.isFile()) return errorResult(`Not a regular file: ${filePath}`);
    if (stat.size > DEFAULT_MAX_SCAN_BYTES) {
      return errorResult(`File size (${(stat.size / (1024 * 1024)).toFixed(2)} MB) exceeds maximum allowed limit of 5 MB.`);
    }
    if (stat.size > 0 && isBinaryFile(check.realPath)) return errorResult(`Cannot handle binary file: ${filePath}`);
    return { realPath: check.realPath, content: readFileSync(check.realPath, 'utf-8'), mode: stat.mode };
  };

  server.tool(
    'read_file_redacted',
    'Reads a text file with every secret replaced by a placeholder unique to that file (e.g. [AWS_ACCESS_KEY_ID_1]). ' +
      'Use it instead of Read for files that contain secrets (.env, configs, credentials), then change them with ' +
      'edit_file_redacted. Secret values never enter the conversation. Returns the redacted content and a revision.',
    {
      filePath: z.string().describe('Relative or absolute path of the file to read')
    },
    async ({ filePath }) => {
      const loaded = loadTextFile(filePath, 'read');
      if ('isError' in loaded) return loaded;
      let vault = fileVaults.get(loaded.realPath);
      if (!vault) {
        vault = new Vault();
        fileVaults.set(loaded.realPath, vault);
      }
      const result = redact(loaded.content, { reversible: true, vault });
      return jsonResult({
        filePath,
        content: result.text,
        revision: sha256(loaded.content),
        totalSecrets: result.totalLeaks,
        stats: result.stats
      });
    }
  );

  server.tool(
    'edit_file_redacted',
    'Edits a file previously read with read_file_redacted, working on the redacted text: oldString must match the ' +
      'redacted content exactly (placeholders included) and be unique unless replaceAll is set. Placeholders of this ' +
      'file in newString are written back as the real secrets; placeholders from other files are refused. Pass the ' +
      'revision from the last read or edit; the edit is refused if the file changed in between.',
    {
      filePath: z.string().describe('Path of a file already read with read_file_redacted'),
      oldString: z.string().describe('Exact text to replace, as shown by read_file_redacted'),
      newString: z.string().describe('Replacement text; may contain this file\'s placeholders'),
      replaceAll: z.boolean().default(false).describe('Replace every occurrence of oldString'),
      revision: z.string().describe('Revision returned by the last read_file_redacted / edit_file_redacted call')
    },
    async ({ filePath, oldString, newString, replaceAll, revision }) => {
      const loaded = loadTextFile(filePath, 'write');
      if ('isError' in loaded) return loaded;
      const vault = fileVaults.get(loaded.realPath);
      if (!vault) return errorResult(`Call read_file_redacted first on ${filePath}.`);
      if (sha256(loaded.content) !== revision) {
        return errorResult(`${filePath} changed since read_file_redacted (revision mismatch). Read it again, then retry the edit.`);
      }
      if (oldString === '') return errorResult('oldString must not be empty.');

      const redacted = redact(loaded.content, { reversible: true, vault }).text;
      const crlf = loaded.content.includes('\r\n');
      const toEol = (s: string) => (crlf ? s.replace(/\r?\n/g, '\r\n') : s);
      const oldText = toEol(oldString);
      const newText = toEol(newString);

      const count = redacted.split(oldText).length - 1;
      if (count === 0) return errorResult(`oldString not found in the redacted content of ${filePath}.`);
      if (count > 1 && !replaceAll) {
        return errorResult(`oldString occurs ${count} times in ${filePath}; add surrounding context to make it unique, or set replaceAll.`);
      }

      for (const token of newText.match(PLACEHOLDER_TOKEN_RE) ?? []) {
        if (vault.getOriginal(token) !== undefined) continue;
        const foreign =
          sessionVault.getOriginal(token) !== undefined ||
          [...fileVaults.values()].some((v) => v !== vault && v.getOriginal(token) !== undefined);
        if (foreign) {
          return errorResult(
            `Placeholder ${token} does not belong to this file; secrets cannot be copied between files. ` +
              'Ask the user to add the value themselves.'
          );
        }
        // Not a placeholder of any vault: ordinary text such as "[STEP_1]"
      }

      const updated = replaceAll ? redacted.split(oldText).join(newText) : redacted.replace(oldText, () => newText);
      const evicted = vault.findEvictedPlaceholders(updated);
      if (evicted.length > 0) {
        return errorResult(`Cannot restore ${evicted.join(', ')}: evicted from this file's vault. Read the file again.`);
      }
      const restored = vault.unmask(updated);
      try {
        atomicReplaceFile(loaded.realPath, restored, loaded.mode);
      } catch (err: unknown) {
        return errorResult(`Failed writing ${filePath}: ${err instanceof Error ? err.message : String(err)}`);
      }
      return jsonResult({ filePath, replacements: replaceAll ? count : 1, revision: sha256(restored) });
    }
  );

  // Tool 4: get_vault_status
  server.tool(
    'get_vault_status',
    'Returns summary statistics about currently vaulted secrets (without leaking raw secrets).',
    {},
    async () => {
      const entries = sessionVault.entries().map((e) => ({
        placeholder: e.placeholder,
        patternId: e.patternId,
        category: e.category,
        timestamp: new Date(e.timestamp).toISOString()
      }));

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                vaultSize: sessionVault.size,
                entries
              },
              null,
              2
            )
          }
        ]
      };
    }
  );

  // Tool 5: clear_vault
  server.tool(
    'clear_vault',
    'Purges all stored secrets and token mappings from the session vault.',
    {},
    async () => {
      const count = sessionVault.size;
      sessionVault.clear();
      return {
        content: [
          {
            type: 'text',
            text: `Vault successfully cleared. Purged ${count} secret(s).`
          }
        ]
      };
    }
  );

  // Tool 6: list_supported_patterns
  server.tool(
    'list_supported_patterns',
    'Returns all built-in credential and PII patterns recognized by agent-redact.',
    {},
    async () => {
      const patterns = DEFAULT_PATTERNS.map((p) => ({
        id: p.id,
        name: p.name,
        category: p.category,
        severity: p.severity,
        placeholder: p.placeholder,
        description: p.description
      }));

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({ totalPatterns: patterns.length, patterns }, null, 2)
          }
        ]
      };
    }
  );

  return server;
}

/** `args`: the arguments after `agent-redact mcp` (or of `agent-redact-mcp`) */
export async function runMcpServer(args: string[] = process.argv.slice(2)): Promise<void> {
  const server = createMcpServer(mcpOptionsFromArgs(args));
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

