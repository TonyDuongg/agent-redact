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
  statSync,
  constants as fsConstants
} from 'node:fs';
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

export async function runMcpServer(): Promise<void> {
  const server = createMcpServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

