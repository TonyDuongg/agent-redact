import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { redact, unmask } from '../core/engine.js';
import { Vault } from '../core/vault.js';
import { DEFAULT_PATTERNS } from '../patterns/index.js';

export function createMcpServer(): McpServer {
  const sessionVault = new Vault();

  const server = new McpServer({
    name: 'agent-redact',
    version: '0.1.0'
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
    'Restores masked session placeholders (e.g. [ANTHROPIC_API_KEY_1]) in agent response back to original secret values using the secure in-memory vault. If outputFilePath is specified, writes to disk directly to isolate credentials from chat context.',
    {
      text: z.string().describe('The text containing session placeholders to restore'),
      outputFilePath: z
        .string()
        .optional()
        .describe(
          'Optional path to file where restored content should be written without leaking plaintext secrets in context'
        )
    },
    async ({ text, outputFilePath }) => {
      const restored = unmask(text, sessionVault);
      if (outputFilePath) {
        writeFileSync(outputFilePath, restored, 'utf-8');
        return {
          content: [
            {
              type: 'text',
              text: `Successfully restored content to ${outputFilePath}. Plaintext secrets were not exposed in context.`
            }
          ]
        };
      }
      return {
        content: [
          {
            type: 'text',
            text: restored
          }
        ]
      };
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
        .describe('If true, sanitizes the file directly in-place on disk'),
      outputFilePath: z
        .string()
        .optional()
        .describe('Optional destination path to write sanitized content')
    },
    async ({ filePath, reversible, inPlace, outputFilePath }) => {
      if (!existsSync(filePath)) {
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

      try {
        const rawContent = readFileSync(filePath, 'utf-8');
        const result = redact(rawContent, { reversible, vault: sessionVault });

        if (inPlace) {
          writeFileSync(filePath, result.text, 'utf-8');
        } else if (outputFilePath) {
          writeFileSync(outputFilePath, result.text, 'utf-8');
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
                  writtenTo: inPlace ? filePath : (outputFilePath ?? null)
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
          content: [{ type: 'text', text: `Failed reading file ${filePath}: ${errorMsg}` }]
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

