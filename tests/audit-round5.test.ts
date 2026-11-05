import { describe, it, expect, afterEach } from 'vitest';
import { redact, Vault } from '../src/index.js';
import { createMcpServer } from '../src/mcp/server.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

// Assemble token-shaped fixtures at runtime so they never appear verbatim in the repo
const j = (...parts: string[]) => parts.join('');

/**
 * Tokens drawn from base64url end in '-' about 1 time in 64. A trailing `\b` cannot match
 * between '-' and a following space/punctuation, which made fixed-length patterns skip the
 * token entirely and variable-length ones leave the final '-' visible.
 */
const dashTerminated: Array<{ name: string; token: string; placeholder: string }> = [
  { name: 'Telegram bot token', token: j('123456789', ':', 'A'.repeat(34), '-'), placeholder: 'TELEGRAM_BOT_TOKEN' },
  { name: 'GCP OAuth client secret', token: j('GOCSPX', '-', 'b'.repeat(27), '-'), placeholder: 'GCP_OAUTH_CLIENT_SECRET' },
  { name: 'Google API key', token: j('AIza', 'S'.repeat(34), '-'), placeholder: 'GOOGLE_API_KEY' },
  { name: 'SendGrid API key', token: j('SG', '.', 'c'.repeat(22), '.', 'd'.repeat(42), '-'), placeholder: 'SENDGRID_API_KEY' },
  { name: 'GitLab token', token: j('glpat', '-', 'e'.repeat(19), '-'), placeholder: 'GITLAB_TOKEN' },
  { name: 'Discord bot token', token: j('M', 'f'.repeat(23), '.', 'g'.repeat(6), '.', 'h'.repeat(30), '-'), placeholder: 'DISCORD_TOKEN' },
  { name: 'Anthropic API key', token: j('sk-', 'ant-', 'api03-', 'i'.repeat(92), '-'), placeholder: 'ANTHROPIC_API_KEY' },
  { name: 'OpenAI project key', token: j('sk-', 'proj-', 'k'.repeat(60), '-'), placeholder: 'OPENAI_API_KEY' },
  { name: 'JWT', token: j('eyJ', 'hbGciOiJIUzI1NiJ9', '.', 'eyJ', 'zdWIiOiIxMjM0NTY3ODkwIn0', '.', 'sig', 'n'.repeat(20), '-'), placeholder: 'JWT_TOKEN' }
];

describe('Audit round 5', () => {
  describe("tokens whose last character is '-'", () => {
    for (const { name, token, placeholder } of dashTerminated) {
      it(`redacts a ${name} ending in '-' completely`, () => {
        for (const [before, after] of [[' ', ' '], ['"', '",'], ['=', '\n'], [' ', '.'], [' ', '']]) {
          // after === '' means the token ends the input
          const tail = after === '' ? '' : `${after}y`;
          const res = redact(`x${before}${token}${tail}`);
          expect(res.text, `${name} with ${JSON.stringify(after)}`).toBe(
            `x${before}[REDACTED_${placeholder}]${tail}`
          );
        }
      });
    }

    it('keeps the previous behaviour for tokens followed by word characters or by "-suffix"', () => {
      // 36 word chars is not a Telegram token: still not matched
      const notTelegram = j('123456789', ':', 'A'.repeat(35), 'x');
      expect(redact(`bot ${notTelegram} end`).text).toBe(`bot ${notTelegram} end`);
      // a fixed-length secret followed by "-old" is still redacted (fail closed), as before
      const gcp = j('GOCSPX', '-', 'b'.repeat(28));
      expect(redact(`k ${gcp}-old v`).text).toBe('k [REDACTED_GCP_OAUTH_CLIENT_SECRET]-old v');
    });
  });

  describe('IPv4 in version contexts', () => {
    it('does not redact four-part version numbers after a version keyword', () => {
      for (const text of [
        'version 1.0.0.1',
        'Version: 2.4.0.10',
        'ver 10.0.19045.1',
        'v 1.2.3.4',
        'v1.2.3.4',
        'VERSION=4.0.0.1'
      ]) {
        expect(redact(text).text, text).toBe(text);
      }
    });

    it('still redacts real IPv4 addresses, including ones that look like versions', () => {
      expect(redact('dns 1.0.0.1').text).toBe('dns [REDACTED_IPV4_ADDRESS]');
      expect(redact('host 10.0.0.12 port 22').text).toBe('host [REDACTED_IPV4_ADDRESS] port 22');
      expect(redact('server=192.168.1.10').text).toBe('server=[REDACTED_IPV4_ADDRESS]');
    });
  });

  describe('Vault eviction reporting', () => {
    const dirs: string[] = [];
    afterEach(() => {
      for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
    });

    it('lists placeholders that were evicted from a capped vault', () => {
      const v = new Vault({ maxEntries: 2 });
      const first = redact(`a ${j('AKIA', 'IOSFODNN7EXAMPLE')}`, { reversible: true, vault: v });
      redact(`b ${j('ghp_', 'a'.repeat(36))}`, { reversible: true, vault: v });
      redact(`c ${j('ghp_', 'b'.repeat(36))}`, { reversible: true, vault: v });

      expect(v.unmask(first.text)).toBe('a [AWS_ACCESS_KEY_ID_1]');
      expect(v.findEvictedPlaceholders(`${first.text} [GITHUB_TOKEN_2]`)).toEqual([
        '[AWS_ACCESS_KEY_ID_1]'
      ]);
      expect(v.findEvictedPlaceholders('nothing here')).toEqual([]);
    });

    it('makes MCP unmask_text report placeholders it could not restore', async () => {
      const dir = mkdtempSync(join(tmpdir(), 'ar-evict-'));
      dirs.push(dir);
      const server = createMcpServer({ allowedRoots: [dir], vaultMaxEntries: 1 });
      const [c, s] = InMemoryTransport.createLinkedPair();
      const client = new Client({ name: 'round5', version: '1' }, { capabilities: {} });
      await Promise.all([client.connect(c), server.connect(s)]);

      await client.callTool({ name: 'redact_text', arguments: { text: j('AKIA', 'IOSFODNN7EXAMPLE') } });
      await client.callTool({ name: 'redact_text', arguments: { text: j('ghp_', 'a'.repeat(36)) } });

      const out = join(dir, 'restored.txt');
      const res = await client.callTool({
        name: 'unmask_text',
        arguments: { text: '[AWS_ACCESS_KEY_ID_1] and [GITHUB_TOKEN_1]', outputFilePath: out }
      });
      const reply = (res.content as Array<{ text: string }>)[0]!.text;
      await client.close();

      expect(reply).toContain('[AWS_ACCESS_KEY_ID_1]');
      expect(reply).toMatch(/could not be restored/i);
      expect(reply).not.toContain('AKIA');
      expect(readFileSync(out, 'utf-8')).toBe(`[AWS_ACCESS_KEY_ID_1] and ${j('ghp_', 'a'.repeat(36))}`);
    });
  });
});
