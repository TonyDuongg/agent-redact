import { describe, it, expect, afterEach, vi } from 'vitest';
import {
  redact,
  Vault,
  createRedactStream,
  resolveCustomPattern
} from '../src/index.js';
import { createMcpServer } from '../src/mcp/server.js';
import { runAction } from '../src/action/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import {
  writeFileSync,
  readFileSync,
  existsSync,
  mkdtempSync,
  rmSync,
  statSync,
  chmodSync
} from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

const execFileAsync = promisify(execFile);
const cliPath = join(process.cwd(), 'dist', 'cli', 'index.js');
// Assemble token-shaped fixtures at runtime so they never appear verbatim in the repo
const sampleKey = (...parts: string[]) => parts.join('');
const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const pseudoRandom = (n: number, abc = ALNUM) =>
  Array.from({ length: n }, (_, i) => abc[(i * 7919 + 13) % abc.length]).join('');

const dirs: string[] = [];
function makeTmpDir(prefix: string): string {
  const d = mkdtempSync(join(tmpdir(), prefix));
  dirs.push(d);
  return d;
}
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

async function runCli(args: string[], cwd: string) {
  try {
    const { stdout, stderr } = await execFileAsync('node', [cliPath, ...args], { cwd });
    return { code: 0, stdout, stderr };
  } catch (err: unknown) {
    const e = err as { code: number; stdout: string; stderr: string };
    return { code: e.code, stdout: e.stdout, stderr: e.stderr };
  }
}

describe('Audit round 4', () => {
  describe('Custom patterns with capturing groups', () => {
    it('redacts the whole match when a custom regex uses a capturing group for alternation', () => {
      const token = 'acme_' + pseudoRandom(32);
      const res = redact(`token ${token}`, {
        customPatterns: [
          resolveCustomPattern({
            id: 'corp',
            name: 'Corp',
            regex: '(acme|corp)_[A-Za-z0-9]{32}',
            placeholder: 'CORP'
          })
        ]
      });
      expect(res.text).toBe('token [REDACTED_CORP]');
    });

    it('redacts only the named "secret" group when present', () => {
      const res = redact('corp_key = abcd1234efgh5678', {
        customPatterns: [
          resolveCustomPattern({
            id: 'corp-assign',
            name: 'Corp assignment',
            regex: 'corp_key\\s*=\\s*(?<secret>[a-z0-9]{16})',
            placeholder: 'CORP_KEY'
          })
        ]
      });
      expect(res.text).toBe('corp_key = [REDACTED_CORP_KEY]');
    });

    it('honours an explicit secretGroup in custom pattern config', () => {
      const res = redact('corp_key: abcd1234efgh5678', {
        customPatterns: [
          resolveCustomPattern({
            id: 'corp-assign',
            name: 'Corp assignment',
            regex: '(corp_key):\\s*([a-z0-9]{16})',
            placeholder: 'CORP_KEY',
            secretGroup: 2
          })
        ]
      });
      expect(res.text).toBe('corp_key: [REDACTED_CORP_KEY]');
    });

    it('keeps built-in assignment patterns redacting only the value', () => {
      const secret = sampleKey('wJalrXUtnFEMI/K7MDENG/', 'bPxRfiCYEXAMPLEKEY');
      expect(redact(`aws_secret_access_key=${secret}\n`).text).toBe(
        'aws_secret_access_key=[REDACTED_AWS_SECRET_ACCESS_KEY]\n'
      );
    });
  });

  describe('Vendor token coverage', () => {
    it('redacts Stripe keys longer than 99 characters', () => {
      for (const len of [100, 160]) {
        const key = sampleKey('sk', '_', 'live_', pseudoRandom(len));
        expect(redact(`STRIPE=${key}`).text).toBe('STRIPE=[REDACTED_STRIPE_API_KEY]');
      }
    });

    it('redacts 4-part Slack user tokens and still redacts 3-part bot tokens', () => {
      const user = sampleKey('xo', 'xp-', '123456789012-123456789012-123456789012-', pseudoRandom(32, 'abcdef0123456789'));
      const bot = sampleKey('xo', 'xb-', '1234567890123-1234567890123-', pseudoRandom(24));
      expect(redact(`a ${user} b`).text).toBe('a [REDACTED_SLACK_TOKEN] b');
      expect(redact(`a ${bot} b`).text).toBe('a [REDACTED_SLACK_TOKEN] b');
    });

    it('redacts the whole high-entropy token even when it is longer than maxLength', () => {
      const token = pseudoRandom(200);
      const res = redact(`api_key=${token}`, { detectHighEntropy: true });
      expect(res.text).toBe('api_key=[REDACTED_GENERIC_SECRET]');
    });
  });

  describe('Input validation', () => {
    it('rejects custom pattern configs without a placeholder or regex', () => {
      expect(() =>
        resolveCustomPattern({ id: 'x', name: 'x', regex: 'acme_x' } as never)
      ).toThrow(/placeholder/);
      expect(() =>
        resolveCustomPattern({ id: 'x', name: 'x', placeholder: 'X' } as never)
      ).toThrow(/regex/);
    });

    it('rejects malformed vault files with a clear error that never echoes secrets', () => {
      expect(() => Vault.fromJSON('[{}]')).toThrow(/Invalid vault/);
      const secret = sampleKey('AKIA', 'IOSFODNN7EXAMPLE');
      try {
        Vault.fromJSON(JSON.stringify([{ original: secret }]));
        expect.unreachable();
      } catch (e) {
        expect((e as Error).message).toMatch(/Invalid vault/);
        expect((e as Error).message).not.toContain(secret);
      }
    });
  });

  describe('Stream: oversized open PEM block', () => {
    async function runStream(chunks: string[]): Promise<string> {
      const s = createRedactStream();
      let out = '';
      s.on('data', (d) => (out += d));
      await new Promise<void>((resolve) => {
        s.on('end', resolve);
        for (const c of chunks) s.write(c);
        s.end();
      });
      return out;
    }

    it('keeps dropping key body lines after the 1MB buffer limit until the END marker', async () => {
      const out = await runStream([
        '-----BEGIN PRIVATE KEY-----\n' + 'X'.repeat(1_100_000) + '\n',
        'LEAKED_KEY_BODY_LINE\n',
        '-----END PRIVATE KEY-----\nafter\n'
      ]);
      expect(out).not.toContain('LEAKED_KEY_BODY_LINE');
      expect(out).not.toContain('-----END PRIVATE KEY-----');
      expect(out).toContain('[REDACTED_PRIVATE_KEY]');
      expect(out).toContain('after\n');
    });

    it('detects an END marker split across chunks while dropping an oversized block', async () => {
      const out = await runStream([
        '-----BEGIN PRIVATE KEY-----\n' + 'X'.repeat(1_100_000) + '\n',
        'LEAKED\n-----END PRIV',
        'ATE KEY-----\nafter\n'
      ]);
      expect(out).not.toContain('LEAKED');
      expect(out).toContain('after\n');
    });
  });

  describe('MCP scan_file in-place', () => {
    it.runIf(process.platform !== 'win32')('preserves the permissions of the sanitized file', async () => {
      const dir = makeTmpDir('ar-perm-');
      const file = join(dir, 'deploy.sh');
      writeFileSync(file, `#!/bin/sh\nexport K=${sampleKey('AKIA', 'IOSFODNN7EXAMPLE')}\n`);
      chmodSync(file, 0o755);

      const server = createMcpServer({ allowedRoots: [dir] });
      const [c, s] = InMemoryTransport.createLinkedPair();
      const client = new Client({ name: 'round4', version: '1' }, { capabilities: {} });
      await Promise.all([client.connect(c), server.connect(s)]);
      await client.callTool({ name: 'scan_file', arguments: { filePath: file, inPlace: true } });
      await client.close();

      expect(readFileSync(file, 'utf-8')).toContain('[REDACTED_AWS_ACCESS_KEY_ID]');
      expect(statSync(file).mode & 0o777).toBe(0o755);
    });
  });

  describe('CLI reversible in-place safety', () => {
    const key = sampleKey('AKIA', 'IOSFODNN7EXAMPLE');

    it('refuses -r with -i when no --vault-out is given (placeholders would be unrecoverable)', async () => {
      const dir = makeTmpDir('ar-cli-');
      writeFileSync(join(dir, 'c.env'), `A=${key}\n`);
      const res = await runCli(['c.env', '-r', '-i'], dir);
      expect(res.code).toBe(2);
      expect(res.stderr).toMatch(/--vault-out/);
      expect(readFileSync(join(dir, 'c.env'), 'utf-8')).toBe(`A=${key}\n`);
    });

    it('does not modify any file when one of several inputs cannot be read', async () => {
      const dir = makeTmpDir('ar-cli-');
      writeFileSync(join(dir, 'a.env'), `A=${key}\n`);
      writeFileSync(join(dir, 'b.env'), `B=${key}\n`);
      const res = await runCli(['-r', '-i', '--vault-out', 'v.json', 'a.env', 'b.env', 'missing.env'], dir);
      expect(res.code).toBe(1);
      expect(readFileSync(join(dir, 'a.env'), 'utf-8')).toBe(`A=${key}\n`);
      expect(readFileSync(join(dir, 'b.env'), 'utf-8')).toBe(`B=${key}\n`);
    });

    it('writes a vault that restores every file sanitized in multi-file reversible mode', async () => {
      const dir = makeTmpDir('ar-cli-');
      writeFileSync(join(dir, 'a.env'), `A=${key}\n`);
      writeFileSync(join(dir, 'b.env'), `B=${key}\n`);
      await runCli(['-r', '-i', '--vault-out', 'v.json', 'a.env', 'b.env'], dir);
      expect(existsSync(join(dir, 'v.json'))).toBe(true);
      expect(readFileSync(join(dir, 'a.env'), 'utf-8')).not.toContain(key);
      const restored = await runCli(['a.env', '--unmask', 'v.json'], dir);
      expect(restored.stdout).toBe(`A=${key}\n`);
    });
  });

  describe('GitHub Action annotations', () => {
    it('escapes workflow-command properties in file names', async () => {
      const dir = makeTmpDir('ar-annot-');
      // ':' is not allowed in Windows file names, so only ',' is exercised here
      writeFileSync(join(dir, 'a,b.env'), `K=${key4()}\n`);
      const logs: string[] = [];
      const spy = vi.spyOn(console, 'log').mockImplementation((m: unknown) => {
        logs.push(String(m));
      });
      const oldEnv = process.env;
      process.env = { ...oldEnv, INPUT_SCAN_PATH: dir, INPUT_FAIL_ON_LEAK: 'false' };
      try {
        await runAction();
      } finally {
        process.env = oldEnv;
        spy.mockRestore();
      }
      const annotation = logs.find((l) => l.startsWith('::error '));
      expect(annotation).toBeDefined();
      expect(annotation).toContain('a%2Cb.env');
      expect(annotation).not.toContain('a,b.env');
    });
  });
});

function key4(): string {
  return sampleKey('AKIA', 'IOSFODNN7EXAMPLE');
}
