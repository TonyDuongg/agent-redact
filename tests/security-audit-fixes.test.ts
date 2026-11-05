import { describe, it, expect } from 'vitest';
import { redact, createRedactStream, createExpressMiddleware } from '../src/index.js';
import { createMcpServer } from '../src/mcp/server.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { writeFileSync, unlinkSync, existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

const execFileAsync = promisify(execFile);
const cliPath = join(process.cwd(), 'dist', 'cli', 'index.js');
const sampleKey = (...parts: string[]) => parts.join('');

describe('Security Audit Fixes & Verification', () => {
  describe('1. Secret Leak Prevention (--json & JSON.stringify)', () => {
    it('should never expose raw secret in JSON.stringify(result)', () => {
      const secret = sampleKey('AKIA', 'IOSFODNN7EXAMPLE');
      const r = redact(`my aws key is ${secret}`, { reversible: true });
      const serialized = JSON.stringify(r);

      expect(serialized).not.toContain(secret);
      expect(JSON.parse(serialized).hasLeaks).toBe(true);
      expect(JSON.parse(serialized).text).toContain('[AWS_ACCESS_KEY_ID_1]');
    });
  });

  describe('2. Allowlist Precision (No substring or empty string leaks)', () => {
    it('should not skip redaction when allowlist token is a substring of the secret', () => {
      const fullKey = sampleKey('sk-ant-api03-', 'a'.repeat(30), 'test', 'b'.repeat(60));
      const res = redact(`key=${fullKey}`, { allowlist: ['test'] });
      expect(res.text).toBe('key=[REDACTED_ANTHROPIC_API_KEY]');
      expect(res.hasLeaks).toBe(true);
    });

    it('should not allow empty string to match all secrets', () => {
      const secret = sampleKey('AKIA', 'IOSFODNN7EXAMPLE');
      const res = redact(secret, { allowlist: [''] });
      expect(res.text).toBe('[REDACTED_AWS_ACCESS_KEY_ID]');
      expect(res.hasLeaks).toBe(true);
    });
  });

  describe('3. MCP Server unmask_text & scan_file safety', () => {
    it('should safely unmask to file when outputFilePath is specified in MCP', async () => {
      const server = createMcpServer();
      const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
      const client = new Client({ name: 'test-mcp', version: '1.0.0' }, { capabilities: {} });
      await Promise.all([client.connect(clientTransport), server.connect(serverTransport)]);

      const key = sampleKey('AKIA', 'IOSFODNN7EXAMPLE');
      await client.callTool({
        name: 'redact_text',
        arguments: { text: `aws_key=${key}`, reversible: true }
      });

      const tempOut = join(tmpdir(), `mcp-unmask-test-${Date.now()}.txt`);
      const unmaskCall = await client.callTool({
        name: 'unmask_text',
        arguments: {
          text: 'aws_key=[AWS_ACCESS_KEY_ID_1]',
          outputFilePath: tempOut
        }
      });

      const reply = (unmaskCall.content as Array<{ text: string }>)[0]!.text;
      expect(reply).toContain('Successfully restored content to');
      expect(reply).not.toContain(key);

      const diskContent = readFileSync(tempOut, 'utf-8');
      expect(diskContent).toBe(`aws_key=${key}`);
      unlinkSync(tempOut);

      await client.close();
    });

    it('should support scan_file with inPlace and outputFilePath', async () => {
      const server = createMcpServer();
      const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
      const client = new Client({ name: 'test-mcp', version: '1.0.0' }, { capabilities: {} });
      await Promise.all([client.connect(clientTransport), server.connect(serverTransport)]);

      const key = sampleKey('ghp_', 'a'.repeat(36));
      const tempIn = join(tmpdir(), `mcp-scan-in-${Date.now()}.txt`);
      const tempOut = join(tmpdir(), `mcp-scan-out-${Date.now()}.txt`);
      writeFileSync(tempIn, `GH_TOKEN=${key}`, 'utf-8');

      const call = await client.callTool({
        name: 'scan_file',
        arguments: {
          filePath: tempIn,
          outputFilePath: tempOut
        }
      });

      const result = JSON.parse((call.content as Array<{ text: string }>)[0]!.text);
      expect(result.hasLeaks).toBe(true);
      expect(existsSync(tempOut)).toBe(true);
      expect(readFileSync(tempOut, 'utf-8')).toBe('GH_TOKEN=[REDACTED_GITHUB_TOKEN]');

      unlinkSync(tempIn);
      unlinkSync(tempOut);
      await client.close();
    });
  });

  describe('4. Pattern Accuracy (Database URLs, OpenAI, PGP, CC Luhn)', () => {
    it('should redact Database URLs without path or with query strings', () => {
      const u1 = 'postgres://admin:SuperS3cret@db.example.com:5432';
      const u2 = 'mongodb+srv://user:P4ssw0rd@cluster0.abc.mongodb.net/?retryWrites=true';
      const u3 = 'redis://:MyRedisPass@localhost:6379/0';

      expect(redact(u1).text).toBe('[REDACTED_DATABASE_URL]');
      expect(redact(u2).text).toBe('[REDACTED_DATABASE_URL]');
      expect(redact(u3).text).toBe('[REDACTED_DATABASE_URL]');
    });

    it('should redact OpenAI project keys exceeding 160 characters', () => {
      const longProj = sampleKey('sk-proj-', 'A'.repeat(100), '-', 'B'.repeat(70));
      expect(redact(longProj).text).toBe('[REDACTED_OPENAI_API_KEY]');
    });

    it('should redact PGP Private Key blocks and Encrypted PKCS8 keys', () => {
      const pgp = '-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQOYBFsecret...\n-----END PGP PRIVATE KEY BLOCK-----';
      const encrypted = '-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFHDBOBgkq...\n-----END ENCRYPTED PRIVATE KEY-----';

      expect(redact(pgp).text).toBe('[REDACTED_PRIVATE_KEY]');
      expect(redact(encrypted).text).toBe('[REDACTED_PRIVATE_KEY]');
    });

    it('should redact formatted credit cards and reject non-Luhn numbers', () => {
      const validDashed = '4111-1111-1111-1111';
      const validSpaced = '4111 1111 1111 1111';
      expect(redact(validDashed).text).toBe('[REDACTED_CREDIT_CARD]');
      expect(redact(validSpaced).text).toBe('[REDACTED_CREDIT_CARD]');

      // Invalid Luhn
      const invalidLuhn = '4111-1111-1111-1112';
      expect(redact(invalidLuhn).text).toBe(invalidLuhn);
    });

    it('should not false positive on math/code expressions for phone numbers', () => {
      const code = 'const x = a+12345; n = i+1000;';
      expect(redact(code).text).toBe(code);
    });
  });

  describe('5. Stream Processing with StringDecoder & PEM Boundary', () => {
    it('should preserve split multibyte UTF-8 characters across chunks', async () => {
      const stream = createRedactStream();
      let output = '';
      stream.on('data', (d) => (output += d));

      const buf = Buffer.from('Xin chào Việt Nam\n', 'utf8');
      await new Promise<void>((res) => {
        stream.on('end', res);
        stream.write(buf.subarray(0, 7));
        stream.write(buf.subarray(7));
        stream.end();
      });

      expect(output).toBe('Xin chào Việt Nam\n');
    });

    it('should not split trailing keys across chunks after PEM block', async () => {
      const stream = createRedactStream();
      let output = '';
      stream.on('data', (d) => (output += d));

      const key = sampleKey('AKIA', 'IOSFODNN7EXAMPLE');
      await new Promise<void>((res) => {
        stream.on('end', res);
        stream.write(
          '-----BEGIN PRIVATE KEY-----\nMIIabc\n-----END PRIVATE KEY-----\nnext ' + key.slice(0, 10)
        );
        stream.write(key.slice(10) + '\n');
        stream.end();
      });

      expect(output).toContain('[REDACTED_PRIVATE_KEY]');
      expect(output).toContain('next [REDACTED_AWS_ACCESS_KEY_ID]\n');
      expect(output).not.toContain(key);
    });

    it('should process consecutive PEM blocks correctly', async () => {
      const stream = createRedactStream();
      let output = '';
      stream.on('data', (d) => (output += d));

      await new Promise<void>((res) => {
        stream.on('end', res);
        stream.write(
          '-----BEGIN PRIVATE KEY-----\nAAA\n-----END PRIVATE KEY-----\n-----BEGIN RSA PRIVATE KEY-----\nKEY1\n'
        );
        stream.write('KEY2\n-----END RSA PRIVATE KEY-----\n');
        stream.end();
      });

      expect(output).toBe('[REDACTED_PRIVATE_KEY]\n[REDACTED_PRIVATE_KEY]\n');
    });
  });

  describe('6. CLI Multi-File & Pre-commit Exit Code', () => {
    it('should exit code 1 when secrets are detected across multiple files in pre-commit mode', async () => {
      const f1 = join(tmpdir(), `pre-commit-1-${Date.now()}.txt`);
      const f2 = join(tmpdir(), `pre-commit-2-${Date.now()}.txt`);
      const key = sampleKey('AKIA', 'IOSFODNN7EXAMPLE');

      writeFileSync(f1, `AWS_KEY=${key}`, 'utf-8');
      writeFileSync(f2, 'clean file content', 'utf-8');

      try {
        await execFileAsync(process.execPath, [cliPath, f1, f2]);
        expect.fail('Should have exited with code 1');
      } catch (err: any) {
        expect(err.code).toBe(1);
        expect(err.stderr).toContain('Audit failed');
      } finally {
        if (existsSync(f1)) unlinkSync(f1);
        if (existsSync(f2)) unlinkSync(f2);
      }
    });

    it('should exit code 0 when all files are clean in pre-commit mode', async () => {
      const f1 = join(tmpdir(), `pre-commit-clean-1-${Date.now()}.txt`);
      const f2 = join(tmpdir(), `pre-commit-clean-2-${Date.now()}.txt`);

      writeFileSync(f1, 'clean content 1', 'utf-8');
      writeFileSync(f2, 'clean content 2', 'utf-8');

      const { stderr } = await execFileAsync(process.execPath, [cliPath, f1, f2]);
      expect(stderr).toContain('All 2 files are clean');

      unlinkSync(f1);
      unlinkSync(f2);
    });
  });

  describe('7. Express Middleware Deep Structures', () => {
    it('should redact Anthropic content blocks, system prompts, and string arrays', () => {
      const mw = createExpressMiddleware();
      const key = sampleKey('AKIA', 'IOSFODNN7EXAMPLE');

      const req: any = {
        body: {
          system: `System key: ${key}`,
          messages: [
            {
              role: 'user',
              content: [{ type: 'text', text: `My key is ${key}` }]
            }
          ],
          input: [key]
        }
      };

      mw(req, null, () => {});

      expect(req.body.system).toContain('[AWS_ACCESS_KEY_ID_1]');
      expect(req.body.messages[0].content[0].text).toContain('[AWS_ACCESS_KEY_ID_1]');
      expect(req.body.input[0]).toBe('[AWS_ACCESS_KEY_ID_1]');
      expect(req.redact.totalLeaks).toBe(3);
    });
  });
});
