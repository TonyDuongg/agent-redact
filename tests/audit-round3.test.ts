import { describe, it, expect, afterEach } from 'vitest';
import { redact, Vault } from '../src/index.js';
import { createMcpServer } from '../src/mcp/server.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import {
  writeFileSync,
  readFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  symlinkSync,
  rmSync,
  unlinkSync,
  rmdirSync,
  lstatSync
} from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';

const sampleKey = (...parts: string[]) => parts.join('');

async function connectClient(allowedRoots: string[]): Promise<Client> {
  const server = createMcpServer({ allowedRoots });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'audit-round3', version: '1.0.0' }, { capabilities: {} });
  await Promise.all([client.connect(clientTransport), server.connect(serverTransport)]);
  return client;
}

function replyText(res: unknown): string {
  return (res as { content: Array<{ text: string }> }).content[0]!.text;
}

describe('Audit round 3: remaining findings', () => {
  describe('IPv6 false positives in source code', () => {
    it('does not redact Python slices', () => {
      const code = 'evens = arr[::2]; odds = arr[1::2]; rev = s[::3]';
      expect(redact(code).text).toBe(code);
    });

    it('does not redact hex-looking C++/Rust namespace paths', () => {
      const code = 'db::add(x); ab::cd; Fade::Add; dead::beef';
      expect(redact(code).text).toBe(code);
    });

    it('still redacts real compressed and full IPv6 addresses', () => {
      const addrs = [
        'fe80::1ff:fe23:4567:890a',
        '2001:db8::1',
        'fe80::1',
        'ff02::1',
        '::1',
        '2001:0db8:85a3:0000:0000:8a2e:0370:7334'
      ];
      for (const a of addrs) {
        expect(redact(`addr ${a} end`).text).toBe('addr [REDACTED_IPV6_ADDRESS] end');
      }
    });

    it('redacts bracketed IPv6 hosts in URLs', () => {
      expect(redact('http://[2001:db8::1]:8080/').text).toBe('http://[[REDACTED_IPV6_ADDRESS]]:8080/');
    });
  });

  describe('Credential URL false positives', () => {
    it('does not treat "host:port/@path" URLs as basic-auth credentials', () => {
      const text = 'http://localhost:5173/@vite/client https://registry.npmjs.org:443/@types/node';
      expect(redact(text).text).toBe(text);
    });

    it('does not treat "host:port/@path" database URLs as credentials', () => {
      const text = 'postgres://db.internal:5432/@weird-path';
      expect(redact(text).text).toBe(text);
    });

    it('still redacts real basic-auth and database credentials', () => {
      expect(redact('https://admin:hunter2pass@internal.example.com/api').text).toBe(
        '[REDACTED_BASIC_AUTH_URL]'
      );
      expect(redact('postgres://admin:S3cret@10.0.0.5:5432').text).toBe('[REDACTED_DATABASE_URL]');
      expect(redact('redis://:MyRedisPass@localhost:6379/0').text).toBe('[REDACTED_DATABASE_URL]');
    });
  });

  describe('Reversible vault correctness', () => {
    it('rejects a customFormatter that maps two different secrets to the same placeholder', () => {
      const key1 = sampleKey('AKIA', 'IOSFODNN7EXAMPLE');
      const key2 = 'ghp_' + 'a'.repeat(36);
      expect(() =>
        redact(`${key1} and ${key2}`, { reversible: true, customFormatter: () => '[SECRET]' })
      ).toThrow(/same placeholder/i);
    });

    it('allows a customFormatter that reuses a placeholder for the same secret', () => {
      const key = sampleKey('AKIA', 'IOSFODNN7EXAMPLE');
      const res = redact(`${key} again ${key}`, {
        reversible: true,
        customFormatter: () => '[SECRET]'
      });
      expect(res.text).toBe('[SECRET] again [SECRET]');
      expect(res.vault!.unmask('[SECRET]')).toBe(key);
    });

    it('does not duplicate entries when the same entries are restored twice', () => {
      const res = redact(`${sampleKey('AKIA', 'IOSFODNN7EXAMPLE')} ${'ghp_' + 'b'.repeat(36)}`, {
        reversible: true
      });
      const json = res.vault!.toJSON();
      const v = Vault.fromJSON(json);
      v.restoreEntries(JSON.parse(json));
      expect(v.entries()).toHaveLength(2);
      expect(v.size).toBe(2);
    });
  });

  describe('MCP file sandbox', () => {
    const dirs: string[] = [];
    const links: string[] = [];

    afterEach(() => {
      // Remove links first so cleanup can never traverse into the link target.
      for (const l of links.splice(0)) {
        try {
          if (lstatSync(l).isSymbolicLink() || process.platform === 'win32') {
            process.platform === 'win32' ? rmdirSync(l) : unlinkSync(l);
          }
        } catch {
          // ignore
        }
      }
      for (const d of dirs.splice(0)) {
        rmSync(d, { recursive: true, force: true });
      }
    });

    function makeTmpDir(prefix: string): string {
      const d = mkdtempSync(join(tmpdir(), prefix));
      dirs.push(d);
      return d;
    }

    /** sandbox/escape -> outside (a sibling temp dir that is NOT an allowed root) */
    function makeEscapeLink(): { sandbox: string; outside: string; link: string } {
      const sandbox = makeTmpDir('ar-sandbox-');
      const outside = makeTmpDir('ar-outside-');
      const link = join(sandbox, 'escape');
      symlinkSync(outside, link, process.platform === 'win32' ? 'junction' : 'dir');
      links.push(link);
      return { sandbox, outside, link };
    }

    it('rejects paths outside the configured roots', async () => {
      const sandbox = makeTmpDir('ar-sandbox-');
      const outside = makeTmpDir('ar-outside-');
      writeFileSync(join(outside, 'secret.env'), 'X=1');

      const client = await connectClient([sandbox]);
      const res = await client.callTool({
        name: 'scan_file',
        arguments: { filePath: join(outside, 'secret.env') }
      });
      expect(res.isError).toBe(true);
      await client.close();
    });

    it('rejects reads that escape the sandbox through a symlink/junction', async () => {
      const { sandbox, outside, link } = makeEscapeLink();
      writeFileSync(join(outside, 'secret.env'), 'X=1');

      const client = await connectClient([sandbox]);
      const res = await client.callTool({
        name: 'scan_file',
        arguments: { filePath: join(link, 'secret.env') }
      });
      expect(res.isError).toBe(true);
      expect(replyText(res)).toMatch(/outside the allowed directories/);
      await client.close();
    });

    it('rejects writes that escape the sandbox through a symlink/junction', async () => {
      const { sandbox, outside, link } = makeEscapeLink();

      const client = await connectClient([sandbox]);
      const res = await client.callTool({
        name: 'unmask_text',
        arguments: { text: 'hello', outputFilePath: join(link, 'escaped.txt') }
      });
      expect(res.isError).toBe(true);
      expect(existsSync(join(outside, 'escaped.txt'))).toBe(false);
      await client.close();
    });

    it('refuses to write inside a .git directory', async () => {
      const repo = makeTmpDir('ar-gitdir-');
      const hookPath = join(repo, '.git', 'hooks', 'pre-commit');
      mkdirSync(dirname(hookPath), { recursive: true });

      const client = await connectClient([repo]);
      const res = await client.callTool({
        name: 'unmask_text',
        arguments: { text: '#!/bin/sh\necho pwned', outputFilePath: hookPath }
      });
      expect(res.isError).toBe(true);
      expect(existsSync(hookPath)).toBe(false);
      await client.close();
    });

    it('refuses .git aliases (trailing dot/space) and alternate data stream paths', async () => {
      const repo = makeTmpDir('ar-gitalias-');
      mkdirSync(join(repo, '.git', 'hooks'), { recursive: true });

      const client = await connectClient([repo]);
      for (const outputFilePath of [
        join(repo, '.git.', 'hooks', 'pre-commit'),
        join(repo, '.git ', 'hooks', 'pre-commit'),
        join(repo, 'notes.txt:hidden-stream')
      ]) {
        const res = await client.callTool({
          name: 'unmask_text',
          arguments: { text: 'x', outputFilePath }
        });
        expect(res.isError, outputFilePath).toBe(true);
      }
      expect(existsSync(join(repo, '.git', 'hooks', 'pre-commit'))).toBe(false);
      await client.close();
    });

    it('never overwrites an existing .bak backup on repeated in-place scans', async () => {
      const dir = makeTmpDir('ar-bak-');
      const file = join(dir, 'victim.env');
      const key = sampleKey('AKIA', 'IOSFODNN7EXAMPLE');
      writeFileSync(file, `AWS=${key}\n`, 'utf-8');

      const client = await connectClient([dir]);
      await client.callTool({ name: 'scan_file', arguments: { filePath: file, inPlace: true } });
      const second = await client.callTool({
        name: 'scan_file',
        arguments: { filePath: file, inPlace: true }
      });

      // first backup keeps the original secret
      expect(readFileSync(`${file}.bak`, 'utf-8')).toBe(`AWS=${key}\n`);
      // second scan had nothing to sanitize, so no new backup or write
      expect(JSON.parse(replyText(second)).backupCreated).toBeNull();

      // a new leak with an existing .bak goes to a fresh backup file
      writeFileSync(file, `AWS=${key}\nNEW=${'ghp_' + 'c'.repeat(36)}\n`, 'utf-8');
      const third = await client.callTool({
        name: 'scan_file',
        arguments: { filePath: file, inPlace: true }
      });
      const thirdBackup = JSON.parse(replyText(third)).backupCreated as string;
      expect(thirdBackup).not.toBe(`${file}.bak`);
      expect(readFileSync(thirdBackup, 'utf-8')).toContain('ghp_');
      expect(readFileSync(`${file}.bak`, 'utf-8')).toBe(`AWS=${key}\n`);
      await client.close();
    });
  });
});
