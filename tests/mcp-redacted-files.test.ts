import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { createMcpServer, mcpOptionsFromArgs, type McpServerOptions } from '../src/mcp/server.js';
import { evaluateHook } from '../src/cli/hook.js';

// Token-shaped fixtures are assembled at runtime so none appears verbatim in the repo
const AWS = ['AKIA', 'IOSFODNN7EXAMPLE'].join('');
const AWS2 = ['AKIA', 'ABCDEFGHIJKLMNOP'].join('');
const ANT = ['sk-', 'ant-api03-', 'a'.repeat(93), 'AA'].join('');

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});
function workspace(): string {
  const d = mkdtempSync(join(tmpdir(), 'ar-mcp-edit-'));
  dirs.push(d);
  return d;
}

type Result = { isError: boolean; text: string; json?: any };
async function connect(options: McpServerOptions) {
  const server = createMcpServer(options);
  const [c, s] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'test', version: '1' }, { capabilities: {} });
  await Promise.all([client.connect(c), server.connect(s)]);
  const transcript: string[] = [];
  const call = async (name: string, args: Record<string, unknown>): Promise<Result> => {
    const res = await client.callTool({ name, arguments: args });
    const text = (res.content as Array<{ text: string }>)[0]!.text;
    transcript.push(text);
    let json: unknown;
    try {
      json = JSON.parse(text);
    } catch {
      json = undefined;
    }
    return { isError: res.isError === true, text, json };
  };
  return { client, call, transcript };
}

describe('MCP read_file_redacted / edit_file_redacted', () => {
  it('lists both tools', async () => {
    const { client } = await connect({ allowedRoots: [workspace()] });
    const names = (await client.listTools()).tools.map((t) => t.name);
    expect(names).toEqual(expect.arrayContaining(['read_file_redacted', 'edit_file_redacted']));
  });

  it('reads with stable per-file placeholders and a revision, never the secret', async () => {
    const dir = workspace();
    const file = join(dir, '.env');
    writeFileSync(file, `API_URL=https://x.example\nAWS_KEY=${AWS}\nOTHER=${AWS2}\nDEBUG=false\n`);
    const { call, transcript } = await connect({ allowedRoots: [dir] });
    const first = await call('read_file_redacted', { filePath: file });
    expect(first.isError).toBe(false);
    expect(first.json.content).toBe(
      'API_URL=https://x.example\nAWS_KEY=[AWS_ACCESS_KEY_ID_1]\nOTHER=[AWS_ACCESS_KEY_ID_2]\nDEBUG=false\n'
    );
    expect(first.json.revision).toMatch(/^[0-9a-f]{64}$/);
    expect(first.json.totalSecrets).toBe(2);
    const again = await call('read_file_redacted', { filePath: file });
    expect(again.json.content).toBe(first.json.content);
    expect(again.json.revision).toBe(first.json.revision);
    expect(transcript.join('\n')).not.toContain(AWS);
    expect(transcript.join('\n')).not.toContain(AWS2);
  });

  it('applies edits in redacted space and keeps the real secrets in the file', async () => {
    const dir = workspace();
    const file = join(dir, '.env');
    writeFileSync(file, `API_URL=https://x.example\nAWS_KEY=${AWS}\nDEBUG=false\n`);
    const { call, transcript } = await connect({ allowedRoots: [dir] });
    const { json } = await call('read_file_redacted', { filePath: file });

    const edit = await call('edit_file_redacted', {
      filePath: file,
      oldString: 'DEBUG=false',
      newString: 'DEBUG=true',
      revision: json.revision
    });
    expect(edit.isError).toBe(false);
    expect(edit.json.replacements).toBe(1);
    expect(readFileSync(file, 'utf8')).toBe(`API_URL=https://x.example\nAWS_KEY=${AWS}\nDEBUG=true\n`);

    // Renaming the variable moves the secret within the same file
    const renamed = await call('edit_file_redacted', {
      filePath: file,
      oldString: 'AWS_KEY=[AWS_ACCESS_KEY_ID_1]',
      newString: 'AWS_ACCESS_KEY_ID=[AWS_ACCESS_KEY_ID_1]',
      revision: edit.json.revision
    });
    expect(renamed.isError).toBe(false);
    expect(readFileSync(file, 'utf8')).toBe(`API_URL=https://x.example\nAWS_ACCESS_KEY_ID=${AWS}\nDEBUG=true\n`);
    expect(transcript.join('\n')).not.toContain(AWS);
  });

  it('refuses to copy a secret into a file it does not come from', async () => {
    const dir = workspace();
    const a = join(dir, 'a.env');
    const b = join(dir, 'b.md');
    writeFileSync(a, `KEY=${ANT}\n`);
    writeFileSync(b, '# Notes\n');
    const { call } = await connect({ allowedRoots: [dir] });
    await call('read_file_redacted', { filePath: a }); // [ANTHROPIC_API_KEY_1] lives in a.env's vault
    const { json } = await call('read_file_redacted', { filePath: b });
    const res = await call('edit_file_redacted', {
      filePath: b,
      oldString: '# Notes',
      newString: '# Notes\nleaked: [ANTHROPIC_API_KEY_1]',
      revision: json.revision
    });
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/does not belong to this file/);
    expect(readFileSync(b, 'utf8')).toBe('# Notes\n');

    // Placeholder-shaped text unknown to every vault is ordinary text
    const ok = await call('edit_file_redacted', { filePath: b, oldString: '# Notes', newString: '# Notes [STEP_1]', revision: json.revision });
    expect(ok.isError).toBe(false);
    expect(readFileSync(b, 'utf8')).toBe('# Notes [STEP_1]\n');
  });

  it('refuses stale revisions, unread files, missing and ambiguous matches', async () => {
    const dir = workspace();
    const file = join(dir, 'config.yml');
    writeFileSync(file, `a: 1\nb: 1\nkey: ${AWS}\n`);
    const { call } = await connect({ allowedRoots: [dir] });

    const unread = await call('edit_file_redacted', { filePath: file, oldString: 'a: 1', newString: 'a: 2', revision: 'x' });
    expect(unread.isError).toBe(true);
    expect(unread.text).toMatch(/read_file_redacted first/);

    const { json } = await call('read_file_redacted', { filePath: file });
    const missing = await call('edit_file_redacted', { filePath: file, oldString: 'zzz', newString: 'y', revision: json.revision });
    expect(missing.text).toMatch(/not found/);
    const ambiguous = await call('edit_file_redacted', { filePath: file, oldString: ': 1', newString: ': 2', revision: json.revision });
    expect(ambiguous.text).toMatch(/2 times/);
    const all = await call('edit_file_redacted', { filePath: file, oldString: ': 1', newString: ': 2', replaceAll: true, revision: json.revision });
    expect(all.json.replacements).toBe(2);
    expect(readFileSync(file, 'utf8')).toBe(`a: 2\nb: 2\nkey: ${AWS}\n`);

    writeFileSync(file, `a: 9\nb: 2\nkey: ${AWS}\n`); // changed behind the agent's back
    const stale = await call('edit_file_redacted', { filePath: file, oldString: 'b: 2', newString: 'b: 3', revision: all.json.revision });
    expect(stale.isError).toBe(true);
    expect(stale.text).toMatch(/changed since/);
    expect(readFileSync(file, 'utf8')).toBe(`a: 9\nb: 2\nkey: ${AWS}\n`);
  });

  it('keeps CRLF line endings', async () => {
    const dir = workspace();
    const file = join(dir, 'win.env');
    writeFileSync(file, `A=1\r\nKEY=${AWS}\r\nB=2\r\n`);
    const { call } = await connect({ allowedRoots: [dir] });
    const { json } = await call('read_file_redacted', { filePath: file });
    const res = await call('edit_file_redacted', { filePath: file, oldString: 'A=1\nKEY', newString: 'A=10\nKEY', revision: json.revision });
    expect(res.isError).toBe(false);
    expect(readFileSync(file, 'utf8')).toBe(`A=10\r\nKEY=${AWS}\r\nB=2\r\n`);
  });

  it('stays inside the allowed roots and out of .git', async () => {
    const dir = workspace();
    const outside = workspace();
    writeFileSync(join(outside, 'x.env'), `K=${AWS}\n`);
    mkdirSync(join(dir, '.git'));
    writeFileSync(join(dir, '.git', 'config'), '[core]\n');
    const { call } = await connect({ allowedRoots: [dir] });
    expect((await call('read_file_redacted', { filePath: join(outside, 'x.env') })).text).toMatch(/Security error/);
    const { json } = await call('read_file_redacted', { filePath: join(dir, '.git', 'config') });
    const res = await call('edit_file_redacted', { filePath: join(dir, '.git', 'config'), oldString: '[core]', newString: '[x]', revision: json.revision });
    expect(res.text).toMatch(/Security error/);
  });
});

describe('MCP unmask_text is opt-in', () => {
  it('refuses by default and explains how to enable it', async () => {
    const dir = workspace();
    const { call } = await connect({ allowedRoots: [dir] });
    const res = await call('unmask_text', { text: 'x', outputFilePath: join(dir, 'out.txt') });
    expect(res.isError).toBe(true);
    expect(res.text).toMatch(/--allow-unmask-text/);
  });

  it('works when enabled', async () => {
    const dir = workspace();
    const { call } = await connect({ allowedRoots: [dir], allowUnmaskText: true });
    const r = await call('redact_text', { text: `k ${AWS}`, reversible: true });
    const out = join(dir, 'out.txt');
    expect((await call('unmask_text', { text: r.json.sanitizedText, outputFilePath: out })).isError).toBe(false);
    expect(readFileSync(out, 'utf8')).toBe(`k ${AWS}`);
  });

  it('is enabled by the --allow-unmask-text flag or AGENT_REDACT_ALLOW_UNMASK_TEXT=1', () => {
    expect(mcpOptionsFromArgs([], {}).allowUnmaskText).toBe(false);
    expect(mcpOptionsFromArgs(['--allow-unmask-text'], {}).allowUnmaskText).toBe(true);
    expect(mcpOptionsFromArgs([], { AGENT_REDACT_ALLOW_UNMASK_TEXT: '1' }).allowUnmaskText).toBe(true);
    expect(() => mcpOptionsFromArgs(['--bogus'], {})).toThrow(/Unknown/);
  });
});

describe('Claude Code hook and the redacted file tools', () => {
  it('lets read_file_redacted through on a secret file and points blocked reads at it', () => {
    const dir = workspace();
    const file = join(dir, '.env');
    writeFileSync(file, `KEY=${AWS}\n`);
    const read = evaluateHook({ hook_event_name: 'PreToolUse', tool_name: 'Read', tool_input: { file_path: file }, cwd: dir });
    expect(read.block).toBe(true);
    expect(read.message).toMatch(/read_file_redacted/);
    expect(read.message).toMatch(/edit_file_redacted/);
    expect(
      evaluateHook({ hook_event_name: 'PreToolUse', tool_name: 'mcp__agent-redact__read_file_redacted', tool_input: { filePath: file }, cwd: dir }).block
    ).toBe(false);
  });

  it('lets edit_file_redacted through with placeholders, but blocks literal secrets in its input', () => {
    const dir = workspace();
    const file = join(dir, '.env');
    writeFileSync(file, `KEY=${AWS}\n`);
    const tool_name = 'mcp__agent-redact__edit_file_redacted';
    const ok = evaluateHook({
      hook_event_name: 'PreToolUse',
      tool_name,
      tool_input: { filePath: file, oldString: 'KEY=[AWS_ACCESS_KEY_ID_1]', newString: 'AWS_KEY=[AWS_ACCESS_KEY_ID_1]', revision: 'r' },
      cwd: dir
    });
    expect(ok.block).toBe(false);
    const literal = evaluateHook({
      hook_event_name: 'PreToolUse',
      tool_name,
      tool_input: { filePath: file, oldString: 'KEY', newString: `KEY2=${AWS2}`, revision: 'r' },
      cwd: dir
    });
    expect(literal.block).toBe(true);
  });
});
