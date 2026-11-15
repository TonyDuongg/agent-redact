import { describe, it, expect, afterEach } from 'vitest';
import { spawn, spawnSync, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { join } from 'node:path';
import { VERSION } from '../src/version.js';

const cliPath = join(process.cwd(), 'dist', 'cli', 'index.js');
// Token-shaped fixtures are assembled at runtime so none appears verbatim in the repo
const AWS = ['AKIA', 'IOSFODNN7EXAMPLE'].join('');
const AWS2 = ['AKIA', 'ABCDEFGHIJKLMNOP'].join('');

type Response = { jsonrpc: string; id: number | string | null; result?: any; error?: { code: number; message: string } };

/** A worker process plus a line-oriented request/response helper. */
class Worker {
  readonly proc: ChildProcessWithoutNullStreams;
  readonly lines: string[] = [];
  stderr = '';
  private waiters: Array<() => void> = [];
  private buf = '';
  readonly exited: Promise<number | null>;

  constructor(env: Record<string, string> = {}, args = ['serve', '--stdio']) {
    this.proc = spawn(process.execPath, [cliPath, ...args], { env: { ...process.env, ...env } });
    this.proc.stdout.setEncoding('utf8');
    this.proc.stdout.on('data', (chunk: string) => {
      this.buf += chunk;
      let nl: number;
      while ((nl = this.buf.indexOf('\n')) !== -1) {
        this.lines.push(this.buf.slice(0, nl));
        this.buf = this.buf.slice(nl + 1);
      }
      this.waiters.splice(0).forEach((w) => w());
    });
    this.proc.stderr.on('data', (d) => (this.stderr += d));
    this.exited = new Promise((resolve) => this.proc.on('exit', (code) => resolve(code)));
  }

  async next(): Promise<Response> {
    while (this.lines.length === 0) await new Promise<void>((r) => this.waiters.push(r));
    return JSON.parse(this.lines.shift()!) as Response;
  }

  sendRaw(line: string): void {
    this.proc.stdin.write(line + '\n');
  }

  private id = 0;
  async call(method: string, params: unknown = {}): Promise<Response> {
    const id = ++this.id;
    this.sendRaw(JSON.stringify({ jsonrpc: '2.0', id, method, params }));
    const res = await this.next();
    expect(res.id).toBe(id);
    return res;
  }
}

const workers: Worker[] = [];
const start = (env?: Record<string, string>, args?: string[]) => {
  const w = new Worker(env, args);
  workers.push(w);
  return w;
};
afterEach(() => {
  for (const w of workers.splice(0)) w.proc.kill();
});

describe('agent-redact serve --stdio (worker for the Python package)', () => {
  it('answers version with the package version', async () => {
    const w = start();
    expect(await w.call('version')).toEqual({ jsonrpc: '2.0', id: 1, result: { version: VERSION } });
  });

  it('redact returns the same result shape as `--json`, never the secret values', async () => {
    const w = start();
    const res = await w.call('redact', { text: `key ${AWS} end` });
    expect(res.result.text).toBe('key [REDACTED_AWS_ACCESS_KEY_ID] end');
    expect(res.result.totalLeaks).toBe(1);
    expect(res.result.matches[0]).toMatchObject({ patternId: 'aws-access-key-id', startIndex: 4, endIndex: 24 });
    expect(JSON.stringify(res)).not.toContain(AWS);

    const cli = spawnSync(process.execPath, [cliPath, '--json'], { input: `key ${AWS} end`, encoding: 'utf8' });
    const viaCli = JSON.parse(cli.stdout);
    expect({ ...res.result, durationMs: 0 }).toEqual({ ...viaCli, durationMs: 0 });
  });

  it('applies presets per request and rejects unknown ones without dying', async () => {
    const w = start();
    const cccd = ['079', '2', '03', '012345'].join('');
    expect((await w.call('redact', { text: `CCCD ${cccd}` })).result.text).toBe(`CCCD ${cccd}`);
    expect((await w.call('redact', { text: `CCCD ${cccd}`, presets: ['vn-pii'] })).result.text).toBe('CCCD [REDACTED_VN_CITIZEN_ID]');
    const bad = await w.call('redact', { text: 'x', presets: ['nope'] });
    expect(bad.error?.message).toMatch(/Unknown preset/);
    expect((await w.call('version')).result.version).toBe(VERSION);
  });

  it('sessions keep an in-memory vault: consistent numbering across calls and unmask', async () => {
    const w = start();
    const { session } = (await w.call('session.open', {})).result;
    expect(session).toMatch(/^[0-9a-f-]{36}$/);
    expect((await w.call('redact', { session, text: `first ${AWS}` })).result.text).toBe('first [AWS_ACCESS_KEY_ID_1]');
    expect((await w.call('redact', { session, text: `second ${AWS2} and ${AWS}` })).result.text).toBe(
      'second [AWS_ACCESS_KEY_ID_2] and [AWS_ACCESS_KEY_ID_1]'
    );
    expect((await w.call('unmask', { session, text: 'use [AWS_ACCESS_KEY_ID_2]' })).result.text).toBe(`use ${AWS2}`);

    // A second session is independent
    const other = (await w.call('session.open', {})).result.session;
    expect((await w.call('unmask', { session: other, text: '[AWS_ACCESS_KEY_ID_1]' })).result.text).toBe('[AWS_ACCESS_KEY_ID_1]');

    expect((await w.call('session.close', { session })).result).toEqual({ closed: true });
    const gone = await w.call('unmask', { session, text: 'x' });
    expect(gone.error?.message).toMatch(/Unknown session/);
  });

  it('reports protocol errors as JSON-RPC errors and keeps serving', async () => {
    const w = start();
    w.sendRaw('{not json');
    expect((await w.next()).error?.code).toBe(-32700);
    w.sendRaw(JSON.stringify({ jsonrpc: '2.0', id: 7, method: 'nope', params: {} }));
    expect(await w.next()).toMatchObject({ id: 7, error: { code: -32601 } });
    w.sendRaw(JSON.stringify({ jsonrpc: '2.0', id: 8, method: 'redact', params: { text: 42 } }));
    expect(await w.next()).toMatchObject({ id: 8, error: { code: -32602 } });
    w.sendRaw(JSON.stringify({ id: 9, method: 'version' }));
    expect(await w.next()).toMatchObject({ id: 9, error: { code: -32600 } });
    expect((await w.call('version')).result.version).toBe(VERSION);
  });

  it('writes only protocol lines to stdout, and exits 0 when stdin closes', async () => {
    const w = start();
    await w.call('redact', { text: `noise ${AWS}`, entropy: true });
    w.proc.stdin.end();
    expect(await w.exited).toBe(0);
    for (const line of w.lines) expect(() => JSON.parse(line)).not.toThrow();
  });

  it('rejects an oversized message and exits non-zero (fail closed)', async () => {
    const w = start({ AGENT_REDACT_SERVE_MAX_BYTES: '1024' });
    w.sendRaw(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'redact', params: { text: 'a'.repeat(4096) } }));
    const res = await w.next();
    expect(res).toMatchObject({ id: null, error: { code: -32600 } });
    expect(res.error!.message).toMatch(/too large/);
    expect(await w.exited).not.toBe(0);
  });

  it('requires the --stdio transport', async () => {
    const res = spawnSync(process.execPath, [cliPath, 'serve'], { encoding: 'utf8', input: '' });
    expect(res.status).toBe(2);
    expect(res.stderr).toMatch(/--stdio/);
  });
});
