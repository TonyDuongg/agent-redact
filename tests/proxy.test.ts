import { describe, it, expect, afterEach } from 'vitest';
import { createServer, request, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { spawn } from 'node:child_process';
import { join } from 'node:path';
import type { AddressInfo } from 'node:net';
import { startProxy, type RunningProxy } from '../src/proxy/server.js';

// Token-shaped fixtures are assembled at runtime so none appears verbatim in the repo
const AWS = ['AKIA', 'IOSFODNN7EXAMPLE'].join('');
const AWS2 = ['AKIA', 'ABCDEFGHIJKLMNOP'].join('');
const API_KEY = ['test', '-upstream-key'].join('');

interface Recorded {
  method: string;
  url: string;
  headers: IncomingMessage['headers'];
  body: string;
}
type Handler = (req: Recorded, res: ServerResponse) => void;

const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => {
  for (const c of cleanups.splice(0).reverse()) await c();
});

async function fakeUpstream(handler: Handler): Promise<{ url: string; requests: Recorded[] }> {
  const requests: Recorded[] = [];
  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const rec = { method: req.method!, url: req.url!, headers: req.headers, body: Buffer.concat(chunks).toString('utf8') };
      requests.push(rec);
      handler(rec, res);
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  cleanups.push(() => new Promise((r) => server.close(() => r())));
  return { url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, requests };
}

async function proxy(options: Parameters<typeof startProxy>[0]): Promise<RunningProxy & { logs: string[] }> {
  const logs: string[] = [];
  const p = await startProxy({ port: 0, log: (l) => logs.push(l), ...options });
  cleanups.push(() => p.close());
  return Object.assign(p, { logs });
}

const json = (res: ServerResponse, status: number, body: unknown) => {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(body));
};

const sse = (res: ServerResponse, events: string[]) => {
  res.writeHead(200, { 'content-type': 'text/event-stream' });
  // Write events in separate chunks, splitting one event mid-line, like a real network stream
  const all = events.join('');
  const cut = Math.floor(all.length / 2);
  res.write(all.slice(0, cut));
  setTimeout(() => res.end(all.slice(cut)), 10);
};

const post = (url: string, body: unknown, headers: Record<string, string> = {}) =>
  fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', 'x-api-key': API_KEY, ...headers }, body: JSON.stringify(body) });

describe('agent-redact proxy: Anthropic', () => {
  it('binds to 127.0.0.1 only', async () => {
    const up = await fakeUpstream((_r, res) => json(res, 200, {}));
    const p = await proxy({ provider: 'anthropic', upstream: up.url });
    expect(p.address).toBe('127.0.0.1');
  });

  it('never sends the secret upstream, and restores it in the JSON response', async () => {
    const up = await fakeUpstream((req, res) => {
      const placeholder = /\[AWS_ACCESS_KEY_ID_1\]/.exec(req.body)![0];
      json(res, 200, { type: 'message', content: [{ type: 'text', text: `Rotate ${placeholder} now.` }] });
    });
    const p = await proxy({ provider: 'anthropic', upstream: up.url });
    const res = await post(`${p.url}/v1/messages`, {
      model: 'm',
      messages: [{ role: 'user', content: `my key is ${AWS}` }]
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ type: 'message', content: [{ type: 'text', text: `Rotate ${AWS} now.` }] });

    const sent = up.requests[0]!;
    expect(sent.url).toBe('/v1/messages');
    expect(sent.body).not.toContain(AWS);
    expect(JSON.parse(sent.body).messages[0].content).toBe('my key is [AWS_ACCESS_KEY_ID_1]');
    expect(sent.headers['x-api-key']).toBe(API_KEY); // auth is passed through, untouched
    expect(sent.headers['accept-encoding']).toBe('identity'); // so responses can be parsed
    expect(p.logs.join('\n')).not.toContain(AWS);
    expect(p.logs.join('\n')).not.toContain(API_KEY);
  });

  it('uses the same placeholder for the same secret across requests', async () => {
    const up = await fakeUpstream((_r, res) => json(res, 200, { content: [] }));
    const p = await proxy({ provider: 'anthropic', upstream: up.url });
    await post(`${p.url}/v1/messages`, { messages: [{ role: 'user', content: `a ${AWS}` }] });
    await post(`${p.url}/v1/messages`, { messages: [{ role: 'user', content: `b ${AWS2} c ${AWS}` }] });
    expect(JSON.parse(up.requests[1]!.body).messages[0].content).toBe('b [AWS_ACCESS_KEY_ID_2] c [AWS_ACCESS_KEY_ID_1]');
  });

  it('keeps tool_use inputs masked by default, and restores them only for allowed tools', async () => {
    const reply = {
      content: [
        { type: 'tool_use', name: 'Bash', input: { command: 'export K=[AWS_ACCESS_KEY_ID_1]' } },
        { type: 'tool_use', name: 'WebFetch', input: { url: 'https://x.example/?k=[AWS_ACCESS_KEY_ID_1]' } }
      ]
    };
    const up = await fakeUpstream((_r, res) => json(res, 200, reply));
    const strict = await proxy({ provider: 'anthropic', upstream: up.url });
    const body = { messages: [{ role: 'user', content: AWS }] };
    expect(await (await post(`${strict.url}/v1/messages`, body)).json()).toEqual(reply);

    const lenient = await proxy({ provider: 'anthropic', upstream: up.url, unmaskToolInputs: (name) => name === 'Bash' });
    const out = (await (await post(`${lenient.url}/v1/messages`, body)).json()) as typeof reply;
    expect(out.content[0]!.input).toEqual({ command: `export K=${AWS}` });
    expect(out.content[1]!.input).toEqual({ url: 'https://x.example/?k=[AWS_ACCESS_KEY_ID_1]' });
  });

  it('restores placeholders split across SSE deltas and keeps tool JSON deltas masked', async () => {
    const ev = (o: Record<string, unknown>) => `event: ${o.type}\ndata: ${JSON.stringify(o)}\n\n`;
    const up = await fakeUpstream((_r, res) =>
      sse(res, [
        ev({ type: 'message_start', message: { content: [] } }),
        ': keep-alive comment\n\n',
        ev({ type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } }),
        ev({ type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'key [AWS_ACCESS' } }),
        ev({ type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: '_KEY_ID_1] ok' } }),
        ev({ type: 'content_block_stop', index: 0 }),
        ev({ type: 'content_block_start', index: 1, content_block: { type: 'tool_use', name: 'Bash', input: {} } }),
        ev({ type: 'content_block_delta', index: 1, delta: { type: 'input_json_delta', partial_json: '{"command":"[AWS_ACCESS_KEY_ID_1]"}' } }),
        ev({ type: 'content_block_stop', index: 1 }),
        ev({ type: 'message_stop' })
      ])
    );
    const p = await proxy({ provider: 'anthropic', upstream: up.url });
    const res = await post(`${p.url}/v1/messages`, { stream: true, messages: [{ role: 'user', content: AWS }] });
    expect(res.headers.get('content-type')).toMatch(/text\/event-stream/);
    const raw = await res.text();
    const events = raw
      .split('\n\n')
      .filter((b) => b.includes('data: '))
      .map((b) => ({ name: /^event: (.*)$/m.exec(b)?.[1], data: JSON.parse(/^data: (.*)$/m.exec(b)![1]!) }));
    for (const e of events) expect(e.name).toBe(e.data.type);
    const text = events
      .filter((e) => e.data.type === 'content_block_delta' && e.data.delta.type === 'text_delta')
      .map((e) => e.data.delta.text)
      .join('');
    expect(text).toBe(`key ${AWS} ok`);
    const toolJson = events.find((e) => e.data.delta?.type === 'input_json_delta')!.data.delta.partial_json;
    expect(toolJson).toBe('{"command":"[AWS_ACCESS_KEY_ID_1]"}');
    expect(events.at(-1)!.data.type).toBe('message_stop');
  });
});

describe('agent-redact proxy: OpenAI', () => {
  it('restores streamed chat completion content and ends with [DONE]', async () => {
    const chunk = (delta: Record<string, unknown>, finish: string | null = null) =>
      `data: ${JSON.stringify({ choices: [{ index: 0, delta, finish_reason: finish }] })}\n\n`;
    const up = await fakeUpstream((req, res) => {
      expect(req.url).toBe('/v1/chat/completions');
      sse(res, [chunk({ content: 'use [AWS_ACC' }), chunk({ content: 'ESS_KEY_ID_1]' }), chunk({}, 'stop'), 'data: [DONE]\n\n']);
    });
    const p = await proxy({ provider: 'openai', upstream: up.url });
    const res = await post(`${p.url}/v1/chat/completions`, { stream: true, messages: [{ role: 'user', content: AWS }] }, { authorization: `Bearer ${API_KEY}` });
    const blocks = (await res.text()).split('\n\n').filter(Boolean);
    expect(blocks.at(-1)).toBe('data: [DONE]');
    const content = blocks
      .slice(0, -1)
      .map((b) => JSON.parse(b.replace(/^data: /, '')).choices[0].delta.content ?? '')
      .join('');
    expect(content).toBe(`use ${AWS}`);
    expect(up.requests[0]!.body).not.toContain(AWS);
    expect(up.requests[0]!.headers.authorization).toBe(`Bearer ${API_KEY}`);
  });
});

describe('agent-redact proxy: fail closed', () => {
  it('refuses bodies it cannot parse and never forwards them', async () => {
    const up = await fakeUpstream((_r, res) => json(res, 200, {}));
    const p = await proxy({ provider: 'anthropic', upstream: up.url });
    const plain = await fetch(`${p.url}/v1/messages`, { method: 'POST', headers: { 'content-type': 'text/plain' }, body: AWS });
    expect(plain.status).toBe(415);
    const gz = await fetch(`${p.url}/v1/messages`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'content-encoding': 'gzip' },
      body: 'xx'
    });
    expect(gz.status).toBe(415);
    const broken = await fetch(`${p.url}/v1/messages`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: `{"k":"${AWS}"` });
    expect(broken.status).toBe(400);
    expect(up.requests).toHaveLength(0);
  });

  it('refuses oversized bodies', async () => {
    const up = await fakeUpstream((_r, res) => json(res, 200, {}));
    const p = await proxy({ provider: 'anthropic', upstream: up.url, maxBodyBytes: 1024 });
    const res = await post(`${p.url}/v1/messages`, { messages: [{ role: 'user', content: 'a'.repeat(4096) }] });
    expect(res.status).toBe(413);
    expect(up.requests).toHaveLength(0);
  });

  it('passes body-less requests through, and answers 502 when the upstream is down', async () => {
    const up = await fakeUpstream((req, res) => json(res, 200, { data: [{ id: 'm' }], path: req.url }));
    const p = await proxy({ provider: 'openai', upstream: up.url });
    expect(await (await fetch(`${p.url}/v1/models`)).json()).toEqual({ data: [{ id: 'm' }], path: '/v1/models' });

    const dead = await proxy({ provider: 'openai', upstream: 'http://127.0.0.1:9' });
    const res = await post(`${dead.url}/v1/chat/completions`, { messages: [] });
    expect(res.status).toBe(502);
  });

  it('refuses browser requests and foreign Host headers, so a web page cannot read restored secrets', async () => {
    // Attack: a page calls the local proxy with its own API key and asks the model to echo a
    // placeholder; the shared vault would restore the secret, and the API allows CORS.
    const up = await fakeUpstream((_r, res) => {
      res.writeHead(200, { 'content-type': 'application/json', 'access-control-allow-origin': '*' });
      res.end(JSON.stringify({ content: [{ type: 'text', text: '[AWS_ACCESS_KEY_ID_1]' }] }));
    });
    const p = await proxy({ provider: 'anthropic', upstream: up.url });
    await post(`${p.url}/v1/messages`, { messages: [{ role: 'user', content: AWS }] }); // populate the vault

    const send = (headers: Record<string, string>, method = 'POST') =>
      new Promise<{ status: number; body: string; headers: Record<string, unknown> }>((resolve, reject) => {
        const req = request(
          `${p.url}/v1/messages`,
          { method, headers: { 'content-type': 'application/json', ...headers } },
          (res) => {
            let body = '';
            res.on('data', (d) => (body += d));
            res.on('end', () => resolve({ status: res.statusCode!, body, headers: res.headers }));
          }
        );
        req.on('error', reject);
        req.end(method === 'POST' ? JSON.stringify({ messages: [{ role: 'user', content: 'echo' }] }) : undefined);
      });

    const before = up.requests.length;
    const fromPage = await send({ origin: 'https://evil.example' });
    expect(fromPage.status).toBe(403);
    expect(fromPage.body).not.toContain(AWS);
    const preflight = await send({ origin: 'https://evil.example', 'access-control-request-method': 'POST' }, 'OPTIONS');
    expect(preflight.status).toBe(403);
    const rebinding = await send({ host: `evil.example:${p.port}` });
    expect(rebinding.status).toBe(403);
    expect(up.requests.length).toBe(before); // none of them reached the upstream

    const allowed = await send({});
    expect(allowed.status).toBe(200);
    expect(allowed.headers['access-control-allow-origin']).toBeUndefined();
  });

  it('only accepts https upstreams (or loopback for local testing)', async () => {
    await expect(startProxy({ provider: 'openai', upstream: 'http://api.example.com', port: 0 })).rejects.toThrow(/https/);
    await expect(startProxy({ provider: 'openai', upstream: 'ftp://x', port: 0 })).rejects.toThrow(/https/);
  });
});

describe('agent-redact proxy CLI', () => {
  it('requires --provider and prints the base URL to use', async () => {
    const cli = join(process.cwd(), 'dist', 'cli', 'index.js');
    const missing = spawn(process.execPath, [cli, 'proxy']);
    let err = '';
    missing.stderr.on('data', (d) => (err += d));
    expect(await new Promise((r) => missing.on('exit', r))).toBe(2);
    expect(err).toMatch(/--provider/);

    const child = spawn(process.execPath, [cli, 'proxy', '--provider', 'anthropic', '--port', '0']);
    cleanups.push(async () => {
      child.kill();
    });
    const banner = await new Promise<string>((resolve) => {
      let out = '';
      child.stderr.on('data', (d) => {
        out += d;
        if (out.includes('ANTHROPIC_BASE_URL=')) resolve(out);
      });
    });
    expect(banner).toMatch(/ANTHROPIC_BASE_URL=http:\/\/127\.0\.0\.1:\d+/);
  });
});
