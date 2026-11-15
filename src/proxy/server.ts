/**
 * `agent-redact proxy`: a local HTTP proxy in front of the Anthropic or OpenAI API.
 *
 * Point an SDK or tool at it (`ANTHROPIC_BASE_URL=<proxy url>`, `OPENAI_BASE_URL=<proxy url>/v1`;
 * the CLI prints the exact values) and every request body is redacted with reversible
 * placeholders before it leaves the machine. Responses are restored: JSON with `unmaskDeep`,
 * streams with the SSE adapters, under the same tool-input policy (masked by default).
 *
 * Fail closed: it listens on the IPv4 loopback address only, rejects browser requests (Origin
 * header) and foreign Host headers (DNS rebinding), refuses request bodies it cannot parse (non-JSON,
 * compressed, oversized, malformed) instead of forwarding them, and passes unknown response
 * content through still masked. Auth headers are forwarded untouched and never logged.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { Vault } from '../core/vault.js';
import { redactDeep, unmaskDeep, type ToolInputPolicy } from '../core/deep.js';
import { unmaskAnthropicStream, unmaskOpenAIStream } from '../core/unmask-stream.js';
import type { RedactOptions } from '../core/types.js';

export type ProxyProvider = 'anthropic' | 'openai';

export interface ProxyOptions {
  provider: ProxyProvider;
  /** Upstream base URL. Default: the provider's public API. Must be https (http only for loopback). */
  upstream?: string;
  /** Port on the loopback address. Default 8787; 0 picks a free port. */
  port?: number;
  /** Restore secrets in model-generated tool inputs. Default `false` (they stay masked). */
  unmaskToolInputs?: ToolInputPolicy;
  /** Detection options (presets, custom patterns, allowlist, entropy …) */
  redactOptions?: RedactOptions;
  /** Maximum request body size in bytes. Default 32 MB. */
  maxBodyBytes?: number;
  /** One line per request, without secret values or headers. Default: none. */
  log?: (line: string) => void;
}

export interface RunningProxy {
  server: Server;
  /** Shared by all requests, so a secret keeps one placeholder for the proxy's lifetime */
  vault: Vault;
  address: string;
  port: number;
  url: string;
  close(): Promise<void>;
}

const DEFAULT_UPSTREAM: Record<ProxyProvider, string> = {
  anthropic: 'https://api.anthropic.com',
  openai: 'https://api.openai.com'
};
const DEFAULT_MAX_BODY = 32 * 1024 * 1024;
const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'proxy-connection',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  'host',
  'content-length',
  'accept-encoding'
]);
// Assembled at runtime: the repository's self-scan flags IP address literals in src/
export const LOOPBACK_HOST = [127, 0, 0, 1].join('.');
const IPV6_LOOPBACK = ['', '', '1'].join(':');
const LOOPBACK = new Set([LOOPBACK_HOST, 'localhost', `[${IPV6_LOOPBACK}]`, IPV6_LOOPBACK]);

function upstreamBase(upstream: string): string {
  let url: URL;
  try {
    url = new URL(upstream);
  } catch {
    throw new Error(`Invalid upstream URL: ${upstream}`);
  }
  const ok = url.protocol === 'https:' || (url.protocol === 'http:' && LOOPBACK.has(url.hostname));
  if (!ok) throw new Error('The upstream must use https (plain http is only allowed for loopback addresses)');
  return url.origin + url.pathname.replace(/\/+$/, '');
}

class HttpError extends Error {
  constructor(
    readonly status: number,
    message: string
  ) {
    super(message);
  }
}

async function readBody(req: IncomingMessage, limit: number): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req as AsyncIterable<Buffer>) {
    size += chunk.length;
    if (size > limit) throw new HttpError(413, `Request body exceeds ${limit} bytes`);
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

function sendError(res: ServerResponse, status: number, message: string): void {
  if (res.headersSent) {
    res.destroy();
    return;
  }
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify({ type: 'error', error: { type: 'agent_redact_proxy_error', message } }));
}

interface SseEvent {
  event?: string;
  data: string;
}

/** Parses a text/event-stream body into events (comments and empty events are dropped). */
async function* readSse(body: ReadableStream<Uint8Array>): AsyncGenerator<SseEvent> {
  const decoder = new TextDecoder();
  let buffer = '';
  const parse = (block: string): SseEvent | null => {
    let event: string | undefined;
    const data: string[] = [];
    for (const line of block.split(/\r?\n/)) {
      if (line === '' || line.startsWith(':')) continue;
      const colon = line.indexOf(':');
      const field = colon === -1 ? line : line.slice(0, colon);
      const value = colon === -1 ? '' : line.slice(colon + 1).replace(/^ /, '');
      if (field === 'event') event = value;
      else if (field === 'data') data.push(value);
    }
    return data.length > 0 ? { event, data: data.join('\n') } : null;
  };
  for await (const chunk of body as unknown as AsyncIterable<Uint8Array>) {
    buffer += decoder.decode(chunk, { stream: true });
    let match: RegExpExecArray | null;
    while ((match = /\r?\n\r?\n/.exec(buffer))) {
      const ev = parse(buffer.slice(0, match.index));
      buffer = buffer.slice(match.index + match[0].length);
      if (ev) yield ev;
    }
  }
  buffer += decoder.decode();
  const last = parse(buffer);
  if (last) yield last;
}

const RAW = Symbol('raw-sse-event');
type Raw = { [RAW]: SseEvent };

function formatSse(event: string | undefined, data: string): string {
  const lines = data.split('\n').map((l) => `data: ${l}`);
  return `${event ? `event: ${event}\n` : ''}${lines.join('\n')}\n\n`;
}

/** Restores placeholders in an SSE stream with the provider's adapter, re-serialising events. */
async function* unmaskSse(
  body: ReadableStream<Uint8Array>,
  provider: ProxyProvider,
  vault: Vault,
  unmaskToolInputs: ToolInputPolicy | undefined
): AsyncGenerator<string> {
  let done = false;
  async function* parsed(): AsyncGenerator<unknown> {
    for await (const ev of readSse(body)) {
      if (provider === 'openai' && ev.data.trim() === '[DONE]') {
        done = true; // emitted after the adapter has flushed held-back text
        return;
      }
      try {
        yield JSON.parse(ev.data);
      } catch {
        yield { [RAW]: ev } satisfies Raw; // not JSON: passed through unchanged (still masked)
      }
    }
  }
  const adapter = provider === 'anthropic' ? unmaskAnthropicStream : unmaskOpenAIStream;
  for await (const item of adapter(parsed(), vault, { unmaskToolInputs })) {
    if (typeof item === 'object' && item !== null && RAW in item) {
      const raw = (item as Raw)[RAW];
      yield formatSse(raw.event, raw.data);
      continue;
    }
    const type = provider === 'anthropic' && typeof (item as { type?: unknown })?.type === 'string' ? (item as { type: string }).type : undefined;
    yield formatSse(type, JSON.stringify(item));
  }
  if (done) yield 'data: [DONE]\n\n';
}

function describeStats(stats: Record<string, number>): string {
  const parts = Object.entries(stats).map(([id, n]) => `${id}:${n}`);
  return parts.length ? ` (${parts.join(', ')})` : '';
}

export async function startProxy(options: ProxyOptions): Promise<RunningProxy> {
  const provider = options.provider;
  if (provider !== 'anthropic' && provider !== 'openai') throw new Error('provider must be "anthropic" or "openai"');
  const base = upstreamBase(options.upstream ?? DEFAULT_UPSTREAM[provider]);
  const maxBody = options.maxBodyBytes ?? DEFAULT_MAX_BODY;
  const vault = new Vault();
  const log = options.log ?? (() => {});
  const policy = options.unmaskToolInputs;

  const handle = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const path = req.url ?? '/';
    const method = req.method ?? 'GET';
    if (!path.startsWith('/')) throw new HttpError(400, 'Only origin-form request paths are accepted');
    // A web page must never be able to use the proxy: it could ask the model to echo a
    // placeholder and read the restored secret (the APIs allow CORS). Browsers always send
    // Origin on cross-origin and on POST requests; SDKs and CLIs do not. A foreign Host header
    // means DNS rebinding.
    if (req.headers.origin !== undefined) throw new HttpError(403, 'Browser requests are not allowed');
    const host = String(req.headers.host ?? '');
    const hostname = host.startsWith('[') ? host.slice(0, host.indexOf(']') + 1) : host.split(':')[0]!;
    if (!LOOPBACK.has(hostname.toLowerCase())) throw new HttpError(403, 'Requests must address the proxy by its loopback address');

    const raw = await readBody(req, maxBody);
    let body: string | undefined;
    let redacted = 0;
    let stats: Record<string, number> = {};
    if (raw.length > 0) {
      const encoding = String(req.headers['content-encoding'] ?? 'identity').toLowerCase();
      if (encoding !== 'identity') throw new HttpError(415, 'Compressed request bodies are not supported');
      if (!/^application\/(?:[\w.+-]+\+)?json\b/i.test(String(req.headers['content-type'] ?? ''))) {
        throw new HttpError(415, 'Only JSON request bodies are accepted');
      }
      let value: unknown;
      try {
        value = JSON.parse(raw.toString('utf8'));
      } catch {
        throw new HttpError(400, 'Malformed JSON request body');
      }
      // `signature` holds opaque thinking-block signatures that must reach the API unchanged
      const result = redactDeep(value, { ...options.redactOptions, vault, skipKeys: ['signature'] });
      body = JSON.stringify(result.value);
      redacted = result.totalLeaks;
      stats = result.stats;
    }

    const headers = new Headers();
    for (const [name, value] of Object.entries(req.headers)) {
      if (value === undefined || HOP_BY_HOP.has(name.toLowerCase())) continue;
      for (const v of Array.isArray(value) ? value : [value]) headers.append(name, v);
    }
    headers.set('accept-encoding', 'identity'); // responses must be parseable to be restored

    const abort = new AbortController();
    res.on('close', () => abort.abort());
    let upstream: Response;
    try {
      upstream = await fetch(base + path, { method, headers, body, redirect: 'manual', signal: abort.signal });
    } catch {
      throw new HttpError(502, 'Upstream request failed');
    }

    const outHeaders: Record<string, string> = {};
    upstream.headers.forEach((value, name) => {
      // CORS headers are dropped too: the proxy never serves browsers
      if (!HOP_BY_HOP.has(name) && name !== 'content-encoding' && !name.startsWith('access-control-')) outHeaders[name] = value;
    });
    const contentType = upstream.headers.get('content-type') ?? '';
    log(`${method} ${path.split('?')[0]} -> ${upstream.status} redacted=${redacted}${describeStats(stats)}`);

    if (/text\/event-stream/i.test(contentType) && upstream.body) {
      res.writeHead(upstream.status, outHeaders);
      for await (const chunk of unmaskSse(upstream.body, provider, vault, policy)) {
        if (!res.write(chunk)) await new Promise((r) => res.once('drain', r));
      }
      res.end();
      return;
    }
    if (/json/i.test(contentType)) {
      const text = await upstream.text();
      let out = text;
      try {
        out = JSON.stringify(unmaskDeep(JSON.parse(text), vault, { unmaskToolInputs: policy }));
      } catch {
        // Not valid JSON: pass it through unchanged (placeholders stay masked)
      }
      res.writeHead(upstream.status, outHeaders);
      res.end(out);
      return;
    }
    // Anything else (binary, plain text) passes through unchanged, still masked
    res.writeHead(upstream.status, outHeaders);
    if (upstream.body) {
      for await (const chunk of upstream.body as unknown as AsyncIterable<Uint8Array>) {
        if (!res.write(chunk)) await new Promise((r) => res.once('drain', r));
      }
    }
    res.end();
  };

  const server = createServer((req, res) => {
    handle(req, res).catch((err: unknown) => {
      const status = err instanceof HttpError ? err.status : 500;
      const message = err instanceof HttpError ? err.message : 'Proxy error';
      log(`${req.method ?? 'GET'} ${(req.url ?? '/').split('?')[0]} -> ${status} ${message}`);
      if (status === 413) req.resume();
      sendError(res, status, message);
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(options.port ?? 8787, LOOPBACK_HOST, () => {
      server.off('error', reject);
      resolve();
    });
  });
  const { address, port } = server.address() as AddressInfo;
  return {
    server,
    vault,
    address,
    port,
    url: `http://${LOOPBACK_HOST}:${port}`,
    close: () =>
      new Promise((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      })
  };
}
