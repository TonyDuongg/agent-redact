/**
 * `agent-redact serve --stdio`: a long-lived worker speaking newline-delimited JSON-RPC 2.0 on
 * stdin/stdout. The Python package keeps one worker per process instead of starting Node for
 * every call. Only stdio is supported (no network listener), so no other process can connect.
 *
 * Methods:
 *   version                                      -> { version }
 *   redact   { text, presets?, entropy?, config?, cwd?, session? } -> RedactResult (no values)
 *   unmask   { text, session }                   -> { text }
 *   session.open  { presets?, entropy?, config?, cwd? } -> { session }
 *   session.close { session }                    -> { closed }
 *
 * Session vaults live only in this process's memory. stdout carries protocol lines only.
 */
import { randomUUID } from 'node:crypto';
import type { Readable, Writable } from 'node:stream';
import { redact, unmask } from '../core/engine.js';
import { Vault } from '../core/vault.js';
import { loadConfig } from '../core/config.js';
import { resolvePresets } from '../patterns/presets.js';
import type { RedactOptions } from '../core/types.js';
import { VERSION } from '../version.js';

const HARD_MAX_BYTES = 64 * 1024 * 1024;
const MAX_SESSIONS = 1024;

const PARSE_ERROR = -32700;
const INVALID_REQUEST = -32600;
const METHOD_NOT_FOUND = -32601;
const INVALID_PARAMS = -32602;
const APPLICATION_ERROR = -32000;

class RpcError extends Error {
  constructor(
    readonly code: number,
    message: string
  ) {
    super(message);
  }
}

interface Session {
  vault: Vault;
  options: RedactOptions;
}

/** The message size limit; the environment may only lower it (used by tests). */
function maxBytes(): number {
  const raw = Number(process.env.AGENT_REDACT_SERVE_MAX_BYTES);
  return Number.isInteger(raw) && raw > 0 ? Math.min(raw, HARD_MAX_BYTES) : HARD_MAX_BYTES;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function optionalString(params: Record<string, unknown>, key: string): string | undefined {
  const value = params[key];
  if (value === undefined || value === null) return undefined;
  if (typeof value !== 'string') throw new RpcError(INVALID_PARAMS, `"${key}" must be a string`);
  return value;
}

function requiredString(params: Record<string, unknown>, key: string): string {
  const value = optionalString(params, key);
  if (value === undefined) throw new RpcError(INVALID_PARAMS, `"${key}" is required`);
  return value;
}

/** The same options the CLI builds from --config / --preset / --entropy and the config file. */
function buildOptions(params: Record<string, unknown>): RedactOptions {
  const presets = params.presets ?? [];
  if (!Array.isArray(presets) || !presets.every((p) => typeof p === 'string')) {
    throw new RpcError(INVALID_PARAMS, '"presets" must be an array of strings');
  }
  if (params.entropy !== undefined && typeof params.entropy !== 'boolean') {
    throw new RpcError(INVALID_PARAMS, '"entropy" must be a boolean');
  }
  const cwd = optionalString(params, 'cwd') ?? process.cwd();
  try {
    const config = loadConfig(optionalString(params, 'config'), cwd);
    const effectivePresets = [...(config?.presets ?? []), ...(presets as string[])];
    resolvePresets(effectivePresets); // throws on unknown names
    return {
      include: config?.include,
      exclude: config?.exclude,
      allowlist: config?.allowlist,
      customPatterns: config?.customPatterns,
      detectHighEntropy: params.entropy === true || (config?.detectHighEntropy ?? false),
      presets: effectivePresets,
      entropy: config?.entropy
    };
  } catch (err) {
    throw new RpcError(APPLICATION_ERROR, err instanceof Error ? err.message : String(err));
  }
}

export function createHandler(): (method: string, params: Record<string, unknown>) => unknown {
  const sessions = new Map<string, Session>();

  const getSession = (params: Record<string, unknown>): Session => {
    const id = requiredString(params, 'session');
    const session = sessions.get(id);
    if (!session) throw new RpcError(APPLICATION_ERROR, 'Unknown session (closed, or the worker restarted)');
    return session;
  };

  return (method, params) => {
    switch (method) {
      case 'version':
        return { version: VERSION };

      case 'redact': {
        const text = requiredString(params, 'text');
        if (params.session !== undefined) {
          const session = getSession(params);
          const { vault: _vault, ...result } = redact(text, { ...session.options, reversible: true, vault: session.vault });
          return result;
        }
        const { vault: _vault, ...result } = redact(text, buildOptions(params));
        return result;
      }

      case 'unmask': {
        const text = requiredString(params, 'text');
        return { text: unmask(text, getSession(params).vault) };
      }

      case 'session.open': {
        if (sessions.size >= MAX_SESSIONS) throw new RpcError(APPLICATION_ERROR, `Too many open sessions (${MAX_SESSIONS})`);
        const id = randomUUID();
        sessions.set(id, { vault: new Vault(), options: buildOptions(params) });
        return { session: id };
      }

      case 'session.close':
        return { closed: sessions.delete(requiredString(params, 'session')) };

      default:
        throw new RpcError(METHOD_NOT_FOUND, `Method not found: ${method}`);
    }
  };
}

function respond(handle: ReturnType<typeof createHandler>, line: string): object {
  let message: unknown;
  try {
    message = JSON.parse(line);
  } catch {
    return { jsonrpc: '2.0', id: null, error: { code: PARSE_ERROR, message: 'Parse error' } };
  }
  const id = isObject(message) && (typeof message.id === 'number' || typeof message.id === 'string') ? message.id : null;
  if (!isObject(message) || message.jsonrpc !== '2.0' || id === null || typeof message.method !== 'string') {
    return { jsonrpc: '2.0', id, error: { code: INVALID_REQUEST, message: 'Invalid request' } };
  }
  const params = message.params ?? {};
  if (!isObject(params)) {
    return { jsonrpc: '2.0', id, error: { code: INVALID_PARAMS, message: '"params" must be an object' } };
  }
  try {
    return { jsonrpc: '2.0', id, result: handle(message.method, params) };
  } catch (err) {
    const code = err instanceof RpcError ? err.code : APPLICATION_ERROR;
    // Engine errors never contain input text; report only the message
    return { jsonrpc: '2.0', id, error: { code, message: err instanceof Error ? err.message : String(err) } };
  }
}

/** Runs the worker until stdin ends. Returns the process exit code. */
export async function runServe(
  args: string[],
  input: Readable = process.stdin,
  output: Writable = process.stdout,
  errors: Writable = process.stderr
): Promise<number> {
  if (args.length !== 1 || args[0] !== '--stdio') {
    errors.write('Usage: agent-redact serve --stdio   (newline-delimited JSON-RPC 2.0 on stdin/stdout)\n');
    return 2;
  }
  const limit = maxBytes();
  const handle = createHandler();

  const write = (obj: object): Promise<void> =>
    new Promise((resolve) => {
      if (output.write(JSON.stringify(obj) + '\n')) resolve();
      else output.once('drain', resolve);
    });

  let pending: Buffer[] = [];
  let pendingBytes = 0;
  for await (const chunk of input as AsyncIterable<Buffer>) {
    let data = chunk;
    let nl: number;
    while ((nl = data.indexOf(0x0a)) !== -1) {
      const line = Buffer.concat([...pending, data.subarray(0, nl)]).toString('utf8').replace(/\r$/, '');
      pending = [];
      pendingBytes = 0;
      data = data.subarray(nl + 1);
      if (Buffer.byteLength(line) > limit) {
        await write({ jsonrpc: '2.0', id: null, error: { code: INVALID_REQUEST, message: `Message too large (limit ${limit} bytes)` } });
        return 1;
      }
      if (line.trim() !== '') await write(respond(handle, line));
    }
    pending.push(data);
    pendingBytes += data.length;
    // Fail closed on an unterminated oversized line instead of buffering without bound
    if (pendingBytes > limit) {
      await write({ jsonrpc: '2.0', id: null, error: { code: INVALID_REQUEST, message: `Message too large (limit ${limit} bytes)` } });
      return 1;
    }
  }
  return 0;
}
