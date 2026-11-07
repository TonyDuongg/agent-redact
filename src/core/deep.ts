import { redact } from './engine.js';
import type { RedactOptions } from './types.js';
import { Vault } from './vault.js';

export interface DeepRedactOptions extends RedactOptions {
  /** Vault to reuse across calls (a new one is created otherwise) */
  vault?: Vault;
  /** Object keys whose values are never scanned (in addition to binary payloads) */
  skipKeys?: string[];
}

export interface DeepRedactResult<T> {
  /** Deep copy of the input with every string value redacted */
  value: T;
  /** Vault holding the placeholders, for `unmaskDeep` / streaming unmask of the response */
  vault: Vault;
  totalLeaks: number;
  stats: Record<string, number>;
}

const isPlainObject = (v: unknown): v is Record<string, unknown> => {
  if (typeof v !== 'object' || v === null) return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
};

/**
 * Base64 payloads (images, documents, audio) must never be rewritten: a random match
 * inside them would corrupt the data, and scanning megabytes of base64 is wasted work.
 */
function isBinaryPayload(value: string, key: string | undefined, parent: Record<string, unknown> | undefined): boolean {
  if (value.startsWith('data:') && value.slice(0, 200).includes(';base64,')) return true;
  if (key === 'data' && parent && (parent['type'] === 'base64' || 'media_type' in parent || 'mime_type' in parent)) {
    return true;
  }
  return false;
}

function mapStrings(
  value: unknown,
  fn: (s: string, key: string | undefined, parent: Record<string, unknown> | undefined) => string,
  skipKeys: ReadonlySet<string>,
  seen = new WeakMap<object, unknown>(),
  key?: string,
  parent?: Record<string, unknown>
): unknown {
  if (typeof value === 'string') return fn(value, key, parent);
  if (Array.isArray(value)) {
    if (seen.has(value)) return seen.get(value);
    const out: unknown[] = [];
    seen.set(value, out);
    for (const item of value) out.push(mapStrings(item, fn, skipKeys, seen, key, parent));
    return out;
  }
  if (isPlainObject(value)) {
    if (seen.has(value)) return seen.get(value);
    const out: Record<string, unknown> = {};
    seen.set(value, out);
    for (const [k, v] of Object.entries(value)) {
      out[k] = skipKeys.has(k) ? v : mapStrings(v, fn, skipKeys, seen, k, value);
    }
    return out;
  }
  // Class instances (Dates, Buffers, SDK objects) are returned untouched
  return value;
}

/**
 * Redacts every string inside a JSON-like value (e.g. an Anthropic or OpenAI request body)
 * with one shared vault, so placeholders are numbered consistently across messages.
 * Reversible by default; base64 payloads and `data:` URLs are skipped. The input is not mutated.
 */
export function redactDeep<T>(value: T, options: DeepRedactOptions = {}): DeepRedactResult<T> {
  const { vault = new Vault(), skipKeys = [], ...redactOptions } = options;
  const reversible = redactOptions.reversible ?? true;
  const stats: Record<string, number> = {};
  let totalLeaks = 0;

  const out = mapStrings(
    value,
    (s, key, parent) => {
      if (isBinaryPayload(s, key, parent)) return s;
      const res = redact(s, { ...redactOptions, reversible, vault });
      totalLeaks += res.totalLeaks;
      for (const [id, n] of Object.entries(res.stats)) stats[id] = (stats[id] ?? 0) + n;
      return res.text;
    },
    new Set(skipKeys)
  ) as T;

  return { value: out, vault, totalLeaks, stats };
}

/**
 * Restores placeholders in every string of a JSON-like value (e.g. an SDK response,
 * including `tool_use` inputs). Returns a deep copy; the input is not mutated.
 */
export function unmaskDeep<T>(value: T, vault: Vault): T {
  return mapStrings(value, (s) => vault.unmask(s), new Set()) as T;
}
