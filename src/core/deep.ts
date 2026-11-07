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

type Obj = Record<string, unknown>;

const isPlainObject = (v: unknown): v is Obj => {
  if (typeof v !== 'object' || v === null) return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
};

/**
 * Policy for restoring secrets inside model-generated tool-call inputs.
 * `false` (default) keeps placeholders there: a prompt-injected model could otherwise
 * smuggle a placeholder into e.g. an HTTP tool's URL and have the real secret sent out.
 * `true` restores every tool; a function decides per tool name.
 */
export type ToolInputPolicy = boolean | ((toolName: string) => boolean);

export function isToolUnmaskAllowed(policy: ToolInputPolicy | undefined, toolName: string): boolean {
  if (policy === true) return true;
  if (typeof policy === 'function') return policy(toolName);
  return false;
}

/**
 * Returns the tool name when `parent[key]` holds model-generated tool arguments:
 * Anthropic `{ type: 'tool_use', name, input }`, OpenAI `{ name, arguments }`
 * (chat `function`, legacy `function_call`, Responses API `function_call` items).
 */
function toolInputSlot(key: string, parent: Obj): string | null {
  if (key === 'input' && parent['type'] === 'tool_use') return String(parent['name'] ?? '');
  if (key === 'arguments' && typeof parent['name'] === 'string') return parent['name'];
  return null;
}

const BASE64_RE = /^[A-Za-z0-9+/_-]*={0,2}$/;
const TEXT_MIME_RE =
  /^(?:text\/|application\/(?:json|xml|yaml|x-yaml|toml|x-toml|javascript|ecmascript|x-sh|x-shellscript|sql|csv|x-ndjson)\b)|\+(?:json|xml)\b/i;

interface Base64Payload {
  mime: string | undefined;
  encoded: string;
  rebuild: (encoded: string) => string;
}

/** Locates a base64 payload: a `data:…;base64,` URL, or a `data` field next to a media type */
function findBase64Payload(value: string, key: string | undefined, parent: Obj | undefined): Base64Payload | null {
  const dataUrl = /^data:([^;,]*)((?:;[^;,]*)*);base64,/i.exec(value.slice(0, 512));
  if (dataUrl) {
    const head = dataUrl[0];
    return { mime: dataUrl[1] || undefined, encoded: value.slice(head.length), rebuild: (e) => head + e };
  }
  if (key === 'data' && parent && (parent['type'] === 'base64' || 'media_type' in parent || 'mime_type' in parent)) {
    const mime = parent['media_type'] ?? parent['mime_type'];
    return { mime: typeof mime === 'string' ? mime : undefined, encoded: value, rebuild: (e) => e };
  }
  return null;
}

function mapStrings(
  value: unknown,
  fn: (s: string, key: string | undefined, parent: Obj | undefined) => string,
  skipProp: (key: string, parent: Obj) => boolean,
  seen = new WeakMap<object, unknown>(),
  key?: string,
  parent?: Obj
): unknown {
  if (typeof value === 'string') return fn(value, key, parent);
  if (Array.isArray(value)) {
    if (seen.has(value)) return seen.get(value);
    const out: unknown[] = [];
    seen.set(value, out);
    for (const item of value) out.push(mapStrings(item, fn, skipProp, seen, key, parent));
    return out;
  }
  if (isPlainObject(value)) {
    if (seen.has(value)) return seen.get(value);
    const out: Obj = {};
    seen.set(value, out);
    for (const [k, v] of Object.entries(value)) {
      out[k] = skipProp(k, value) ? v : mapStrings(v, fn, skipProp, seen, k, value);
    }
    return out;
  }
  // Class instances (Dates, Buffers, SDK objects) are returned untouched
  return value;
}

/**
 * Redacts every string inside a JSON-like value (e.g. an Anthropic or OpenAI request body)
 * with one shared vault, so placeholders are numbered consistently across messages.
 * Reversible by default. The input is not mutated.
 *
 * Base64 payloads (`data:…;base64,` URLs, `data` next to a media type) fail closed:
 * - content that is not actually base64 is redacted like any other string;
 * - base64 that decodes to text (text MIME type, or no NUL bytes) is decoded, redacted
 *   and re-encoded, because the model reads the decoded document;
 * - genuine binary (images, audio, PDFs with binary streams) is left byte-for-byte intact.
 *   Text inside binary formats such as PDFs is NOT scanned.
 */
export function redactDeep<T>(value: T, options: DeepRedactOptions = {}): DeepRedactResult<T> {
  const { vault = new Vault(), skipKeys = [], ...redactOptions } = options;
  const reversible = redactOptions.reversible ?? true;
  const skip = new Set(skipKeys);
  const stats: Record<string, number> = {};
  let totalLeaks = 0;

  const scan = (s: string): string => {
    const res = redact(s, { ...redactOptions, reversible, vault });
    totalLeaks += res.totalLeaks;
    for (const [id, n] of Object.entries(res.stats)) stats[id] = (stats[id] ?? 0) + n;
    return res.text;
  };

  const out = mapStrings(
    value,
    (s, key, parent) => {
      const payload = findBase64Payload(s, key, parent);
      if (payload) {
        // Only MIME line breaks are allowed inside base64; stripping all whitespace would let
        // "AKIA… and more" pass the base64 check and skip redaction
        const compact = payload.encoded.replace(/\r?\n/g, '');
        if (BASE64_RE.test(compact)) {
          const bytes = Buffer.from(compact, 'base64');
          const textual = (payload.mime !== undefined && TEXT_MIME_RE.test(payload.mime)) || !bytes.includes(0);
          if (!textual) return s; // genuine binary: never rewritten
          const decoded = bytes.toString('utf8');
          const redacted = scan(decoded);
          return redacted === decoded ? s : payload.rebuild(Buffer.from(redacted, 'utf8').toString('base64'));
        }
        // Declared as base64 but is not: treat as ordinary text (fail closed)
      }
      return scan(s);
    },
    (k) => skip.has(k)
  ) as T;

  return { value: out, vault, totalLeaks, stats };
}

export interface UnmaskDeepOptions {
  /** See {@link ToolInputPolicy}. Default `false`: tool-call inputs keep their placeholders. */
  unmaskToolInputs?: ToolInputPolicy;
}

/**
 * Restores placeholders in every string of a JSON-like value (e.g. an SDK response).
 * Model-generated tool-call inputs are left masked unless `unmaskToolInputs` allows it.
 * Returns a deep copy; the input is not mutated.
 */
export function unmaskDeep<T>(value: T, vault: Vault, options: UnmaskDeepOptions = {}): T {
  const policy = options.unmaskToolInputs;
  return mapStrings(
    value,
    (s) => vault.unmask(s),
    (k, parent) => {
      const tool = toolInputSlot(k, parent);
      return tool !== null && !isToolUnmaskAllowed(policy, tool);
    }
  ) as T;
}
