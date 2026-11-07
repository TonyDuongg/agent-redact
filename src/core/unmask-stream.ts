import { Transform, type TransformCallback } from 'node:stream';
import { StringDecoder } from 'node:string_decoder';
import type { Vault } from './vault.js';
import { unmaskDeep } from './deep.js';

/** Escapes a restored secret so it can be spliced into a JSON string literal */
export const jsonStringEscape = (secret: string): string => JSON.stringify(secret).slice(1, -1);

/**
 * Incremental unmasker for streamed LLM output. A placeholder such as
 * `[AWS_ACCESS_KEY_ID_1]` can be split across chunks (`[AWS_ACC` | `ESS_KEY_ID_1]`);
 * the unmasker holds back a chunk tail only while it is the beginning of a placeholder
 * that actually exists in the vault, so ordinary text like `[1]` is never delayed.
 */
export class StreamingUnmasker {
  private pending = '';

  constructor(
    private readonly vault: Vault,
    private readonly encode?: (secret: string) => string
  ) {}

  /** Feeds the next chunk and returns the text that is safe to emit now */
  push(chunk: string): string {
    const text = this.pending + chunk;
    this.pending = '';
    const hold = this.holdStart(text);
    if (hold === -1) {
      return this.vault.unmask(text, this.encode);
    }
    this.pending = text.slice(hold);
    return this.vault.unmask(text.slice(0, hold), this.encode);
  }

  /** Returns everything still buffered (call once the stream has ended) */
  flush(): string {
    const rest = this.pending;
    this.pending = '';
    return this.vault.unmask(rest, this.encode);
  }

  private holdStart(text: string): number {
    // Placeholders never contain '[', so only the last one can open an unfinished placeholder
    const open = text.lastIndexOf('[');
    if (open === -1) return -1;
    const tail = text.slice(open);
    if (tail.includes(']')) return -1;
    return this.vault.hasPlaceholderPrefix(tail) ? open : -1;
  }
}

/** Unmasks an async (or sync) iterable of text chunks, e.g. an LLM token stream */
export async function* unmaskTextStream(
  source: AsyncIterable<string> | Iterable<string>,
  vault: Vault
): AsyncGenerator<string> {
  const unmasker = new StreamingUnmasker(vault);
  for await (const chunk of source) {
    const out = unmasker.push(String(chunk));
    if (out) yield out;
  }
  const rest = unmasker.flush();
  if (rest) yield rest;
}

/** Node.js Transform that unmasks placeholders in a byte or text stream */
export class UnmaskTransformStream extends Transform {
  private readonly decoder = new StringDecoder('utf8');
  private readonly unmasker: StreamingUnmasker;

  constructor(vault: Vault) {
    super();
    this.unmasker = new StreamingUnmasker(vault);
  }

  override _transform(chunk: Buffer | string, _enc: BufferEncoding, callback: TransformCallback): void {
    const text = typeof chunk === 'string' ? chunk : this.decoder.write(chunk);
    const out = this.unmasker.push(text);
    if (out) this.push(out);
    callback();
  }

  override _flush(callback: TransformCallback): void {
    const rest = this.unmasker.push(this.decoder.end()) + this.unmasker.flush();
    if (rest) this.push(rest);
    callback();
  }
}

export function createUnmaskStream(vault: Vault): UnmaskTransformStream {
  return new UnmaskTransformStream(vault);
}

type Json = Record<string, unknown>;
const isObject = (v: unknown): v is Json => typeof v === 'object' && v !== null;

function getOrCreate<K, V>(map: Map<K, V>, key: K, create: () => V): V {
  let value = map.get(key);
  if (value === undefined) {
    value = create();
    map.set(key, value);
  }
  return value;
}

/**
 * Unmasks an Anthropic Messages API event stream (`stream: true`), based on the documented
 * event shapes: `text_delta` and `input_json_delta` inside `content_block_delta`. Text split
 * across deltas is restored, tool-input JSON stays valid (secrets are JSON-escaped), and any
 * held-back text is emitted as an extra delta right before the block's `content_block_stop`.
 * Other events are deep-unmasked. Events are copied, never mutated.
 */
export async function* unmaskAnthropicStream<E>(events: AsyncIterable<E>, vault: Vault): AsyncGenerator<E> {
  const text = new Map<number, StreamingUnmasker>();
  const json = new Map<number, StreamingUnmasker>();

  function* flushBlock(index: number): Generator<E> {
    const t = text.get(index)?.flush();
    if (t) yield { type: 'content_block_delta', index, delta: { type: 'text_delta', text: t } } as E;
    const j = json.get(index)?.flush();
    if (j) yield { type: 'content_block_delta', index, delta: { type: 'input_json_delta', partial_json: j } } as E;
    text.delete(index);
    json.delete(index);
  }

  for await (const event of events) {
    const e = event as unknown;
    if (isObject(e) && e['type'] === 'content_block_delta' && isObject(e['delta'])) {
      const index = Number(e['index'] ?? 0);
      const delta = e['delta'];
      if (delta['type'] === 'text_delta' && typeof delta['text'] === 'string') {
        const out = getOrCreate(text, index, () => new StreamingUnmasker(vault)).push(delta['text']);
        yield { ...e, delta: { ...delta, text: out } } as E;
        continue;
      }
      if (delta['type'] === 'input_json_delta' && typeof delta['partial_json'] === 'string') {
        const out = getOrCreate(json, index, () => new StreamingUnmasker(vault, jsonStringEscape)).push(
          delta['partial_json']
        );
        yield { ...e, delta: { ...delta, partial_json: out } } as E;
        continue;
      }
    }
    if (isObject(e) && e['type'] === 'content_block_stop') {
      yield* flushBlock(Number(e['index'] ?? 0));
    }
    if (isObject(e) && e['type'] === 'message_stop') {
      for (const index of new Set([...text.keys(), ...json.keys()])) yield* flushBlock(index);
    }
    yield unmaskDeep(event, vault);
  }
  for (const index of new Set([...text.keys(), ...json.keys()])) yield* flushBlock(index);
}

/**
 * Unmasks an OpenAI Chat Completions chunk stream (`stream: true`), based on the documented
 * chunk shape: `choices[].delta.content` and `choices[].delta.tool_calls[].function.arguments`.
 * Held-back text is released on the chunk that carries the choice's `finish_reason`
 * (or in a trailing chunk if the stream ends without one). Chunks are copied, never mutated.
 */
export async function* unmaskOpenAIStream<C>(chunks: AsyncIterable<C>, vault: Vault): AsyncGenerator<C> {
  const content = new Map<number, StreamingUnmasker>();
  const args = new Map<string, StreamingUnmasker>();

  for await (const chunk of chunks) {
    const c = chunk as unknown;
    if (!isObject(c) || !Array.isArray(c['choices'])) {
      yield unmaskDeep(chunk, vault);
      continue;
    }
    const choices = (c['choices'] as unknown[]).map((choice) => {
      if (!isObject(choice) || !isObject(choice['delta'])) return unmaskDeep(choice, vault);
      const index = Number(choice['index'] ?? 0);
      const delta: Json = { ...choice['delta'] };
      const finished = choice['finish_reason'] != null;

      if (typeof delta['content'] === 'string' || (finished && content.has(index))) {
        const u = getOrCreate(content, index, () => new StreamingUnmasker(vault));
        let out = typeof delta['content'] === 'string' ? u.push(delta['content']) : '';
        if (finished) out += u.flush();
        if (typeof delta['content'] === 'string' || out) delta['content'] = out;
      }

      const toolCalls = Array.isArray(delta['tool_calls']) ? [...(delta['tool_calls'] as unknown[])] : [];
      const mapped = toolCalls.map((tc) => {
        if (!isObject(tc) || !isObject(tc['function']) || typeof tc['function']['arguments'] !== 'string') {
          return unmaskDeep(tc, vault);
        }
        const key = `${index}:${Number(tc['index'] ?? 0)}`;
        const u = getOrCreate(args, key, () => new StreamingUnmasker(vault, jsonStringEscape));
        return { ...tc, function: { ...tc['function'], arguments: u.push(tc['function']['arguments']) } };
      });
      if (finished) {
        for (const [key, u] of args) {
          if (!key.startsWith(`${index}:`)) continue;
          const rest = u.flush();
          if (rest) mapped.push({ index: Number(key.split(':')[1]), function: { arguments: rest } });
          args.delete(key);
        }
        content.delete(index);
      }
      if (mapped.length > 0) delta['tool_calls'] = mapped;
      return { ...choice, delta };
    });
    yield { ...c, choices } as C;
  }

  // Stream ended without finish_reason: release whatever is still buffered
  const trailing: Json[] = [];
  for (const [index, u] of content) {
    const rest = u.flush();
    if (rest) trailing.push({ index, delta: { content: rest }, finish_reason: null });
  }
  for (const [key, u] of args) {
    const rest = u.flush();
    if (!rest) continue;
    const [choiceIndex, toolIndex] = key.split(':').map(Number);
    trailing.push({ index: choiceIndex, delta: { tool_calls: [{ index: toolIndex, function: { arguments: rest } }] }, finish_reason: null });
  }
  if (trailing.length > 0) yield { choices: trailing } as C;
}
