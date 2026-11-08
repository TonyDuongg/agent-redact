import { Transform, type TransformCallback } from 'node:stream';
import type { Vault } from './vault.js';
import { type ToolInputPolicy } from './deep.js';
export interface StreamAdapterOptions {
    /**
     * Restore secrets inside streamed tool-call arguments. Default `false`: a prompt-injected
     * model could place a placeholder in, say, an HTTP tool's URL and exfiltrate the secret.
     * Pass `true` or a per-tool-name predicate only for tools you trust with real secrets.
     */
    unmaskToolInputs?: ToolInputPolicy;
}
/** Escapes a restored secret so it can be spliced into a JSON string literal */
export declare const jsonStringEscape: (secret: string) => string;
/**
 * Incremental unmasker for streamed LLM output. A placeholder such as
 * `[AWS_ACCESS_KEY_ID_1]` can be split across chunks (`[AWS_ACC` | `ESS_KEY_ID_1]`);
 * the unmasker holds back a chunk tail only while it is the beginning of a placeholder
 * that actually exists in the vault, so ordinary text like `[1]` is never delayed.
 */
export declare class StreamingUnmasker {
    private readonly vault;
    private readonly encode?;
    private pending;
    constructor(vault: Vault, encode?: ((secret: string) => string) | undefined);
    /** Feeds the next chunk and returns the text that is safe to emit now */
    push(chunk: string): string;
    /** Returns everything still buffered (call once the stream has ended) */
    flush(): string;
    private holdStart;
}
/** Unmasks an async (or sync) iterable of text chunks, e.g. an LLM token stream */
export declare function unmaskTextStream(source: AsyncIterable<string> | Iterable<string>, vault: Vault): AsyncGenerator<string>;
/** Node.js Transform that unmasks placeholders in a byte or text stream */
export declare class UnmaskTransformStream extends Transform {
    private readonly decoder;
    private readonly unmasker;
    constructor(vault: Vault);
    _transform(chunk: Buffer | string, _enc: BufferEncoding, callback: TransformCallback): void;
    _flush(callback: TransformCallback): void;
}
export declare function createUnmaskStream(vault: Vault): UnmaskTransformStream;
/**
 * Unmasks an Anthropic Messages API event stream (`stream: true`), based on the documented
 * event shapes: `text_delta` and `input_json_delta` inside `content_block_delta`. Text split
 * across deltas is restored and any held-back text is emitted as an extra delta right before
 * the block's `content_block_stop`. Tool-input JSON is only restored when allowed by
 * `unmaskToolInputs` (secrets are then JSON-escaped so it stays valid). Other events are
 * deep-unmasked under the same policy. Events are copied, never mutated.
 */
export declare function unmaskAnthropicStream<E>(events: AsyncIterable<E>, vault: Vault, options?: StreamAdapterOptions): AsyncGenerator<E>;
/**
 * Unmasks an OpenAI Chat Completions chunk stream (`stream: true`), based on the documented
 * chunk shape: `choices[].delta.content` and `choices[].delta.tool_calls[].function.arguments`.
 * Held-back text is released on the chunk that carries the choice's `finish_reason`
 * (or in a trailing chunk if the stream ends without one). Tool-call arguments are only
 * restored when allowed by `unmaskToolInputs`. Chunks are copied, never mutated.
 */
export declare function unmaskOpenAIStream<C>(chunks: AsyncIterable<C>, vault: Vault, options?: StreamAdapterOptions): AsyncGenerator<C>;
