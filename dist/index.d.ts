import { R as RedactPattern, V as VaultEntry, a as RedactOptions, b as RedactResult, E as EntropyConfig, S as SecretCategory, c as Severity } from './index-DBBXvRS7.js';
export { C as CREDENTIAL_PATTERNS, D as DEFAULT_PATTERNS, P as PATTERN_MAP, d as PII_PATTERNS, e as RedactMatch, f as anthropicApiKeyPattern, g as awsAccessKeyPattern, h as awsSecretKeyPattern, i as azureStorageKeyPattern, j as basicAuthUrlPattern, k as calculateShannonEntropy, l as createHighEntropyPattern, m as creditCardPattern, n as databaseUriPattern, o as databaseUrlPattern, p as digitalOceanTokenPattern, q as discordTokenPattern, r as emailPattern, s as gcpOauthSecretPattern, t as githubTokenPattern, u as gitlabTokenPattern, v as googleApiKeyPattern, w as huggingFaceTokenPattern, x as ipv4Pattern, y as ipv6Pattern, z as isHighEntropyToken, A as jwtTokenPattern, B as mailgunApiKeyPattern, F as npmTokenPattern, G as openaiApiKeyPattern, H as phonePattern, I as privateKeyPattern, J as sendgridApiKeyPattern, K as slackTokenPattern, L as ssnPattern, M as stripeKeyPattern, N as supabaseKeyPattern, O as telegramBotTokenPattern, Q as twilioAccountSidPattern, T as twilioApiKeyPattern } from './index-DBBXvRS7.js';
import { Transform, TransformCallback } from 'node:stream';

/**
 * Vault manages session-scoped mappings between sensitive tokens
 * and their reversible placeholders.
 */
declare class Vault {
    private placeholderToEntry;
    private placeholderToEntries;
    private originalToPlaceholder;
    private counters;
    private maxEntries?;
    /** Names (never values) of placeholders dropped by the size cap, oldest first */
    private evictedPlaceholders;
    /** Bumped on every change to the placeholder set; invalidates the cached unmask regex */
    private mutations;
    private unmaskRegexCache?;
    constructor(options?: {
        maxEntries?: number;
    });
    /**
     * True when `prefix` is the beginning of at least one known placeholder.
     * Used by streaming unmaskers to decide whether a chunk tail must be held back.
     */
    hasPlaceholderPrefix(prefix: string): boolean;
    private getUnmaskRegex;
    private evictOldestIfNeeded;
    private rememberEvicted;
    /**
     * Placeholders present in `text` that were evicted by the `maxEntries` cap and
     * therefore cannot be restored by `unmask`. Returns placeholder names only.
     */
    findEvictedPlaceholders(text: string): string[];
    /**
     * Retrieves an existing placeholder or allocates a new numbered placeholder
     * for the given secret token. Optionally ensures placeholder does not collide
     * with literal text already in the document.
     */
    getOrCreate(original: string, pattern: RedactPattern, existingText?: string | ReadonlySet<string>): string;
    /**
     * Retrieves original secret from placeholder.
     */
    getOriginal(placeholder: string): string | undefined;
    /**
     * Replaces all placeholders in a string back with their original secrets
     * in a deterministic, collision-free single regex pass. Handles multiple
     * secrets mapped to identical custom placeholders sequentially.
     *
     * @param encode Optional transform applied to each restored secret, e.g. JSON string
     *   escaping when the placeholder sits inside a JSON document.
     */
    unmask(text: string, encode?: (secret: string) => string): string;
    /**
     * Directly restores an entry into the vault without altering placeholder names.
     */
    restoreEntry(entry: VaultEntry): void;
    /**
     * Restores a list of entries into the vault.
     */
    restoreEntries(entries: VaultEntry[]): void;
    /**
     * Serializes the vault entries to JSON string.
     */
    toJSON(): string;
    /**
     * Deserializes a JSON string or array of entries into a new Vault instance.
     */
    static fromJSON(data: string | VaultEntry[]): Vault;
    /**
     * Returns list of all entries currently in the vault.
     */
    entries(): VaultEntry[];
    /**
     * Number of unique secrets stored.
     */
    get size(): number;
    /**
     * Wipes all secrets from memory.
     */
    clear(): void;
}

declare class RedactEngine {
    private patterns;
    private vault?;
    constructor(options?: {
        patterns?: RedactPattern[];
        vault?: Vault;
    });
    /**
     * Redacts sensitive secrets and PII from the input string.
     */
    redact(text: string, options?: RedactOptions & {
        vault?: Vault;
    }): RedactResult & {
        vault?: Vault;
    };
    /**
     * Unmasks a string using the provided Vault instance.
     */
    unmask(text: string, vault: Vault): string;
}
/**
 * Quick one-off redaction helper
 */
declare function redact(text: string, options?: RedactOptions & {
    vault?: Vault;
}): RedactResult & {
    vault?: Vault;
};
/**
 * Quick unmasking helper
 */
declare function unmask(text: string, vault: Vault): string;

interface RedactStreamOptions extends RedactOptions {
    vault?: Vault;
    /**
     * Optional listener triggered whenever a line with secrets is processed.
     */
    onLineRedacted?: (result: RedactResult) => void;
}
declare class RedactTransformStream extends Transform {
    private buffer;
    /** True while discarding the body of an oversized private key block that has no END yet */
    private droppingOpenPem;
    private decoder;
    private options;
    readonly vault: Vault;
    constructor(options?: RedactStreamOptions);
    _transform(chunk: Buffer | string, _encoding: BufferEncoding, callback: TransformCallback): void;
    _flush(callback: TransformCallback): void;
}
/**
 * Helper to create a new Transform stream instance.
 */
declare function createRedactStream(options?: RedactStreamOptions): RedactTransformStream;

interface DeepRedactOptions extends RedactOptions {
    /** Vault to reuse across calls (a new one is created otherwise) */
    vault?: Vault;
    /** Object keys whose values are never scanned (in addition to binary payloads) */
    skipKeys?: string[];
}
interface DeepRedactResult<T> {
    /** Deep copy of the input with every string value redacted */
    value: T;
    /** Vault holding the placeholders, for `unmaskDeep` / streaming unmask of the response */
    vault: Vault;
    totalLeaks: number;
    stats: Record<string, number>;
}
/**
 * Policy for restoring secrets inside model-generated tool-call inputs.
 * `false` (default) keeps placeholders there: a prompt-injected model could otherwise
 * smuggle a placeholder into e.g. an HTTP tool's URL and have the real secret sent out.
 * `true` restores every tool; a function decides per tool name.
 */
type ToolInputPolicy = boolean | ((toolName: string) => boolean);
declare function isToolUnmaskAllowed(policy: ToolInputPolicy | undefined, toolName: string): boolean;
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
declare function redactDeep<T>(value: T, options?: DeepRedactOptions): DeepRedactResult<T>;
interface UnmaskDeepOptions {
    /** See {@link ToolInputPolicy}. Default `false`: tool-call inputs keep their placeholders. */
    unmaskToolInputs?: ToolInputPolicy;
}
/**
 * Restores placeholders in every string of a JSON-like value (e.g. an SDK response).
 * Model-generated tool-call inputs are left masked unless `unmaskToolInputs` allows it.
 * Returns a deep copy; the input is not mutated.
 */
declare function unmaskDeep<T>(value: T, vault: Vault, options?: UnmaskDeepOptions): T;

interface StreamAdapterOptions {
    /**
     * Restore secrets inside streamed tool-call arguments. Default `false`: a prompt-injected
     * model could place a placeholder in, say, an HTTP tool's URL and exfiltrate the secret.
     * Pass `true` or a per-tool-name predicate only for tools you trust with real secrets.
     */
    unmaskToolInputs?: ToolInputPolicy;
}
/** Escapes a restored secret so it can be spliced into a JSON string literal */
declare const jsonStringEscape: (secret: string) => string;
/**
 * Incremental unmasker for streamed LLM output. A placeholder such as
 * `[AWS_ACCESS_KEY_ID_1]` can be split across chunks (`[AWS_ACC` | `ESS_KEY_ID_1]`);
 * the unmasker holds back a chunk tail only while it is the beginning of a placeholder
 * that actually exists in the vault, so ordinary text like `[1]` is never delayed.
 */
declare class StreamingUnmasker {
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
declare function unmaskTextStream(source: AsyncIterable<string> | Iterable<string>, vault: Vault): AsyncGenerator<string>;
/** Node.js Transform that unmasks placeholders in a byte or text stream */
declare class UnmaskTransformStream extends Transform {
    private readonly decoder;
    private readonly unmasker;
    constructor(vault: Vault);
    _transform(chunk: Buffer | string, _enc: BufferEncoding, callback: TransformCallback): void;
    _flush(callback: TransformCallback): void;
}
declare function createUnmaskStream(vault: Vault): UnmaskTransformStream;
/**
 * Unmasks an Anthropic Messages API event stream (`stream: true`), based on the documented
 * event shapes: `text_delta` and `input_json_delta` inside `content_block_delta`. Text split
 * across deltas is restored and any held-back text is emitted as an extra delta right before
 * the block's `content_block_stop`. Tool-input JSON is only restored when allowed by
 * `unmaskToolInputs` (secrets are then JSON-escaped so it stays valid). Other events are
 * deep-unmasked under the same policy. Events are copied, never mutated.
 */
declare function unmaskAnthropicStream<E>(events: AsyncIterable<E>, vault: Vault, options?: StreamAdapterOptions): AsyncGenerator<E>;
/**
 * Unmasks an OpenAI Chat Completions chunk stream (`stream: true`), based on the documented
 * chunk shape: `choices[].delta.content` and `choices[].delta.tool_calls[].function.arguments`.
 * Held-back text is released on the chunk that carries the choice's `finish_reason`
 * (or in a trailing chunk if the stream ends without one). Tool-call arguments are only
 * restored when allowed by `unmaskToolInputs`. Chunks are copied, never mutated.
 */
declare function unmaskOpenAIStream<C>(chunks: AsyncIterable<C>, vault: Vault, options?: StreamAdapterOptions): AsyncGenerator<C>;

interface CustomPatternConfig {
    id: string;
    name: string;
    category?: SecretCategory;
    severity?: Severity;
    /** Regex string pattern (e.g. "corp_[a-zA-Z0-9]{32}" or with flags "/.../gi") */
    regex: string;
    placeholder: string;
    description?: string;
    /**
     * Capturing group (number or name) holding the secret, e.g. 2 for "(key):\s*(value)".
     * Without it, a named group "(?<secret>...)" is used if present, otherwise the whole match.
     */
    secretGroup?: number | string;
}
interface AgentRedactConfig {
    /** Pattern IDs to activate */
    include?: string[];
    /** Pattern IDs to disable */
    exclude?: string[];
    /** Exact strings to ignore (whitelist). Substrings are NOT matched. */
    allowlist?: string[];
    /** Default to reversible session masking */
    reversible?: boolean;
    /** Enable generic high-entropy secret detection */
    detectHighEntropy?: boolean;
    /** Custom entropy parameters */
    entropy?: EntropyConfig;
    /** User-defined custom secret patterns */
    customPatterns?: CustomPatternConfig[];
}
interface ResolvedConfig extends Omit<AgentRedactConfig, 'customPatterns'> {
    customPatterns?: RedactPattern[];
}
/**
 * Parses a regex string like "/abc/gi" or "abc" into a RegExp object
 */
declare function parseRegexString(patternStr: string): RegExp;
/**
 * Converts a raw JSON pattern configuration into a live RedactPattern
 */
declare function resolveCustomPattern(cfg: CustomPatternConfig): RedactPattern;
/**
 * Searches and loads configuration from explicit path or default config file in directory.
 */
declare function loadConfig(explicitPath?: string, searchDir?: string): ResolvedConfig | null;

interface AgentInterceptorOptions extends RedactOptions {
    /**
     * If true, automatically unmasks placeholders in the response: strings, plain
     * objects/arrays (deeply) and async-generator token streams. Class instances are
     * returned untouched; use `unmaskAnthropicStream` / `unmaskOpenAIStream` for SDK streams.
     * @default true
     */
    unmaskResponse?: boolean;
    /**
     * Restore secrets inside model-generated tool-call inputs of object/stream responses.
     * Default `false`: a prompt-injected model could otherwise exfiltrate a secret by placing
     * its placeholder in a tool argument (e.g. a URL). See {@link ToolInputPolicy}.
     */
    unmaskToolInputs?: ToolInputPolicy;
    /**
     * Optional callback invoked whenever one or more secrets are detected and masked.
     */
    onLeakDetected?: (info: {
        result: RedactResult;
        originalPrompt: string;
        sanitizedPrompt: string;
    }) => void;
}
/**
 * Universal agent wrapper. Intercepts prompts sent to ANY AI agent or LLM call,
 * masks credentials before network transmission, and safely unmasks tokens
 * in the returned output.
 *
 * Compatible with OpenAI, Anthropic, Google Gemini, Ollama, DeepSeek,
 * Mistral, LangChain, Vercel AI SDK, and custom multi-agent workflows.
 */
declare function wrapAgent<TOutput>(agentFn: (sanitizedPrompt: string) => Promise<TOutput> | TOutput, options?: AgentInterceptorOptions): (rawPrompt: string) => Promise<TOutput>;

interface RedactRequestExtension {
    vault: Vault;
    totalLeaks: number;
    hasLeaks: boolean;
    stats: Record<string, number>;
    matches: RedactResult['matches'];
}
declare global {
    namespace Express {
        interface Request {
            redact?: RedactRequestExtension;
        }
    }
}
/**
 * Express / Connect compatible HTTP middleware.
 * Automatically scans and redacts incoming prompt/message bodies
 * before AI agents or route handlers consume them.
 */
declare function createExpressMiddleware(options?: RedactOptions & {
    targetFields?: string[];
}): (req: {
    body?: Record<string, unknown>;
    redact?: RedactRequestExtension;
}, _res: unknown, next: () => void) => void;

export { type AgentInterceptorOptions, type AgentRedactConfig, type CustomPatternConfig, type DeepRedactOptions, type DeepRedactResult, EntropyConfig, RedactEngine, RedactOptions, RedactPattern, type RedactRequestExtension, RedactResult, type RedactStreamOptions, RedactTransformStream, type ResolvedConfig, SecretCategory, Severity, type StreamAdapterOptions, StreamingUnmasker, type ToolInputPolicy, type UnmaskDeepOptions, UnmaskTransformStream, Vault, VaultEntry, createExpressMiddleware, createRedactStream, createUnmaskStream, isToolUnmaskAllowed, jsonStringEscape, loadConfig, parseRegexString, redact, redactDeep, resolveCustomPattern, unmask, unmaskAnthropicStream, unmaskDeep, unmaskOpenAIStream, unmaskTextStream, wrapAgent };
