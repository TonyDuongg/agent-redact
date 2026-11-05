import { R as RedactPattern, V as VaultEntry, a as RedactOptions, b as RedactResult, E as EntropyConfig, S as SecretCategory, c as Severity } from './index-GsZVMWMi.js';
export { C as CREDENTIAL_PATTERNS, D as DEFAULT_PATTERNS, P as PATTERN_MAP, d as PII_PATTERNS, e as RedactMatch, f as anthropicApiKeyPattern, g as awsAccessKeyPattern, h as awsSecretKeyPattern, i as basicAuthUrlPattern, j as calculateShannonEntropy, k as createHighEntropyPattern, l as creditCardPattern, m as databaseUriPattern, n as databaseUrlPattern, o as discordTokenPattern, p as emailPattern, q as githubTokenPattern, r as gitlabTokenPattern, s as googleApiKeyPattern, t as huggingFaceTokenPattern, u as ipv4Pattern, v as ipv6Pattern, w as isHighEntropyToken, x as jwtTokenPattern, y as npmTokenPattern, z as openaiApiKeyPattern, A as phonePattern, B as privateKeyPattern, F as sendgridApiKeyPattern, G as slackTokenPattern, H as ssnPattern, I as stripeKeyPattern, J as supabaseKeyPattern, K as twilioAccountSidPattern } from './index-GsZVMWMi.js';
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
    /**
     * Retrieves an existing placeholder or allocates a new numbered placeholder
     * for the given secret token. Optionally ensures placeholder does not collide
     * with literal text already in the document.
     */
    getOrCreate(original: string, pattern: RedactPattern, existingText?: string): string;
    /**
     * Retrieves original secret from placeholder.
     */
    getOriginal(placeholder: string): string | undefined;
    /**
     * Replaces all placeholders in a string back with their original secrets
     * in a deterministic, collision-free single regex pass. Handles multiple
     * secrets mapped to identical custom placeholders sequentially.
     */
    unmask(text: string): string;
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
/**
 * Node.js Transform Stream for memory-efficient O(1) continuous
 * stream redaction of large logs or piped inputs.
 */
declare class RedactTransformStream extends Transform {
    private buffer;
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

interface CustomPatternConfig {
    id: string;
    name: string;
    category?: SecretCategory;
    severity?: Severity;
    /** Regex string pattern (e.g. "corp_[a-zA-Z0-9]{32}" or with flags "/.../gi") */
    regex: string;
    placeholder: string;
    description?: string;
}
interface AgentRedactConfig {
    /** Pattern IDs to activate */
    include?: string[];
    /** Pattern IDs to disable */
    exclude?: string[];
    /** Exact strings or substrings to ignore (whitelist) */
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
     * If true, automatically unmasks placeholders in string responses.
     * @default true
     */
    unmaskResponse?: boolean;
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

export { type AgentInterceptorOptions, type AgentRedactConfig, type CustomPatternConfig, EntropyConfig, RedactEngine, RedactOptions, RedactPattern, type RedactRequestExtension, RedactResult, type RedactStreamOptions, RedactTransformStream, type ResolvedConfig, SecretCategory, Severity, Vault, VaultEntry, createExpressMiddleware, createRedactStream, loadConfig, parseRegexString, redact, resolveCustomPattern, unmask, wrapAgent };
