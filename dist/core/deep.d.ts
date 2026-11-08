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
/**
 * Policy for restoring secrets inside model-generated tool-call inputs.
 * `false` (default) keeps placeholders there: a prompt-injected model could otherwise
 * smuggle a placeholder into e.g. an HTTP tool's URL and have the real secret sent out.
 * `true` restores every tool; a function decides per tool name.
 */
export type ToolInputPolicy = boolean | ((toolName: string) => boolean);
export declare function isToolUnmaskAllowed(policy: ToolInputPolicy | undefined, toolName: string): boolean;
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
export declare function redactDeep<T>(value: T, options?: DeepRedactOptions): DeepRedactResult<T>;
export interface UnmaskDeepOptions {
    /** See {@link ToolInputPolicy}. Default `false`: tool-call inputs keep their placeholders. */
    unmaskToolInputs?: ToolInputPolicy;
}
/**
 * Restores placeholders in every string of a JSON-like value (e.g. an SDK response).
 * Model-generated tool-call inputs are left masked unless `unmaskToolInputs` allows it.
 * Returns a deep copy; the input is not mutated.
 */
export declare function unmaskDeep<T>(value: T, vault: Vault, options?: UnmaskDeepOptions): T;
