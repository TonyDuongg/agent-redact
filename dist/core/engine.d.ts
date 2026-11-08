import type { RedactOptions, RedactPattern, RedactResult } from './types.js';
import { Vault } from './vault.js';
export declare class RedactEngine {
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
export declare function redact(text: string, options?: RedactOptions & {
    vault?: Vault;
}): RedactResult & {
    vault?: Vault;
};
/**
 * Quick unmasking helper
 */
export declare function unmask(text: string, vault: Vault): string;
