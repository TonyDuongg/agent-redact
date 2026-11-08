import type { RedactPattern, VaultEntry } from './types.js';
/**
 * Collects every "[NAME_<number>]" token already present in `text`, so new placeholders
 * never collide with literal text. One linear pass per document.
 */
export declare function collectPlaceholderLiterals(text: string): Set<string>;
/**
 * Vault manages session-scoped mappings between sensitive tokens
 * and their reversible placeholders.
 */
export declare class Vault {
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
