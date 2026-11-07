import type { RedactPattern, VaultEntry } from './types.js';

/**
 * Collects every "[NAME_<number>]" token already present in `text`, so new placeholders
 * never collide with literal text. One linear pass per document.
 */
export function collectPlaceholderLiterals(text: string): Set<string> {
  const found = new Set<string>();
  for (const m of text.matchAll(/\[[^[\]\r\n]{1,256}_\d+\]/g)) {
    found.add(m[0]);
  }
  return found;
}

/**
 * Vault manages session-scoped mappings between sensitive tokens
 * and their reversible placeholders.
 */
export class Vault {
  private placeholderToEntry = new Map<string, VaultEntry>();
  private placeholderToEntries = new Map<string, VaultEntry[]>();
  private originalToPlaceholder = new Map<string, string>();
  private counters = new Map<string, number>();
  private maxEntries?: number;
  /** Names (never values) of placeholders dropped by the size cap, oldest first */
  private evictedPlaceholders = new Set<string>();
  /** Bumped on every change to the placeholder set; invalidates the cached unmask regex */
  private mutations = 0;
  private unmaskRegexCache?: { mutations: number; regex: RegExp };

  constructor(options?: { maxEntries?: number }) {
    this.maxEntries = options?.maxEntries;
  }

  /**
   * True when `prefix` is the beginning of at least one known placeholder.
   * Used by streaming unmaskers to decide whether a chunk tail must be held back.
   */
  public hasPlaceholderPrefix(prefix: string): boolean {
    for (const placeholder of this.placeholderToEntries.keys()) {
      if (placeholder.startsWith(prefix)) return true;
    }
    return false;
  }

  private getUnmaskRegex(): RegExp {
    if (this.unmaskRegexCache?.mutations !== this.mutations) {
      // Longest first so a placeholder that is a prefix of another never wins
      const escaped = Array.from(this.placeholderToEntries.keys())
        .sort((a, b) => b.length - a.length)
        .map((p) => p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
      this.unmaskRegexCache = { mutations: this.mutations, regex: new RegExp(escaped.join('|'), 'g') };
    }
    const { regex } = this.unmaskRegexCache;
    regex.lastIndex = 0;
    return regex;
  }

  private evictOldestIfNeeded(): void {
    if (this.maxEntries && this.originalToPlaceholder.size >= this.maxEntries) {
      const oldestPlaceholder = this.placeholderToEntry.keys().next().value;
      if (oldestPlaceholder) {
        // Drop every secret mapped to this placeholder, not only the most recent one,
        // so no original keeps pointing at a placeholder that can no longer be unmasked
        for (const entry of this.placeholderToEntries.get(oldestPlaceholder) ?? []) {
          if (this.originalToPlaceholder.get(entry.original) === oldestPlaceholder) {
            this.originalToPlaceholder.delete(entry.original);
          }
        }
        this.placeholderToEntry.delete(oldestPlaceholder);
        this.placeholderToEntries.delete(oldestPlaceholder);
        this.mutations++;
        this.rememberEvicted(oldestPlaceholder);
      }
    }
  }

  private rememberEvicted(placeholder: string): void {
    this.evictedPlaceholders.add(placeholder);
    // Bound the bookkeeping itself so a long-running session cannot grow it forever
    const limit = (this.maxEntries ?? 0) * 10 || 100_000;
    if (this.evictedPlaceholders.size > limit) {
      const oldest = this.evictedPlaceholders.values().next().value;
      if (oldest !== undefined) this.evictedPlaceholders.delete(oldest);
    }
  }

  /**
   * Placeholders present in `text` that were evicted by the `maxEntries` cap and
   * therefore cannot be restored by `unmask`. Returns placeholder names only.
   */
  public findEvictedPlaceholders(text: string): string[] {
    if (this.evictedPlaceholders.size === 0 || !text) return [];
    return [...this.evictedPlaceholders].filter(
      (p) => text.includes(p) && !this.placeholderToEntries.has(p)
    );
  }

  /**
   * Retrieves an existing placeholder or allocates a new numbered placeholder
   * for the given secret token. Optionally ensures placeholder does not collide
   * with literal text already in the document.
   */
  public getOrCreate(
    original: string,
    pattern: RedactPattern,
    existingText?: string | ReadonlySet<string>
  ): string {
    const existing = this.originalToPlaceholder.get(original);
    if (existing) {
      return existing;
    }

    this.evictOldestIfNeeded();

    let count = (this.counters.get(pattern.placeholder) ?? 0) + 1;
    if (existingText) {
      // A Set of literal placeholder-shaped tokens (see collectPlaceholderLiterals) avoids
      // rescanning the whole document for every new secret, which was quadratic.
      const isTaken =
        typeof existingText === 'string'
          ? (p: string) => existingText.includes(p)
          : (p: string) => existingText.has(p);
      while (isTaken(`[${pattern.placeholder}_${count}]`)) {
        count++;
      }
    }
    this.counters.set(pattern.placeholder, count);

    const placeholder = `[${pattern.placeholder}_${count}]`;

    const entry: VaultEntry = {
      placeholder,
      original,
      patternId: pattern.id,
      category: pattern.category,
      timestamp: Date.now()
    };

    this.placeholderToEntry.set(placeholder, entry);
    this.placeholderToEntries.set(placeholder, [entry]);
    this.originalToPlaceholder.set(original, placeholder);
    this.mutations++;

    return placeholder;
  }

  /**
   * Retrieves original secret from placeholder.
   */
  public getOriginal(placeholder: string): string | undefined {
    return this.placeholderToEntry.get(placeholder)?.original;
  }

  /**
   * Replaces all placeholders in a string back with their original secrets
   * in a deterministic, collision-free single regex pass. Handles multiple
   * secrets mapped to identical custom placeholders sequentially.
   *
   * @param encode Optional transform applied to each restored secret, e.g. JSON string
   *   escaping when the placeholder sits inside a JSON document.
   */
  public unmask(text: string, encode?: (secret: string) => string): string {
    if (this.placeholderToEntries.size === 0 || !text) {
      return text;
    }

    // Cached between calls (rebuilt only when the vault changes): streaming unmaskers call
    // this once per chunk, and rebuilding a large alternation every time was wasteful.
    const regex = this.getUnmaskRegex();
    const occurrences = new Map<string, number>();
    const out = (secret: string) => (encode ? encode(secret) : secret);

    return text.replace(regex, (matched) => {
      const list = this.placeholderToEntries.get(matched);
      if (!list || list.length === 0) {
        return matched;
      }
      if (list.length === 1) {
        return out(list[0]!.original);
      }
      const idx = occurrences.get(matched) ?? 0;
      occurrences.set(matched, idx + 1);
      const entry = list[idx % list.length]!;
      return out(entry.original);
    });
  }

  /**
   * Directly restores an entry into the vault without altering placeholder names.
   */
  public restoreEntry(entry: VaultEntry): void {
    if (!this.originalToPlaceholder.has(entry.original)) {
      this.evictOldestIfNeeded();
    }
    this.placeholderToEntry.set(entry.placeholder, entry);
    const existingList = this.placeholderToEntries.get(entry.placeholder) ?? [];
    // Restoring the same (placeholder, original) pair twice must be idempotent
    if (!existingList.some((e) => e.original === entry.original)) {
      existingList.push(entry);
    }
    this.placeholderToEntries.set(entry.placeholder, existingList);
    this.originalToPlaceholder.set(entry.original, entry.placeholder);
    this.mutations++;

    // Synchronize counter to prevent future collision
    const match = entry.placeholder.match(/^\[(.*)_(\d+)\]$/);
    if (match && match[1] && match[2]) {
      const prefix = match[1];
      const num = parseInt(match[2], 10);
      const current = this.counters.get(prefix) ?? 0;
      if (num > current) {
        this.counters.set(prefix, num);
      }
    }
  }

  /**
   * Restores a list of entries into the vault.
   */
  public restoreEntries(entries: VaultEntry[]): void {
    for (const entry of entries) {
      this.restoreEntry(entry);
    }
  }

  /**
   * Serializes the vault entries to JSON string.
   */
  public toJSON(): string {
    return JSON.stringify(this.entries(), null, 2);
  }

  /**
   * Deserializes a JSON string or array of entries into a new Vault instance.
   */
  public static fromJSON(data: string | VaultEntry[]): Vault {
    const vault = new Vault();
    const list: unknown = typeof data === 'string' ? JSON.parse(data) : data;
    if (!Array.isArray(list)) {
      throw new Error('Invalid vault: expected a JSON array of entries');
    }
    // Validate before restoring; error messages reference the index only, never the secret
    list.forEach((entry: unknown, i: number) => {
      const e = entry as Partial<VaultEntry> | null;
      if (
        !e ||
        typeof e !== 'object' ||
        typeof e.placeholder !== 'string' ||
        e.placeholder.length === 0 ||
        typeof e.original !== 'string' ||
        e.original.length === 0
      ) {
        throw new Error(
          `Invalid vault: entry ${i} must have non-empty string "placeholder" and "original" fields`
        );
      }
    });
    vault.restoreEntries(list as VaultEntry[]);
    return vault;
  }

  /**
   * Returns list of all entries currently in the vault.
   */
  public entries(): VaultEntry[] {
    const all: VaultEntry[] = [];
    for (const list of this.placeholderToEntries.values()) {
      all.push(...list);
    }
    return all;
  }

  /**
   * Number of unique secrets stored.
   */
  public get size(): number {
    return this.originalToPlaceholder.size;
  }

  /**
   * Wipes all secrets from memory.
   */
  public clear(): void {
    this.placeholderToEntry.clear();
    this.placeholderToEntries.clear();
    this.originalToPlaceholder.clear();
    this.counters.clear();
    this.evictedPlaceholders.clear();
    this.mutations++;
  }
}

