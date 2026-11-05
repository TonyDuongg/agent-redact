import type { RedactPattern, VaultEntry } from './types.js';

/**
 * Vault manages session-scoped mappings between sensitive tokens
 * and their reversible placeholders.
 */
export class Vault {
  private placeholderToEntry = new Map<string, VaultEntry>();
  private placeholderToEntries = new Map<string, VaultEntry[]>();
  private originalToPlaceholder = new Map<string, string>();
  private counters = new Map<string, number>();

  /**
   * Retrieves an existing placeholder or allocates a new numbered placeholder
   * for the given secret token. Optionally ensures placeholder does not collide
   * with literal text already in the document.
   */
  public getOrCreate(original: string, pattern: RedactPattern, existingText?: string): string {
    const existing = this.originalToPlaceholder.get(original);
    if (existing) {
      return existing;
    }

    let count = (this.counters.get(pattern.placeholder) ?? 0) + 1;
    if (existingText) {
      while (existingText.includes(`[${pattern.placeholder}_${count}]`)) {
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
   */
  public unmask(text: string): string {
    if (this.placeholderToEntries.size === 0 || !text) {
      return text;
    }

    // Sort placeholders by length descending to prevent substring collisions
    const placeholders = Array.from(this.placeholderToEntries.keys()).sort(
      (a, b) => b.length - a.length
    );

    // Escape regex characters (e.g. [ and ])
    const escaped = placeholders.map((p) => p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
    const regex = new RegExp(escaped.join('|'), 'g');

    const occurrences = new Map<string, number>();

    return text.replace(regex, (matched) => {
      const list = this.placeholderToEntries.get(matched);
      if (!list || list.length === 0) {
        return matched;
      }
      if (list.length === 1) {
        return list[0]!.original;
      }
      const idx = occurrences.get(matched) ?? 0;
      occurrences.set(matched, idx + 1);
      const entry = list[idx % list.length]!;
      return entry.original;
    });
  }

  /**
   * Directly restores an entry into the vault without altering placeholder names.
   */
  public restoreEntry(entry: VaultEntry): void {
    this.placeholderToEntry.set(entry.placeholder, entry);
    const existingList = this.placeholderToEntries.get(entry.placeholder) ?? [];
    // Restoring the same (placeholder, original) pair twice must be idempotent
    if (!existingList.some((e) => e.original === entry.original)) {
      existingList.push(entry);
    }
    this.placeholderToEntries.set(entry.placeholder, existingList);
    this.originalToPlaceholder.set(entry.original, entry.placeholder);

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
    const list: VaultEntry[] = typeof data === 'string' ? JSON.parse(data) : data;
    if (Array.isArray(list)) {
      vault.restoreEntries(list);
    }
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
  }
}

