import type { RedactPattern, VaultEntry } from './types.js';

/**
 * Vault manages session-scoped mappings between sensitive tokens
 * and their reversible placeholders.
 */
export class Vault {
  private placeholderToEntry = new Map<string, VaultEntry>();
  private originalToPlaceholder = new Map<string, string>();
  private counters = new Map<string, number>();

  /**
   * Retrieves an existing placeholder or allocates a new numbered placeholder
   * for the given secret token.
   */
  public getOrCreate(original: string, pattern: RedactPattern): string {
    const existing = this.originalToPlaceholder.get(original);
    if (existing) {
      return existing;
    }

    const count = (this.counters.get(pattern.placeholder) ?? 0) + 1;
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
   * Replaces all placeholders in a string back with their original secrets.
   */
  public unmask(text: string): string {
    let result = text;
    for (const [placeholder, entry] of this.placeholderToEntry.entries()) {
      result = result.split(placeholder).join(entry.original);
    }
    return result;
  }

  /**
   * Returns list of all entries currently in the vault.
   */
  public entries(): VaultEntry[] {
    return Array.from(this.placeholderToEntry.values());
  }

  /**
   * Number of unique secrets stored.
   */
  public get size(): number {
    return this.placeholderToEntry.size;
  }

  /**
   * Wipes all secrets from memory.
   */
  public clear(): void {
    this.placeholderToEntry.clear();
    this.originalToPlaceholder.clear();
    this.counters.clear();
  }
}

