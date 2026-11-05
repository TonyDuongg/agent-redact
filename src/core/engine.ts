import { DEFAULT_PATTERNS } from '../patterns/index.js';
import {
  createHighEntropyPattern,
  isHighEntropyToken,
  DEFAULT_ENTROPY_MAX_LENGTH,
  type EntropyConfig
} from './entropy.js';
import type {
  RedactMatch,
  RedactOptions,
  RedactPattern,
  RedactResult
} from './types.js';
import { Vault } from './vault.js';

const SEVERITY_WEIGHT: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1
};

interface RawMatch {
  pattern: RedactPattern;
  secret: string;
  startIndex: number;
  endIndex: number;
}

type IndexedMatch = RegExpExecArray & {
  indices?: Array<[number, number] | undefined> & {
    groups?: Record<string, [number, number] | undefined>;
  };
};

/**
 * Picks the span to redact: the pattern's declared `secretGroup`, else a named
 * `secret` group, else the whole match. Falling back to the whole match keeps
 * redaction fail-closed when a group did not participate.
 */
function selectSecretSpan(
  match: IndexedMatch,
  pattern: RedactPattern
): { secret: string; startIndex: number; endIndex: number } {
  let group: number | string | undefined = pattern.secretGroup;
  if (group === undefined && match.groups?.['secret'] !== undefined) {
    group = 'secret';
  }

  if (group !== undefined) {
    const value = typeof group === 'number' ? match[group] : match.groups?.[group];
    const span = typeof group === 'number' ? match.indices?.[group] : match.indices?.groups?.[group];
    if (value && span) {
      return { secret: value, startIndex: span[0], endIndex: span[1] };
    }
  }

  return { secret: match[0], startIndex: match.index, endIndex: match.index + match[0].length };
}

export class RedactEngine {
  private patterns: RedactPattern[];
  private vault?: Vault;

  constructor(options?: { patterns?: RedactPattern[]; vault?: Vault }) {
    this.patterns = options?.patterns ?? [...DEFAULT_PATTERNS];
    this.vault = options?.vault;
  }

  /**
   * Redacts sensitive secrets and PII from the input string.
   */
  public redact(
    text: string,
    options?: RedactOptions & { vault?: Vault }
  ): RedactResult & { vault?: Vault } {
    const startTime = performance.now();
    const reversible = options?.reversible ?? false;
    const vault = options?.vault ?? this.vault ?? (reversible ? new Vault() : undefined);

    // Filter patterns according to options
    let activePatterns = options?.customPatterns
      ? [...this.patterns, ...options.customPatterns]
      : [...this.patterns];

    if (options?.detectHighEntropy) {
      activePatterns.push(createHighEntropyPattern(options.entropy as EntropyConfig | undefined));
    }

    if (options?.include && options.include.length > 0) {
      const includeSet = new Set(options.include);
      const customIds = new Set((options.customPatterns ?? []).map((p) => p.id));
      activePatterns = activePatterns.filter(
        (p) =>
          includeSet.has(p.id) ||
          customIds.has(p.id) ||
          (options.detectHighEntropy && p.id === 'generic-high-entropy-secret')
      );
    }

    if (options?.exclude && options.exclude.length > 0) {
      const excludeSet = new Set(options.exclude);
      activePatterns = activePatterns.filter((p) => !excludeSet.has(p.id));
    }

    const allowlist = options?.allowlist ?? [];
    const rawMatches: RawMatch[] = [];

    // Scan each pattern
    for (const pattern of activePatterns) {
      // Create a fresh regex instance with global and indices flags to avoid race conditions and guarantee byte-exact offsets
      let flags = pattern.regex.flags;
      if (!flags.includes('g')) flags += 'g';
      if (!flags.includes('d')) flags += 'd';
      const regex = new RegExp(pattern.regex.source, flags);

      let match: IndexedMatch | null;
      while ((match = regex.exec(text) as IndexedMatch | null) !== null) {
        // Prevent infinite loops on zero-length regex matches (e.g. (?=a))
        if (match[0].length === 0) {
          regex.lastIndex++;
          continue;
        }

        const { secret, startIndex, endIndex } = selectSecretSpan(match, pattern);

        // Check if token matches allowlist (exact match only, ignore empty strings)
        if (
          allowlist.length > 0 &&
          allowlist.some((al) => typeof al === 'string' && al.length > 0 && secret === al)
        ) {
          continue;
        }

        // Run secondary pattern validator if defined (e.g. Luhn algorithm for credit cards)
        if (pattern.validator && !pattern.validator(secret)) {
          continue;
        }

        // If generic high entropy pattern, verify that the token actually exhibits high randomness.
        // Tokens longer than maxLength are judged on their prefix and then redacted in full,
        // so a long secret is never left half-visible.
        if (pattern.id === 'generic-high-entropy-secret') {
          const entropyConfig = options?.entropy as EntropyConfig | undefined;
          const maxLength = entropyConfig?.maxLength ?? DEFAULT_ENTROPY_MAX_LENGTH;
          const sample = secret.length > maxLength ? secret.slice(0, maxLength) : secret;
          if (!isHighEntropyToken(sample, entropyConfig)) {
            continue;
          }
        }

        rawMatches.push({
          pattern,
          secret,
          startIndex,
          endIndex
        });
      }
    }

    // Prioritize candidates: highest severity first, then longest span, then earliest start
    rawMatches.sort((a, b) => {
      const weightA = SEVERITY_WEIGHT[a.pattern.severity] ?? 0;
      const weightB = SEVERITY_WEIGHT[b.pattern.severity] ?? 0;
      if (weightA !== weightB) {
        return weightB - weightA;
      }
      const lenA = a.endIndex - a.startIndex;
      const lenB = b.endIndex - b.startIndex;
      if (lenA !== lenB) {
        return lenB - lenA;
      }
      return a.startIndex - b.startIndex;
    });

    // Accept candidate matches without overlapping already accepted higher-priority matches
    const accepted: RawMatch[] = [];
    for (const candidate of rawMatches) {
      const hasOverlap = accepted.some(
        (acc) => candidate.startIndex < acc.endIndex && acc.startIndex < candidate.endIndex
      );
      if (!hasOverlap) {
        accepted.push(candidate);
      }
    }

    // Sort accepted matches in textual reading order (startIndex ascending)
    accepted.sort((a, b) => a.startIndex - b.startIndex);

    // Construct final text and format replacements
    const matches: RedactMatch[] = [];
    const stats: Record<string, number> = {};
    let redactedText = '';
    let cursor = 0;

    for (let i = 0; i < accepted.length; i++) {
      const m = accepted[i]!;

      // Determine replacement token
      let replacement: string;
      if (options?.customFormatter) {
        replacement = options.customFormatter({
          pattern: m.pattern,
          matchedText: m.secret,
          index: i + 1,
          reversible
        });
        if (reversible && vault) {
          // A shared placeholder for different secrets cannot be unmasked reliably:
          // fail loudly instead of silently restoring the wrong secret later.
          const existingOriginal = vault.getOriginal(replacement);
          if (existingOriginal !== undefined && existingOriginal !== m.secret) {
            throw new Error(
              `customFormatter returned the same placeholder "${replacement}" for two different secrets. ` +
                'Reversible mode requires a unique placeholder per secret (e.g. include info.index or a hash).'
            );
          }
          vault.restoreEntry({
            placeholder: replacement,
            original: m.secret,
            patternId: m.pattern.id,
            category: m.pattern.category,
            timestamp: Date.now()
          });
        }
      } else if (reversible && vault) {
        replacement = vault.getOrCreate(m.secret, m.pattern, text);
      } else {
        replacement = `[REDACTED_${m.pattern.placeholder}]`;
      }

      // Append text before match
      redactedText += text.slice(cursor, m.startIndex);
      redactedText += replacement;
      cursor = m.endIndex;

      const matchItem: RedactMatch = {
        patternId: m.pattern.id,
        patternName: m.pattern.name,
        category: m.pattern.category,
        severity: m.pattern.severity,
        startIndex: m.startIndex,
        endIndex: m.endIndex,
        replacement
      };
      if (options?.includeMatchedText) {
        matchItem.matchedText = m.secret;
      }
      matches.push(matchItem);

      stats[m.pattern.id] = (stats[m.pattern.id] ?? 0) + 1;
    }

    // Append remaining tail text
    redactedText += text.slice(cursor);

    const durationMs = Math.round((performance.now() - startTime) * 100) / 100;

    const resultObj: RedactResult & { vault?: Vault } = {
      text: redactedText,
      matches,
      hasLeaks: matches.length > 0,
      totalLeaks: matches.length,
      stats,
      durationMs
    };

    // Keep vault non-enumerable so { ...result } and JSON.stringify never leak raw secrets
    if (vault) {
      Object.defineProperty(resultObj, 'vault', {
        value: vault,
        enumerable: false,
        writable: true,
        configurable: true
      });
    }

    // Ensure JSON.stringify(result) never leaks vault or raw secret keys
    Object.defineProperty(resultObj, 'toJSON', {
      value: function () {
        return {
          text: this.text,
          hasLeaks: this.hasLeaks,
          totalLeaks: this.totalLeaks,
          stats: this.stats,
          durationMs: this.durationMs,
          matches: this.matches
        };
      },
      enumerable: false,
      writable: true,
      configurable: true
    });

    return resultObj;
  }

  /**
   * Unmasks a string using the provided Vault instance.
   */
  public unmask(text: string, vault: Vault): string {
    return vault.unmask(text);
  }
}

/**
 * Singleton engine instance for quick functional usage
 */
const defaultEngine = new RedactEngine();

/**
 * Quick one-off redaction helper
 */
export function redact(
  text: string,
  options?: RedactOptions & { vault?: Vault }
): RedactResult & { vault?: Vault } {
  return defaultEngine.redact(text, options);
}

/**
 * Quick unmasking helper
 */
export function unmask(text: string, vault: Vault): string {
  return defaultEngine.unmask(text, vault);
}
