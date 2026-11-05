import type { EntropyConfig } from './entropy.js';

export type SecretCategory = 'credential' | 'pii' | 'network' | 'custom';

export type Severity = 'critical' | 'high' | 'medium' | 'low';

export interface RedactPattern {
  /** Unique identifier for the pattern (e.g., 'anthropic-api-key') */
  id: string;
  /** Human-readable name */
  name: string;
  /** Classification category */
  category: SecretCategory;
  /** Risk severity if leaked */
  severity: Severity;
  /** Regular expression used for detection */
  regex: RegExp;
  /** Default token placeholder label (e.g., 'ANTHROPIC_API_KEY') */
  placeholder: string;
  /** Short description of the matched token */
  description: string;
  /** Optional secondary validation function (e.g., Luhn check) */
  validator?: (match: string) => boolean;
  /**
   * Capturing group that holds the secret (number or group name), e.g. for
   * `key=(value)` assignments. When omitted, a named group `(?<secret>...)` is
   * used if present, otherwise the WHOLE match is redacted. Plain capturing
   * groups used only for alternation no longer cause partial redaction.
   */
  secretGroup?: number | string;
}

export interface RedactMatch {
  patternId: string;
  patternName: string;
  category: SecretCategory;
  severity: Severity;
  matchedText?: string;
  startIndex: number;
  endIndex: number;
  replacement: string;
}

export interface VaultEntry {
  placeholder: string;
  original: string;
  patternId: string;
  category: SecretCategory;
  timestamp: number;
}

export interface RedactOptions {
  /**
   * If true, generates sequential session placeholders (e.g., [ANTHROPIC_API_KEY_1])
   * that can be reversibly unmasked using `unmask(text, vault)`.
   * If false, one-way redaction is used (e.g., [REDACTED_ANTHROPIC_API_KEY]).
   * @default false
   */
  reversible?: boolean;

  /**
   * List of specific pattern IDs to include.
   * If not specified, all active patterns are used.
   */
  include?: string[];

  /**
   * List of specific pattern IDs to exclude.
   */
  exclude?: string[];

  /**
   * Custom list of patterns to use (overriding or supplementing defaults).
   */
  customPatterns?: RedactPattern[];

  /**
   * Whitelist of exact strings or substrings that should NEVER be redacted.
   */
  allowlist?: string[];

  /**
   * If true, enables Shannon entropy analysis to detect generic high-entropy
   * cryptographic secrets that lack fixed vendor prefixes.
   * @default false
   */
  detectHighEntropy?: boolean;

  /**
   * Custom entropy parameters (thresholds, min/max length).
   */
  entropy?: EntropyConfig;

  /**
   * Optional custom replacement formatting function.
   */
  customFormatter?: (info: {
    pattern: RedactPattern;
    matchedText: string;
    index: number;
    reversible: boolean;
  }) => string;

  /**
   * If true, includes the raw matched secret text in match results.
   * By default false for security to prevent secrets leaking in JSON serialization.
   * @default false
   */
  includeMatchedText?: boolean;
}

export interface RedactResult {
  /** The sanitized text with all secrets redacted or masked */
  text: string;
  /** Details of all detected leaks */
  matches: RedactMatch[];
  /** True if any sensitive token was detected and redacted */
  hasLeaks: boolean;
  /** Total count of leaked tokens detected */
  totalLeaks: number;
  /** Breakdown count by pattern ID */
  stats: Record<string, number>;
  /** Execution time in milliseconds */
  durationMs: number;
}

