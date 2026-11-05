import type { RedactPattern } from './types.js';

/** Shared defaults so the detection regex and the entropy check agree on token length */
export const DEFAULT_ENTROPY_MIN_LENGTH = 20;
export const DEFAULT_ENTROPY_MAX_LENGTH = 120;

export interface EntropyConfig {
  /** Minimum token length to analyze (default: 20) */
  minLength?: number;
  /** Maximum token length to analyze (default: 120) */
  maxLength?: number;
  /** Shannon entropy threshold for Base64/Alphanumeric strings (default: 4.3) */
  base64Threshold?: number;
  /** Shannon entropy threshold for Hex strings (default: 3.2) */
  hexThreshold?: number;
}

/**
 * Calculates the Shannon Entropy of a string:
 * H(X) = -sum(P(x) * log2(P(x)))
 * Higher entropy means higher randomness / unpredictability (characteristic of cryptographic keys).
 */
export function calculateShannonEntropy(str: string): number {
  if (!str || str.length === 0) {
    return 0;
  }

  const frequencies = new Map<string, number>();
  for (let i = 0; i < str.length; i++) {
    const char = str[i]!;
    frequencies.set(char, (frequencies.get(char) ?? 0) + 1);
  }

  let entropy = 0;
  const len = str.length;

  for (const count of frequencies.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }

  return Math.round(entropy * 1000) / 1000;
}

/**
 * Determines whether a candidate string exhibits high entropy (randomness)
 * typical of generated API keys or secrets.
 */
export function isHighEntropyToken(
  token: string,
  config: EntropyConfig = {}
): boolean {
  const minLength = config.minLength ?? DEFAULT_ENTROPY_MIN_LENGTH;
  const maxLength = config.maxLength ?? DEFAULT_ENTROPY_MAX_LENGTH;
  const base64Threshold = config.base64Threshold ?? 4.3;
  const hexThreshold = config.hexThreshold ?? 3.2;

  if (token.length < minLength || token.length > maxLength) {
    return false;
  }

  const entropy = calculateShannonEntropy(token);

  // Check if token is purely hexadecimal ([0-9a-fA-F])
  const isHex = /^[0-9a-fA-F]+$/.test(token);
  if (isHex) {
    return entropy >= hexThreshold;
  }

  // Base64 or alphanumeric with symbols
  return entropy >= base64Threshold;
}

/**
 * Pattern definition to detect generic high-entropy secrets preceded by key/token/secret context
 */
export function createHighEntropyPattern(config: EntropyConfig = {}): RedactPattern {
  // No upper bound in the regex: a bounded quantifier would cut a long secret in half and
  // leave its tail visible. maxLength is applied to the entropy sample in the engine instead.
  const min = config.minLength ?? DEFAULT_ENTROPY_MIN_LENGTH;
  return {
    id: 'generic-high-entropy-secret',
    name: 'Generic High-Entropy Secret',
    category: 'credential',
    severity: 'high',
    regex: new RegExp(
      `(?:api[_-]?key|secret|token|password|auth[_-]?key|access[_-]?key)[\\s=:'"]+([^\\s"';,\\n]{${min},})`,
      'gi'
    ),
    secretGroup: 1,
    placeholder: 'GENERIC_SECRET',
    description: 'High-entropy random token detected in sensitive assignment context'
  };
}
