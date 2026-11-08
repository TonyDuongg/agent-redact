import type { RedactPattern } from './types.js';
/** Shared defaults so the detection regex and the entropy check agree on token length */
export declare const DEFAULT_ENTROPY_MIN_LENGTH = 20;
export declare const DEFAULT_ENTROPY_MAX_LENGTH = 120;
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
export declare function calculateShannonEntropy(str: string): number;
/**
 * Determines whether a candidate string exhibits high entropy (randomness)
 * typical of generated API keys or secrets.
 */
export declare function isHighEntropyToken(token: string, config?: EntropyConfig): boolean;
/**
 * Pattern definition to detect generic high-entropy secrets preceded by key/token/secret context
 */
export declare function createHighEntropyPattern(config?: EntropyConfig): RedactPattern;
