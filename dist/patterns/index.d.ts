import type { RedactPattern } from '../core/types.js';
export * from './credentials.js';
export * from './pii.js';
export * from './vn.js';
export { PATTERN_PRESETS, resolvePresets } from './presets.js';
/**
 * All default patterns included in agent-redact
 */
export declare const DEFAULT_PATTERNS: RedactPattern[];
/**
 * Map pattern ID to RedactPattern for fast lookup
 */
export declare const PATTERN_MAP: ReadonlyMap<string, RedactPattern>;
