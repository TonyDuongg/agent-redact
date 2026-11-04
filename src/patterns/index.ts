import { CREDENTIAL_PATTERNS } from './credentials.js';
import { PII_PATTERNS } from './pii.js';
import type { RedactPattern } from '../core/types.js';

export * from './credentials.js';
export * from './pii.js';

/**
 * All default patterns included in agent-redact
 */
export const DEFAULT_PATTERNS: RedactPattern[] = [
  ...CREDENTIAL_PATTERNS,
  ...PII_PATTERNS
];

/**
 * Map pattern ID to RedactPattern for fast lookup
 */
export const PATTERN_MAP: ReadonlyMap<string, RedactPattern> = new Map(
  DEFAULT_PATTERNS.map((p) => [p.id, p])
);

