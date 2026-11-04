// Core Engine & Vault
export { RedactEngine, redact, unmask } from './core/engine.js';
export { Vault } from './core/vault.js';

// Types
export type {
  SecretCategory,
  Severity,
  RedactPattern,
  RedactMatch,
  VaultEntry,
  RedactOptions,
  RedactResult
} from './core/types.js';

// Patterns
export * from './patterns/index.js';

