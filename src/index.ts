// Core Engine & Vault
export { RedactEngine, redact, unmask } from './core/engine.js';
export { Vault } from './core/vault.js';
export { createRedactStream, RedactTransformStream } from './core/stream.js';
export type { RedactStreamOptions } from './core/stream.js';

// Configuration & Extensibility
export { loadConfig, parseRegexString, resolveCustomPattern } from './core/config.js';
export type { AgentRedactConfig, CustomPatternConfig, ResolvedConfig } from './core/config.js';

// Shannon Entropy & Heuristics
export { calculateShannonEntropy, isHighEntropyToken, createHighEntropyPattern } from './core/entropy.js';
export type { EntropyConfig } from './core/entropy.js';

// Universal Agent Interceptors & Middlewares
export { wrapAgent, createExpressMiddleware } from './middleware/index.js';
export type { AgentInterceptorOptions, RedactRequestExtension } from './middleware/index.js';

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

