import type { RedactPattern, SecretCategory, Severity } from './types.js';
import type { EntropyConfig } from './entropy.js';
export interface CustomPatternConfig {
    id: string;
    name: string;
    category?: SecretCategory;
    severity?: Severity;
    /** Regex string pattern (e.g. "corp_[a-zA-Z0-9]{32}" or with flags "/.../gi") */
    regex: string;
    placeholder: string;
    description?: string;
    /**
     * Capturing group (number or name) holding the secret, e.g. 2 for "(key):\s*(value)".
     * Without it, a named group "(?<secret>...)" is used if present, otherwise the whole match.
     */
    secretGroup?: number | string;
}
export interface AgentRedactConfig {
    /** Pattern IDs to activate */
    include?: string[];
    /** Pattern IDs to disable */
    exclude?: string[];
    /** Exact strings to ignore (whitelist). Substrings are NOT matched. */
    allowlist?: string[];
    /** Default to reversible session masking */
    reversible?: boolean;
    /** Enable generic high-entropy secret detection */
    detectHighEntropy?: boolean;
    /** Custom entropy parameters */
    entropy?: EntropyConfig;
    /** User-defined custom secret patterns */
    customPatterns?: CustomPatternConfig[];
    /** Opt-in pattern bundles, e.g. ["vn-pii"] */
    presets?: string[];
}
export interface ResolvedConfig extends Omit<AgentRedactConfig, 'customPatterns'> {
    customPatterns?: RedactPattern[];
}
/**
 * Parses a regex string like "/abc/gi" or "abc" into a RegExp object
 */
export declare function parseRegexString(patternStr: string): RegExp;
/**
 * Converts a raw JSON pattern configuration into a live RedactPattern
 */
export declare function resolveCustomPattern(cfg: CustomPatternConfig): RedactPattern;
/**
 * Searches and loads configuration from explicit path or default config file in directory.
 */
export declare function loadConfig(explicitPath?: string, searchDir?: string): ResolvedConfig | null;
