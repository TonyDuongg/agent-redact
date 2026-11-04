import { readFileSync, existsSync } from 'node:fs';
import { resolve, join } from 'node:path';
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
}

export interface AgentRedactConfig {
  /** Pattern IDs to activate */
  include?: string[];
  /** Pattern IDs to disable */
  exclude?: string[];
  /** Exact strings or substrings to ignore (whitelist) */
  allowlist?: string[];
  /** Default to reversible session masking */
  reversible?: boolean;
  /** Enable generic high-entropy secret detection */
  detectHighEntropy?: boolean;
  /** Custom entropy parameters */
  entropy?: EntropyConfig;
  /** User-defined custom secret patterns */
  customPatterns?: CustomPatternConfig[];
}

export interface ResolvedConfig extends Omit<AgentRedactConfig, 'customPatterns'> {
  customPatterns?: RedactPattern[];
}

const DEFAULT_CONFIG_FILENAMES = [
  'agent-redact.config.json',
  '.agentredactrc.json',
  '.agentredactrc'
];

/**
 * Parses a regex string like "/abc/gi" or "abc" into a RegExp object
 */
export function parseRegexString(patternStr: string): RegExp {
  const match = patternStr.match(/^\/(.+)\/([a-z]*)$/);
  if (match && match[1]) {
    const flags = match[2]?.includes('g') ? match[2] : (match[2] ?? '') + 'g';
    return new RegExp(match[1], flags);
  }
  return new RegExp(patternStr, 'g');
}

/**
 * Converts a raw JSON pattern configuration into a live RedactPattern
 */
export function resolveCustomPattern(cfg: CustomPatternConfig): RedactPattern {
  return {
    id: cfg.id,
    name: cfg.name,
    category: cfg.category ?? 'custom',
    severity: cfg.severity ?? 'high',
    regex: parseRegexString(cfg.regex),
    placeholder: cfg.placeholder,
    description: cfg.description ?? cfg.name
  };
}

/**
 * Searches and loads configuration from explicit path or default config file in directory.
 */
export function loadConfig(
  explicitPath?: string,
  searchDir: string = process.cwd()
): ResolvedConfig | null {
  let targetPath: string | undefined;

  if (explicitPath) {
    const resolved = resolve(searchDir, explicitPath);
    if (!existsSync(resolved)) {
      throw new Error(`Config file not found at: ${resolved}`);
    }
    targetPath = resolved;
  } else {
    for (const filename of DEFAULT_CONFIG_FILENAMES) {
      const candidate = join(searchDir, filename);
      if (existsSync(candidate)) {
        targetPath = candidate;
        break;
      }
    }
  }

  if (!targetPath) {
    return null;
  }

  try {
    const raw = readFileSync(targetPath, 'utf-8');
    const parsed = JSON.parse(raw) as AgentRedactConfig;

    const resolvedCustomPatterns = parsed.customPatterns?.map(resolveCustomPattern);

    return {
      ...parsed,
      customPatterns: resolvedCustomPatterns
    };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Failed to parse agent-redact config at ${targetPath}: ${msg}`);
  }
}
