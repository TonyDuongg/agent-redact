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
  const label = typeof cfg?.id === 'string' && cfg.id ? `"${cfg.id}"` : '(missing id)';
  for (const field of ['id', 'name', 'regex', 'placeholder'] as const) {
    const value = cfg?.[field];
    if (typeof value !== 'string' || value.trim().length === 0) {
      throw new Error(`Custom pattern ${label}: "${field}" must be a non-empty string`);
    }
  }
  if (
    cfg.secretGroup !== undefined &&
    !(
      (typeof cfg.secretGroup === 'number' && Number.isInteger(cfg.secretGroup) && cfg.secretGroup > 0) ||
      (typeof cfg.secretGroup === 'string' && cfg.secretGroup.length > 0)
    )
  ) {
    throw new Error(`Custom pattern ${label}: "secretGroup" must be a positive integer or a group name`);
  }

  return {
    id: cfg.id,
    name: cfg.name,
    category: cfg.category ?? 'custom',
    severity: cfg.severity ?? 'high',
    regex: parseRegexString(cfg.regex),
    placeholder: cfg.placeholder,
    description: cfg.description ?? cfg.name,
    ...(cfg.secretGroup !== undefined ? { secretGroup: cfg.secretGroup } : {})
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

