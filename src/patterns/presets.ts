import type { RedactPattern } from '../core/types.js';
import { VN_PII_PATTERNS } from './vn.js';

/** Opt-in pattern bundles that are not part of DEFAULT_PATTERNS */
export const PATTERN_PRESETS: Readonly<Record<string, readonly RedactPattern[]>> = {
  'vn-pii': VN_PII_PATTERNS
};

export function resolvePresets(names: readonly string[] | undefined): RedactPattern[] {
  if (!names || names.length === 0) return [];
  const out: RedactPattern[] = [];
  for (const name of names) {
    const preset = PATTERN_PRESETS[name];
    if (!preset) {
      throw new Error(`Unknown preset "${name}". Available presets: ${Object.keys(PATTERN_PRESETS).join(', ')}`);
    }
    out.push(...preset);
  }
  return out;
}
