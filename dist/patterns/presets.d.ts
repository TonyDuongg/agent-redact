import type { RedactPattern } from '../core/types.js';
/** Opt-in pattern bundles that are not part of DEFAULT_PATTERNS */
export declare const PATTERN_PRESETS: Readonly<Record<string, readonly RedactPattern[]>>;
export declare function resolvePresets(names: readonly string[] | undefined): RedactPattern[];
