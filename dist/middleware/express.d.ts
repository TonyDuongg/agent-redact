import type { RedactOptions, RedactResult } from '../core/types.js';
import { Vault } from '../core/vault.js';
export interface RedactRequestExtension {
    vault: Vault;
    totalLeaks: number;
    hasLeaks: boolean;
    stats: Record<string, number>;
    matches: RedactResult['matches'];
}
declare global {
    namespace Express {
        interface Request {
            redact?: RedactRequestExtension;
        }
    }
}
/**
 * Express / Connect compatible HTTP middleware.
 * Automatically scans and redacts incoming prompt/message bodies
 * before AI agents or route handlers consume them.
 */
export declare function createExpressMiddleware(options?: RedactOptions & {
    targetFields?: string[];
}): (req: {
    body?: Record<string, unknown>;
    redact?: RedactRequestExtension;
}, _res: unknown, next: () => void) => void;
