import { redact } from '../core/engine.js';
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
  // eslint-disable-next-line @typescript-eslint/no-namespace
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
export function createExpressMiddleware(
  options: RedactOptions & { targetFields?: string[] } = {}
) {
  const { targetFields = ['prompt', 'message', 'content', 'input'], ...redactOpts } = options;

  return (
    req: { body?: Record<string, unknown>; redact?: RedactRequestExtension },
    _res: unknown,
    next: () => void
  ) => {
    if (!req.body || typeof req.body !== 'object') {
      return next();
    }

    const vault = new Vault();
    let totalLeaks = 0;
    const combinedStats: Record<string, number> = {};
    const allMatches: RedactResult['matches'] = [];

    // Helper to recursively or selectively redact target fields
    const redactObject = (obj: Record<string, unknown>) => {
      for (const [key, value] of Object.entries(obj)) {
        if (typeof value === 'string' && targetFields.includes(key)) {
          const result = redact(value, { ...redactOpts, reversible: true, vault });
          obj[key] = result.text;
          if (result.hasLeaks) {
            totalLeaks += result.totalLeaks;
            allMatches.push(...result.matches);
            for (const [pId, count] of Object.entries(result.stats)) {
              combinedStats[pId] = (combinedStats[pId] ?? 0) + count;
            }
          }
        } else if (Array.isArray(value)) {
          for (const item of value) {
            if (item && typeof item === 'object') {
              redactObject(item as Record<string, unknown>);
            }
          }
        } else if (value && typeof value === 'object') {
          redactObject(value as Record<string, unknown>);
        }
      }
    };

    redactObject(req.body);

    req.redact = {
      vault,
      totalLeaks,
      hasLeaks: totalLeaks > 0,
      stats: combinedStats,
      matches: allMatches
    };

    next();
  };
}
