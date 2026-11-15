/**
 * `agent-redact proxy`: a local HTTP proxy in front of the Anthropic or OpenAI API.
 *
 * Point an SDK or tool at it (`ANTHROPIC_BASE_URL=<proxy url>`, `OPENAI_BASE_URL=<proxy url>/v1`;
 * the CLI prints the exact values) and every request body is redacted with reversible
 * placeholders before it leaves the machine. Responses are restored: JSON with `unmaskDeep`,
 * streams with the SSE adapters, under the same tool-input policy (masked by default).
 *
 * Fail closed: it listens on the IPv4 loopback address only, rejects browser requests (Origin
 * header) and foreign Host headers (DNS rebinding), refuses request bodies it cannot parse (non-JSON,
 * compressed, oversized, malformed) instead of forwarding them, and passes unknown response
 * content through still masked. Auth headers are forwarded untouched and never logged.
 */
import { type Server } from 'node:http';
import { Vault } from '../core/vault.js';
import { type ToolInputPolicy } from '../core/deep.js';
import type { RedactOptions } from '../core/types.js';
export type ProxyProvider = 'anthropic' | 'openai';
export interface ProxyOptions {
    provider: ProxyProvider;
    /** Upstream base URL. Default: the provider's public API. Must be https (http only for loopback). */
    upstream?: string;
    /** Port on the loopback address. Default 8787; 0 picks a free port. */
    port?: number;
    /** Restore secrets in model-generated tool inputs. Default `false` (they stay masked). */
    unmaskToolInputs?: ToolInputPolicy;
    /** Detection options (presets, custom patterns, allowlist, entropy …) */
    redactOptions?: RedactOptions;
    /** Maximum request body size in bytes. Default 32 MB. */
    maxBodyBytes?: number;
    /** One line per request, without secret values or headers. Default: none. */
    log?: (line: string) => void;
}
export interface RunningProxy {
    server: Server;
    /** Shared by all requests, so a secret keeps one placeholder for the proxy's lifetime */
    vault: Vault;
    address: string;
    port: number;
    url: string;
    close(): Promise<void>;
}
export declare const LOOPBACK_HOST: string;
export declare function startProxy(options: ProxyOptions): Promise<RunningProxy>;
