import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
export interface McpServerOptions {
    /**
     * Directories the file tools may read from / write to.
     * Defaults to the process cwd, the OS temp dir and AGENT_REDACT_ALLOWED_DIR (if set).
     */
    allowedRoots?: string[];
    /** Maximum number of distinct secrets kept in the session vault (default 10,000) */
    vaultMaxEntries?: number;
}
export declare function createMcpServer(options?: McpServerOptions): McpServer;
export declare function runMcpServer(): Promise<void>;
