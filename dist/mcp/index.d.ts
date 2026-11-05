#!/usr/bin/env node
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

interface McpServerOptions {
    /**
     * Directories the file tools may read from / write to.
     * Defaults to the process cwd, the OS temp dir and AGENT_REDACT_ALLOWED_DIR (if set).
     */
    allowedRoots?: string[];
    /** Maximum number of distinct secrets kept in the session vault (default 10,000) */
    vaultMaxEntries?: number;
}
declare function createMcpServer(options?: McpServerOptions): McpServer;
declare function runMcpServer(): Promise<void>;

export { type McpServerOptions, createMcpServer, runMcpServer };
