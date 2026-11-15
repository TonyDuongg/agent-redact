import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
export interface McpServerOptions {
    /**
     * Directories the file tools may read from / write to.
     * Defaults to the process cwd, the OS temp dir and AGENT_REDACT_ALLOWED_DIR (if set).
     */
    allowedRoots?: string[];
    /** Maximum number of distinct secrets kept in the session vault (default 10,000) */
    vaultMaxEntries?: number;
    /**
     * Enable `unmask_text`, which writes restored secrets into any file inside the allowed
     * roots. Off by default since 0.5: a prompt-injected model could copy a secret into a file
     * that is later published. Prefer `edit_file_redacted`, which only restores a file's own
     * secrets into that same file.
     */
    allowUnmaskText?: boolean;
}
/** Options from `agent-redact mcp` / `agent-redact-mcp` arguments and the environment */
export declare function mcpOptionsFromArgs(args: string[], env?: NodeJS.ProcessEnv): McpServerOptions;
export declare function createMcpServer(options?: McpServerOptions): McpServer;
/** `args`: the arguments after `agent-redact mcp` (or of `agent-redact-mcp`) */
export declare function runMcpServer(args?: string[]): Promise<void>;
