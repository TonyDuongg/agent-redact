#!/usr/bin/env node
import { fileURLToPath } from 'node:url';
import { runMcpServer, createMcpServer } from './server.js';

export { runMcpServer, createMcpServer };
export type { McpServerOptions } from './server.js';

// Determine if this file is executed directly (via CLI / npx) vs imported as a library module
const isMain =
  typeof require !== 'undefined' && typeof module !== 'undefined' && require.main === module
    ? true
    : Boolean(
        process.argv[1] &&
          (fileURLToPath(import.meta.url) === process.argv[1] ||
            process.argv[1].replace(/\\/g, '/').endsWith('/mcp/index.js') ||
            process.argv[1].endsWith('agent-redact-mcp'))
      );

if (isMain) {
  runMcpServer().catch((err) => {
    console.error('Fatal error in agent-redact MCP server:', err);
    process.exit(1);
  });
}

