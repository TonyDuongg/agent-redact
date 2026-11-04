#!/usr/bin/env node
import { runMcpServer } from './server.js';

runMcpServer().catch((err) => {
  console.error('Fatal error in agent-redact MCP server:', err);
  process.exit(1);
});

