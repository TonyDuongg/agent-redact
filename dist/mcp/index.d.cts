#!/usr/bin/env node
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

declare function createMcpServer(): McpServer;
declare function runMcpServer(): Promise<void>;

export { createMcpServer, runMcpServer };
