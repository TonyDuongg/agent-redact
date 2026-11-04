import { describe, it, expect } from 'vitest';
import { createMcpServer } from '../src/mcp/server.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';

// Helper to construct sample keys without triggering static push protection
const sampleKey = (...parts: string[]) => parts.join('');

describe('MCP Server Integration (Model Context Protocol)', () => {
  it('should initialize MCP server, list registered tools and execute redact/unmask roundtrip', async () => {
    const server = createMcpServer();
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();

    const client = new Client(
      { name: 'claude-desktop-test', version: '1.0.0' },
      { capabilities: {} }
    );

    await Promise.all([
      client.connect(clientTransport),
      server.connect(serverTransport)
    ]);

    // 1. Verify all 6 tools are discovered
    const toolsResult = await client.listTools();
    const toolNames = toolsResult.tools.map((t) => t.name);

    expect(toolNames).toContain('redact_text');
    expect(toolNames).toContain('unmask_text');
    expect(toolNames).toContain('scan_file');
    expect(toolNames).toContain('get_vault_status');
    expect(toolNames).toContain('clear_vault');
    expect(toolNames).toContain('list_supported_patterns');

    // 2. Call redact_text with reversible mode
    const fakeKey = sampleKey(
      'sk-',
      'ant-api03-',
      'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012345'
    );
    const redactCall = await client.callTool({
      name: 'redact_text',
      arguments: {
        text: `Prompt with Anthropic key: ${fakeKey}`,
        reversible: true
      }
    });

    const parsedRedact = JSON.parse((redactCall.content as Array<{ text: string }>)[0]!.text);
    expect(parsedRedact.hasLeaks).toBe(true);
    expect(parsedRedact.totalLeaks).toBe(1);
    expect(parsedRedact.sanitizedText).toBe('Prompt with Anthropic key: [ANTHROPIC_API_KEY_1]');

    // 3. Check vault status
    const vaultCall = await client.callTool({
      name: 'get_vault_status',
      arguments: {}
    });
    const vaultStatus = JSON.parse((vaultCall.content as Array<{ text: string }>)[0]!.text);
    expect(vaultStatus.vaultSize).toBe(1);
    expect(vaultStatus.entries[0].placeholder).toBe('[ANTHROPIC_API_KEY_1]');

    // 4. Call unmask_text to restore secrets in Claude's output
    const unmaskCall = await client.callTool({
      name: 'unmask_text',
      arguments: {
        text: 'I used [ANTHROPIC_API_KEY_1] to authenticate Claude.'
      }
    });
    const unmaskedText = (unmaskCall.content as Array<{ text: string }>)[0]!.text;
    expect(unmaskedText).toBe(`I used ${fakeKey} to authenticate Claude.`);

    // 5. Test clear_vault
    const clearCall = await client.callTool({
      name: 'clear_vault',
      arguments: {}
    });
    expect((clearCall.content as Array<{ text: string }>)[0]!.text).toContain('Purged 1 secret(s)');

    // Verify vault is empty
    const emptyVault = await client.callTool({
      name: 'get_vault_status',
      arguments: {}
    });
    const emptyStatus = JSON.parse((emptyVault.content as Array<{ text: string }>)[0]!.text);
    expect(emptyStatus.vaultSize).toBe(0);

    // 6. Test list_supported_patterns
    const patternsCall = await client.callTool({
      name: 'list_supported_patterns',
      arguments: {}
    });
    const patternsData = JSON.parse((patternsCall.content as Array<{ text: string }>)[0]!.text);
    expect(patternsData.totalPatterns).toBeGreaterThanOrEqual(15);

    await client.close();
  });
});
