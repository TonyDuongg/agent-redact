import { describe, it, expect } from 'vitest';
import { Readable } from 'node:stream';
import { createRedactStream, unmask } from '../src/index.js';

// Helper to construct sample secrets without triggering static push protection
const sampleKey = (...parts: string[]) => parts.join('');

describe('Stream Redaction (createRedactStream)', () => {
  it('should process multi-line stream and redact secrets line by line', async () => {
    const fakeKey = sampleKey(
      'sk-',
      'ant-api03-',
      'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012345'
    );

    const logLines = [
      'Line 1: Server started',
      `Line 2: ANTHROPIC_API_KEY=${fakeKey}`,
      'Line 3: Server listening on port 3000'
    ].join('\n');

    const source = Readable.from([logLines]);
    const redactStream = createRedactStream({ reversible: true });

    let output = '';
    for await (const chunk of source.pipe(redactStream)) {
      output += chunk.toString();
    }

    expect(output).not.toContain(fakeKey);
    expect(output).toContain('[ANTHROPIC_API_KEY_1]');
    expect(output).toContain('Line 1: Server started');
    expect(output).toContain('Line 3: Server listening on port 3000');

    // Test unmasking via the stream's vault
    const restored = unmask(output, redactStream.vault);
    expect(restored).toContain(fakeKey);
  });
});

