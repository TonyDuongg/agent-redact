import { describe, it, expect } from 'vitest';
import { Readable } from 'node:stream';
import {
  redact,
  Vault,
  StreamingUnmasker,
  unmaskTextStream,
  createUnmaskStream,
  redactDeep,
  unmaskDeep,
  unmaskAnthropicStream,
  unmaskOpenAIStream,
  wrapAgent
} from '../src/index.js';

// Token-shaped fixtures are assembled at runtime so they never appear verbatim in the repo
const AWS = ['AKIA', 'IOSFODNN7EXAMPLE'].join('');
const GH = ['ghp_', 'a'.repeat(36)].join('');

function vaultWith(...secrets: string[]): { vault: Vault; masked: string } {
  const vault = new Vault();
  const masked = redact(secrets.join(' '), { reversible: true, vault }).text;
  return { vault, masked };
}

async function* fromArray<T>(items: T[]): AsyncGenerator<T> {
  for (const item of items) yield item;
}

async function collect<T>(it: AsyncIterable<T>): Promise<T[]> {
  const out: T[] = [];
  for await (const x of it) out.push(x);
  return out;
}

describe('StreamingUnmasker', () => {
  it('restores a placeholder split at every possible position across two chunks', () => {
    const { vault } = vaultWith(AWS);
    const text = 'key=[AWS_ACCESS_KEY_ID_1] done';
    for (let cut = 0; cut <= text.length; cut++) {
      const u = new StreamingUnmasker(vault);
      const out = u.push(text.slice(0, cut)) + u.push(text.slice(cut)) + u.flush();
      expect(out, `cut at ${cut}`).toBe(`key=${AWS} done`);
    }
  });

  it('restores placeholders split across many single-character chunks', () => {
    const { vault } = vaultWith(AWS, GH);
    const text = '[AWS_ACCESS_KEY_ID_1] and [GITHUB_TOKEN_1]!';
    const u = new StreamingUnmasker(vault);
    let out = '';
    for (const ch of text) out += u.push(ch);
    out += u.flush();
    expect(out).toBe(`${AWS} and ${GH}!`);
  });

  it('does not hold back brackets that cannot start a known placeholder', () => {
    const { vault } = vaultWith(AWS);
    const u = new StreamingUnmasker(vault);
    expect(u.push('see [1')).toBe('see [1');
    expect(u.push('] and [x')).toBe('] and [x');
  });

  it('emits an unfinished placeholder prefix unchanged on flush', () => {
    const { vault } = vaultWith(AWS);
    const u = new StreamingUnmasker(vault);
    expect(u.push('tail [AWS_ACC')).toBe('tail ');
    expect(u.flush()).toBe('[AWS_ACC');
  });
});

describe('text stream helpers', () => {
  it('unmaskTextStream unmasks an async iterable of chunks', async () => {
    const { vault } = vaultWith(AWS);
    const chunks = await collect(unmaskTextStream(fromArray(['a [AWS_', 'ACCESS_KEY', '_ID_1] b']), vault));
    expect(chunks.join('')).toBe(`a ${AWS} b`);
  });

  it('createUnmaskStream works as a Node transform, including split UTF-8', async () => {
    const { vault } = vaultWith(AWS);
    const bytes = Buffer.from('Việt [AWS_ACCESS_KEY_ID_1] ổn', 'utf8');
    const parts = [bytes.subarray(0, 3), bytes.subarray(3, 12), bytes.subarray(12)];
    let out = '';
    await new Promise<void>((resolve, reject) => {
      Readable.from(parts)
        .pipe(createUnmaskStream(vault))
        .on('data', (d) => (out += d))
        .on('end', resolve)
        .on('error', reject);
    });
    expect(out).toBe(`Việt ${AWS} ổn`);
  });
});

describe('redactDeep / unmaskDeep', () => {
  const imageData = 'iVBORw0KGgo' + 'A'.repeat(64) + ['AKIA', 'ABCDEFGHIJKLMNOP'].join('');

  it('redacts every string in an Anthropic-shaped request with one shared vault', () => {
    const request = {
      model: 'claude-sonnet-5-5',
      system: `deploy key ${AWS}`,
      messages: [
        { role: 'user', content: [{ type: 'text', text: `token ${GH}` }] },
        {
          role: 'user',
          content: [
            { type: 'tool_result', tool_use_id: 'tu_1', content: `again ${AWS}` },
            { type: 'image', source: { type: 'base64', media_type: 'image/png', data: imageData } }
          ]
        }
      ]
    };
    const before = JSON.stringify(request);
    const { value, vault, totalLeaks } = redactDeep(request);

    expect(JSON.stringify(request)).toBe(before); // input is not mutated
    expect(value.system).toBe('deploy key [AWS_ACCESS_KEY_ID_1]');
    expect((value.messages[0]!.content[0] as { text: string }).text).toBe('token [GITHUB_TOKEN_1]');
    expect((value.messages[1]!.content[0] as { content: string }).content).toBe('again [AWS_ACCESS_KEY_ID_1]');
    // base64 image payloads are left byte-for-byte intact
    expect((value.messages[1]!.content[1] as { source: { data: string } }).source.data).toBe(imageData);
    expect(totalLeaks).toBe(3);
    expect(vault.size).toBe(2);
  });

  it('leaves data: URLs untouched', () => {
    const url = 'data:image/png;base64,' + ['AKIA', 'ABCDEFGHIJKLMNOP'].join('');
    expect(redactDeep({ image_url: { url } }).value.image_url.url).toBe(url);
  });

  it('unmasks nested tool_use input objects in a response', () => {
    const { vault } = vaultWith(AWS);
    const response = {
      content: [
        { type: 'text', text: 'Calling tool' },
        { type: 'tool_use', id: 'tu_1', name: 'deploy', input: { env: { KEY: '[AWS_ACCESS_KEY_ID_1]' }, args: ['[AWS_ACCESS_KEY_ID_1]'] } }
      ]
    };
    type Block = { type: string; input?: { env: { KEY: string }; args: string[] } };
    const out = unmaskDeep(response, vault) as { content: Block[] };
    expect(out.content[1]!.input).toEqual({ env: { KEY: AWS }, args: [AWS] });
    expect((response.content[1] as Block).input!.env.KEY).toBe('[AWS_ACCESS_KEY_ID_1]'); // not mutated
  });
});

describe('SDK stream adapters', () => {
  it('unmaskAnthropicStream restores text deltas split mid-placeholder', async () => {
    const { vault } = vaultWith(AWS);
    const events = [
      { type: 'message_start', message: { id: 'm1' } },
      { type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } },
      { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'use [AWS_ACC' } },
      { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'ESS_KEY_ID_1] now' } },
      { type: 'content_block_stop', index: 0 },
      { type: 'message_stop' }
    ];
    const out = await collect(unmaskAnthropicStream(fromArray(events), vault));
    const text = out
      .filter((e) => e.type === 'content_block_delta')
      .map((e) => (e as { delta: { text: string } }).delta.text)
      .join('');
    expect(text).toBe(`use ${AWS} now`);
    expect(out.map((e) => e.type)).toContain('content_block_stop');
  });

  it('unmaskAnthropicStream keeps tool input JSON valid when the secret needs escaping', async () => {
    const vault = new Vault();
    const tricky = 'pa"ss\\word\n-' + 'x'.repeat(20); // quote, backslash and newline
    const placeholder = '[DB_PASSWORD_1]';
    vault.restoreEntry({ placeholder, original: tricky, patternId: 'custom', category: 'credential', timestamp: 0 });
    const json = JSON.stringify({ password: placeholder });
    const events = [
      { type: 'content_block_start', index: 1, content_block: { type: 'tool_use', id: 't', name: 'n', input: {} } },
      { type: 'content_block_delta', index: 1, delta: { type: 'input_json_delta', partial_json: json.slice(0, 18) } },
      { type: 'content_block_delta', index: 1, delta: { type: 'input_json_delta', partial_json: json.slice(18) } },
      { type: 'content_block_stop', index: 1 }
    ];
    const out = await collect(unmaskAnthropicStream(fromArray(events), vault));
    const partial = out
      .filter((e) => e.type === 'content_block_delta')
      .map((e) => (e as { delta: { partial_json: string } }).delta.partial_json)
      .join('');
    expect(JSON.parse(partial)).toEqual({ password: tricky });
  });

  it('unmaskOpenAIStream restores content and tool-call arguments across chunks', async () => {
    const { vault } = vaultWith(AWS);
    type Chunk = {
      choices: Array<{
        index: number;
        delta: { content?: string; tool_calls?: Array<{ index: number; function?: { arguments?: string } }> };
        finish_reason: string | null;
      }>;
    };
    const chunks: Chunk[] = [
      { choices: [{ index: 0, delta: { content: 'key [AWS_ACCESS' }, finish_reason: null }] },
      { choices: [{ index: 0, delta: { content: '_KEY_ID_1].' }, finish_reason: null }] },
      { choices: [{ index: 0, delta: { tool_calls: [{ index: 0, function: { arguments: '{"k":"[AWS_' } }] }, finish_reason: null }] },
      { choices: [{ index: 0, delta: { tool_calls: [{ index: 0, function: { arguments: 'ACCESS_KEY_ID_1]"}' } }] }, finish_reason: null }] },
      { choices: [{ index: 0, delta: {}, finish_reason: 'stop' }] }
    ];
    const out = await collect(unmaskOpenAIStream(fromArray(chunks), vault));
    const content = out.map((c) => c.choices[0]!.delta.content ?? '').join('');
    const args = out
      .map((c) => c.choices[0]!.delta.tool_calls?.[0]?.function?.arguments ?? '')
      .join('');
    expect(content).toBe(`key ${AWS}.`);
    expect(JSON.parse(args)).toEqual({ k: AWS });
  });
});

describe('wrapAgent', () => {
  it('deep-unmasks object responses', async () => {
    const agent = wrapAgent(async (prompt: string) => ({ echo: prompt, nested: [prompt] }));
    const res = await agent(`my key ${AWS}`);
    expect(res).toEqual({ echo: `my key ${AWS}`, nested: [`my key ${AWS}`] });
  });

  it('stream-unmasks async iterable responses', async () => {
    const agent = wrapAgent(async (prompt: string) => {
      const half = Math.floor(prompt.length / 2);
      return fromArray([prompt.slice(0, half), prompt.slice(half)]);
    });
    const res = await agent(`key ${AWS} end`);
    expect((await collect(res)).join('')).toBe(`key ${AWS} end`);
  });

  it('never sends the raw secret to the agent function', async () => {
    let seen = '';
    const agent = wrapAgent(async (prompt: string) => {
      seen = prompt;
      return 'ok';
    });
    await agent(`key ${AWS}`);
    expect(seen).not.toContain(AWS);
  });
});
