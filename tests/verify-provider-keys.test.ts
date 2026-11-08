import { describe, it, expect } from 'vitest';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { join } from 'node:path';

const execFileAsync = promisify(execFile);
const script = join(process.cwd(), 'scripts', 'verify-provider-keys.mjs');

// Token-shaped fixtures are assembled at runtime so none appears verbatim in the repo
const j = (...p: string[]) => p.join('');
const r = (n: number, abc = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789') =>
  Array.from({ length: n }, (_, i) => abc[(i * 5 + 1) % abc.length]).join('');
const hex = (n: number) => r(n, '0123456789abcdef');

const PROVIDERS = ['openrouter', 'groq', 'xai', 'perplexity', 'replicate', 'huggingface-org', 'langsmith'];

/** Every variable the script reads, so keys from the developer's own shell never leak into a test */
const KEY_VARS = [
  'OPENROUTER_KEY', 'OPENROUTER_API_KEY',
  'GROQ_KEY', 'GROQ_API_KEY',
  'XAI_KEY', 'XAI_API_KEY',
  'PERPLEXITY_KEY', 'PERPLEXITY_API_KEY',
  'REPLICATE_KEY', 'REPLICATE_API_TOKEN',
  'HF_ORG_KEY',
  'LANGSMITH_KEY', 'LANGSMITH_API_KEY', 'LANGCHAIN_API_KEY'
];

const VALID: Record<string, string> = {
  OPENROUTER_KEY: j('sk-', 'or-v1-', hex(64)),
  GROQ_KEY: j('gsk_', r(52)),
  XAI_KEY: j('xai', '-', r(40), '_', r(39)),
  PERPLEXITY_KEY: j('pplx', '-', r(48)),
  REPLICATE_KEY: j('r8_', r(20), '-', r(16)),
  HF_ORG_KEY: j('api_org_', r(34)),
  LANGSMITH_KEY: j('lsv2_', 'sk_', hex(32), '_', hex(10))
};

async function run(keys: Record<string, string>, args: string[] = []) {
  const env: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) if (v !== undefined && !KEY_VARS.includes(k)) env[k] = v;
  Object.assign(env, keys);
  try {
    const { stdout, stderr } = await execFileAsync(process.execPath, [script, ...args], { env });
    return { code: 0, stdout, stderr };
  } catch (e) {
    const err = e as { code?: number; stdout?: string; stderr?: string };
    return { code: err.code ?? -1, stdout: err.stdout ?? '', stderr: err.stderr ?? '' };
  }
}

const lines = (status: Record<string, string>) =>
  PROVIDERS.map((p) => `${p}: ${status[p] ?? 'SKIPPED'}`).join('\n') + '\n';

describe('scripts/verify-provider-keys.mjs', () => {
  it('reports PASS for every provider with a well-formed key, and prints nothing else', async () => {
    const res = await run(VALID);
    expect(res.stdout).toBe(lines(Object.fromEntries(PROVIDERS.map((p) => [p, 'PASS']))));
    expect(res.code).toBe(0);
    for (const key of Object.values(VALID)) expect(res.stdout + res.stderr).not.toContain(key.slice(-12));
  });

  it('reports SKIPPED for providers without a key and exits 0', async () => {
    const res = await run({});
    expect(res.stdout).toBe(lines({}));
    expect(res.code).toBe(0);
    expect(res.stderr).toMatch(/No keys found/);
  });

  it('reads the providers\' usual variable names as aliases', async () => {
    const res = await run({ OPENROUTER_API_KEY: VALID.OPENROUTER_KEY!, LANGCHAIN_API_KEY: VALID.LANGSMITH_KEY! });
    expect(res.stdout).toBe(lines({ openrouter: 'PASS', langsmith: 'PASS' }));
  });

  it('reports FAIL with exit 1 when a key is not detected, without echoing any part of it', async () => {
    const short = j('gsk_', r(10));
    const res = await run({ GROQ_KEY: short });
    expect(res.stdout).toBe(lines({ groq: 'FAIL' }));
    expect(res.code).toBe(1);
    expect(res.stdout + res.stderr).not.toContain(short.slice(4));
  });

  it('--explain adds only non-secret hints (reason, length, character classes)', async () => {
    const short = j('gsk_', r(10));
    const res = await run({ GROQ_KEY: short, XAI_KEY: j('xyz', '-', r(80)) }, ['--explain']);
    expect(res.stdout).toBe(
      lines({
        groq: 'FAIL (not detected; prefix ok, 10 chars after prefix, characters: A-Z a-z)',
        xai: 'FAIL (not detected; unexpected prefix, 84 chars, characters: A-Z a-z 0-9 -)'
      })
    );
    expect(res.stdout).not.toContain(short.slice(4));
  });

  it('flags a key that is only partly matched', async () => {
    // A trailing character outside the provider's alphabet would leave part of the key unmasked
    const res = await run({ PERPLEXITY_KEY: j('pplx', '-', r(48), '.', r(6)) }, ['--explain']);
    expect(res.stdout).toBe(lines({ perplexity: 'FAIL (partial match; prefix ok, 55 chars after prefix, characters: A-Z a-z 0-9 other)' }));
  });

  it('ignores surrounding whitespace (e.g. a trailing newline from a file)', async () => {
    const res = await run({ GROQ_KEY: `  ${VALID.GROQ_KEY!}\n` });
    expect(res.stdout).toBe(lines({ groq: 'PASS' }));
  });
});
