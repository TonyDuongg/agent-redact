import { describe, it, expect, afterEach } from 'vitest';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  redact,
  Vault,
  DEFAULT_PATTERNS,
  VN_PII_PATTERNS,
  loadConfig,
  encryptVaultJson,
  decryptVaultJson,
  isEncryptedVault
} from '../src/index.js';

const execFileAsync = promisify(execFile);
const cliPath = join(process.cwd(), 'dist', 'cli', 'index.js');
// All token-shaped fixtures are assembled at runtime so none appears verbatim in the repo
const j = (...p: string[]) => p.join('');
const r = (n: number, abc = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789') =>
  Array.from({ length: n }, (_, i) => abc[(i * 7 + 3) % abc.length]).join('');
const hex = (n: number) => r(n, '0123456789abcdef');

/** Labelled positive corpus: one or more samples per built-in pattern id */
const POSITIVES: Record<string, string[]> = {
  'anthropic-api-key': [j('sk-', 'ant-', 'api03-', r(93), 'AA')],
  'openai-api-key': [j('sk-', 'proj-', r(60)), j('sk-', r(48))],
  'aws-access-key-id': [j('AKIA', 'IOSFODNN7EXAMPLE')],
  'aws-secret-access-key': [j('wJalrXUtnFEMI/K7MDENG/', 'bPxRfiCYEXAMPLEKEY')], // needs context, see below
  'github-token': [j('ghp_', r(36)), j('github_pat_', r(82))],
  'stripe-api-key': [j('sk_', 'live_', r(99)), j('rk_', 'test_', r(30))],
  'jwt-token': [j('eyJ', 'hbGciOiJIUzI1NiJ9', '.', 'eyJ', 'zdWIiOiIxMjM0NTY3ODkwIn0', '.', r(43))],
  'private-key': [j('-----BEGIN ', 'PRIVATE KEY-----\nMIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7\n-----END ', 'PRIVATE KEY-----')],
  'google-api-key': [j('AIza', r(35))],
  'slack-token': [j('xo', 'xb-', '1234567890123-1234567890123-', r(24))],
  'database-url': [j('postgres', '://app:S3cret@db.example.com:5432/app')],
  'basic-auth-url': [j('https', '://deploy:hunter2pass@ci.example.com/hook')],
  'huggingface-token': [j('hf_', r(34))],
  'huggingface-org-token': [j('api_org_', r(34))],
  'gitlab-token': [j('glpat', '-', r(20))],
  'discord-token': [j('M', r(23), '.', r(6), '.', r(27))],
  'npm-token': [j('npm_', r(36))],
  'sendgrid-api-key': [j('SG', '.', r(22), '.', r(43))],
  'twilio-account-sid': [j('AC', hex(32))],
  'twilio-api-key': [j('SK', hex(32))],
  'supabase-key': [j('sbp_', r(40))],
  'telegram-bot-token': [j('123456789', ':', r(35))],
  'azure-storage-key': [j('AccountKey', '=', r(86), '==')],
  'gcp-oauth-client-secret': [j('GOCSPX', '-', r(28))],
  'digitalocean-token': [j('dop_', 'v1_', hex(64))],
  'mailgun-api-key': [j('key', '-', r(32))],
  'openrouter-api-key': [j('sk-', 'or-v1-', hex(64))],
  'groq-api-key': [j('gsk_', r(52))],
  'xai-api-key': [j('xai', '-', r(80))],
  'perplexity-api-key': [j('pplx', '-', r(48))],
  'replicate-api-token': [j('r8_', r(37))],
  'langsmith-api-key': [j('lsv2_', 'pt_', hex(32), '_', hex(10)), j('lsv2_', 'sk_', hex(32), '_', hex(10))],
  'email-address': ['jane.doe+tests@example.org'],
  'ipv4-address': ['192.168.10.42'],
  'ipv6-address': ['2001:db8:85a3::8a2e:370:7334'],
  'phone-number': ['+1 415 555 0132', '0912 345 678'],
  'us-ssn': ['123-45-6789'],
  'credit-card': ['4111 1111 1111 1111', '5500-0000-0000-0004']
};

/** Patterns that only match with surrounding context */
const CONTEXT: Record<string, (s: string) => string> = {
  'aws-secret-access-key': (s) => `aws_secret_access_key = ${s}\n`
};

describe('Labelled detection corpus', () => {
  it('has at least one positive sample for every built-in pattern', () => {
    const missing = DEFAULT_PATTERNS.map((p) => p.id).filter((id) => !POSITIVES[id]?.length);
    expect(missing, 'add samples to POSITIVES for new patterns').toEqual([]);
  });

  for (const [id, samples] of Object.entries(POSITIVES)) {
    it(`detects ${id} with the full span`, () => {
      for (const sample of samples) {
        const text = CONTEXT[id] ? CONTEXT[id]!(sample) : `value: ${sample} end`;
        const res = redact(text, { includeMatchedText: true });
        const hit = res.matches.find((m) => m.patternId === id);
        expect(hit, `${id}: ${sample.slice(0, 12)}…`).toBeDefined();
        expect(hit!.matchedText).toBe(sample);
      }
    });
  }

  it('reports zero findings on the negative corpus (realistic text without secrets)', () => {
    const negatives = readFileSync(join(process.cwd(), 'tests', 'fixtures', 'negatives.txt'), 'utf-8');
    const res = redact(negatives, { includeMatchedText: true });
    expect(res.matches.map((m) => `${m.patternId}: ${m.matchedText}`)).toEqual([]);
  });
});

describe('Vietnamese PII preset (opt-in)', () => {
  const cccd = j('079', '2', '03', '012345'); // province 079 (HCMC)
  it('is not active by default', () => {
    expect(redact(`CCCD ${cccd}`).totalLeaks).toBe(0);
  });

  it('detects citizen IDs, contextual ID/tax/bank numbers when enabled', () => {
    const text = [
      `số CCCD: ${cccd}`,
      `CMND so ${j('0123', '45678')}`,
      `MST: ${j('0101', '234567')}-001`,
      `STK ${j('1903', '4567', '8901', '23')} Techcombank`
    ].join('\n');
    const res = redact(text, { presets: ['vn-pii'], includeMatchedText: true });
    const ids = res.matches.map((m) => m.patternId).sort();
    expect(ids).toEqual(['vn-bank-account', 'vn-citizen-id', 'vn-id-number', 'vn-tax-code']);
    expect(res.text).not.toContain(cccd);
    expect(res.text).toContain('MST: [REDACTED_VN_TAX_CODE]');
  });

  it('rejects 12-digit numbers with an invalid province code', () => {
    expect(redact(`ref ${j('099', '1', '23', '456789')}`, { presets: ['vn-pii'] }).totalLeaks).toBe(0);
    expect(redact(`ref ${j('000', '1', '23', '456789')}`, { presets: ['vn-pii'] }).totalLeaks).toBe(0);
  });

  it('exports the preset patterns and loads presets from config, rejecting unknown ones', () => {
    expect(VN_PII_PATTERNS.length).toBeGreaterThanOrEqual(4);
    const dir = mkdtempSync(join(tmpdir(), 'ar-preset-'));
    try {
      writeFileSync(join(dir, '.agentredactrc'), JSON.stringify({ presets: ['vn-pii'] }));
      expect(loadConfig(undefined, dir)?.presets).toEqual(['vn-pii']);
      writeFileSync(join(dir, '.agentredactrc'), JSON.stringify({ presets: ['nope'] }));
      expect(() => loadConfig(undefined, dir)).toThrow(/Unknown preset/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
    expect(() => redact('x', { presets: ['nope'] })).toThrow(/Unknown preset/);
  });
});

describe('Encrypted vault files', () => {
  const secret = j('AKIA', 'IOSFODNN7EXAMPLE');
  const dirs: string[] = [];
  afterEach(() => {
    for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
  });

  it('round-trips with the right passphrase and never stores plaintext', () => {
    const v = new Vault();
    redact(`k ${secret}`, { reversible: true, vault: v });
    const enc = encryptVaultJson(v.toJSON(), 'correct horse battery staple');
    expect(isEncryptedVault(enc)).toBe(true);
    expect(enc).not.toContain(secret);
    expect(enc).not.toContain('AWS_ACCESS_KEY_ID');
    const back = Vault.fromJSON(decryptVaultJson(enc, 'correct horse battery staple'));
    expect(back.unmask('[AWS_ACCESS_KEY_ID_1]')).toBe(secret);
  });

  it('rejects a wrong passphrase, tampered ciphertext and tampered KDF parameters', () => {
    const enc = encryptVaultJson('[]', 'pw-1');
    expect(() => decryptVaultJson(enc, 'pw-2')).toThrow(/wrong passphrase or corrupted/);
    const parsed = JSON.parse(enc);
    const flipped = { ...parsed, data: Buffer.from(Buffer.from(parsed.data, 'base64').map((b: number, i: number) => (i === 0 ? b ^ 1 : b))).toString('base64') };
    expect(() => decryptVaultJson(JSON.stringify(flipped), 'pw-1')).toThrow(/wrong passphrase or corrupted/);
    const weaker = { ...parsed, kdf: { ...parsed.kdf, N: 1024 } };
    expect(() => decryptVaultJson(JSON.stringify(weaker), 'pw-1')).toThrow(/wrong passphrase or corrupted/);
    expect(() => encryptVaultJson('[]', '')).toThrow(/passphrase/);
  });

  async function cli(args: string[], cwd: string, env: Record<string, string> = {}) {
    try {
      const { stdout, stderr } = await execFileAsync('node', [cliPath, ...args], { cwd, env: { ...process.env, ...env } });
      return { code: 0, stdout, stderr };
    } catch (err: unknown) {
      const e = err as { code: number; stdout: string; stderr: string };
      return { code: e.code, stdout: e.stdout, stderr: e.stderr };
    }
  }

  it('CLI encrypts --vault-out with --vault-key-env and requires the key to unmask', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'ar-encvault-'));
    dirs.push(dir);
    writeFileSync(join(dir, 'app.env'), `KEY=${secret}\n`);
    const env = { MY_VAULT_PASS: 'a long passphrase for tests' };

    const masked = await cli(['app.env', '-r', '-o', 'safe.env', '--vault-out', 'v.json', '--vault-key-env', 'MY_VAULT_PASS'], dir, env);
    expect(masked.code).toBe(0);
    const vaultFile = readFileSync(join(dir, 'v.json'), 'utf-8');
    expect(isEncryptedVault(vaultFile)).toBe(true);
    expect(vaultFile).not.toContain(secret);

    const noKey = await cli(['safe.env', '--unmask', 'v.json'], dir);
    expect(noKey.code).toBe(2);
    expect(noKey.stderr).toMatch(/encrypted/i);

    const restored = await cli(['safe.env', '--unmask', 'v.json', '--vault-key-env', 'MY_VAULT_PASS'], dir, env);
    expect(restored.stdout).toBe(`KEY=${secret}\n`);

    const missingVar = await cli(['app.env', '-r', '-o', 'x.env', '--vault-out', 'w.json', '--vault-key-env', 'NOT_SET_ANYWHERE'], dir);
    expect(missingVar.code).toBe(2);
  });

  it('CLI warns when a vault is written unencrypted', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'ar-plainvault-'));
    dirs.push(dir);
    writeFileSync(join(dir, 'app.env'), `KEY=${secret}\n`);
    const res = await cli(['app.env', '-r', '-o', 'safe.env', '--vault-out', 'v.json'], dir, { AGENT_REDACT_VAULT_KEY: '' });
    expect(res.stderr).toMatch(/unencrypted/i);
  });
});
