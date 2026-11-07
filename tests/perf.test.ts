import { describe, it, expect, afterEach, vi } from 'vitest';
import { redact } from '../src/index.js';
import { runAction } from '../src/action/index.js';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

/**
 * Performance regression guards. Each input below took 4–19 s before the fix
 * (quadratic behaviour); after the fix they run in well under a second locally.
 * Thresholds leave ~10x headroom for slow CI runners.
 */
function timed<T>(fn: () => T): { value: T; ms: number } {
  const t0 = performance.now();
  const value = fn();
  return { value, ms: performance.now() - t0 };
}

const lines = (n: number, f: (i: number) => string) => Array.from({ length: n }, (_, i) => f(i)).join('\n');
const ip = (i: number) => `10.${(i >> 16) & 255}.${(i >> 8) & 255}.${i & 255}`;

describe('Performance guards', () => {
  it('resolves 100k matches in linear time (was 18.8 s)', () => {
    const text = lines(100_000, (i) => `host ${ip(i)} ok`);
    const { value, ms } = timed(() => redact(text));
    expect(value.totalLeaks).toBe(100_000);
    expect(ms).toBeLessThan(3000);
  });

  it('allocates 40k reversible placeholders in linear time (was 11 s)', () => {
    const text = lines(40_000, (i) => `user${i}@example.com`);
    const { value, ms } = timed(() => redact(text, { reversible: true }));
    expect(value.totalLeaks).toBe(40_000);
    expect(value.vault!.size).toBe(40_000);
    expect(ms).toBeLessThan(3000);
  });

  it('is not vulnerable to polynomial backtracking in the email pattern (was 10 s for 80KB)', () => {
    for (const unit of ['a-', 'a.', '1.', '1-']) {
      const text = unit.repeat(40_000); // 80KB adversarial input
      const { ms } = timed(() => redact(text));
      expect(ms, `unit ${JSON.stringify(unit)}`).toBeLessThan(1500);
    }
    const { ms } = timed(() => redact('a'.repeat(40_000) + '@' + 'a.'.repeat(40_000) + '1'));
    expect(ms).toBeLessThan(1500);
  });

  it('handles many private-key BEGIN markers without END in linear time (was 4.3 s)', () => {
    const text = '-----BEGIN PRIVATE KEY-----\nAAAA\n'.repeat(40_000);
    const { ms } = timed(() => redact(text));
    expect(ms).toBeLessThan(2000);
  });

  it('keeps email detection behaviour for normal addresses', () => {
    const text = 'mail john.doe+tag@sub.example.co.uk, a@b.io and x_y%z@host-name.dev';
    expect(redact(text).text).toBe(
      'mail [REDACTED_EMAIL_ADDRESS], [REDACTED_EMAIL_ADDRESS] and [REDACTED_EMAIL_ADDRESS]'
    );
  });

  it('keeps overlap priority: higher severity wins, then longer span', () => {
    // database URL (critical) contains an email-like and an IP-like substring
    const text = 'db postgres://admin:S3cret@10.0.0.5:5432/app ok';
    expect(redact(text).text).toBe('db [REDACTED_DATABASE_URL] ok');
  });
});

describe('GitHub Action file selection', () => {
  const dirs: string[] = [];
  afterEach(() => {
    for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
  });

  async function scan(dir: string, extraEnv: Record<string, string> = {}) {
    const logs: string[] = [];
    const spy = vi.spyOn(console, 'log').mockImplementation((m: unknown) => {
      logs.push(String(m));
    });
    const oldEnv = process.env;
    process.env = { ...oldEnv, INPUT_SCAN_PATH: dir, INPUT_FAIL_ON_LEAK: 'false', ...extraEnv };
    try {
      await runAction();
    } finally {
      process.env = oldEnv;
      spy.mockRestore();
    }
    return logs;
  }

  it('skips binary files regardless of extension (NUL byte sniffing)', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'ar-bin-'));
    dirs.push(dir);
    const blob = Buffer.alloc(4096);
    blob.write(['AKIA', 'IOSFODNN7EXAMPLE'].join(''), 100);
    for (const name of ['font.woff2', 'video.mp4', 'lib.jar', 'noext']) writeFileSync(join(dir, name), blob);
    writeFileSync(join(dir, 'real.env'), `K=${['AKIA', 'IOSFODNN7EXAMPLE'].join('')}\n`);

    const logs = await scan(dir);
    const errors = logs.filter((l) => l.startsWith('::error '));
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain('real.env');
  });

  it('skips files larger than max-file-size and reports them', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'ar-big-'));
    dirs.push(dir);
    writeFileSync(join(dir, 'big.log'), `K=${['AKIA', 'IOSFODNN7EXAMPLE'].join('')}\n` + 'x'.repeat(2 * 1024 * 1024));
    const logs = await scan(dir, { 'INPUT_MAX-FILE-SIZE': '1' });
    expect(logs.some((l) => l.startsWith('::error '))).toBe(false);
    expect(logs.join('\n')).toMatch(/skipped 1 file/i);
  });
});
