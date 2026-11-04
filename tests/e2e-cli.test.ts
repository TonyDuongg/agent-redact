import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFile, execSync } from 'node:child_process';
import { promisify } from 'node:util';
import { writeFileSync, readFileSync, unlinkSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

const execFileAsync = promisify(execFile);
const cliPath = join(process.cwd(), 'dist', 'cli', 'index.js');

const sampleKey = (...parts: string[]) => parts.join('');

describe('End-to-End (E2E) CLI Testing', () => {
  const tempDir = tmpdir();
  const rawFile = join(tempDir, 'e2e-raw-test.log');
  const safeFile = join(tempDir, 'e2e-safe-test.log');
  const vaultFile = join(tempDir, 'e2e-vault-test.json');
  const restoredFile = join(tempDir, 'e2e-restored-test.log');

  const antKey = sampleKey(
    'sk-',
    'ant-api03-',
    'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012345'
  );
  const openAiKey = sampleKey(
    'sk-',
    'proj-',
    'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'
  );

  const rawContent = `
# Production Credentials
ANTHROPIC_KEY=${antKey}
OPENAI_KEY=${openAiKey}
DB_URL=postgres://user:SecretPass123@internal.db:5432/core
`.trim();

  beforeAll(() => {
    // Ensure dist bundle exists prior to E2E execution
    if (!existsSync(cliPath)) {
      execSync('npm run build', { stdio: 'ignore' });
    }
    writeFileSync(rawFile, rawContent, 'utf-8');
  });

  afterAll(() => {
    for (const f of [rawFile, safeFile, vaultFile, restoredFile]) {
      if (existsSync(f)) {
        try {
          unlinkSync(f);
        } catch {
          // ignore cleanup errors
        }
      }
    }
  });

  it('should print help message and exit 0', async () => {
    const { stdout } = await execFileAsync(process.execPath, [cliPath, '--help']);
    expect(stdout).toContain('agent-redact');
    expect(stdout).toContain('USAGE:');
    expect(stdout).toContain('OPTIONS:');
  });

  it('should print version and exit 0', async () => {
    const { stdout } = await execFileAsync(process.execPath, [cliPath, '--version']);
    expect(stdout.trim()).toBe('agent-redact v0.1.0');
  });

  it('should fail with exit code 1 when input file does not exist', async () => {
    try {
      await execFileAsync(process.execPath, [cliPath, 'non-existent-file-404.txt']);
      expect.fail('Should have exited with error code 1');
    } catch (err: any) {
      expect(err.code).toBe(1);
      expect(err.stderr).toContain('Cannot read file');
    }
  });

  it('should redact secrets to target file using -o flag', async () => {
    await execFileAsync(process.execPath, [cliPath, rawFile, '-o', safeFile]);
    expect(existsSync(safeFile)).toBe(true);

    const safeContent = readFileSync(safeFile, 'utf-8');
    expect(safeContent).not.toContain(antKey);
    expect(safeContent).not.toContain(openAiKey);
    expect(safeContent).toContain('[REDACTED_ANTHROPIC_API_KEY]');
    expect(safeContent).toContain('[REDACTED_OPENAI_API_KEY]');
    expect(safeContent).toContain('[REDACTED_DATABASE_URL]');
  });

  it('should perform reversible masking and unmasking roundtrip with exact byte fidelity', async () => {
    // 1. Mask and output session vault
    await execFileAsync(process.execPath, [
      cliPath,
      rawFile,
      '-r',
      '-o',
      safeFile,
      '--vault-out',
      vaultFile
    ]);

    expect(existsSync(vaultFile)).toBe(true);
    const maskedContent = readFileSync(safeFile, 'utf-8');
    expect(maskedContent).toContain('[ANTHROPIC_API_KEY_1]');
    expect(maskedContent).toContain('[OPENAI_API_KEY_1]');

    // 2. Unmask using the vault file
    await execFileAsync(process.execPath, [
      cliPath,
      safeFile,
      '--unmask',
      vaultFile,
      '-o',
      restoredFile
    ]);

    expect(existsSync(restoredFile)).toBe(true);
    const restoredContent = readFileSync(restoredFile, 'utf-8');
    expect(restoredContent).toBe(rawContent);
  });
});
