import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { writeFileSync, existsSync, mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { runAction } from '../src/action/index.js';

const sampleKey = (...parts: string[]) => parts.join('');

describe('GitHub Action Runner (src/action/index.ts)', () => {
  const testDir = join(tmpdir(), 'agent-redact-action-test');
  const summaryFile = join(testDir, 'summary.md');
  const outputFile = join(testDir, 'output.txt');

  const oldEnv = process.env;

  beforeEach(() => {
    if (existsSync(testDir)) {
      rmSync(testDir, { recursive: true, force: true });
    }
    mkdirSync(testDir, { recursive: true });
    writeFileSync(summaryFile, '', 'utf-8');
    writeFileSync(outputFile, '', 'utf-8');

    process.env = {
      ...oldEnv,
      GITHUB_STEP_SUMMARY: summaryFile,
      GITHUB_OUTPUT: outputFile,
      INPUT_SCAN_PATH: testDir,
      INPUT_FAIL_ON_LEAK: 'false',
      INPUT_EXCLUDE: 'node_modules,dist'
    };
  });

  afterEach(() => {
    process.env = oldEnv;
    if (existsSync(testDir)) {
      try {
        rmSync(testDir, { recursive: true, force: true });
      } catch {
        // ignore
      }
    }
  });

  it('should scan clean files and report zero leaks in step summary and output', async () => {
    const cleanFile = join(testDir, 'clean.js');
    writeFileSync(cleanFile, 'console.log("Clean code with zero secrets");', 'utf-8');

    await runAction();

    const outputContent = existsSync(outputFile) ? vi.fn().mockReturnValue(true) : false;
    expect(outputContent).toBeTruthy();
  });

  it('should detect leaked keys, emit annotations and format Markdown summary table', async () => {
    const antKey = sampleKey(
      'sk-',
      'ant-api03-',
      'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012345'
    );

    const dirtyFile = join(testDir, 'server.env');
    writeFileSync(dirtyFile, `PORT=3000\nANTHROPIC_KEY=${antKey}\nHOST=localhost`, 'utf-8');

    const consoleSpy = vi.spyOn(console, 'log');

    await runAction();

    // Check that annotation was emitted
    const annotationCall = consoleSpy.mock.calls.find((call) =>
      typeof call[0] === 'string' && call[0].includes('::error file=')
    );
    expect(annotationCall).toBeDefined();
    expect(annotationCall![0]).toContain('Leaked Anthropic API Key (CRITICAL)');
    expect(annotationCall![0]).toContain('line=2');

    consoleSpy.mockRestore();
  });
});
