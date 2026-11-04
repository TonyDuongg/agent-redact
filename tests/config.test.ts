import { describe, it, expect, afterEach } from 'vitest';
import { writeFileSync, unlinkSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  loadConfig,
  parseRegexString,
  redact
} from '../src/index.js';

describe('Configuration & Allowlist (Giai đoạn 1)', () => {
  const tempConfigFile = join(tmpdir(), 'test-agentredact.config.json');

  afterEach(() => {
    if (existsSync(tempConfigFile)) {
      try {
        unlinkSync(tempConfigFile);
      } catch {
        // ignore
      }
    }
  });

  it('should parse regex strings with or without flags', () => {
    const r1 = parseRegexString('/mykey_[a-z0-9]{16}/i');
    expect(r1.flags).toContain('i');
    expect(r1.flags).toContain('g');
    expect(r1.test('MYKEY_1234567890abcdef')).toBe(true);

    const r2 = parseRegexString('internal_token_[0-9]+');
    expect(r2.test('internal_token_99999')).toBe(true);
  });

  it('should load config file and apply custom patterns and allowlist', () => {
    const configData = {
      allowlist: ['sk-ant-api03-ALLOWED-TEST-KEY-DO-NOT-REDACT'],
      detectHighEntropy: true,
      customPatterns: [
        {
          id: 'custom-corp-key',
          name: 'Corporate Key',
          category: 'credential',
          severity: 'critical',
          regex: 'corp_token_[a-zA-Z0-9]{20}',
          placeholder: 'CORP_TOKEN'
        }
      ]
    };

    writeFileSync(tempConfigFile, JSON.stringify(configData), 'utf-8');
    const loaded = loadConfig(tempConfigFile);

    expect(loaded).toBeDefined();
    expect(loaded?.allowlist).toContain('sk-ant-api03-ALLOWED-TEST-KEY-DO-NOT-REDACT');
    expect(loaded?.customPatterns).toHaveLength(1);

    // Test custom pattern detection
    const inputWithCustom = 'Connect with corp_token_Abc123XyZ456Abc12345';
    const resCustom = redact(inputWithCustom, {
      customPatterns: loaded?.customPatterns
    });
    expect(resCustom.hasLeaks).toBe(true);
    expect(resCustom.matches[0]?.patternId).toBe('custom-corp-key');
    expect(resCustom.text).toBe('Connect with [REDACTED_CORP_TOKEN]');

    // Test allowlist exemption
    const inputWithAllowed = 'Key is sk-ant-api03-ALLOWED-TEST-KEY-DO-NOT-REDACT and is safe.';
    const resAllowed = redact(inputWithAllowed, {
      allowlist: loaded?.allowlist
    });
    expect(resAllowed.hasLeaks).toBe(false);
    expect(resAllowed.text).toBe(inputWithAllowed);
  });

  it('should throw an informative error if explicit config path does not exist', () => {
    expect(() => loadConfig('non-existent-config.json')).toThrowError('Config file not found');
  });
});

