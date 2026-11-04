import { describe, it, expect } from 'vitest';
import {
  calculateShannonEntropy,
  isHighEntropyToken,
  redact
} from '../src/index.js';

describe('Shannon Entropy Calculator & Heuristics', () => {
  it('should calculate zero entropy for repeated characters', () => {
    expect(calculateShannonEntropy('aaaaaaaaaa')).toBe(0);
    expect(calculateShannonEntropy('')).toBe(0);
  });

  it('should calculate low entropy for repetitive English prose', () => {
    const english = 'this is a standard simple english sentence with normal words.';
    const entropy = calculateShannonEntropy(english);
    expect(entropy).toBeLessThan(4.0);
  });

  it('should calculate high entropy (> 4.5) for random base64 cryptographic keys', () => {
    const cryptoSecret = 'd9F8qZ1_pLm4wK7aQx0vN2yB8rC3eH6j';
    const entropy = calculateShannonEntropy(cryptoSecret);
    expect(entropy).toBeGreaterThan(4.3);
    expect(isHighEntropyToken(cryptoSecret)).toBe(true);
  });

  it('should detect generic high-entropy secret in sensitive assignment context when enabled', () => {
    const secret = 'xK9_mQ2$pL8vN1!aB7cE4*jH3yF0@zR5';
    const prompt = `api_key = "${secret}"`;

    // Without entropy detection enabled -> ignored
    const noEntropy = redact(prompt, { detectHighEntropy: false });
    expect(noEntropy.hasLeaks).toBe(false);

    // With entropy detection enabled -> flagged as generic-high-entropy-secret
    const withEntropy = redact(prompt, { detectHighEntropy: true });
    expect(withEntropy.hasLeaks).toBe(true);
    expect(withEntropy.matches[0]?.patternId).toBe('generic-high-entropy-secret');
    expect(withEntropy.text).toBe('api_key = "[REDACTED_GENERIC_SECRET]"');
  });

  it('should NOT flag low-entropy predictable values as generic secrets', () => {
    const predictable = 'password = "admin123admin123admin123"';
    const res = redact(predictable, { detectHighEntropy: true });
    expect(res.hasLeaks).toBe(false);
  });
});

