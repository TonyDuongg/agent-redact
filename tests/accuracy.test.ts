import { describe, it, expect } from 'vitest';
import { redact, unmask } from '../src/index.js';

const sampleKey = (...parts: string[]) => parts.join('');

describe('Accuracy & Defect Verification (False Positives & False Negatives)', () => {
  describe('False Positives Resistance (Must NOT redact benign strings)', () => {
    it('should NOT redact UUIDs', () => {
      const benign = 'id: 123e4567-e89b-12d3-a456-426614174000 and 550e8400-e29b-41d4-a716-446655440000';
      const res = redact(benign);
      expect(res.hasLeaks).toBe(false);
      expect(res.text).toBe(benign);
    });

    it('should NOT redact standard Git commit hashes and SHA-256 digests', () => {
      const gitHash = 'commit 3f9b57de2029a1d8ae217ef9243cc5a67543376c';
      const sha256 = 'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
      const input = `${gitHash}\n${sha256}`;
      const res = redact(input);
      expect(res.hasLeaks).toBe(false);
      expect(res.text).toBe(input);
    });

    it('should NOT redact CSS hex colors or markdown anchors', () => {
      const benign = 'color: #ffffff; background: #3178c6; border: 1px solid #000; anchor: #heading-1';
      const res = redact(benign);
      expect(res.hasLeaks).toBe(false);
      expect(res.text).toBe(benign);
    });

    it('should NOT redact benign public URLs without credentials', () => {
      const urls = [
        'https://github.com/TonyDuongg/agent-redact',
        'https://api.anthropic.com/v1/messages',
        'https://registry.npmjs.org/agent-redact',
        'https://news.ycombinator.com/item?id=12345'
      ].join('\n');
      const res = redact(urls);
      expect(res.hasLeaks).toBe(false);
      expect(res.text).toBe(urls);
    });

    it('should NOT redact normal mathematical or code operators', () => {
      const code = 'const result = a > b && c <= d || x != y; const path = "/usr/local/bin";';
      const res = redact(code);
      expect(res.hasLeaks).toBe(false);
      expect(res.text).toBe(code);
    });
  });

  describe('False Negatives Resistance (Must reliably catch secrets in all contexts)', () => {
    it('should catch Anthropic API key embedded inside complex JSON strings', () => {
      const key = sampleKey('sk-', 'ant-api03-', 'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012345');
      const json = JSON.stringify({
        model: 'claude-3-5-sonnet',
        headers: {
          'x-api-key': key
        }
      });

      const res = redact(json);
      expect(res.hasLeaks).toBe(true);
      expect(res.text).not.toContain(key);
      expect(res.text).toContain('[REDACTED_ANTHROPIC_API_KEY]');
    });

    it('should catch GitHub PAT in git clone URL', () => {
      const pat = sampleKey('gh', 'p_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789');
      const gitUrl = `git clone https://${pat}@github.com/org/private-repo.git`;
      const res = redact(gitUrl);
      expect(res.hasLeaks).toBe(true);
      expect(res.matches[0]?.patternId).toBe('github-token');
      expect(res.text).toBe('git clone https://[REDACTED_GITHUB_TOKEN]@github.com/org/private-repo.git');
    });

    it('should catch secrets surrounded by various punctuation characters', () => {
      const key = sampleKey('sk-', 'proj-', 'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890');
      const text = `Use this key (${key}), or [${key}], or '${key}', or "${key}".`;
      const res = redact(text);
      expect(res.hasLeaks).toBe(true);
      expect(res.totalLeaks).toBe(4);
      expect(res.text).not.toContain(key);
    });

    it('should catch database connection URI with special characters in password', () => {
      const dbUrl = 'postgresql://db_user:P%40ssw0rd%21%23%24@cluster.aws.internal:5432/production';
      const res = redact(`DATABASE_URL="${dbUrl}"`);
      expect(res.hasLeaks).toBe(true);
      expect(res.matches[0]?.patternId).toBe('database-url');
      expect(res.text).toBe('DATABASE_URL="[REDACTED_DATABASE_URL]"');
    });

    it('should catch AWS secret access key with different variable naming conventions', () => {
      const raw = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
      const variants = [
        `aws_secret_access_key: "${raw}"`,
        `AWS_SECRET_ACCESS_KEY = '${raw}'`,
        `secret_access_key=${raw}`
      ];

      for (const variant of variants) {
        const res = redact(variant);
        expect(res.hasLeaks).toBe(true);
        expect(res.matches[0]?.patternId).toBe('aws-secret-access-key');
        expect(res.text).not.toContain(raw);
      }
    });
  });

  describe('Roundtrip Integrity & Conservation', () => {
    it('should achieve 100% byte-for-byte fidelity when masking and unmasking multiple mixed secrets', () => {
      const antKey = sampleKey('sk-', 'ant-api03-', 'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012345');
      const openAiKey = sampleKey('sk-', 'proj-', 'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890');
      const ghToken = sampleKey('gh', 'p_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789');

      const original = `
# Server Configuration
ANTHROPIC_KEY=${antKey}
OPENAI_KEY=${openAiKey}
GITHUB_PAT=${ghToken}
DATABASE_URL=postgres://root:AdminSecret999@localhost:5432/app
EMAIL=admin@enterprise.org

function connect() {
  const token = "${antKey}";
  console.log("Connecting with", token);
}
`;

      const { text: masked, vault } = redact(original, { reversible: true });
      expect(masked).not.toContain(antKey);
      expect(masked).not.toContain(openAiKey);
      expect(masked).not.toContain(ghToken);

      const restored = unmask(masked, vault!);
      expect(restored).toBe(original);
    });
  });
});

