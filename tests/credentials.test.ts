import { describe, it, expect } from 'vitest';
import { redact, unmask } from '../src/index.js';

// Helper to assemble mock secrets dynamically without tripping git push protection / scanners
const sampleKey = (...parts: string[]) => parts.join('');

describe('Credential Patterns & Redact Engine', () => {
  describe('Anthropic Claude API Keys', () => {
    it('should detect and redact standard Anthropic API keys', () => {
      const dummyAnthropicKey = sampleKey(
        'sk-',
        'ant-api03-',
        'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012345'
      );
      const prompt = `Use this key: ${dummyAnthropicKey} to call Claude 3.5 Sonnet`;

      const result = redact(prompt);
      expect(result.hasLeaks).toBe(true);
      expect(result.totalLeaks).toBe(1);
      expect(result.matches[0]?.patternId).toBe('anthropic-api-key');
      expect(result.text).toBe('Use this key: [REDACTED_ANTHROPIC_API_KEY] to call Claude 3.5 Sonnet');
    });

    it('should detect Anthropic Admin keys', () => {
      const dummyAdminKey = sampleKey(
        'sk-',
        'ant-admin01-',
        'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012345'
      );
      const input = `export ANTHROPIC_ADMIN_KEY="${dummyAdminKey}"`;

      const result = redact(input);
      expect(result.hasLeaks).toBe(true);
      expect(result.matches[0]?.patternId).toBe('anthropic-api-key');
      expect(result.text).toBe('export ANTHROPIC_ADMIN_KEY="[REDACTED_ANTHROPIC_API_KEY]"');
    });
  });

  describe('OpenAI API Keys', () => {
    it('should detect legacy OpenAI keys', () => {
      const legacyKey = sampleKey('sk-', '1234567890abcdefghijklmnopqrstuvwxyzABCD123456');
      const input = `OPENAI_API_KEY=${legacyKey}`;

      const result = redact(input);
      expect(result.hasLeaks).toBe(true);
      expect(result.matches[0]?.patternId).toBe('openai-api-key');
      expect(result.text).toBe('OPENAI_API_KEY=[REDACTED_OPENAI_API_KEY]');
    });

    it('should detect project-based OpenAI keys', () => {
      const projectKey = sampleKey(
        'sk-',
        'proj-',
        'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'
      );
      const input = `const client = new OpenAI({ apiKey: '${projectKey}' });`;

      const result = redact(input);
      expect(result.hasLeaks).toBe(true);
      expect(result.matches[0]?.patternId).toBe('openai-api-key');
      expect(result.text).toBe('const client = new OpenAI({ apiKey: \'[REDACTED_OPENAI_API_KEY]\' });');
    });
  });

  describe('AWS Credentials', () => {
    it('should detect AWS Access Key IDs', () => {
      const awsKeyId = 'AKIAIOSFODNN7EXAMPLE';
      const input = `AWS_ACCESS_KEY_ID=${awsKeyId}`;

      const result = redact(input);
      expect(result.hasLeaks).toBe(true);
      expect(result.matches[0]?.patternId).toBe('aws-access-key-id');
      expect(result.text).toBe('AWS_ACCESS_KEY_ID=[REDACTED_AWS_ACCESS_KEY_ID]');
    });

    it('should detect AWS Secret Access Key in key-value context', () => {
      const input = 'aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';

      const result = redact(input);
      expect(result.hasLeaks).toBe(true);
      expect(result.matches[0]?.patternId).toBe('aws-secret-access-key');
      expect(result.text).toBe('aws_secret_access_key = [REDACTED_AWS_SECRET_ACCESS_KEY]');
    });
  });

  describe('GitHub Tokens', () => {
    it('should detect classic personal access tokens', () => {
      const classicPat = sampleKey('gh', 'p_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789');
      const input = `git clone https://${classicPat}@github.com/org/repo.git`;

      const result = redact(input);
      expect(result.hasLeaks).toBe(true);
      expect(result.matches[0]?.patternId).toBe('github-token');
      expect(result.text).toBe('git clone https://[REDACTED_GITHUB_TOKEN]@github.com/org/repo.git');
    });

    it('should detect fine-grained personal access tokens', () => {
      const fineGrained = sampleKey(
        'git',
        'hub_pat_11AAAAAAA0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuv_1234567890'
      );
      const input = `Authorization: Bearer ${fineGrained}`;

      const result = redact(input);
      expect(result.hasLeaks).toBe(true);
      expect(result.matches[0]?.patternId).toBe('github-token');
      expect(result.text).toBe('Authorization: Bearer [REDACTED_GITHUB_TOKEN]');
    });
  });

  describe('Stripe Keys', () => {
    it('should detect Stripe secret live keys', () => {
      const stripeLiveSecret = sampleKey('sk', '_', 'live_51AbcdefghijklmnopqrstuvwxyzA1B2C3D4E5');
      const input = `STRIPE_SECRET=${stripeLiveSecret}`;

      const result = redact(input);
      expect(result.hasLeaks).toBe(true);
      expect(result.matches[0]?.patternId).toBe('stripe-api-key');
      expect(result.text).toBe('STRIPE_SECRET=[REDACTED_STRIPE_API_KEY]');
    });

    it('should detect Stripe publishable keys', () => {
      const stripePk = sampleKey('pk', '_', 'live_51AbcdefghijklmnopqrstuvwxyzA1B2C3D4E5');
      const input = `publishableKey: "${stripePk}"`;

      const result = redact(input);
      expect(result.hasLeaks).toBe(true);
      expect(result.matches[0]?.patternId).toBe('stripe-api-key');
      expect(result.text).toBe('publishableKey: "[REDACTED_STRIPE_API_KEY]"');
    });
  });

  describe('JSON Web Token (JWT)', () => {
    it('should detect JWT tokens', () => {
      const dummyJwt =
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
      const input = `Bearer ${dummyJwt}`;

      const result = redact(input);
      expect(result.hasLeaks).toBe(true);
      expect(result.matches[0]?.patternId).toBe('jwt-token');
      expect(result.text).toBe('Bearer [REDACTED_JWT_TOKEN]');
    });
  });

  describe('Private Keys', () => {
    it('should detect and redact PEM private keys block', () => {
      const fakePem = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y3y1e2...fake...data...
...more...lines...
-----END RSA PRIVATE KEY-----`;
      const input = `Config:\n${fakePem}\nEnd of config.`;

      const result = redact(input);
      expect(result.hasLeaks).toBe(true);
      expect(result.matches[0]?.patternId).toBe('private-key');
      expect(result.text).toBe('Config:\n[REDACTED_PRIVATE_KEY]\nEnd of config.');
    });
  });

  describe('Database Connection URLs', () => {
    it('should detect PostgreSQL URI with password', () => {
      const uri = 'postgres://admin:superSecretPass123@db.prod.internal:5432/production_db';
      const input = `DATABASE_URL="${uri}"`;

      const result = redact(input);
      expect(result.hasLeaks).toBe(true);
      expect(result.matches[0]?.patternId).toBe('database-url');
      expect(result.text).toBe('DATABASE_URL="[REDACTED_DATABASE_URL]"');
    });
  });

  describe('Reversible Masking & Unmasking (2-Way Session)', () => {
    it('should reversibly mask and unmask multiple secrets', () => {
      const dummyAnthropicKey = sampleKey(
        'sk-',
        'ant-api03-',
        'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012345'
      );
      const dummyOpenAIKey = sampleKey(
        'sk-',
        'proj-',
        'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'
      );

      const prompt = `Use Anthropic: ${dummyAnthropicKey} and OpenAI: ${dummyOpenAIKey}. Again Anthropic: ${dummyAnthropicKey}`;

      // Mask with reversible mode
      const result = redact(prompt, { reversible: true });
      expect(result.hasLeaks).toBe(true);
      expect(result.vault).toBeDefined();

      // Ensure identical secret gets the same placeholder
      expect(result.text).toBe(
        'Use Anthropic: [ANTHROPIC_API_KEY_1] and OpenAI: [OPENAI_API_KEY_1]. Again Anthropic: [ANTHROPIC_API_KEY_1]'
      );

      // LLM process simulation: LLM responds using the placeholders
      const llmResponse =
        'I received your request with [ANTHROPIC_API_KEY_1] and confirmed [OPENAI_API_KEY_1] is ready.';

      // Unmask
      const restored = unmask(llmResponse, result.vault!);
      expect(restored).toBe(
        `I received your request with ${dummyAnthropicKey} and confirmed ${dummyOpenAIKey} is ready.`
      );
    });
  });

  describe('Edge cases & False positive resistance', () => {
    it('should not alter clean text without secrets', () => {
      const clean = 'This is a normal log message with numbers 12345 and text.';
      const result = redact(clean);
      expect(result.hasLeaks).toBe(false);
      expect(result.totalLeaks).toBe(0);
      expect(result.text).toBe(clean);
    });
  });
});
