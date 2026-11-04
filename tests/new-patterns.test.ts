import { describe, it, expect } from 'vitest';
import { redact } from '../src/index.js';

// Helper to assemble mock tokens dynamically without tripping push protection
const sampleKey = (...parts: string[]) => parts.join('');

describe('New Extended Patterns', () => {
  it('should detect and redact NPM automation tokens', () => {
    const fakeNpm = sampleKey('np', 'm_111122223333444455556666777788889999');
    const input = `NPM_TOKEN=${fakeNpm}`;
    const res = redact(input);
    expect(res.hasLeaks).toBe(true);
    expect(res.matches[0]?.patternId).toBe('npm-token');
    expect(res.text).toBe('NPM_TOKEN=[REDACTED_NPM_TOKEN]');
  });

  it('should detect and redact SendGrid API keys', () => {
    const fakeSg = sampleKey(
      'SG.',
      '1234567890123456789012.',
      '1234567890123456789012345678901234567890123'
    );
    const input = `SENDGRID_API_KEY=${fakeSg}`;
    const res = redact(input);
    expect(res.hasLeaks).toBe(true);
    expect(res.matches[0]?.patternId).toBe('sendgrid-api-key');
    expect(res.text).toBe('SENDGRID_API_KEY=[REDACTED_SENDGRID_API_KEY]');
  });

  it('should detect Twilio Account SIDs', () => {
    const fakeTwilio = sampleKey('AC', '0123456789abcdef0123456789abcdef');
    const input = `TWILIO_SID=${fakeTwilio}`;
    const res = redact(input);
    expect(res.hasLeaks).toBe(true);
    expect(res.matches[0]?.patternId).toBe('twilio-account-sid');
    expect(res.text).toBe('TWILIO_SID=[REDACTED_TWILIO_ACCOUNT_SID]');
  });

  it('should detect Supabase API keys', () => {
    const fakeSbp = sampleKey('sbp_', '0123456789abcdef0123456789abcdef01234567');
    const input = `SUPABASE_KEY=${fakeSbp}`;
    const res = redact(input);
    expect(res.hasLeaks).toBe(true);
    expect(res.matches[0]?.patternId).toBe('supabase-key');
    expect(res.text).toBe('SUPABASE_KEY=[REDACTED_SUPABASE_KEY]');
  });

  it('should detect IPv6 addresses', () => {
    const input = 'Connecting to 2001:0db8:85a3:0000:0000:8a2e:0370:7334...';
    const res = redact(input);
    expect(res.hasLeaks).toBe(true);
    expect(res.matches[0]?.patternId).toBe('ipv6-address');
    expect(res.text).toBe('Connecting to [REDACTED_IPV6_ADDRESS]...');
  });

  it('should detect Phone numbers', () => {
    const input = 'Call customer support at +1-800-555-0199 or 415-555-2671';
    const res = redact(input);
    expect(res.hasLeaks).toBe(true);
    expect(res.totalLeaks).toBe(2);
    expect(res.text).toBe('Call customer support at [REDACTED_PHONE_NUMBER] or [REDACTED_PHONE_NUMBER]');
  });
});

