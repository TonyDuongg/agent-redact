import type { RedactPattern } from '../core/types.js';

/**
 * Email Address
 */
export const emailPattern: RedactPattern = {
  id: 'email-address',
  name: 'Email Address',
  category: 'pii',
  severity: 'medium',
  regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
  placeholder: 'EMAIL_ADDRESS',
  description: 'Standard RFC 5322 email address'
};

/**
 * IPv4 Address (Public / Private)
 */
export const ipv4Pattern: RedactPattern = {
  id: 'ipv4-address',
  name: 'IPv4 Address',
  category: 'network',
  severity: 'low',
  regex: /\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b/g,
  placeholder: 'IPV4_ADDRESS',
  description: 'Standard IPv4 network address'
};

/**
 * US Social Security Number (SSN)
 */
export const ssnPattern: RedactPattern = {
  id: 'us-ssn',
  name: 'US Social Security Number',
  category: 'pii',
  severity: 'critical',
  regex: /\b\d{3}-\d{2}-\d{4}\b/g,
  placeholder: 'US_SSN',
  description: 'US Social Security Number in AAA-GG-SSSS format'
};

function isValidLuhn(numStr: string): boolean {
  const digits = numStr.replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let shouldDouble = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let digit = parseInt(digits.charAt(i), 10);
    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    shouldDouble = !shouldDouble;
  }
  return sum % 10 === 0;
}

/**
 * Credit Card Number (Visa, MasterCard, Amex, Discover)
 */
export const creditCardPattern: RedactPattern = {
  id: 'credit-card',
  name: 'Credit Card Number',
  category: 'pii',
  severity: 'critical',
  regex: /\b(?:4[0-9]{3}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{1,4}|5[1-5][0-9]{2}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}|2[2-7][0-9]{2}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}|3[47][0-9]{2}[-\s]?[0-9]{6}[-\s]?[0-9]{5}|6(?:011|5[0-9]{2})[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4})\b/g,
  placeholder: 'CREDIT_CARD',
  description: 'Major credit card numbers (Visa, MasterCard, Amex, Discover)',
  validator: isValidLuhn
};

/**
 * IPv6 Address
 */
export const ipv6Pattern: RedactPattern = {
  id: 'ipv6-address',
  name: 'IPv6 Address',
  category: 'network',
  severity: 'low',
  regex: /(?<![a-zA-Z0-9_:])(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|:(?::[0-9a-fA-F]{1,4}){1,7}|(?:[0-9a-fA-F]{1,4}:){1,6}:(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}|::1)(?![a-zA-Z0-9_:])/gi,
  placeholder: 'IPV6_ADDRESS',
  description: 'Standard or compressed 128-bit IPv6 address'
};

/**
 * Phone Number (US & International E.164 formats with separators or + prefix)
 */
export const phonePattern: RedactPattern = {
  id: 'phone-number',
  name: 'Phone Number',
  category: 'pii',
  severity: 'medium',
  regex: /(?:(?<![\w$])\+(?:[0-9]{1,4}[-.\s](?:\([0-9]{1,4}\)[-.\s]?)?[0-9]{1,4}[-.\s]?[0-9]{1,4}[-.\s]?[0-9]{1,9}|[0-9]{7,15})\b|(?:\([0-9]{3}\)|\b[0-9]{3})[-.\s][0-9]{3}[-.\s][0-9]{4}\b)/g,
  placeholder: 'PHONE_NUMBER',
  description: 'Telephone number in formatted local or international E.164 format'
};

/**
 * Export array of all built-in PII patterns
 */
export const PII_PATTERNS: RedactPattern[] = [
  emailPattern,
  ipv4Pattern,
  ipv6Pattern,
  phonePattern,
  ssnPattern,
  creditCardPattern
];

