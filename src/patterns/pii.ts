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

/**
 * Credit Card Number (Visa, MasterCard, Amex, Discover)
 */
export const creditCardPattern: RedactPattern = {
  id: 'credit-card',
  name: 'Credit Card Number',
  category: 'pii',
  severity: 'critical',
  regex: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/g,
  placeholder: 'CREDIT_CARD',
  description: 'Major credit card numbers (Visa, MasterCard, Amex, Discover)'
};

/**
 * IPv6 Address
 */
export const ipv6Pattern: RedactPattern = {
  id: 'ipv6-address',
  name: 'IPv6 Address',
  category: 'network',
  severity: 'low',
  regex: /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b/g,
  placeholder: 'IPV6_ADDRESS',
  description: 'Standard 128-bit IPv6 address'
};

/**
 * Phone Number (US & International E.164 formats)
 */
export const phonePattern: RedactPattern = {
  id: 'phone-number',
  name: 'Phone Number',
  category: 'pii',
  severity: 'medium',
  regex: /(?:\+\d{1,3}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?)\d{3,4}[-.\s]?\d{3,4}\b/g,
  placeholder: 'PHONE_NUMBER',
  description: 'Telephone number in local or international format'
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

