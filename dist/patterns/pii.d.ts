import type { RedactPattern } from '../core/types.js';
/**
 * Email Address
 */
export declare const emailPattern: RedactPattern;
/**
 * IPv4 Address (Public / Private)
 */
export declare const ipv4Pattern: RedactPattern;
/**
 * US Social Security Number (SSN)
 */
export declare const ssnPattern: RedactPattern;
/**
 * Credit Card Number (Visa, MasterCard, Amex, Discover)
 */
export declare const creditCardPattern: RedactPattern;
/**
 * IPv6 Address
 */
export declare const ipv6Pattern: RedactPattern;
/**
 * Phone Number (US & International E.164 formats with separators or + prefix)
 */
export declare const phonePattern: RedactPattern;
/**
 * Export array of all built-in PII patterns
 */
export declare const PII_PATTERNS: RedactPattern[];
