import type { RedactPattern } from '../core/types.js';

/*
 * Vietnamese PII, opt-in through the "vn-pii" preset (`presets: ['vn-pii']`).
 * Bare numbers are ambiguous (order ids, invoice numbers), so only the 12-digit citizen ID
 * is matched without context, and only with a valid province code; the others require a
 * keyword such as CMND/CCCD, MST or STK in front of the number.
 */

/** Province / city codes used as the first three digits of a CCCD run from 001 to 096 */
function hasValidProvinceCode(id: string): boolean {
  const province = Number(id.slice(0, 3));
  return province >= 1 && province <= 96;
}

export const vnCitizenIdPattern: RedactPattern = {
  id: 'vn-citizen-id',
  name: 'Vietnamese Citizen ID (CCCD)',
  category: 'pii',
  severity: 'high',
  regex: /(?<![\w$])0\d{11}(?!\d)/g,
  placeholder: 'VN_CITIZEN_ID',
  description: '12-digit Vietnamese citizen identity card number (CCCD) with a valid province code',
  validator: hasValidProvinceCode
};

export const vnIdNumberPattern: RedactPattern = {
  id: 'vn-id-number',
  name: 'Vietnamese ID Number (CMND/CCCD, with context)',
  category: 'pii',
  severity: 'high',
  regex: /(?:CMND|CCCD|CMT|căn cước|can cuoc|chứng minh|chung minh)(?:\s+(?:số|so|no\.?))?[\s:#.=-]*(\d{9}|\d{12})(?!\d)/giu,
  secretGroup: 1,
  placeholder: 'VN_ID_NUMBER',
  description: '9-digit CMND or 12-digit CCCD number preceded by an ID keyword'
};

export const vnTaxCodePattern: RedactPattern = {
  id: 'vn-tax-code',
  name: 'Vietnamese Tax Code (MST)',
  category: 'pii',
  severity: 'medium',
  regex: /(?:MST|mã số thuế|ma so thue|tax\s*code)[\s:#.=-]*(\d{10}(?:-\d{3})?)(?!\d)/giu,
  secretGroup: 1,
  placeholder: 'VN_TAX_CODE',
  description: '10- or 13-digit Vietnamese tax code preceded by MST / mã số thuế'
};

export const vnBankAccountPattern: RedactPattern = {
  id: 'vn-bank-account',
  name: 'Vietnamese Bank Account Number',
  category: 'pii',
  severity: 'high',
  regex: /(?:STK|số tài khoản|so tai khoan|tài khoản số|tai khoan so|account\s*(?:no\.?|number))[\s:#.=-]*(\d{6,20})(?!\d)/giu,
  secretGroup: 1,
  placeholder: 'VN_BANK_ACCOUNT',
  description: 'Bank account number preceded by STK / số tài khoản / account number'
};

export const VN_PII_PATTERNS: RedactPattern[] = [
  vnCitizenIdPattern,
  vnIdNumberPattern,
  vnTaxCodePattern,
  vnBankAccountPattern
];
