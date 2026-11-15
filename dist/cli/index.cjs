#!/usr/bin/env node
'use strict';

var fs = require('fs');
var path = require('path');
var mcp_js = require('@modelcontextprotocol/sdk/server/mcp.js');
var stdio_js = require('@modelcontextprotocol/sdk/server/stdio.js');
var zod = require('zod');
var crypto = require('crypto');
var os = require('os');
var child_process = require('child_process');
var http = require('http');
require('stream');
require('string_decoder');

var __defProp = Object.defineProperty;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __esm = (fn, res, err) => function __init() {
  if (err) throw err[0];
  try {
    return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
  } catch (e) {
    throw err = [e], e;
  }
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// src/patterns/credentials.ts
var anthropicApiKeyPattern, openaiApiKeyPattern, awsAccessKeyPattern, awsSecretKeyPattern, githubTokenPattern, stripeKeyPattern, jwtTokenPattern, privateKeyPattern, googleApiKeyPattern, slackTokenPattern, databaseUrlPattern, basicAuthUrlPattern, huggingFaceTokenPattern, gitlabTokenPattern, discordTokenPattern, npmTokenPattern, sendgridApiKeyPattern, twilioAccountSidPattern, supabaseKeyPattern, telegramBotTokenPattern, twilioApiKeyPattern, azureStorageKeyPattern, gcpOauthSecretPattern, digitalOceanTokenPattern, mailgunApiKeyPattern, openrouterApiKeyPattern, groqApiKeyPattern, xaiApiKeyPattern, perplexityApiKeyPattern, replicateApiTokenPattern, huggingFaceOrgTokenPattern, langsmithApiKeyPattern, CREDENTIAL_PATTERNS;
var init_credentials = __esm({
  "src/patterns/credentials.ts"() {
    anthropicApiKeyPattern = {
      id: "anthropic-api-key",
      name: "Anthropic API Key",
      category: "credential",
      severity: "critical",
      regex: /\bsk-ant-(?:api03|admin01)-[A-Za-z0-9_\-]{80,120}(?![A-Za-z0-9_])|\bsk-ant-[A-Za-z0-9_\-]{20,}(?![A-Za-z0-9_])/g,
      placeholder: "ANTHROPIC_API_KEY",
      description: "Anthropic Claude API key or Admin key"
    };
    openaiApiKeyPattern = {
      id: "openai-api-key",
      name: "OpenAI API Key",
      category: "credential",
      severity: "critical",
      regex: /\bsk-(?:proj|svcacct)-[A-Za-z0-9_\-]{40,}(?![A-Za-z0-9_])|\bsk-[a-zA-Z0-9]{20,}\b/g,
      placeholder: "OPENAI_API_KEY",
      description: "OpenAI API key (standard, project, or service account)"
    };
    awsAccessKeyPattern = {
      id: "aws-access-key-id",
      name: "AWS Access Key ID",
      category: "credential",
      severity: "high",
      regex: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g,
      placeholder: "AWS_ACCESS_KEY_ID",
      description: "Amazon Web Services 20-character Access Key ID"
    };
    awsSecretKeyPattern = {
      id: "aws-secret-access-key",
      name: "AWS Secret Access Key",
      category: "credential",
      severity: "critical",
      regex: /(?:aws_secret_access_key|aws_secret_key|secret_access_key)[\s=:'"]+([A-Za-z0-9\/+=]{40})(?:\s|$|['",;])/gi,
      secretGroup: 1,
      placeholder: "AWS_SECRET_ACCESS_KEY",
      description: "Amazon Web Services 40-character Secret Access Key"
    };
    githubTokenPattern = {
      id: "github-token",
      name: "GitHub Token",
      category: "credential",
      severity: "critical",
      regex: /\b(?:ghp_[A-Za-z0-9]{36,40}|github_pat_[A-Za-z0-9_]{60,100}|gho_[A-Za-z0-9]{36,40}|ghu_[A-Za-z0-9]{36,40}|ghs_[A-Za-z0-9]{36,40}|ghr_[A-Za-z0-9]{36,40})\b/g,
      placeholder: "GITHUB_TOKEN",
      description: "GitHub Personal Access Token, OAuth token, or App token"
    };
    stripeKeyPattern = {
      id: "stripe-api-key",
      name: "Stripe API Key",
      category: "credential",
      severity: "critical",
      // Unbounded: Stripe documents that key length may grow, and a bounded
      // quantifier followed by \b silently skips longer keys entirely.
      regex: /\b(?:sk|pk|rk)_(?:live|test)_[0-9a-zA-Z]{24,}\b/g,
      placeholder: "STRIPE_API_KEY",
      description: "Stripe API key (live or test, secret or publishable)"
    };
    jwtTokenPattern = {
      id: "jwt-token",
      name: "JSON Web Token (JWT)",
      category: "credential",
      severity: "critical",
      regex: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-]{10,}(?![A-Za-z0-9_])/g,
      placeholder: "JWT_TOKEN",
      description: "JSON Web Token (JWT) in header.payload.signature format"
    };
    privateKeyPattern = {
      id: "private-key",
      name: "Private Key",
      category: "credential",
      severity: "critical",
      // The body may not run past another BEGIN marker: without that, every unterminated
      // BEGIN rescanned to the end of the input (quadratic on many BEGINs without END).
      regex: /-----BEGIN (?:(?:RSA |OPENSSH |DSA |EC |ENCRYPTED )?PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----(?:(?!-----BEGIN )[\s\S])*?-----END (?:(?:RSA |OPENSSH |DSA |EC |ENCRYPTED )?PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----/g,
      placeholder: "PRIVATE_KEY",
      description: "RSA, OpenSSH, DSA, EC, Encrypted, or PGP private key certificate"
    };
    googleApiKeyPattern = {
      id: "google-api-key",
      name: "Google API Key",
      category: "credential",
      severity: "high",
      regex: /\bAIza[0-9A-Za-z\-_]{35}(?![A-Za-z0-9_])/g,
      placeholder: "GOOGLE_API_KEY",
      description: "Google Cloud or Gemini AI Studio API key"
    };
    slackTokenPattern = {
      id: "slack-token",
      name: "Slack Token",
      category: "credential",
      severity: "high",
      // Bot tokens have two numeric segments, user/refresh tokens have three
      regex: /\b(?:xoxb|xoxp|xoxr|xoxa|xoxe|xoxs)-[0-9]{10,13}(?:-[0-9]{10,13}){1,2}-[a-zA-Z0-9]{24,34}\b|\bxapp-[0-9]{1,}-[a-zA-Z0-9]{10,32}-[0-9]{10,13}-[a-zA-Z0-9]{24,64}\b/g,
      placeholder: "SLACK_TOKEN",
      description: "Slack Bot, User, or App token"
    };
    databaseUrlPattern = {
      id: "database-url",
      name: "Database Connection URL",
      category: "credential",
      severity: "critical",
      regex: /\b(?:postgres|postgresql|mysql|mariadb|mongodb|mongodb\+srv|redis|rediss):\/\/[^\s:/@]*:[^\s/@]+@[^\s/:]+(?::\d+)?(?:\/[^\s?"']*)?(?:\?[^\s"']*)?\b/g,
      placeholder: "DATABASE_URL",
      description: "Database connection URL containing user and password credentials"
    };
    basicAuthUrlPattern = {
      id: "basic-auth-url",
      name: "HTTP Basic Auth URL",
      category: "credential",
      severity: "critical",
      regex: /\bhttps?:\/\/[^\s:/@]+:[^\s/@]+@[^\s/:]+(?::\d+)?(?:\/[^\s?"']*)?(?:\?[^\s"']*)?\b/g,
      placeholder: "BASIC_AUTH_URL",
      description: "HTTP/HTTPS URL containing username and password credentials"
    };
    huggingFaceTokenPattern = {
      id: "huggingface-token",
      name: "Hugging Face Token",
      category: "credential",
      severity: "high",
      regex: /\bhf_[a-zA-Z0-9]{34}\b/g,
      placeholder: "HUGGINGFACE_TOKEN",
      description: "Hugging Face User Access Token"
    };
    gitlabTokenPattern = {
      id: "gitlab-token",
      name: "GitLab Token",
      category: "credential",
      severity: "high",
      regex: /\bglpat-[0-9a-zA-Z\-_]{20,}(?![A-Za-z0-9_])/g,
      placeholder: "GITLAB_TOKEN",
      description: "GitLab Personal Access Token"
    };
    discordTokenPattern = {
      id: "discord-token",
      name: "Discord Bot Token",
      category: "credential",
      severity: "high",
      regex: /\b[MNO][a-zA-Z0-9_-]{23,25}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27,38}(?![A-Za-z0-9_])/g,
      placeholder: "DISCORD_TOKEN",
      description: "Discord Bot Authentication Token"
    };
    npmTokenPattern = {
      id: "npm-token",
      name: "NPM Access Token",
      category: "credential",
      severity: "critical",
      regex: /\bnpm_[A-Za-z0-9]{36}\b/g,
      placeholder: "NPM_TOKEN",
      description: "Node Package Manager (npm) access token"
    };
    sendgridApiKeyPattern = {
      id: "sendgrid-api-key",
      name: "SendGrid API Key",
      category: "credential",
      severity: "high",
      regex: /\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}(?![A-Za-z0-9_])/g,
      placeholder: "SENDGRID_API_KEY",
      description: "SendGrid Email API key"
    };
    twilioAccountSidPattern = {
      id: "twilio-account-sid",
      name: "Twilio Account SID",
      category: "credential",
      severity: "high",
      regex: /\bAC[0-9a-fA-F]{32}\b/g,
      placeholder: "TWILIO_ACCOUNT_SID",
      description: "Twilio Account Identifier"
    };
    supabaseKeyPattern = {
      id: "supabase-key",
      name: "Supabase Key",
      category: "credential",
      severity: "critical",
      regex: /\bsbp_[a-zA-Z0-9]{40}\b/g,
      placeholder: "SUPABASE_KEY",
      description: "Supabase Project or Management API key"
    };
    telegramBotTokenPattern = {
      id: "telegram-bot-token",
      name: "Telegram Bot Token",
      category: "credential",
      severity: "critical",
      regex: /\b\d{8,10}:[A-Za-z0-9_-]{35}(?![A-Za-z0-9_])/g,
      placeholder: "TELEGRAM_BOT_TOKEN",
      description: "Telegram Bot API authentication token"
    };
    twilioApiKeyPattern = {
      id: "twilio-api-key",
      name: "Twilio API Key",
      category: "credential",
      severity: "critical",
      regex: /\bSK[0-9a-fA-F]{32}\b/g,
      placeholder: "TWILIO_API_KEY",
      description: "Twilio API Key starting with SK prefix"
    };
    azureStorageKeyPattern = {
      id: "azure-storage-key",
      name: "Azure Storage Key",
      category: "credential",
      severity: "critical",
      regex: /\bAccountKey=[A-Za-z0-9+/]{86}==|\bAccountKey=[A-Za-z0-9+/=]{88}\b/g,
      placeholder: "AZURE_STORAGE_KEY",
      description: "Azure Storage Account access key"
    };
    gcpOauthSecretPattern = {
      id: "gcp-oauth-client-secret",
      name: "GCP OAuth Client Secret",
      category: "credential",
      severity: "critical",
      regex: /\bGOCSPX-[A-Za-z0-9_-]{28}(?![A-Za-z0-9_])/g,
      placeholder: "GCP_OAUTH_CLIENT_SECRET",
      description: "Google Cloud Platform OAuth 2.0 client secret"
    };
    digitalOceanTokenPattern = {
      id: "digitalocean-token",
      name: "DigitalOcean Token",
      category: "credential",
      severity: "critical",
      regex: /\bdop_v1_[a-f0-9]{64}\b/g,
      placeholder: "DIGITALOCEAN_TOKEN",
      description: "DigitalOcean Personal Access Token"
    };
    mailgunApiKeyPattern = {
      id: "mailgun-api-key",
      name: "Mailgun API Key",
      category: "credential",
      severity: "high",
      regex: /\bkey-[0-9a-zA-Z]{32}\b/g,
      placeholder: "MAILGUN_API_KEY",
      description: "Mailgun API authentication key"
    };
    openrouterApiKeyPattern = {
      id: "openrouter-api-key",
      name: "OpenRouter API Key",
      category: "credential",
      severity: "critical",
      regex: /\bsk-or-v1-[a-f0-9]{40,}(?![A-Za-z0-9_])/g,
      placeholder: "OPENROUTER_API_KEY",
      description: "OpenRouter API key (sk-or-v1-...)"
    };
    groqApiKeyPattern = {
      id: "groq-api-key",
      name: "Groq API Key",
      category: "credential",
      severity: "critical",
      regex: /\bgsk_[A-Za-z0-9]{40,}(?![A-Za-z0-9_])/g,
      placeholder: "GROQ_API_KEY",
      description: "Groq API key (gsk_...)"
    };
    xaiApiKeyPattern = {
      id: "xai-api-key",
      name: "xAI API Key",
      category: "credential",
      severity: "critical",
      regex: /\bxai-[A-Za-z0-9_]{60,}(?![A-Za-z0-9_])/g,
      placeholder: "XAI_API_KEY",
      description: "xAI (Grok) API key (xai-...)"
    };
    perplexityApiKeyPattern = {
      id: "perplexity-api-key",
      name: "Perplexity API Key",
      category: "credential",
      severity: "critical",
      regex: /\bpplx-[A-Za-z0-9]{32,}(?![A-Za-z0-9_])/g,
      placeholder: "PERPLEXITY_API_KEY",
      description: "Perplexity API key (pplx-...)"
    };
    replicateApiTokenPattern = {
      id: "replicate-api-token",
      name: "Replicate API Token",
      category: "credential",
      severity: "critical",
      regex: /\br8_[A-Za-z0-9_-]{30,}(?![A-Za-z0-9_-])/g,
      placeholder: "REPLICATE_API_TOKEN",
      description: "Replicate API token (r8_...)"
    };
    huggingFaceOrgTokenPattern = {
      id: "huggingface-org-token",
      name: "Hugging Face Organization Token",
      category: "credential",
      severity: "high",
      regex: /\bapi_org_[A-Za-z0-9]{30,}(?![A-Za-z0-9_])/g,
      placeholder: "HUGGINGFACE_ORG_TOKEN",
      description: "Hugging Face organization API token (api_org_...)"
    };
    langsmithApiKeyPattern = {
      id: "langsmith-api-key",
      name: "LangSmith API Key",
      category: "credential",
      severity: "high",
      regex: /\blsv2_(?:pt|sk)_[a-f0-9]{32}_[a-f0-9]{10}(?![A-Za-z0-9_])/g,
      placeholder: "LANGSMITH_API_KEY",
      description: "LangSmith / LangChain personal or service key (lsv2_pt_ / lsv2_sk_)"
    };
    CREDENTIAL_PATTERNS = [
      anthropicApiKeyPattern,
      openaiApiKeyPattern,
      awsAccessKeyPattern,
      awsSecretKeyPattern,
      githubTokenPattern,
      stripeKeyPattern,
      jwtTokenPattern,
      privateKeyPattern,
      googleApiKeyPattern,
      slackTokenPattern,
      databaseUrlPattern,
      basicAuthUrlPattern,
      huggingFaceTokenPattern,
      gitlabTokenPattern,
      discordTokenPattern,
      npmTokenPattern,
      sendgridApiKeyPattern,
      twilioAccountSidPattern,
      supabaseKeyPattern,
      telegramBotTokenPattern,
      twilioApiKeyPattern,
      azureStorageKeyPattern,
      gcpOauthSecretPattern,
      digitalOceanTokenPattern,
      mailgunApiKeyPattern,
      openrouterApiKeyPattern,
      groqApiKeyPattern,
      xaiApiKeyPattern,
      perplexityApiKeyPattern,
      replicateApiTokenPattern,
      huggingFaceOrgTokenPattern,
      langsmithApiKeyPattern
    ];
  }
});

// src/patterns/pii.ts
function isValidLuhn(numStr) {
  const digits = numStr.replace(/\D/g, "");
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
function isLikelyIpv6(candidate) {
  if (candidate === IPV6_LOOPBACK) return true;
  const groups = candidate.split(":").filter((g) => g.length > 0);
  if (groups.length < 2) return false;
  if (!/[0-9]/.test(candidate)) return false;
  if (groups.length === 2 && candidate.includes("::") && groups[0].length < 3) return false;
  return true;
}
var emailPattern, ipv4Pattern, ssnPattern, creditCardPattern, ipv6Pattern, IPV6_LOOPBACK, phonePattern, PII_PATTERNS;
var init_pii = __esm({
  "src/patterns/pii.ts"() {
    emailPattern = {
      id: "email-address",
      name: "Email Address",
      category: "pii",
      severity: "medium",
      // RFC 5321 length limits (local part 64, domain 253, label 63) keep matching linear;
      // unbounded quantifiers backtracked quadratically on inputs like "a-a-a-..." (80KB took 10 s).
      regex: /\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}\b/g,
      placeholder: "EMAIL_ADDRESS",
      description: "Standard RFC 5322 email address"
    };
    ipv4Pattern = {
      id: "ipv4-address",
      name: "IPv4 Address",
      category: "network",
      severity: "low",
      // Skip four-part version numbers introduced by v / ver / version (see tests/audit-round5).
      // `\b` before the keyword keeps words that merely end in "ver" (e.g. server=) matching.
      regex: /(?<!\b(?:[vV](?:er(?:sion)?)?|VER(?:SION)?)[\s:=]{0,2})\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b/g,
      placeholder: "IPV4_ADDRESS",
      description: "Standard IPv4 network address"
    };
    ssnPattern = {
      id: "us-ssn",
      name: "US Social Security Number",
      category: "pii",
      severity: "critical",
      regex: /\b\d{3}-\d{2}-\d{4}\b/g,
      placeholder: "US_SSN",
      description: "US Social Security Number in AAA-GG-SSSS format"
    };
    creditCardPattern = {
      id: "credit-card",
      name: "Credit Card Number",
      category: "pii",
      severity: "critical",
      regex: /\b(?:4[0-9]{3}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{1,4}|5[1-5][0-9]{2}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}|2[2-7][0-9]{2}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}|3[47][0-9]{2}[- ]?[0-9]{6}[- ]?[0-9]{5}|6(?:011|5[0-9]{2})[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4})\b/g,
      placeholder: "CREDIT_CARD",
      description: "Major credit card numbers (Visa, MasterCard, Amex, Discover)",
      validator: isValidLuhn
    };
    ipv6Pattern = {
      id: "ipv6-address",
      name: "IPv6 Address",
      category: "network",
      severity: "low",
      regex: /(?<![a-zA-Z0-9_:])(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|:(?::[0-9a-fA-F]{1,4}){1,7}|(?:[0-9a-fA-F]{1,4}:){1,6}:(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}|::[1])(?![a-zA-Z0-9_:])/gi,
      placeholder: "IPV6_ADDRESS",
      description: "Standard or compressed 128-bit IPv6 address",
      validator: isLikelyIpv6
    };
    IPV6_LOOPBACK = ["", "", "1"].join(":");
    phonePattern = {
      id: "phone-number",
      name: "Phone Number",
      category: "pii",
      severity: "medium",
      regex: /(?:(?<![\w$])\+(?:[0-9]{1,4}[-.\s](?:\([0-9]{1,4}\)[-.\s]?)?[0-9]{1,4}[-.\s]?[0-9]{1,4}[-.\s]?[0-9]{1,9}|[0-9]{7,15})\b|(?:\([0-9]{3}\)|\b[0-9]{3})[-.\s][0-9]{3}[-.\s][0-9]{4}\b|(?<![\w$])\b0[35789](?:[0-9]{8}|[0-9]{2}[-.\s][0-9]{3}[-.\s][0-9]{3}|[0-9][-.\s][0-9]{3}[-.\s][0-9]{4})\b|(?<![\w$])\b02(?:[48][-.\s]?[0-9]{4}[-.\s]?[0-9]{4}|[0-35-79][0-9][-.\s]?[0-9]{3}[-.\s]?[0-9]{3,4})\b)/g,
      placeholder: "PHONE_NUMBER",
      description: "Telephone number in formatted local, international E.164, or domestic VN format"
    };
    PII_PATTERNS = [
      emailPattern,
      ipv4Pattern,
      ipv6Pattern,
      phonePattern,
      ssnPattern,
      creditCardPattern
    ];
  }
});

// src/patterns/vn.ts
function hasValidProvinceCode(id) {
  const province = Number(id.slice(0, 3));
  return province >= 1 && province <= 96;
}
var vnCitizenIdPattern, vnIdNumberPattern, vnTaxCodePattern, vnBankAccountPattern, VN_PII_PATTERNS;
var init_vn = __esm({
  "src/patterns/vn.ts"() {
    vnCitizenIdPattern = {
      id: "vn-citizen-id",
      name: "Vietnamese Citizen ID (CCCD)",
      category: "pii",
      severity: "high",
      regex: /(?<![\w$])0\d{11}(?!\d)/g,
      placeholder: "VN_CITIZEN_ID",
      description: "12-digit Vietnamese citizen identity card number (CCCD) with a valid province code",
      validator: hasValidProvinceCode
    };
    vnIdNumberPattern = {
      id: "vn-id-number",
      name: "Vietnamese ID Number (CMND/CCCD, with context)",
      category: "pii",
      severity: "high",
      regex: /(?:CMND|CCCD|CMT|căn cước|can cuoc|chứng minh|chung minh)(?:\s+(?:số|so|no\.?))?[\s:#.=-]*(\d{9}|\d{12})(?!\d)/giu,
      secretGroup: 1,
      placeholder: "VN_ID_NUMBER",
      description: "9-digit CMND or 12-digit CCCD number preceded by an ID keyword"
    };
    vnTaxCodePattern = {
      id: "vn-tax-code",
      name: "Vietnamese Tax Code (MST)",
      category: "pii",
      severity: "medium",
      regex: /(?:MST|mã số thuế|ma so thue|tax\s*code)[\s:#.=-]*(\d{10}(?:-\d{3})?)(?!\d)/giu,
      secretGroup: 1,
      placeholder: "VN_TAX_CODE",
      description: "10- or 13-digit Vietnamese tax code preceded by MST / m\xE3 s\u1ED1 thu\u1EBF"
    };
    vnBankAccountPattern = {
      id: "vn-bank-account",
      name: "Vietnamese Bank Account Number",
      category: "pii",
      severity: "high",
      regex: /(?:STK|số tài khoản|so tai khoan|tài khoản số|tai khoan so|account\s*(?:no\.?|number))[\s:#.=-]*(\d{6,20})(?!\d)/giu,
      secretGroup: 1,
      placeholder: "VN_BANK_ACCOUNT",
      description: "Bank account number preceded by STK / s\u1ED1 t\xE0i kho\u1EA3n / account number"
    };
    VN_PII_PATTERNS = [
      vnCitizenIdPattern,
      vnIdNumberPattern,
      vnTaxCodePattern,
      vnBankAccountPattern
    ];
  }
});

// src/patterns/presets.ts
function resolvePresets(names) {
  if (!names || names.length === 0) return [];
  const out = [];
  for (const name of names) {
    const preset = PATTERN_PRESETS[name];
    if (!preset) {
      throw new Error(`Unknown preset "${name}". Available presets: ${Object.keys(PATTERN_PRESETS).join(", ")}`);
    }
    out.push(...preset);
  }
  return out;
}
var PATTERN_PRESETS;
var init_presets = __esm({
  "src/patterns/presets.ts"() {
    init_vn();
    PATTERN_PRESETS = {
      "vn-pii": VN_PII_PATTERNS
    };
  }
});

// src/patterns/index.ts
var DEFAULT_PATTERNS;
var init_patterns = __esm({
  "src/patterns/index.ts"() {
    init_credentials();
    init_pii();
    init_credentials();
    init_pii();
    init_vn();
    init_presets();
    DEFAULT_PATTERNS = [
      ...CREDENTIAL_PATTERNS,
      ...PII_PATTERNS
    ];
    new Map([
      ...DEFAULT_PATTERNS.map((p) => [p.id, p]),
      ["database-uri", databaseUrlPattern]
      // Alias for backwards compatibility
    ]);
  }
});

// src/core/entropy.ts
function calculateShannonEntropy(str2) {
  if (!str2 || str2.length === 0) {
    return 0;
  }
  const frequencies = /* @__PURE__ */ new Map();
  for (let i = 0; i < str2.length; i++) {
    const char = str2[i];
    frequencies.set(char, (frequencies.get(char) ?? 0) + 1);
  }
  let entropy = 0;
  const len = str2.length;
  for (const count of frequencies.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return Math.round(entropy * 1e3) / 1e3;
}
function isHighEntropyToken(token, config = {}) {
  const minLength = config.minLength ?? DEFAULT_ENTROPY_MIN_LENGTH;
  const maxLength = config.maxLength ?? DEFAULT_ENTROPY_MAX_LENGTH;
  const base64Threshold = config.base64Threshold ?? 4.3;
  const hexThreshold = config.hexThreshold ?? 3.2;
  if (token.length < minLength || token.length > maxLength) {
    return false;
  }
  const entropy = calculateShannonEntropy(token);
  const isHex = /^[0-9a-fA-F]+$/.test(token);
  if (isHex) {
    return entropy >= hexThreshold;
  }
  return entropy >= base64Threshold;
}
function createHighEntropyPattern(config = {}) {
  const min = config.minLength ?? DEFAULT_ENTROPY_MIN_LENGTH;
  return {
    id: "generic-high-entropy-secret",
    name: "Generic High-Entropy Secret",
    category: "credential",
    severity: "high",
    regex: new RegExp(
      `(?:api[_-]?key|secret|token|password|auth[_-]?key|access[_-]?key)[\\s=:'"]+([^\\s"';,\\n]{${min},})`,
      "gi"
    ),
    secretGroup: 1,
    placeholder: "GENERIC_SECRET",
    description: "High-entropy random token detected in sensitive assignment context"
  };
}
var DEFAULT_ENTROPY_MIN_LENGTH, DEFAULT_ENTROPY_MAX_LENGTH;
var init_entropy = __esm({
  "src/core/entropy.ts"() {
    DEFAULT_ENTROPY_MIN_LENGTH = 20;
    DEFAULT_ENTROPY_MAX_LENGTH = 120;
  }
});

// src/core/vault.ts
function collectPlaceholderLiterals(text) {
  const found = /* @__PURE__ */ new Set();
  for (const m of text.matchAll(/\[[^[\]\r\n]{1,256}_\d+\]/g)) {
    found.add(m[0]);
  }
  return found;
}
var Vault;
var init_vault = __esm({
  "src/core/vault.ts"() {
    Vault = class _Vault {
      placeholderToEntry = /* @__PURE__ */ new Map();
      placeholderToEntries = /* @__PURE__ */ new Map();
      originalToPlaceholder = /* @__PURE__ */ new Map();
      counters = /* @__PURE__ */ new Map();
      maxEntries;
      /** Names (never values) of placeholders dropped by the size cap, oldest first */
      evictedPlaceholders = /* @__PURE__ */ new Set();
      /** Bumped on every change to the placeholder set; invalidates the cached unmask regex */
      mutations = 0;
      unmaskRegexCache;
      constructor(options) {
        this.maxEntries = options?.maxEntries;
      }
      /**
       * True when `prefix` is the beginning of at least one known placeholder.
       * Used by streaming unmaskers to decide whether a chunk tail must be held back.
       */
      hasPlaceholderPrefix(prefix) {
        for (const placeholder of this.placeholderToEntries.keys()) {
          if (placeholder.startsWith(prefix)) return true;
        }
        return false;
      }
      getUnmaskRegex() {
        if (this.unmaskRegexCache?.mutations !== this.mutations) {
          const escaped = Array.from(this.placeholderToEntries.keys()).sort((a, b) => b.length - a.length).map((p) => p.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
          this.unmaskRegexCache = { mutations: this.mutations, regex: new RegExp(escaped.join("|"), "g") };
        }
        const { regex } = this.unmaskRegexCache;
        regex.lastIndex = 0;
        return regex;
      }
      evictOldestIfNeeded() {
        if (this.maxEntries && this.originalToPlaceholder.size >= this.maxEntries) {
          const oldestPlaceholder = this.placeholderToEntry.keys().next().value;
          if (oldestPlaceholder) {
            for (const entry of this.placeholderToEntries.get(oldestPlaceholder) ?? []) {
              if (this.originalToPlaceholder.get(entry.original) === oldestPlaceholder) {
                this.originalToPlaceholder.delete(entry.original);
              }
            }
            this.placeholderToEntry.delete(oldestPlaceholder);
            this.placeholderToEntries.delete(oldestPlaceholder);
            this.mutations++;
            this.rememberEvicted(oldestPlaceholder);
          }
        }
      }
      rememberEvicted(placeholder) {
        this.evictedPlaceholders.add(placeholder);
        const limit = (this.maxEntries ?? 0) * 10 || 1e5;
        if (this.evictedPlaceholders.size > limit) {
          const oldest = this.evictedPlaceholders.values().next().value;
          if (oldest !== void 0) this.evictedPlaceholders.delete(oldest);
        }
      }
      /**
       * Placeholders present in `text` that were evicted by the `maxEntries` cap and
       * therefore cannot be restored by `unmask`. Returns placeholder names only.
       */
      findEvictedPlaceholders(text) {
        if (this.evictedPlaceholders.size === 0 || !text) return [];
        return [...this.evictedPlaceholders].filter(
          (p) => text.includes(p) && !this.placeholderToEntries.has(p)
        );
      }
      /**
       * Retrieves an existing placeholder or allocates a new numbered placeholder
       * for the given secret token. Optionally ensures placeholder does not collide
       * with literal text already in the document.
       */
      getOrCreate(original, pattern, existingText) {
        const existing = this.originalToPlaceholder.get(original);
        if (existing) {
          return existing;
        }
        this.evictOldestIfNeeded();
        let count = (this.counters.get(pattern.placeholder) ?? 0) + 1;
        if (existingText) {
          const isTaken = typeof existingText === "string" ? (p) => existingText.includes(p) : (p) => existingText.has(p);
          while (isTaken(`[${pattern.placeholder}_${count}]`)) {
            count++;
          }
        }
        this.counters.set(pattern.placeholder, count);
        const placeholder = `[${pattern.placeholder}_${count}]`;
        const entry = {
          placeholder,
          original,
          patternId: pattern.id,
          category: pattern.category,
          timestamp: Date.now()
        };
        this.placeholderToEntry.set(placeholder, entry);
        this.placeholderToEntries.set(placeholder, [entry]);
        this.originalToPlaceholder.set(original, placeholder);
        this.mutations++;
        return placeholder;
      }
      /**
       * Retrieves original secret from placeholder.
       */
      getOriginal(placeholder) {
        return this.placeholderToEntry.get(placeholder)?.original;
      }
      /**
       * Replaces all placeholders in a string back with their original secrets
       * in a deterministic, collision-free single regex pass. Handles multiple
       * secrets mapped to identical custom placeholders sequentially.
       *
       * @param encode Optional transform applied to each restored secret, e.g. JSON string
       *   escaping when the placeholder sits inside a JSON document.
       */
      unmask(text, encode) {
        if (this.placeholderToEntries.size === 0 || !text) {
          return text;
        }
        const regex = this.getUnmaskRegex();
        const occurrences = /* @__PURE__ */ new Map();
        const out = (secret) => encode ? encode(secret) : secret;
        return text.replace(regex, (matched) => {
          const list = this.placeholderToEntries.get(matched);
          if (!list || list.length === 0) {
            return matched;
          }
          if (list.length === 1) {
            return out(list[0].original);
          }
          const idx = occurrences.get(matched) ?? 0;
          occurrences.set(matched, idx + 1);
          const entry = list[idx % list.length];
          return out(entry.original);
        });
      }
      /**
       * Directly restores an entry into the vault without altering placeholder names.
       */
      restoreEntry(entry) {
        if (!this.originalToPlaceholder.has(entry.original)) {
          this.evictOldestIfNeeded();
        }
        this.placeholderToEntry.set(entry.placeholder, entry);
        const existingList = this.placeholderToEntries.get(entry.placeholder) ?? [];
        if (!existingList.some((e) => e.original === entry.original)) {
          existingList.push(entry);
        }
        this.placeholderToEntries.set(entry.placeholder, existingList);
        this.originalToPlaceholder.set(entry.original, entry.placeholder);
        this.mutations++;
        const match = entry.placeholder.match(/^\[(.*)_(\d+)\]$/);
        if (match && match[1] && match[2]) {
          const prefix = match[1];
          const num = parseInt(match[2], 10);
          const current = this.counters.get(prefix) ?? 0;
          if (num > current) {
            this.counters.set(prefix, num);
          }
        }
      }
      /**
       * Restores a list of entries into the vault.
       */
      restoreEntries(entries) {
        for (const entry of entries) {
          this.restoreEntry(entry);
        }
      }
      /**
       * Serializes the vault entries to JSON string.
       */
      toJSON() {
        return JSON.stringify(this.entries(), null, 2);
      }
      /**
       * Deserializes a JSON string or array of entries into a new Vault instance.
       */
      static fromJSON(data) {
        const vault = new _Vault();
        const list = typeof data === "string" ? JSON.parse(data) : data;
        if (!Array.isArray(list)) {
          throw new Error("Invalid vault: expected a JSON array of entries");
        }
        list.forEach((entry, i) => {
          const e = entry;
          if (!e || typeof e !== "object" || typeof e.placeholder !== "string" || e.placeholder.length === 0 || typeof e.original !== "string" || e.original.length === 0) {
            throw new Error(
              `Invalid vault: entry ${i} must have non-empty string "placeholder" and "original" fields`
            );
          }
        });
        vault.restoreEntries(list);
        return vault;
      }
      /**
       * Returns list of all entries currently in the vault.
       */
      entries() {
        const all = [];
        for (const list of this.placeholderToEntries.values()) {
          all.push(...list);
        }
        return all;
      }
      /**
       * Number of unique secrets stored.
       */
      get size() {
        return this.originalToPlaceholder.size;
      }
      /**
       * Wipes all secrets from memory.
       */
      clear() {
        this.placeholderToEntry.clear();
        this.placeholderToEntries.clear();
        this.originalToPlaceholder.clear();
        this.counters.clear();
        this.evictedPlaceholders.clear();
        this.mutations++;
      }
    };
  }
});

// src/core/engine.ts
function selectSecretSpan(match, pattern) {
  let group = pattern.secretGroup;
  if (group === void 0 && match.groups?.["secret"] !== void 0) {
    group = "secret";
  }
  if (group !== void 0) {
    const value = typeof group === "number" ? match[group] : match.groups?.[group];
    const span = typeof group === "number" ? match.indices?.[group] : match.indices?.groups?.[group];
    if (value && span) {
      return { secret: value, startIndex: span[0], endIndex: span[1] };
    }
  }
  return { secret: match[0], startIndex: match.index, endIndex: match.index + match[0].length };
}
function redact(text, options) {
  return defaultEngine.redact(text, options);
}
function unmask(text, vault) {
  return defaultEngine.unmask(text, vault);
}
var SEVERITY_WEIGHT, RedactEngine, defaultEngine;
var init_engine = __esm({
  "src/core/engine.ts"() {
    init_patterns();
    init_entropy();
    init_vault();
    SEVERITY_WEIGHT = {
      critical: 4,
      high: 3,
      medium: 2,
      low: 1
    };
    RedactEngine = class {
      patterns;
      vault;
      constructor(options) {
        this.patterns = options?.patterns ?? [...DEFAULT_PATTERNS];
        this.vault = options?.vault;
      }
      /**
       * Redacts sensitive secrets and PII from the input string.
       */
      redact(text, options) {
        const startTime = performance.now();
        const reversible = options?.reversible ?? false;
        const vault = options?.vault ?? this.vault ?? (reversible ? new Vault() : void 0);
        const presetPatterns = resolvePresets(options?.presets);
        let activePatterns = [...this.patterns, ...presetPatterns, ...options?.customPatterns ?? []];
        if (options?.detectHighEntropy) {
          activePatterns.push(createHighEntropyPattern(options.entropy));
        }
        if (options?.include && options.include.length > 0) {
          const includeSet = new Set(options.include);
          const customIds = new Set([...options.customPatterns ?? [], ...presetPatterns].map((p) => p.id));
          activePatterns = activePatterns.filter(
            (p) => includeSet.has(p.id) || customIds.has(p.id) || options.detectHighEntropy && p.id === "generic-high-entropy-secret"
          );
        }
        if (options?.exclude && options.exclude.length > 0) {
          const excludeSet = new Set(options.exclude);
          activePatterns = activePatterns.filter((p) => !excludeSet.has(p.id));
        }
        const allowlist = options?.allowlist ?? [];
        const rawMatches = [];
        for (const pattern of activePatterns) {
          let flags = pattern.regex.flags;
          if (!flags.includes("g")) flags += "g";
          if (!flags.includes("d")) flags += "d";
          const regex = new RegExp(pattern.regex.source, flags);
          let match;
          while ((match = regex.exec(text)) !== null) {
            if (match[0].length === 0) {
              regex.lastIndex++;
              continue;
            }
            const { secret, startIndex, endIndex } = selectSecretSpan(match, pattern);
            if (allowlist.length > 0 && allowlist.some((al) => typeof al === "string" && al.length > 0 && secret === al)) {
              continue;
            }
            if (pattern.validator && !pattern.validator(secret)) {
              continue;
            }
            if (pattern.id === "generic-high-entropy-secret") {
              const entropyConfig = options?.entropy;
              const maxLength = entropyConfig?.maxLength ?? DEFAULT_ENTROPY_MAX_LENGTH;
              const sample = secret.length > maxLength ? secret.slice(0, maxLength) : secret;
              if (!isHighEntropyToken(sample, entropyConfig)) {
                continue;
              }
            }
            rawMatches.push({
              pattern,
              secret,
              startIndex,
              endIndex
            });
          }
        }
        rawMatches.sort((a, b) => {
          const weightA = SEVERITY_WEIGHT[a.pattern.severity] ?? 0;
          const weightB = SEVERITY_WEIGHT[b.pattern.severity] ?? 0;
          if (weightA !== weightB) {
            return weightB - weightA;
          }
          const lenA = a.endIndex - a.startIndex;
          const lenB = b.endIndex - b.startIndex;
          if (lenA !== lenB) {
            return lenB - lenA;
          }
          return a.startIndex - b.startIndex;
        });
        const accepted = [];
        const covered = rawMatches.length > 1 ? new Uint8Array(text.length) : void 0;
        for (const candidate of rawMatches) {
          if (covered) {
            if (covered.subarray(candidate.startIndex, candidate.endIndex).includes(1)) {
              continue;
            }
            covered.fill(1, candidate.startIndex, candidate.endIndex);
          }
          accepted.push(candidate);
        }
        accepted.sort((a, b) => a.startIndex - b.startIndex);
        const matches = [];
        const stats = {};
        let redactedText = "";
        let cursor = 0;
        let literalPlaceholders;
        for (let i = 0; i < accepted.length; i++) {
          const m = accepted[i];
          let replacement;
          if (options?.customFormatter) {
            replacement = options.customFormatter({
              pattern: m.pattern,
              matchedText: m.secret,
              index: i + 1,
              reversible
            });
            if (reversible && vault) {
              const existingOriginal = vault.getOriginal(replacement);
              if (existingOriginal !== void 0 && existingOriginal !== m.secret) {
                throw new Error(
                  `customFormatter returned the same placeholder "${replacement}" for two different secrets. Reversible mode requires a unique placeholder per secret (e.g. include info.index or a hash).`
                );
              }
              vault.restoreEntry({
                placeholder: replacement,
                original: m.secret,
                patternId: m.pattern.id,
                category: m.pattern.category,
                timestamp: Date.now()
              });
            }
          } else if (reversible && vault) {
            literalPlaceholders ??= collectPlaceholderLiterals(text);
            replacement = vault.getOrCreate(m.secret, m.pattern, literalPlaceholders);
          } else {
            replacement = `[REDACTED_${m.pattern.placeholder}]`;
          }
          redactedText += text.slice(cursor, m.startIndex);
          redactedText += replacement;
          cursor = m.endIndex;
          const matchItem = {
            patternId: m.pattern.id,
            patternName: m.pattern.name,
            category: m.pattern.category,
            severity: m.pattern.severity,
            startIndex: m.startIndex,
            endIndex: m.endIndex,
            replacement
          };
          if (options?.includeMatchedText) {
            matchItem.matchedText = m.secret;
          }
          matches.push(matchItem);
          stats[m.pattern.id] = (stats[m.pattern.id] ?? 0) + 1;
        }
        redactedText += text.slice(cursor);
        const durationMs = Math.round((performance.now() - startTime) * 100) / 100;
        const resultObj = {
          text: redactedText,
          matches,
          hasLeaks: matches.length > 0,
          totalLeaks: matches.length,
          stats,
          durationMs
        };
        if (vault) {
          Object.defineProperty(resultObj, "vault", {
            value: vault,
            enumerable: false,
            writable: true,
            configurable: true
          });
        }
        Object.defineProperty(resultObj, "toJSON", {
          value: function() {
            return {
              text: this.text,
              hasLeaks: this.hasLeaks,
              totalLeaks: this.totalLeaks,
              stats: this.stats,
              durationMs: this.durationMs,
              matches: this.matches
            };
          },
          enumerable: false,
          writable: true,
          configurable: true
        });
        return resultObj;
      }
      /**
       * Unmasks a string using the provided Vault instance.
       */
      unmask(text, vault) {
        return vault.unmask(text);
      }
    };
    defaultEngine = new RedactEngine();
  }
});
function hasKnownBinaryExtension(path$1) {
  return KNOWN_BINARY_EXTENSIONS.has(path.extname(path$1).toLowerCase());
}
function isBinaryFile(path, sampleSize = 8192) {
  const fd = fs.openSync(path, "r");
  try {
    const buf = Buffer.alloc(sampleSize);
    const read = fs.readSync(fd, buf, 0, sampleSize, 0);
    return buf.subarray(0, read).includes(0);
  } finally {
    fs.closeSync(fd);
  }
}
function readTextForScan(path, maxBytes2 = DEFAULT_MAX_SCAN_BYTES) {
  try {
    const { size } = fs.statSync(path);
    if (size > maxBytes2) return { ok: false, reason: "too-large", size };
    if (hasKnownBinaryExtension(path) || size > 0 && isBinaryFile(path)) {
      return { ok: false, reason: "binary", size };
    }
    return { ok: true, content: fs.readFileSync(path, "utf-8") };
  } catch {
    return { ok: false, reason: "unreadable" };
  }
}
function walkFiles(dir, excludeDirs, result = [], includeBinaryExtensions = false) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return result;
  }
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name !== ".git" && !excludeDirs.has(entry.name)) {
        walkFiles(fullPath, excludeDirs, result, includeBinaryExtensions);
      }
    } else if (entry.isFile() && (includeBinaryExtensions || !hasKnownBinaryExtension(entry.name))) {
      result.push(fullPath);
    }
  }
  return result;
}
var DEFAULT_MAX_SCAN_BYTES, KNOWN_BINARY_EXTENSIONS;
var init_files = __esm({
  "src/core/files.ts"() {
    DEFAULT_MAX_SCAN_BYTES = 5 * 1024 * 1024;
    KNOWN_BINARY_EXTENSIONS = /* @__PURE__ */ new Set([
      ".png",
      ".jpg",
      ".jpeg",
      ".gif",
      ".ico",
      ".webp",
      ".svg",
      ".bmp",
      ".tif",
      ".tiff",
      ".avif",
      ".psd",
      ".wasm",
      ".zip",
      ".tar",
      ".gz",
      ".tgz",
      ".bz2",
      ".xz",
      ".7z",
      ".rar",
      ".zst",
      ".exe",
      ".dll",
      ".so",
      ".dylib",
      ".node",
      ".o",
      ".a",
      ".lib",
      ".class",
      ".jar",
      ".pyc",
      ".whl",
      ".pdf",
      ".docx",
      ".xlsx",
      ".pptx",
      ".bin",
      ".dat",
      ".db",
      ".sqlite",
      ".woff",
      ".woff2",
      ".ttf",
      ".otf",
      ".eot",
      ".mp3",
      ".mp4",
      ".mov",
      ".avi",
      ".mkv",
      ".webm",
      ".wav",
      ".flac",
      ".ogg"
    ]);
  }
});

// src/version.ts
var VERSION2;
var init_version = __esm({
  "src/version.ts"() {
    VERSION2 = "0.4.0";
  }
});

// src/mcp/server.ts
var server_exports = {};
__export(server_exports, {
  createMcpServer: () => createMcpServer,
  mcpOptionsFromArgs: () => mcpOptionsFromArgs,
  runMcpServer: () => runMcpServer
});
function mcpOptionsFromArgs(args, env = process.env) {
  for (const arg of args) {
    if (arg !== "--allow-unmask-text") throw new Error(`Unknown option for the MCP server: ${arg}`);
  }
  return { allowUnmaskText: args.includes("--allow-unmask-text") || env.AGENT_REDACT_ALLOW_UNMASK_TEXT === "1" };
}
function atomicReplaceFile(path$1, content, mode) {
  const temp = path.join(path.dirname(path$1), `.${path.basename(path$1)}.agent-redact-${crypto.randomBytes(6).toString("hex")}.tmp`);
  fs.writeFileSync(temp, content, { encoding: "utf-8", mode: mode & 511, flag: "wx" });
  try {
    try {
      fs.chmodSync(temp, mode & 511);
    } catch {
    }
    fs.renameSync(temp, path$1);
  } catch (err) {
    try {
      fs.unlinkSync(temp);
    } catch {
    }
    throw err;
  }
}
function realpathOrNearest(p) {
  let current = path.resolve(p);
  const tail = [];
  for (; ; ) {
    try {
      return path.join(fs.realpathSync.native(current), ...tail.reverse());
    } catch {
      const parent = path.dirname(current);
      if (parent === current) {
        return path.resolve(p);
      }
      tail.push(path.basename(current));
      current = parent;
    }
  }
}
function defaultAllowedRoots() {
  const roots = [];
  if (process.env.AGENT_REDACT_ALLOWED_DIR) {
    roots.push(process.env.AGENT_REDACT_ALLOWED_DIR);
  }
  const cwd = process.cwd();
  const rootDir = path.resolve(path.sep);
  const home = os.homedir();
  if (cwd !== rootDir && cwd !== home) {
    roots.push(cwd);
  }
  roots.push(os.tmpdir());
  return roots;
}
function checkPath(targetPath, roots, mode) {
  const realTarget = realpathOrNearest(targetPath);
  for (const root of roots) {
    const rel = path.relative(root, realTarget);
    const inside = rel === "" || !path.isAbsolute(rel) && rel !== ".." && !rel.startsWith(`..${path.sep}`);
    if (!inside) continue;
    if (mode === "write") {
      const segments = rel.split(path.sep);
      if (segments.some((segment) => segment.includes(":"))) {
        return { ok: false, reason: "not a plain file path" };
      }
      if (segments.some((segment) => segment.replace(/[. ]+$/, "").toLowerCase() === ".git")) {
        return { ok: false, reason: "writing inside a .git directory is not allowed" };
      }
    }
    return { ok: true, realPath: realTarget };
  }
  return { ok: false, reason: "outside the allowed directories (workspace or temp)" };
}
function safeWriteFile(path, content, enforceMode) {
  const fd = fs.openSync(path, SAFE_WRITE_FLAGS, enforceMode ?? 420);
  try {
    fs.writeFileSync(fd, content, "utf-8");
    if (enforceMode !== void 0) {
      try {
        fs.fchmodSync(fd, enforceMode);
      } catch {
      }
    }
  } finally {
    fs.closeSync(fd);
  }
}
function writeUniqueBackup(file, content) {
  for (let i = 0; i < 1e3; i++) {
    const candidate = i === 0 ? `${file}.bak` : `${file}.bak.${i}`;
    try {
      fs.writeFileSync(candidate, content, { encoding: "utf-8", mode: 384, flag: "wx" });
      return candidate;
    } catch (err) {
      if (err.code !== "EEXIST") throw err;
    }
  }
  throw new Error(`Unable to allocate a backup file name for ${file}`);
}
function securityError(field, value, reason) {
  return {
    isError: true,
    content: [{ type: "text", text: `Security error: ${field} "${value}" is ${reason}.` }]
  };
}
function createMcpServer(options = {}) {
  const vaultMaxEntries = options.vaultMaxEntries ?? 1e4;
  const sessionVault = new Vault({ maxEntries: vaultMaxEntries });
  const allowedRoots = (options.allowedRoots ?? defaultAllowedRoots()).map(realpathOrNearest);
  const server = new mcp_js.McpServer({
    name: "agent-redact",
    version: VERSION2
  });
  server.tool(
    "redact_text",
    "Scans and redacts sensitive credentials (Anthropic keys, OpenAI keys, AWS tokens, GitHub PATs, JWTs, Stripe keys, SSH keys, database URIs) and PII from a given prompt or text payload.",
    {
      text: zod.z.string().describe("The raw text/prompt to scan and sanitize"),
      reversible: zod.z.boolean().default(true).describe(
        "If true, replaces secrets with reversible placeholders like [ANTHROPIC_API_KEY_1]. If false, uses one-way redaction [REDACTED_ANTHROPIC_API_KEY]."
      )
    },
    async ({ text, reversible }) => {
      const result = redact(text, {
        reversible,
        vault: sessionVault
      });
      const summary = {
        sanitizedText: result.text,
        hasLeaks: result.hasLeaks,
        totalLeaks: result.totalLeaks,
        stats: result.stats,
        durationMs: result.durationMs,
        detectedPatterns: result.matches.map((m) => ({
          pattern: m.patternName,
          category: m.category,
          severity: m.severity,
          placeholder: m.replacement
        }))
      };
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(summary, null, 2)
          }
        ]
      };
    }
  );
  server.tool(
    "unmask_text",
    "Restores masked session placeholders (e.g. [ANTHROPIC_API_KEY_1]) in agent response back to original secret values using the secure in-memory vault. Writes content directly to disk at outputFilePath to prevent exposing plaintext secrets in context.",
    {
      text: zod.z.string().describe("The text containing session placeholders to restore"),
      outputFilePath: zod.z.string().describe(
        "Target file path where restored content will be written. Required: plaintext secrets are never exposed in model context."
      )
    },
    async ({ text, outputFilePath }) => {
      if (!options.allowUnmaskText) {
        return {
          isError: true,
          content: [
            {
              type: "text",
              text: "Error: unmask_text is disabled. It can write any secret of this session into any file, so a prompt-injected model could copy secrets into files that get published. To change a file that contains secrets, use read_file_redacted and edit_file_redacted instead. If you really need unmask_text, ask the user to start the server with --allow-unmask-text (or AGENT_REDACT_ALLOW_UNMASK_TEXT=1)."
            }
          ]
        };
      }
      if (!outputFilePath || outputFilePath.trim().length === 0) {
        return {
          isError: true,
          content: [
            {
              type: "text",
              text: "Error: outputFilePath is required. For security, unmasked secrets cannot be returned to the conversation context."
            }
          ]
        };
      }
      const outCheck = checkPath(outputFilePath, allowedRoots, "write");
      if (!outCheck.ok) {
        return securityError("outputFilePath", outputFilePath, outCheck.reason);
      }
      try {
        const restored = unmask(text, sessionVault);
        safeWriteFile(outCheck.realPath, restored, 384);
        const evicted = sessionVault.findEvictedPlaceholders(text);
        const evictionNote = evicted.length > 0 ? ` WARNING: ${evicted.length} placeholder(s) could not be restored because they were evicted from the session vault (limit ${vaultMaxEntries} entries): ${evicted.join(", ")}. Re-run redact_text on the original source to regenerate them.` : "";
        return {
          content: [
            {
              type: "text",
              text: `Successfully restored content to ${outputFilePath}. Plaintext secrets were safely written to disk and remain isolated from model context.${evictionNote}`
            }
          ]
        };
      } catch (err) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        return {
          isError: true,
          content: [{ type: "text", text: `Failed writing to ${outputFilePath}: ${errorMsg}` }]
        };
      }
    }
  );
  server.tool(
    "scan_file",
    "Scans a local file (.env, config, logs) for credentials before importing into agent context window.",
    {
      filePath: zod.z.string().describe("Relative or absolute file path to inspect"),
      reversible: zod.z.boolean().default(false).describe("Whether to generate reversible placeholders (default: false for one-way safe scan)"),
      inPlace: zod.z.boolean().default(false).describe("If true, sanitizes the file directly in-place on disk after creating a .bak backup"),
      outputFilePath: zod.z.string().optional().describe("Optional destination path within workspace to write sanitized content")
    },
    async ({ filePath, reversible, inPlace, outputFilePath }) => {
      const fileCheck = checkPath(filePath, allowedRoots, inPlace ? "write" : "read");
      if (!fileCheck.ok) {
        return securityError("filePath", filePath, fileCheck.reason);
      }
      let resolvedOut;
      if (outputFilePath) {
        const outCheck = checkPath(outputFilePath, allowedRoots, "write");
        if (!outCheck.ok) {
          return securityError("outputFilePath", outputFilePath, outCheck.reason);
        }
        resolvedOut = outCheck.realPath;
      }
      const resolvedFile = fileCheck.realPath;
      if (!fs.existsSync(resolvedFile)) {
        return {
          isError: true,
          content: [
            {
              type: "text",
              text: `File not found: ${filePath}`
            }
          ]
        };
      }
      const fileStat = fs.statSync(resolvedFile);
      if (fileStat.size > DEFAULT_MAX_SCAN_BYTES) {
        return {
          isError: true,
          content: [
            {
              type: "text",
              text: `File size (${(fileStat.size / (1024 * 1024)).toFixed(2)} MB) exceeds maximum allowed limit of 5 MB.`
            }
          ]
        };
      }
      if (fileStat.size > 0) {
        if (isBinaryFile(resolvedFile)) {
          return {
            isError: true,
            content: [
              {
                type: "text",
                text: `Cannot scan binary file: ${filePath}`
              }
            ]
          };
        }
      }
      try {
        const rawContent = fs.readFileSync(resolvedFile, "utf-8");
        const result = redact(rawContent, { reversible, vault: sessionVault });
        let backupPath = null;
        let writtenTo = null;
        if (inPlace) {
          if (result.hasLeaks) {
            const realBackup = writeUniqueBackup(resolvedFile, rawContent);
            backupPath = filePath + realBackup.slice(resolvedFile.length);
            safeWriteFile(resolvedFile, result.text);
            writtenTo = filePath;
          }
        } else if (resolvedOut) {
          safeWriteFile(resolvedOut, result.text);
          writtenTo = outputFilePath ?? null;
        }
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  filePath,
                  sanitizedContent: result.text,
                  hasLeaks: result.hasLeaks,
                  totalLeaks: result.totalLeaks,
                  stats: result.stats,
                  durationMs: result.durationMs,
                  backupCreated: backupPath,
                  backupWarning: backupPath ? "Backup contains the ORIGINAL plaintext secrets. Keep it out of version control and delete it when no longer needed." : void 0,
                  writtenTo
                },
                null,
                2
              )
            }
          ]
        };
      } catch (err) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        return {
          isError: true,
          content: [{ type: "text", text: `Failed reading/writing file ${filePath}: ${errorMsg}` }]
        };
      }
    }
  );
  const fileVaults = /* @__PURE__ */ new Map();
  const errorResult = (text) => ({ isError: true, content: [{ type: "text", text }] });
  const jsonResult = (value) => ({ content: [{ type: "text", text: JSON.stringify(value, null, 2) }] });
  const loadTextFile = (filePath, mode) => {
    const check = checkPath(filePath, allowedRoots, mode);
    if (!check.ok) return securityError("filePath", filePath, check.reason);
    if (!fs.existsSync(check.realPath)) return errorResult(`File not found: ${filePath}`);
    const stat = fs.statSync(check.realPath);
    if (!stat.isFile()) return errorResult(`Not a regular file: ${filePath}`);
    if (stat.size > DEFAULT_MAX_SCAN_BYTES) {
      return errorResult(`File size (${(stat.size / (1024 * 1024)).toFixed(2)} MB) exceeds maximum allowed limit of 5 MB.`);
    }
    if (stat.size > 0 && isBinaryFile(check.realPath)) return errorResult(`Cannot handle binary file: ${filePath}`);
    return { realPath: check.realPath, content: fs.readFileSync(check.realPath, "utf-8"), mode: stat.mode };
  };
  server.tool(
    "read_file_redacted",
    "Reads a text file with every secret replaced by a placeholder unique to that file (e.g. [AWS_ACCESS_KEY_ID_1]). Use it instead of Read for files that contain secrets (.env, configs, credentials), then change them with edit_file_redacted. Secret values never enter the conversation. Returns the redacted content and a revision.",
    {
      filePath: zod.z.string().describe("Relative or absolute path of the file to read")
    },
    async ({ filePath }) => {
      const loaded = loadTextFile(filePath, "read");
      if ("isError" in loaded) return loaded;
      let vault = fileVaults.get(loaded.realPath);
      if (!vault) {
        vault = new Vault();
        fileVaults.set(loaded.realPath, vault);
      }
      const result = redact(loaded.content, { reversible: true, vault });
      return jsonResult({
        filePath,
        content: result.text,
        revision: sha256(loaded.content),
        totalSecrets: result.totalLeaks,
        stats: result.stats
      });
    }
  );
  server.tool(
    "edit_file_redacted",
    "Edits a file previously read with read_file_redacted, working on the redacted text: oldString must match the redacted content exactly (placeholders included) and be unique unless replaceAll is set. Placeholders of this file in newString are written back as the real secrets; placeholders from other files are refused. Pass the revision from the last read or edit; the edit is refused if the file changed in between.",
    {
      filePath: zod.z.string().describe("Path of a file already read with read_file_redacted"),
      oldString: zod.z.string().describe("Exact text to replace, as shown by read_file_redacted"),
      newString: zod.z.string().describe("Replacement text; may contain this file's placeholders"),
      replaceAll: zod.z.boolean().default(false).describe("Replace every occurrence of oldString"),
      revision: zod.z.string().describe("Revision returned by the last read_file_redacted / edit_file_redacted call")
    },
    async ({ filePath, oldString, newString, replaceAll, revision }) => {
      const loaded = loadTextFile(filePath, "write");
      if ("isError" in loaded) return loaded;
      const vault = fileVaults.get(loaded.realPath);
      if (!vault) return errorResult(`Call read_file_redacted first on ${filePath}.`);
      if (sha256(loaded.content) !== revision) {
        return errorResult(`${filePath} changed since read_file_redacted (revision mismatch). Read it again, then retry the edit.`);
      }
      if (oldString === "") return errorResult("oldString must not be empty.");
      const redacted = redact(loaded.content, { reversible: true, vault }).text;
      const crlf = loaded.content.includes("\r\n");
      const toEol = (s) => crlf ? s.replace(/\r?\n/g, "\r\n") : s;
      const oldText = toEol(oldString);
      const newText = toEol(newString);
      const count = redacted.split(oldText).length - 1;
      if (count === 0) return errorResult(`oldString not found in the redacted content of ${filePath}.`);
      if (count > 1 && !replaceAll) {
        return errorResult(`oldString occurs ${count} times in ${filePath}; add surrounding context to make it unique, or set replaceAll.`);
      }
      for (const token of newText.match(PLACEHOLDER_TOKEN_RE) ?? []) {
        if (vault.getOriginal(token) !== void 0) continue;
        const foreign = sessionVault.getOriginal(token) !== void 0 || [...fileVaults.values()].some((v) => v !== vault && v.getOriginal(token) !== void 0);
        if (foreign) {
          return errorResult(
            `Placeholder ${token} does not belong to this file; secrets cannot be copied between files. Ask the user to add the value themselves.`
          );
        }
      }
      const updated = replaceAll ? redacted.split(oldText).join(newText) : redacted.replace(oldText, () => newText);
      const evicted = vault.findEvictedPlaceholders(updated);
      if (evicted.length > 0) {
        return errorResult(`Cannot restore ${evicted.join(", ")}: evicted from this file's vault. Read the file again.`);
      }
      const restored = vault.unmask(updated);
      try {
        atomicReplaceFile(loaded.realPath, restored, loaded.mode);
      } catch (err) {
        return errorResult(`Failed writing ${filePath}: ${err instanceof Error ? err.message : String(err)}`);
      }
      return jsonResult({ filePath, replacements: replaceAll ? count : 1, revision: sha256(restored) });
    }
  );
  server.tool(
    "get_vault_status",
    "Returns summary statistics about currently vaulted secrets (without leaking raw secrets).",
    {},
    async () => {
      const entries = sessionVault.entries().map((e) => ({
        placeholder: e.placeholder,
        patternId: e.patternId,
        category: e.category,
        timestamp: new Date(e.timestamp).toISOString()
      }));
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              {
                vaultSize: sessionVault.size,
                entries
              },
              null,
              2
            )
          }
        ]
      };
    }
  );
  server.tool(
    "clear_vault",
    "Purges all stored secrets and token mappings from the session vault.",
    {},
    async () => {
      const count = sessionVault.size;
      sessionVault.clear();
      return {
        content: [
          {
            type: "text",
            text: `Vault successfully cleared. Purged ${count} secret(s).`
          }
        ]
      };
    }
  );
  server.tool(
    "list_supported_patterns",
    "Returns all built-in credential and PII patterns recognized by agent-redact.",
    {},
    async () => {
      const patterns = DEFAULT_PATTERNS.map((p) => ({
        id: p.id,
        name: p.name,
        category: p.category,
        severity: p.severity,
        placeholder: p.placeholder,
        description: p.description
      }));
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify({ totalPatterns: patterns.length, patterns }, null, 2)
          }
        ]
      };
    }
  );
  return server;
}
async function runMcpServer(args = process.argv.slice(2)) {
  const server = createMcpServer(mcpOptionsFromArgs(args));
  const transport = new stdio_js.StdioServerTransport();
  await server.connect(transport);
}
var sha256, PLACEHOLDER_TOKEN_RE, SAFE_WRITE_FLAGS;
var init_server = __esm({
  "src/mcp/server.ts"() {
    init_engine();
    init_vault();
    init_files();
    init_version();
    init_patterns();
    sha256 = (text) => crypto.createHash("sha256").update(text, "utf8").digest("hex");
    PLACEHOLDER_TOKEN_RE = /\[[A-Z][A-Z0-9_]*_\d+\]/g;
    SAFE_WRITE_FLAGS = fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_TRUNC | (fs.constants.O_NOFOLLOW ?? 0);
  }
});

// src/cli/index.ts
init_engine();
init_vault();

// src/core/config.ts
init_presets();
var DEFAULT_CONFIG_FILENAMES = [
  "agent-redact.config.json",
  ".agentredactrc.json",
  ".agentredactrc"
];
function parseRegexString(patternStr) {
  const match = patternStr.match(/^\/(.+)\/([a-z]*)$/);
  if (match && match[1]) {
    const flags = match[2]?.includes("g") ? match[2] : (match[2] ?? "") + "g";
    return new RegExp(match[1], flags);
  }
  return new RegExp(patternStr, "g");
}
function resolveCustomPattern(cfg) {
  const label = typeof cfg?.id === "string" && cfg.id ? `"${cfg.id}"` : "(missing id)";
  for (const field of ["id", "name", "regex", "placeholder"]) {
    const value = cfg?.[field];
    if (typeof value !== "string" || value.trim().length === 0) {
      throw new Error(`Custom pattern ${label}: "${field}" must be a non-empty string`);
    }
  }
  if (cfg.secretGroup !== void 0 && !(typeof cfg.secretGroup === "number" && Number.isInteger(cfg.secretGroup) && cfg.secretGroup > 0 || typeof cfg.secretGroup === "string" && cfg.secretGroup.length > 0)) {
    throw new Error(`Custom pattern ${label}: "secretGroup" must be a positive integer or a group name`);
  }
  return {
    id: cfg.id,
    name: cfg.name,
    category: cfg.category ?? "custom",
    severity: cfg.severity ?? "high",
    regex: parseRegexString(cfg.regex),
    placeholder: cfg.placeholder,
    description: cfg.description ?? cfg.name,
    ...cfg.secretGroup !== void 0 ? { secretGroup: cfg.secretGroup } : {}
  };
}
function loadConfig(explicitPath, searchDir = process.cwd()) {
  let targetPath;
  if (explicitPath) {
    const resolved = path.resolve(searchDir, explicitPath);
    if (!fs.existsSync(resolved)) {
      throw new Error(`Config file not found at: ${resolved}`);
    }
    targetPath = resolved;
  } else {
    for (const filename of DEFAULT_CONFIG_FILENAMES) {
      const candidate = path.join(searchDir, filename);
      if (fs.existsSync(candidate)) {
        targetPath = candidate;
        break;
      }
    }
  }
  if (!targetPath) {
    return null;
  }
  try {
    const raw = fs.readFileSync(targetPath, "utf-8");
    const parsed = JSON.parse(raw);
    const resolvedCustomPatterns = parsed.customPatterns?.map(resolveCustomPattern);
    if (parsed.presets !== void 0) {
      if (!Array.isArray(parsed.presets) || parsed.presets.some((p) => typeof p !== "string")) {
        throw new Error('"presets" must be an array of preset names');
      }
      resolvePresets(parsed.presets);
    }
    return {
      ...parsed,
      customPatterns: resolvedCustomPatterns
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Failed to parse agent-redact config at ${targetPath}: ${msg}`);
  }
}

// src/cli/index.ts
init_files();
var FORMAT = "agent-redact-vault";
var VERSION = 1;
var KDF = { name: "scrypt", N: 32768, r: 8, p: 1 };
function headerAad(file) {
  return Buffer.from(JSON.stringify([file.format, file.version, file.kdf, file.cipher]), "utf8");
}
var SCRYPT_MAXMEM = 64 * 1024 * 1024;
function deriveKey(passphrase, salt) {
  return crypto.scryptSync(passphrase.normalize("NFC"), salt, 32, { N: KDF.N, r: KDF.r, p: KDF.p, maxmem: SCRYPT_MAXMEM });
}
function hasExpectedKdf(kdf) {
  const k = kdf;
  return !!k && k["name"] === KDF.name && k["N"] === KDF.N && k["r"] === KDF.r && k["p"] === KDF.p && typeof k["salt"] === "string" && Buffer.from(k["salt"], "base64").length === 16;
}
function isEncryptedVault(content) {
  try {
    const parsed = JSON.parse(content);
    return parsed?.format === FORMAT;
  } catch {
    return false;
  }
}
function encryptVaultJson(json, passphrase) {
  if (typeof passphrase !== "string" || passphrase.length === 0) {
    throw new Error("A non-empty passphrase is required to encrypt a vault");
  }
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const kdf = { ...KDF, salt: salt.toString("base64") };
  const header = { format: FORMAT, version: VERSION, kdf, cipher: "aes-256-gcm" };
  const cipher = crypto.createCipheriv("aes-256-gcm", deriveKey(passphrase, salt), iv);
  cipher.setAAD(headerAad(header));
  const data = Buffer.concat([cipher.update(json, "utf8"), cipher.final()]);
  const file = {
    ...header,
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    data: data.toString("base64")
  };
  return JSON.stringify(file, null, 2) + "\n";
}
function decryptVaultJson(content, passphrase) {
  const fail = () => new Error("Cannot decrypt vault: wrong passphrase or corrupted file");
  let file;
  try {
    file = JSON.parse(content);
  } catch {
    throw fail();
  }
  if (file?.format !== FORMAT || file.version !== VERSION || file.cipher !== "aes-256-gcm" || !hasExpectedKdf(file.kdf)) {
    throw fail();
  }
  try {
    const key = deriveKey(passphrase, Buffer.from(file.kdf.salt, "base64"));
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(file.iv, "base64"));
    decipher.setAAD(headerAad(file));
    decipher.setAuthTag(Buffer.from(file.tag, "base64"));
    return Buffer.concat([decipher.update(Buffer.from(file.data, "base64")), decipher.final()]).toString("utf8");
  } catch {
    throw fail();
  }
}

// src/cli/index.ts
init_presets();
init_version();

// src/cli/scan.ts
init_files();
var HARDENING = [
  "-c",
  "core.fsmonitor=false",
  "-c",
  "core.untrackedCache=false",
  "-c",
  "core.pager=cat",
  // A repo-local core.excludesFile (writable by an agent) must not hide files from scans;
  // .gitignore and .git/info/exclude still apply, as they do for ripgrep
  "-c",
  "core.excludesFile="
];
var run = (args, cwd) => child_process.execFileSync("git", [...HARDENING, ...args], {
  cwd,
  stdio: ["ignore", "pipe", "ignore"],
  maxBuffer: 256 * 1024 * 1024,
  env: { ...process.env, GIT_TERMINAL_PROMPT: "0", GIT_OPTIONAL_LOCKS: "0" }
});
var splitNul = (buf) => buf.toString("utf8").split("\0").filter(Boolean);
function isGitWorkTree(cwd) {
  try {
    return run(["rev-parse", "--is-inside-work-tree"], cwd).toString("utf8").trim() === "true";
  } catch {
    return false;
  }
}
function gitListFiles(pathspec, cwd) {
  return splitNul(run(["ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", pathspec], cwd));
}
function gitStagedFiles(cwd) {
  return splitNul(run(["diff", "--cached", "--name-only", "-z", "--diff-filter=ACMR"], cwd));
}
function gitRoot(cwd) {
  return run(["rev-parse", "--show-toplevel"], cwd).toString("utf8").trim();
}
function gitStagedContent(path, repoRoot) {
  return run(["cat-file", "blob", `:${path}`], repoRoot);
}

// src/core/scan.ts
init_engine();
init_patterns();
var IGNORE_LINE_RE = /agent-redact-ignore(?!-next-line)/;
var IGNORE_NEXT_LINE_RE = /agent-redact-ignore-next-line/;
function lineStarts(text) {
  const starts = [0];
  for (let i = text.indexOf("\n"); i !== -1; i = text.indexOf("\n", i + 1)) starts.push(i + 1);
  return starts;
}
function positionAt(starts, offset) {
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = lo + hi + 1 >> 1;
    if (starts[mid] <= offset) lo = mid;
    else hi = mid - 1;
  }
  return { line: lo + 1, column: offset - starts[lo] + 1 };
}
function fingerprintOf(patternId, file, secret) {
  return crypto.createHash("sha256").update(`${patternId}\0${file}\0${secret}`).digest("hex").slice(0, 32);
}
function scanContent(content, file, options = {}) {
  const { respectInlineIgnore = false, baseline, ...redactOptions } = options;
  const result = redact(content, { ...redactOptions, reversible: false, includeMatchedText: true });
  const starts = lineStarts(content);
  const lineText = (line) => content.slice(starts[line - 1], (starts[line] ?? content.length + 1) - 1);
  const findings = [];
  const suppressed = { inline: 0, baseline: 0 };
  for (const m of result.matches) {
    const { line, column } = positionAt(starts, m.startIndex);
    if (respectInlineIgnore && (IGNORE_LINE_RE.test(lineText(line)) || line > 1 && IGNORE_NEXT_LINE_RE.test(lineText(line - 1)))) {
      suppressed.inline++;
      continue;
    }
    const fingerprint = fingerprintOf(m.patternId, file, m.matchedText ?? "");
    if (baseline?.has(fingerprint)) {
      suppressed.baseline++;
      continue;
    }
    findings.push({
      file,
      line,
      column,
      patternId: m.patternId,
      patternName: m.patternName,
      severity: m.severity,
      category: m.category,
      fingerprint
    });
  }
  return { findings, suppressed };
}
function writeBaseline(path, findings) {
  const data = {
    tool: "agent-redact",
    version: 1,
    findings: findings.map(({ fingerprint, patternId, file, line }) => ({ fingerprint, patternId, file, line }))
  };
  fs.writeFileSync(path, JSON.stringify(data, null, 2) + "\n", "utf-8");
}
function loadBaseline(path) {
  const data = JSON.parse(fs.readFileSync(path, "utf-8"));
  if (data?.tool !== "agent-redact" || data.version !== 1 || !Array.isArray(data.findings)) {
    throw new Error(`Invalid baseline file: ${path}`);
  }
  return new Set(data.findings.map((f) => String(f.fingerprint)));
}
var SECURITY_SEVERITY = { critical: "9.5", high: "8.0", medium: "5.5", low: "3.0" };
var SARIF_LEVEL = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note"
};
function toSarif(findings, toolVersion) {
  const descriptions = new Map(DEFAULT_PATTERNS.map((p) => [p.id, p.description]));
  const rules = /* @__PURE__ */ new Map();
  for (const f of findings) {
    if (rules.has(f.patternId)) continue;
    rules.set(f.patternId, {
      id: f.patternId,
      name: f.patternName.replace(/[^A-Za-z0-9]+/g, ""),
      shortDescription: { text: f.patternName },
      fullDescription: { text: descriptions.get(f.patternId) ?? f.patternName },
      defaultConfiguration: { level: SARIF_LEVEL[f.severity] },
      properties: { "security-severity": SECURITY_SEVERITY[f.severity], tags: ["security", "secret", f.category] }
    });
  }
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "agent-redact",
            version: toolVersion,
            informationUri: "https://github.com/TonyDuongg/agent-redact",
            rules: [...rules.values()]
          }
        },
        results: findings.map((f) => ({
          ruleId: f.patternId,
          level: SARIF_LEVEL[f.severity],
          message: { text: `${f.patternName} detected (${f.severity}). The secret value is not included in this report.` },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: f.file, uriBaseId: "%SRCROOT%" },
                region: { startLine: f.line, startColumn: f.column }
              }
            }
          ],
          partialFingerprints: { "agentRedact/v1": f.fingerprint }
        }))
      }
    ]
  };
}

// src/cli/scan.ts
init_version();
var DEFAULT_EXCLUDES = /* @__PURE__ */ new Set([
  "node_modules",
  "dist",
  "build",
  "coverage",
  ".turbo",
  ".next",
  ".nuxt",
  "vendor",
  ".venv",
  "venv",
  "__pycache__"
]);
var toPosix = (p) => p.split("\\").join("/");
var UnverifiableTargetError = class extends Error {
};
function expandTargets(targets, cwd, options = {}) {
  const excludeDirs = options.excludeDirs ?? DEFAULT_EXCLUDES;
  const out = /* @__PURE__ */ new Set();
  const visit = (abs, label, depth) => {
    let isDir;
    try {
      isDir = fs.statSync(abs).isDirectory();
    } catch {
      throw new Error(`Cannot read file: ${label}`);
    }
    if (!isDir) {
      out.add(abs);
    } else if (isGitWorkTree(abs)) {
      for (const p of gitListFiles(".", abs)) {
        const child = path.join(abs, p);
        let childIsDir = false;
        try {
          childIsDir = fs.statSync(child).isDirectory();
        } catch {
          continue;
        }
        if (childIsDir) {
          if (depth >= 8) throw new UnverifiableTargetError(`Submodules nested too deeply to verify: ${p}`);
          visit(child, p, depth + 1);
        } else out.add(child);
      }
    } else {
      for (const p of walkFiles(abs, excludeDirs, [], options.includeBinaryExtensions)) out.add(p);
    }
  };
  for (const target of targets) visit(path.resolve(cwd, target), target, 0);
  return [...out];
}
function runScan(req) {
  const maxBytes2 = req.maxBytes ?? DEFAULT_MAX_SCAN_BYTES;
  const baseline = req.baselineFile ? loadBaseline(path.resolve(req.cwd, req.baselineFile)) : void 0;
  const scanOptions = { ...req.options, respectInlineIgnore: true, baseline };
  const outcome = {
    findings: [],
    filesScanned: 0,
    skipped: { binary: 0, "too-large": 0, unreadable: 0 },
    suppressed: { inline: 0, baseline: 0 }
  };
  const record = (content, file) => {
    const res = scanContent(content, file, scanOptions);
    outcome.filesScanned++;
    outcome.findings.push(...res.findings);
    outcome.suppressed.inline += res.suppressed.inline;
    outcome.suppressed.baseline += res.suppressed.baseline;
  };
  if (req.staged) {
    const root = gitRoot(req.cwd);
    for (const path$1 of gitStagedFiles(root)) {
      let blob;
      try {
        blob = gitStagedContent(path$1, root);
      } catch {
        outcome.skipped.unreadable++;
        continue;
      }
      if (blob.length > maxBytes2) outcome.skipped["too-large"]++;
      else if (blob.subarray(0, 8192).includes(0)) outcome.skipped.binary++;
      else record(blob.toString("utf8"), toPosix(path.relative(req.cwd, path.join(root, path$1))));
    }
    return outcome;
  }
  for (const abs of expandTargets(req.targets, req.cwd)) {
    const read = readTextForScan(abs, maxBytes2);
    if (!read.ok) {
      outcome.skipped[read.reason]++;
      continue;
    }
    record(read.content, toPosix(path.relative(req.cwd, abs)));
  }
  return outcome;
}
function writeScanBaseline(path, outcome) {
  writeBaseline(path, outcome.findings);
}
function formatReport(outcome, format) {
  if (format === "sarif") return JSON.stringify(toSarif(outcome.findings, VERSION2), null, 2) + "\n";
  return JSON.stringify(outcome, null, 2) + "\n";
}
function formatText(outcome, c) {
  const lines = [];
  for (const f of outcome.findings) {
    lines.push(
      `${c.yellow}\u2716 [LEAK]${c.reset} ${f.file}:${f.line}:${f.column}  ${f.patternName} (${f.severity.toUpperCase()})`
    );
  }
  const notes = [];
  const skipped = outcome.skipped.binary + outcome.skipped["too-large"] + outcome.skipped.unreadable;
  if (skipped > 0) notes.push(`${skipped} skipped (binary/too large/unreadable)`);
  if (outcome.suppressed.inline > 0) notes.push(`${outcome.suppressed.inline} ignored inline`);
  if (outcome.suppressed.baseline > 0) notes.push(`${outcome.suppressed.baseline} in baseline`);
  const suffix = notes.length > 0 ? ` ${c.gray}(${notes.join(", ")})${c.reset}` : "";
  const filesWithFindings = new Set(outcome.findings.map((f) => f.file)).size;
  lines.push(
    outcome.findings.length > 0 ? `
${c.red}[agent-redact] Audit failed: detected ${outcome.findings.length} secret(s) across ${filesWithFindings} of ${outcome.filesScanned} files.${c.reset}${suffix}` : `
${c.green}[agent-redact] All ${outcome.filesScanned} files are clean.${c.reset}${suffix}`
  );
  return lines.join("\n");
}

// src/cli/hook.ts
init_engine();
var READER_RE = /(?:^|[\s;&|(`$])(?:cat|tac|head|tail|less|more|bat|nl|grep|egrep|fgrep|rg|ag|awk|gawk|sed|cut|sort|uniq|strings|xxd|od|hexdump|base64|jq|yq|type|Get-Content|gc|Select-String|findstr)(?=\s)/i;
var WRITE_TOOLS = /* @__PURE__ */ new Set(["Write", "Edit", "MultiEdit", "NotebookEdit"]);
var PATH_ONLY_TOOLS = /* @__PURE__ */ new Set(["Glob", "LS", "TodoWrite"]);
var TRUSTED_TOOLS = /* @__PURE__ */ new Set([
  "mcp__agent-redact__scan_file",
  "mcp__agent-redact__read_file_redacted",
  "mcp__agent-redact__redact_text",
  "mcp__agent-redact__unmask_text",
  "mcp__agent-redact__get_vault_status",
  "mcp__agent-redact__clear_vault",
  "mcp__agent-redact__list_supported_patterns"
]);
var PATH_KEYS = ["file_path", "filePath", "path", "paths", "notebook_path", "file", "filename", "uri"];
var MAX_BASH_FILE_ARGS = 50;
var HOOK_MAX_FILE_BYTES = 64 * 1024 * 1024;
var GREP_MAX_FILES = 5e3;
var GREP_MAX_TOTAL_BYTES = 128 * 1024 * 1024;
var str = (v) => typeof v === "string" ? v : "";
function summarize(text, options) {
  const res = redact(text, { ...options, reversible: false });
  return { count: res.totalLeaks, types: [...new Set(res.matches.map((m) => m.patternName))].join(", ") };
}
function redactOptionsFor(cwd, configPath) {
  if (configPath) {
    const c2 = loadConfig(configPath, cwd);
    return {
      include: c2?.include,
      exclude: c2?.exclude,
      allowlist: c2?.allowlist,
      customPatterns: c2?.customPatterns,
      detectHighEntropy: c2?.detectHighEntropy ?? false,
      entropy: c2?.entropy,
      presets: c2?.presets
    };
  }
  let c = null;
  try {
    c = loadConfig(void 0, cwd);
  } catch {
  }
  return {
    customPatterns: c?.customPatterns,
    presets: c?.presets,
    // presets only add patterns
    detectHighEntropy: c?.detectHighEntropy === true,
    entropy: c?.detectHighEntropy === true ? c.entropy : void 0
  };
}
function decodeForScan(buf) {
  if (buf[0] === 255 && buf[1] === 254) return buf.subarray(2).toString("utf16le");
  if (buf[0] === 254 && buf[1] === 255) return Buffer.from(buf.subarray(2)).swap16().toString("utf16le");
  const sample = buf.subarray(0, 8192);
  if (!sample.includes(0)) return buf.toString("utf8");
  let oddZeros = 0;
  let evenZeros = 0;
  for (let i = 0; i < sample.length; i++) if (sample[i] === 0) i % 2 ? oddZeros++ : evenZeros++;
  const half = sample.length / 2;
  if (oddZeros > half * 0.3 && evenZeros < half * 0.05) return buf.toString("utf16le");
  if (evenZeros > half * 0.3 && oddZeros < half * 0.05) {
    return Buffer.from(buf.subarray(0, buf.length - buf.length % 2)).swap16().toString("utf16le");
  }
  return (buf.toString("latin1").match(/[\x20-\x7e\t]{6,}/g) ?? []).join("\n");
}
function checkFile(path$1, cwd, options) {
  const abs = path.isAbsolute(path$1) ? path$1 : path.resolve(cwd, path$1);
  let size;
  try {
    const st = fs.statSync(abs);
    if (!st.isFile()) return null;
    size = st.size;
  } catch {
    return null;
  }
  if (size > HOOK_MAX_FILE_BYTES) return { kind: "too-large" };
  let text;
  try {
    text = decodeForScan(fs.readFileSync(abs));
  } catch {
    return null;
  }
  const summary = summarize(text, options);
  return summary.count > 0 ? { kind: "secrets", summary, text } : null;
}
function fileBlockMessage(what, path, check) {
  if (check.kind === "too-large") {
    return `agent-redact blocked ${what} ${path}: the file is larger than 64 MB and cannot be verified to be free of secrets. Ask the user first.`;
  }
  return `agent-redact blocked ${what} ${path}: it contains ${check.summary.count} secret(s) (${check.summary.types}). Ask the user first, or use the agent-redact MCP tools read_file_redacted (to read it with placeholders) and edit_file_redacted (to change it without seeing the secrets).`;
}
function simpleGlobToRegExp(glob) {
  if (!/^[A-Za-z0-9._\-/*?{},@]+$/.test(glob) || glob.startsWith("/") || glob.endsWith("/")) return null;
  let re = "";
  let braceDepth = 0;
  for (let i = 0; i < glob.length; i++) {
    const ch = glob[i];
    if (ch === "*") {
      if (glob[i + 1] === "*") {
        re += ".*";
        i++;
        if (glob[i + 1] === "/") i++;
      } else re += "[^/]*";
    } else if (ch === "?") re += "[^/]";
    else if (ch === "{") {
      if (++braceDepth > 1) return null;
      re += "(?:";
    } else if (ch === "}") {
      if (--braceDepth < 0) return null;
      re += ")";
    } else if (ch === ",") {
      if (braceDepth === 0) return null;
      re += "|";
    } else re += ch.replace(/[.]/g, "\\.");
  }
  return braceDepth === 0 ? new RegExp(`^${re}$`) : null;
}
function checkGrep(input, cwd, options) {
  const target = str(input["path"]) || cwd;
  const glob = str(input["glob"]);
  const globRe = glob ? simpleGlobToRegExp(glob) : null;
  if (!fs.existsSync(path.isAbsolute(target) ? target : path.resolve(cwd, target))) return { block: false };
  let files;
  try {
    files = expandTargets([target], cwd, { excludeDirs: /* @__PURE__ */ new Set(), includeBinaryExtensions: true });
  } catch (err) {
    const reason = err instanceof UnverifiableTargetError ? err.message : "the searched files could not be enumerated";
    return { block: true, message: `agent-redact blocked Grep: ${reason}. Narrow the path, or ask the user.` };
  }
  if (globRe) {
    files = files.filter((f) => {
      const rel = path.relative(cwd, f).split("\\").join("/");
      return globRe.test(glob.includes("/") ? rel : rel.split("/").pop());
    });
  }
  if (files.length > GREP_MAX_FILES) {
    return { block: true, message: `agent-redact blocked Grep: ${files.length} files are too many to verify. Narrow the path or glob.` };
  }
  let total = 0;
  for (const file of files) {
    try {
      total += fs.statSync(file).size;
    } catch {
      continue;
    }
    if (total > GREP_MAX_TOTAL_BYTES) {
      return { block: true, message: "agent-redact blocked Grep: the search covers too much data to verify. Narrow the path or glob." };
    }
    const check = checkFile(file, cwd, options);
    if (!check) continue;
    const rel = path.relative(cwd, file) || file;
    if (check.kind === "too-large") return { block: true, message: fileBlockMessage("searching", rel, check) };
    return {
      block: true,
      message: `agent-redact blocked Grep: the search includes ${rel}, which contains ${check.summary.count} secret(s) (${check.summary.types}). Narrow the path or glob to files without secrets, or ask the user.`
    };
  }
  return { block: false };
}
function evaluateHook(input, options = {}) {
  const cwd = input.cwd || process.cwd();
  const redactOptions = redactOptionsFor(cwd, options.configPath);
  const event = input.hook_event_name;
  if (event === "UserPromptSubmit") {
    const s2 = summarize(str(input.prompt), redactOptions);
    return s2.count > 0 ? {
      block: true,
      message: `agent-redact blocked this prompt: it contains ${s2.count} secret(s) (${s2.types}). Remove them, or refer to them indirectly (for example "the key in .env") instead of pasting them.`
    } : { block: false };
  }
  if (event !== "PreToolUse") return { block: false };
  const tool = input.tool_name ?? "";
  const toolInput = input.tool_input ?? {};
  if (TRUSTED_TOOLS.has(tool) || PATH_ONLY_TOOLS.has(tool)) return { block: false };
  if (tool === "Read") {
    const path = str(toolInput["file_path"]);
    const check = path ? checkFile(path, cwd, redactOptions) : null;
    return check ? { block: true, message: fileBlockMessage("reading", path, check) } : { block: false };
  }
  if (tool === "Grep") return checkGrep(toolInput, cwd, redactOptions);
  if (tool === "Bash") {
    const command = str(toolInput["command"]);
    const inline = summarize(command, redactOptions);
    if (inline.count > 0) {
      return {
        block: true,
        message: `agent-redact blocked this command: it contains ${inline.count} secret(s) (${inline.types}). Use an environment variable instead of the literal value.`
      };
    }
    if (READER_RE.test(command)) {
      const candidates = command.split(/[\s;&|()<>'"`=]+/).filter((t) => t && !t.startsWith("-")).slice(0, MAX_BASH_FILE_ARGS);
      for (const token of candidates) {
        const check = checkFile(token, cwd, redactOptions);
        if (check) return { block: true, message: fileBlockMessage("printing", token, check) };
      }
    }
    return { block: false };
  }
  if (WRITE_TOOLS.has(tool)) {
    if (!options.blockWrites) return { block: false };
    const s2 = summarize(JSON.stringify(toolInput), redactOptions);
    return s2.count > 0 ? { block: true, message: `agent-redact blocked ${tool}: the new content contains ${s2.count} secret(s) (${s2.types}).` } : { block: false };
  }
  if (tool === "mcp__agent-redact__edit_file_redacted") {
    const s2 = summarize(JSON.stringify(toolInput), redactOptions);
    return s2.count > 0 ? { block: true, message: `agent-redact blocked edit_file_redacted: its input contains ${s2.count} secret(s) (${s2.types}). Use the file's placeholders instead.` } : { block: false };
  }
  for (const key of PATH_KEYS) {
    const value = toolInput[key];
    const paths = Array.isArray(value) ? value : [value];
    for (const p of paths) {
      if (typeof p !== "string" || !p) continue;
      const check = checkFile(p, cwd, redactOptions);
      if (check) return { block: true, message: fileBlockMessage(`${tool} on`, p, check) };
    }
  }
  const s = summarize(JSON.stringify(toolInput), redactOptions);
  return s.count > 0 ? { block: true, message: `agent-redact blocked the ${tool} call: its input contains ${s.count} secret(s) (${s.types}).` } : { block: false };
}
async function readAll(stream) {
  let data = "";
  stream.setEncoding("utf8");
  for await (const chunk of stream) data += chunk;
  return data;
}
async function runHook(args) {
  const raw = await readAll(process.stdin);
  let input;
  try {
    input = JSON.parse(raw);
  } catch {
    process.stderr.write("agent-redact hook: could not parse hook input JSON from stdin\n");
    return 1;
  }
  const configIdx = args.indexOf("--config");
  const configPath = configIdx !== -1 ? args[configIdx + 1] : void 0;
  let decision;
  try {
    decision = evaluateHook(input, { blockWrites: args.includes("--block-writes"), configPath });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    process.stderr.write(`agent-redact hook: refusing because the check failed: ${msg}
`);
    return 2;
  }
  if (decision.block) {
    process.stderr.write(`${decision.message}
`);
    return 2;
  }
  return 0;
}

// src/cli/serve.ts
init_engine();
init_vault();
init_presets();
init_version();
var HARD_MAX_BYTES = 64 * 1024 * 1024;
var MAX_SESSIONS = 1024;
var PARSE_ERROR = -32700;
var INVALID_REQUEST = -32600;
var METHOD_NOT_FOUND = -32601;
var INVALID_PARAMS = -32602;
var APPLICATION_ERROR = -32e3;
var RpcError = class extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
  code;
};
function maxBytes() {
  const raw = Number(process.env.AGENT_REDACT_SERVE_MAX_BYTES);
  return Number.isInteger(raw) && raw > 0 ? Math.min(raw, HARD_MAX_BYTES) : HARD_MAX_BYTES;
}
function isObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function optionalString(params, key) {
  const value = params[key];
  if (value === void 0 || value === null) return void 0;
  if (typeof value !== "string") throw new RpcError(INVALID_PARAMS, `"${key}" must be a string`);
  return value;
}
function requiredString(params, key) {
  const value = optionalString(params, key);
  if (value === void 0) throw new RpcError(INVALID_PARAMS, `"${key}" is required`);
  return value;
}
function buildOptions(params) {
  const presets = params.presets ?? [];
  if (!Array.isArray(presets) || !presets.every((p) => typeof p === "string")) {
    throw new RpcError(INVALID_PARAMS, '"presets" must be an array of strings');
  }
  if (params.entropy !== void 0 && typeof params.entropy !== "boolean") {
    throw new RpcError(INVALID_PARAMS, '"entropy" must be a boolean');
  }
  const cwd = optionalString(params, "cwd") ?? process.cwd();
  try {
    const config = loadConfig(optionalString(params, "config"), cwd);
    const effectivePresets = [...config?.presets ?? [], ...presets];
    resolvePresets(effectivePresets);
    return {
      include: config?.include,
      exclude: config?.exclude,
      allowlist: config?.allowlist,
      customPatterns: config?.customPatterns,
      detectHighEntropy: params.entropy === true || (config?.detectHighEntropy ?? false),
      presets: effectivePresets,
      entropy: config?.entropy
    };
  } catch (err) {
    throw new RpcError(APPLICATION_ERROR, err instanceof Error ? err.message : String(err));
  }
}
function createHandler() {
  const sessions = /* @__PURE__ */ new Map();
  const getSession = (params) => {
    const id = requiredString(params, "session");
    const session = sessions.get(id);
    if (!session) throw new RpcError(APPLICATION_ERROR, "Unknown session (closed, or the worker restarted)");
    return session;
  };
  return (method, params) => {
    switch (method) {
      case "version":
        return { version: VERSION2 };
      case "redact": {
        const text = requiredString(params, "text");
        if (params.session !== void 0) {
          const session = getSession(params);
          const { vault: _vault2, ...result2 } = redact(text, { ...session.options, reversible: true, vault: session.vault });
          return result2;
        }
        const { vault: _vault, ...result } = redact(text, buildOptions(params));
        return result;
      }
      case "unmask": {
        const text = requiredString(params, "text");
        return { text: unmask(text, getSession(params).vault) };
      }
      case "session.open": {
        if (sessions.size >= MAX_SESSIONS) throw new RpcError(APPLICATION_ERROR, `Too many open sessions (${MAX_SESSIONS})`);
        const id = crypto.randomUUID();
        sessions.set(id, { vault: new Vault(), options: buildOptions(params) });
        return { session: id };
      }
      case "session.close":
        return { closed: sessions.delete(requiredString(params, "session")) };
      default:
        throw new RpcError(METHOD_NOT_FOUND, `Method not found: ${method}`);
    }
  };
}
function respond(handle, line) {
  let message;
  try {
    message = JSON.parse(line);
  } catch {
    return { jsonrpc: "2.0", id: null, error: { code: PARSE_ERROR, message: "Parse error" } };
  }
  const id = isObject(message) && (typeof message.id === "number" || typeof message.id === "string") ? message.id : null;
  if (!isObject(message) || message.jsonrpc !== "2.0" || id === null || typeof message.method !== "string") {
    return { jsonrpc: "2.0", id, error: { code: INVALID_REQUEST, message: "Invalid request" } };
  }
  const params = message.params ?? {};
  if (!isObject(params)) {
    return { jsonrpc: "2.0", id, error: { code: INVALID_PARAMS, message: '"params" must be an object' } };
  }
  try {
    return { jsonrpc: "2.0", id, result: handle(message.method, params) };
  } catch (err) {
    const code = err instanceof RpcError ? err.code : APPLICATION_ERROR;
    return { jsonrpc: "2.0", id, error: { code, message: err instanceof Error ? err.message : String(err) } };
  }
}
async function runServe(args, input = process.stdin, output = process.stdout, errors = process.stderr) {
  if (args.length !== 1 || args[0] !== "--stdio") {
    errors.write("Usage: agent-redact serve --stdio   (newline-delimited JSON-RPC 2.0 on stdin/stdout)\n");
    return 2;
  }
  const limit = maxBytes();
  const handle = createHandler();
  const write = (obj) => new Promise((resolve5) => {
    if (output.write(JSON.stringify(obj) + "\n")) resolve5();
    else output.once("drain", resolve5);
  });
  let pending = [];
  let pendingBytes = 0;
  for await (const chunk of input) {
    let data = chunk;
    let nl;
    while ((nl = data.indexOf(10)) !== -1) {
      const line = Buffer.concat([...pending, data.subarray(0, nl)]).toString("utf8").replace(/\r$/, "");
      pending = [];
      pendingBytes = 0;
      data = data.subarray(nl + 1);
      if (Buffer.byteLength(line) > limit) {
        await write({ jsonrpc: "2.0", id: null, error: { code: INVALID_REQUEST, message: `Message too large (limit ${limit} bytes)` } });
        return 1;
      }
      if (line.trim() !== "") await write(respond(handle, line));
    }
    pending.push(data);
    pendingBytes += data.length;
    if (pendingBytes > limit) {
      await write({ jsonrpc: "2.0", id: null, error: { code: INVALID_REQUEST, message: `Message too large (limit ${limit} bytes)` } });
      return 1;
    }
  }
  return 0;
}

// src/cli/proxy.ts
init_presets();

// src/proxy/server.ts
init_vault();

// src/core/deep.ts
init_engine();
init_vault();
var isPlainObject = (v) => {
  if (typeof v !== "object" || v === null) return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
};
function isToolUnmaskAllowed(policy, toolName) {
  if (policy === true) return true;
  if (typeof policy === "function") return policy(toolName);
  return false;
}
var nameOf = (parent) => {
  for (const k of ["name", "toolName", "tool_name"]) {
    if (typeof parent[k] === "string") return parent[k];
  }
  return "";
};
function toolInputSlot(key, parent) {
  const type = typeof parent["type"] === "string" ? parent["type"] : "";
  if (key === "arguments" || key === "args" || key === "partial_json") return nameOf(parent);
  if ((key === "input" || key === "parameters") && (/tool|function/i.test(type) || "toolName" in parent)) {
    return nameOf(parent);
  }
  if (key === "delta" && /function_call_arguments/i.test(type)) return "";
  return null;
}
var BASE64_RE = /^[A-Za-z0-9+/_-]*={0,2}$/;
var TEXT_MIME_RE = /^(?:text\/|application\/(?:json|xml|yaml|x-yaml|toml|x-toml|javascript|ecmascript|x-sh|x-shellscript|sql|csv|x-ndjson)\b)|\+(?:json|xml)\b/i;
function findBase64Payload(value, key, parent) {
  const dataUrl = /^data:([^;,]*)((?:;[^;,]*)*);base64,/i.exec(value.slice(0, 512));
  if (dataUrl) {
    const head = dataUrl[0];
    return { mime: dataUrl[1] || void 0, encoded: value.slice(head.length), rebuild: (e) => head + e };
  }
  if (key === "data" && parent && (parent["type"] === "base64" || "media_type" in parent || "mime_type" in parent)) {
    const mime = parent["media_type"] ?? parent["mime_type"];
    return { mime: typeof mime === "string" ? mime : void 0, encoded: value, rebuild: (e) => e };
  }
  return null;
}
function mapStrings(value, fn, skipProp, seen = /* @__PURE__ */ new WeakMap(), key, parent) {
  if (typeof value === "string") return fn(value, key, parent);
  if (Array.isArray(value)) {
    if (seen.has(value)) return seen.get(value);
    const out = [];
    seen.set(value, out);
    for (const item of value) out.push(mapStrings(item, fn, skipProp, seen, key, parent));
    return out;
  }
  if (isPlainObject(value)) {
    if (seen.has(value)) return seen.get(value);
    const out = {};
    seen.set(value, out);
    for (const [k, v] of Object.entries(value)) {
      const decision = skipProp(k, value);
      out[k] = decision === "skip" ? v : mapStrings(v, fn, decision === "all" ? () => void 0 : skipProp, seen, k, value);
    }
    return out;
  }
  return value;
}
function redactDeep(value, options = {}) {
  const { vault = new Vault(), skipKeys = [], ...redactOptions } = options;
  const reversible = redactOptions.reversible ?? true;
  const skip = new Set(skipKeys);
  const stats = {};
  let totalLeaks = 0;
  const scan = (s) => {
    const res = redact(s, { ...redactOptions, reversible, vault });
    totalLeaks += res.totalLeaks;
    for (const [id, n] of Object.entries(res.stats)) stats[id] = (stats[id] ?? 0) + n;
    return res.text;
  };
  const out = mapStrings(
    value,
    (s, key, parent) => {
      const payload = findBase64Payload(s, key, parent);
      if (payload) {
        const compact = payload.encoded.replace(/\r?\n/g, "");
        if (BASE64_RE.test(compact)) {
          const bytes = Buffer.from(compact, "base64");
          const textual = payload.mime !== void 0 && TEXT_MIME_RE.test(payload.mime) || !bytes.includes(0);
          if (!textual) return s;
          const decoded = bytes.toString("utf8");
          const redacted = scan(decoded);
          return redacted === decoded ? s : payload.rebuild(Buffer.from(redacted, "utf8").toString("base64"));
        }
      }
      return scan(s);
    },
    (k) => skip.has(k) ? "skip" : void 0
  );
  return { value: out, vault, totalLeaks, stats };
}
function unmaskDeep(value, vault, options = {}) {
  const policy = options.unmaskToolInputs;
  return mapStrings(
    value,
    (s) => vault.unmask(s),
    (k, parent) => {
      const tool = toolInputSlot(k, parent);
      if (tool === null) return void 0;
      return isToolUnmaskAllowed(policy, tool) ? "all" : "skip";
    }
  );
}
var jsonStringEscape = (secret) => JSON.stringify(secret).slice(1, -1);
var StreamingUnmasker = class {
  constructor(vault, encode) {
    this.vault = vault;
    this.encode = encode;
  }
  vault;
  encode;
  pending = "";
  /** Feeds the next chunk and returns the text that is safe to emit now */
  push(chunk) {
    const text = this.pending + chunk;
    this.pending = "";
    const hold = this.holdStart(text);
    if (hold === -1) {
      return this.vault.unmask(text, this.encode);
    }
    this.pending = text.slice(hold);
    return this.vault.unmask(text.slice(0, hold), this.encode);
  }
  /** Returns everything still buffered (call once the stream has ended) */
  flush() {
    const rest = this.pending;
    this.pending = "";
    return this.vault.unmask(rest, this.encode);
  }
  holdStart(text) {
    const open = text.lastIndexOf("[");
    if (open === -1) return -1;
    const tail = text.slice(open);
    if (tail.includes("]")) return -1;
    return this.vault.hasPlaceholderPrefix(tail) ? open : -1;
  }
};
var ANTHROPIC_ENVELOPE_EVENTS = /* @__PURE__ */ new Set([
  "message_start",
  "content_block_start",
  "content_block_stop",
  "message_delta",
  "message_stop",
  "ping"
]);
var isObject2 = (v) => typeof v === "object" && v !== null;
function getOrCreate(map, key, create) {
  let value = map.get(key);
  if (value === void 0) {
    value = create();
    map.set(key, value);
  }
  return value;
}
async function* unmaskAnthropicStream(events, vault, options = {}) {
  const policy = options.unmaskToolInputs;
  const text = /* @__PURE__ */ new Map();
  const json = /* @__PURE__ */ new Map();
  const toolNames = /* @__PURE__ */ new Map();
  function* flushBlock(index) {
    const t = text.get(index)?.flush();
    if (t) yield { type: "content_block_delta", index, delta: { type: "text_delta", text: t } };
    const j = json.get(index)?.flush();
    if (j) yield { type: "content_block_delta", index, delta: { type: "input_json_delta", partial_json: j } };
    text.delete(index);
    json.delete(index);
  }
  for await (const event of events) {
    const e = event;
    if (isObject2(e) && e["type"] === "content_block_start" && isObject2(e["content_block"])) {
      const block = e["content_block"];
      if (block["type"] === "tool_use") toolNames.set(Number(e["index"] ?? 0), String(block["name"] ?? ""));
    }
    if (isObject2(e) && e["type"] === "content_block_delta" && isObject2(e["delta"])) {
      const index = Number(e["index"] ?? 0);
      const delta = e["delta"];
      if (delta["type"] === "text_delta" && typeof delta["text"] === "string") {
        const out = getOrCreate(text, index, () => new StreamingUnmasker(vault)).push(delta["text"]);
        yield { ...e, delta: { ...delta, text: out } };
        continue;
      }
      if (delta["type"] === "input_json_delta" && typeof delta["partial_json"] === "string") {
        if (!isToolUnmaskAllowed(policy, toolNames.get(index) ?? "")) {
          yield { ...e, delta: { ...delta } };
          continue;
        }
        const out = getOrCreate(json, index, () => new StreamingUnmasker(vault, jsonStringEscape)).push(
          delta["partial_json"]
        );
        yield { ...e, delta: { ...delta, partial_json: out } };
        continue;
      }
    }
    if (isObject2(e) && e["type"] === "content_block_stop") {
      yield* flushBlock(Number(e["index"] ?? 0));
    }
    if (isObject2(e) && e["type"] === "message_stop") {
      for (const index of /* @__PURE__ */ new Set([...text.keys(), ...json.keys()])) yield* flushBlock(index);
    }
    if (isObject2(e) && typeof e["type"] === "string" && ANTHROPIC_ENVELOPE_EVENTS.has(e["type"])) {
      yield unmaskDeep(event, vault, { unmaskToolInputs: policy });
    } else {
      yield event;
    }
  }
  for (const index of /* @__PURE__ */ new Set([...text.keys(), ...json.keys()])) yield* flushBlock(index);
}
async function* unmaskOpenAIStream(chunks, vault, options = {}) {
  const policy = options.unmaskToolInputs;
  const content = /* @__PURE__ */ new Map();
  const args = /* @__PURE__ */ new Map();
  const toolNames = /* @__PURE__ */ new Map();
  for await (const chunk of chunks) {
    const c = chunk;
    if (!isObject2(c) || !Array.isArray(c["choices"])) {
      yield chunk;
      continue;
    }
    const choices = c["choices"].map((choice) => {
      if (!isObject2(choice) || !isObject2(choice["delta"])) return choice;
      const index = Number(choice["index"] ?? 0);
      const delta = { ...choice["delta"] };
      const finished = choice["finish_reason"] != null;
      if (typeof delta["content"] === "string" || finished && content.has(index)) {
        const u = getOrCreate(content, index, () => new StreamingUnmasker(vault));
        let out = typeof delta["content"] === "string" ? u.push(delta["content"]) : "";
        if (finished) out += u.flush();
        if (typeof delta["content"] === "string" || out) delta["content"] = out;
      }
      const toolCalls = Array.isArray(delta["tool_calls"]) ? [...delta["tool_calls"]] : [];
      const mapped = toolCalls.map((tc) => {
        if (!isObject2(tc) || !isObject2(tc["function"]) || typeof tc["function"]["arguments"] !== "string") {
          return tc;
        }
        const key = `${index}:${Number(tc["index"] ?? 0)}`;
        if (typeof tc["function"]["name"] === "string") toolNames.set(key, tc["function"]["name"]);
        if (!isToolUnmaskAllowed(policy, toolNames.get(key) ?? "")) {
          return { ...tc, function: { ...tc["function"] } };
        }
        const u = getOrCreate(args, key, () => new StreamingUnmasker(vault, jsonStringEscape));
        return { ...tc, function: { ...tc["function"], arguments: u.push(tc["function"]["arguments"]) } };
      });
      if (finished) {
        for (const [key, u] of args) {
          if (!key.startsWith(`${index}:`)) continue;
          const rest = u.flush();
          if (rest) mapped.push({ index: Number(key.split(":")[1]), function: { arguments: rest } });
          args.delete(key);
        }
        content.delete(index);
      }
      if (mapped.length > 0) delta["tool_calls"] = mapped;
      return { ...choice, delta };
    });
    yield { ...c, choices };
  }
  const trailing = [];
  for (const [index, u] of content) {
    const rest = u.flush();
    if (rest) trailing.push({ index, delta: { content: rest }, finish_reason: null });
  }
  for (const [key, u] of args) {
    const rest = u.flush();
    if (!rest) continue;
    const [choiceIndex, toolIndex] = key.split(":").map(Number);
    trailing.push({ index: choiceIndex, delta: { tool_calls: [{ index: toolIndex, function: { arguments: rest } }] }, finish_reason: null });
  }
  if (trailing.length > 0) yield { choices: trailing };
}

// src/proxy/server.ts
var DEFAULT_UPSTREAM = {
  anthropic: "https://api.anthropic.com",
  openai: "https://api.openai.com"
};
var DEFAULT_MAX_BODY = 32 * 1024 * 1024;
var HOP_BY_HOP = /* @__PURE__ */ new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "proxy-connection",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "host",
  "content-length",
  "accept-encoding"
]);
var LOOPBACK_HOST = [127, 0, 0, 1].join(".");
var IPV6_LOOPBACK2 = ["", "", "1"].join(":");
var LOOPBACK = /* @__PURE__ */ new Set([LOOPBACK_HOST, "localhost", `[${IPV6_LOOPBACK2}]`, IPV6_LOOPBACK2]);
function upstreamBase(upstream) {
  let url;
  try {
    url = new URL(upstream);
  } catch {
    throw new Error(`Invalid upstream URL: ${upstream}`);
  }
  const ok = url.protocol === "https:" || url.protocol === "http:" && LOOPBACK.has(url.hostname);
  if (!ok) throw new Error("The upstream must use https (plain http is only allowed for loopback addresses)");
  return url.origin + url.pathname.replace(/\/+$/, "");
}
var HttpError = class extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
  status;
};
async function readBody(req, limit) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > limit) throw new HttpError(413, `Request body exceeds ${limit} bytes`);
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}
function sendError(res, status, message) {
  if (res.headersSent) {
    res.destroy();
    return;
  }
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify({ type: "error", error: { type: "agent_redact_proxy_error", message } }));
}
async function* readSse(body) {
  const decoder = new TextDecoder();
  let buffer = "";
  const parse = (block) => {
    let event;
    const data = [];
    for (const line of block.split(/\r?\n/)) {
      if (line === "" || line.startsWith(":")) continue;
      const colon = line.indexOf(":");
      const field = colon === -1 ? line : line.slice(0, colon);
      const value = colon === -1 ? "" : line.slice(colon + 1).replace(/^ /, "");
      if (field === "event") event = value;
      else if (field === "data") data.push(value);
    }
    return data.length > 0 ? { event, data: data.join("\n") } : null;
  };
  for await (const chunk of body) {
    buffer += decoder.decode(chunk, { stream: true });
    let match;
    while (match = /\r?\n\r?\n/.exec(buffer)) {
      const ev = parse(buffer.slice(0, match.index));
      buffer = buffer.slice(match.index + match[0].length);
      if (ev) yield ev;
    }
  }
  buffer += decoder.decode();
  const last = parse(buffer);
  if (last) yield last;
}
var RAW = /* @__PURE__ */ Symbol("raw-sse-event");
function formatSse(event, data) {
  const lines = data.split("\n").map((l) => `data: ${l}`);
  return `${event ? `event: ${event}
` : ""}${lines.join("\n")}

`;
}
async function* unmaskSse(body, provider, vault, unmaskToolInputs) {
  let done = false;
  async function* parsed() {
    for await (const ev of readSse(body)) {
      if (provider === "openai" && ev.data.trim() === "[DONE]") {
        done = true;
        return;
      }
      try {
        yield JSON.parse(ev.data);
      } catch {
        yield { [RAW]: ev };
      }
    }
  }
  const adapter = provider === "anthropic" ? unmaskAnthropicStream : unmaskOpenAIStream;
  for await (const item of adapter(parsed(), vault, { unmaskToolInputs })) {
    if (typeof item === "object" && item !== null && RAW in item) {
      const raw = item[RAW];
      yield formatSse(raw.event, raw.data);
      continue;
    }
    const type = provider === "anthropic" && typeof item?.type === "string" ? item.type : void 0;
    yield formatSse(type, JSON.stringify(item));
  }
  if (done) yield "data: [DONE]\n\n";
}
function describeStats(stats) {
  const parts = Object.entries(stats).map(([id, n]) => `${id}:${n}`);
  return parts.length ? ` (${parts.join(", ")})` : "";
}
async function startProxy(options) {
  const provider = options.provider;
  if (provider !== "anthropic" && provider !== "openai") throw new Error('provider must be "anthropic" or "openai"');
  const base = upstreamBase(options.upstream ?? DEFAULT_UPSTREAM[provider]);
  const maxBody = options.maxBodyBytes ?? DEFAULT_MAX_BODY;
  const vault = new Vault();
  const log = options.log ?? (() => {
  });
  const policy = options.unmaskToolInputs;
  const handle = async (req, res) => {
    const path = req.url ?? "/";
    const method = req.method ?? "GET";
    if (!path.startsWith("/")) throw new HttpError(400, "Only origin-form request paths are accepted");
    if (req.headers.origin !== void 0) throw new HttpError(403, "Browser requests are not allowed");
    const host = String(req.headers.host ?? "");
    const hostname = host.startsWith("[") ? host.slice(0, host.indexOf("]") + 1) : host.split(":")[0];
    if (!LOOPBACK.has(hostname.toLowerCase())) throw new HttpError(403, "Requests must address the proxy by its loopback address");
    const raw = await readBody(req, maxBody);
    let body;
    let redacted = 0;
    let stats = {};
    if (raw.length > 0) {
      const encoding = String(req.headers["content-encoding"] ?? "identity").toLowerCase();
      if (encoding !== "identity") throw new HttpError(415, "Compressed request bodies are not supported");
      if (!/^application\/(?:[\w.+-]+\+)?json\b/i.test(String(req.headers["content-type"] ?? ""))) {
        throw new HttpError(415, "Only JSON request bodies are accepted");
      }
      let value;
      try {
        value = JSON.parse(raw.toString("utf8"));
      } catch {
        throw new HttpError(400, "Malformed JSON request body");
      }
      const result = redactDeep(value, { ...options.redactOptions, vault, skipKeys: ["signature"] });
      body = JSON.stringify(result.value);
      redacted = result.totalLeaks;
      stats = result.stats;
    }
    const headers = new Headers();
    for (const [name, value] of Object.entries(req.headers)) {
      if (value === void 0 || HOP_BY_HOP.has(name.toLowerCase())) continue;
      for (const v of Array.isArray(value) ? value : [value]) headers.append(name, v);
    }
    headers.set("accept-encoding", "identity");
    const abort = new AbortController();
    res.on("close", () => abort.abort());
    let upstream;
    try {
      upstream = await fetch(base + path, { method, headers, body, redirect: "manual", signal: abort.signal });
    } catch {
      throw new HttpError(502, "Upstream request failed");
    }
    const outHeaders = {};
    upstream.headers.forEach((value, name) => {
      if (!HOP_BY_HOP.has(name) && name !== "content-encoding" && !name.startsWith("access-control-")) outHeaders[name] = value;
    });
    const contentType = upstream.headers.get("content-type") ?? "";
    log(`${method} ${path.split("?")[0]} -> ${upstream.status} redacted=${redacted}${describeStats(stats)}`);
    if (/text\/event-stream/i.test(contentType) && upstream.body) {
      res.writeHead(upstream.status, outHeaders);
      for await (const chunk of unmaskSse(upstream.body, provider, vault, policy)) {
        if (!res.write(chunk)) await new Promise((r) => res.once("drain", r));
      }
      res.end();
      return;
    }
    if (/json/i.test(contentType)) {
      const text = await upstream.text();
      let out = text;
      try {
        out = JSON.stringify(unmaskDeep(JSON.parse(text), vault, { unmaskToolInputs: policy }));
      } catch {
      }
      res.writeHead(upstream.status, outHeaders);
      res.end(out);
      return;
    }
    res.writeHead(upstream.status, outHeaders);
    if (upstream.body) {
      for await (const chunk of upstream.body) {
        if (!res.write(chunk)) await new Promise((r) => res.once("drain", r));
      }
    }
    res.end();
  };
  const server = http.createServer((req, res) => {
    handle(req, res).catch((err) => {
      const status = err instanceof HttpError ? err.status : 500;
      const message = err instanceof HttpError ? err.message : "Proxy error";
      log(`${req.method ?? "GET"} ${(req.url ?? "/").split("?")[0]} -> ${status} ${message}`);
      if (status === 413) req.resume();
      sendError(res, status, message);
    });
  });
  await new Promise((resolve5, reject) => {
    server.once("error", reject);
    server.listen(options.port ?? 8787, LOOPBACK_HOST, () => {
      server.off("error", reject);
      resolve5();
    });
  });
  const { address, port } = server.address();
  return {
    server,
    vault,
    address,
    port,
    url: `http://${LOOPBACK_HOST}:${port}`,
    close: () => new Promise((resolve5) => {
      server.closeAllConnections();
      server.close(() => resolve5());
    })
  };
}

// src/cli/proxy.ts
var USAGE = `Usage: agent-redact proxy --provider <anthropic|openai> [options]

  --provider <name>            anthropic or openai (required)
  --port <n>                   Port on the loopback address (default 8787, 0 = any free port)
  --upstream <url>             Upstream API base (default: the provider's public API; https only)
  --unmask-tool-inputs <list>  Comma-separated tool names whose inputs get real secrets back
                               ("*" for all). Default: tool inputs stay masked.
  --preset <a,b>               Enable opt-in presets (e.g. vn-pii)
  --entropy                    Also redact high-entropy tokens
  --config <path>              Configuration file
`;
var VALUE_FLAGS = /* @__PURE__ */ new Set(["--provider", "--port", "--upstream", "--unmask-tool-inputs", "--preset", "--config"]);
async function runProxyCli(args) {
  const values = /* @__PURE__ */ new Map();
  let entropy = false;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "-h" || arg === "--help") {
      process.stdout.write(USAGE);
      return 0;
    }
    if (arg === "--entropy") {
      entropy = true;
      continue;
    }
    const value = args[i + 1];
    if (!VALUE_FLAGS.has(arg) || value === void 0 || value.startsWith("--")) {
      process.stderr.write(`Error: unexpected argument "${arg}"

${USAGE}`);
      return 2;
    }
    values.set(arg, value);
    i++;
  }
  const provider = values.get("--provider");
  if (provider !== "anthropic" && provider !== "openai") {
    process.stderr.write(`Error: --provider must be "anthropic" or "openai"

${USAGE}`);
    return 2;
  }
  const port = Number(values.get("--port") ?? 8787);
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    process.stderr.write("Error: --port must be an integer between 0 and 65535\n");
    return 2;
  }
  const toolList = (values.get("--unmask-tool-inputs") ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  const unmaskToolInputs = toolList.includes("*") ? true : toolList.length ? (name) => toolList.includes(name) : false;
  let redactOptions;
  try {
    const config = loadConfig(values.get("--config"));
    const presets = [...config?.presets ?? [], ...(values.get("--preset") ?? "").split(",").map((s) => s.trim()).filter(Boolean)];
    resolvePresets(presets);
    redactOptions = {
      include: config?.include,
      exclude: config?.exclude,
      allowlist: config?.allowlist,
      customPatterns: config?.customPatterns,
      detectHighEntropy: entropy || (config?.detectHighEntropy ?? false),
      presets,
      entropy: config?.entropy
    };
  } catch (err) {
    process.stderr.write(`Error: ${err instanceof Error ? err.message : String(err)}
`);
    return 2;
  }
  let proxy;
  try {
    proxy = await startProxy({
      provider,
      upstream: values.get("--upstream"),
      port,
      unmaskToolInputs,
      redactOptions,
      log: (line) => process.stderr.write(`[agent-redact proxy] ${line}
`)
    });
  } catch (err) {
    process.stderr.write(`Error: ${err instanceof Error ? err.message : String(err)}
`);
    return 1;
  }
  const env = provider === "anthropic" ? `ANTHROPIC_BASE_URL=${proxy.url}` : `OPENAI_BASE_URL=${proxy.url}/v1`;
  process.stderr.write(
    `[agent-redact proxy] listening on ${proxy.url} (${provider}); tool inputs ${unmaskToolInputs === false ? "stay masked" : `restored for: ${toolList.join(", ")}`}
[agent-redact proxy] point your client at it: ${env}
`
  );
  await new Promise((resolve5) => {
    const stop = () => resolve5();
    process.once("SIGINT", stop);
    process.once("SIGTERM", stop);
  });
  await proxy.close();
  return 0;
}

// src/cli/index.ts
function writeSecureFile(filePath, content) {
  fs.writeFileSync(filePath, content, { encoding: "utf-8", mode: 384 });
  try {
    fs.chmodSync(filePath, 384);
  } catch {
  }
}
function resolveVaultKey(vaultKeyEnv) {
  if (vaultKeyEnv) {
    const value = process.env[vaultKeyEnv];
    if (!value) {
      console.error(`${colors.red}Error:${colors.reset} environment variable ${vaultKeyEnv} (from --vault-key-env) is not set or empty.`);
      process.exit(2);
    }
    return value;
  }
  return process.env["AGENT_REDACT_VAULT_KEY"] || void 0;
}
function loadVault(path, vaultKeyEnv) {
  let raw;
  try {
    raw = fs.readFileSync(path, "utf-8");
  } catch {
    console.error(`${colors.red}Error:${colors.reset} Cannot read vault file: ${path}`);
    process.exit(1);
  }
  let json = raw;
  if (isEncryptedVault(raw)) {
    const key = resolveVaultKey(vaultKeyEnv);
    if (!key) {
      console.error(
        `${colors.red}Error:${colors.reset} ${path} is encrypted; pass --vault-key-env <VAR> (or set AGENT_REDACT_VAULT_KEY) with the passphrase.`
      );
      process.exit(2);
    }
    try {
      json = decryptVaultJson(raw, key);
    } catch (err) {
      console.error(`${colors.red}Error:${colors.reset} ${err instanceof Error ? err.message : String(err)}`);
      process.exit(1);
    }
  }
  try {
    return Vault.fromJSON(json);
  } catch (err) {
    console.error(`${colors.red}Error:${colors.reset} ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  }
}
function saveVault(path, vault, vaultKeyEnv) {
  const key = resolveVaultKey(vaultKeyEnv);
  writeSecureFile(path, key ? encryptVaultJson(vault.toJSON(), key) : vault.toJSON());
  if (key) {
    console.error(`${colors.green}\u2714${colors.reset} Encrypted session vault saved to ${path}`);
  } else {
    console.error(`${colors.green}\u2714${colors.reset} Session vault saved to ${path}`);
    console.error(
      `${colors.yellow}\u26A0${colors.reset} The vault is stored unencrypted and contains the original secrets. Use --vault-key-env <VAR> (or AGENT_REDACT_VAULT_KEY) to encrypt it.`
    );
  }
}
var colors = {
  reset: "\x1B[0m",
  bold: "\x1B[1m",
  dim: "\x1B[2m",
  green: "\x1B[32m",
  yellow: "\x1B[33m",
  blue: "\x1B[34m",
  magenta: "\x1B[35m",
  cyan: "\x1B[36m",
  red: "\x1B[31m",
  gray: "\x1B[90m"
};
function printHelp() {
  const helpText = `
${colors.bold}${colors.cyan}agent-redact${colors.reset} ${colors.gray}v${VERSION2}${colors.reset}
${colors.dim}Secret & PII redactor for AI agents, LLM pipelines and CI${colors.reset}

${colors.bold}USAGE:${colors.reset}
  npx agent-redact <file> [options]         Redact secrets in a file
  cat log.txt | npx agent-redact [options]  Redact secrets from standard input (stdin)
  npx agent-redact <dir|files...>           Scan (honours .gitignore in git repos); exit 1 on findings
  npx agent-redact --staged                 Scan what is staged for commit (git index)
  npx agent-redact mcp [--allow-unmask-text] Start Model Context Protocol (MCP) server
  npx agent-redact hook [--block-writes]    Claude Code hook (reads hook JSON on stdin)
  npx agent-redact serve --stdio            Long-lived JSON-RPC worker on stdin/stdout (Python package)
  npx agent-redact proxy --provider <name>  Local redacting proxy for the Anthropic/OpenAI API (see proxy --help)

${colors.bold}SCAN OPTIONS:${colors.reset}
  --format <text|json|sarif>  Report format (json/sarif go to stdout or --report)
  --report <file>             Write the json/sarif report to a file
  --baseline <file>           Ignore findings recorded in a baseline file
  --write-baseline <file>     Record current findings as accepted, then exit 0
  Inline: add "agent-redact-ignore" to a line, or "agent-redact-ignore-next-line" above it

${colors.bold}OPTIONS:${colors.reset}
  -r, --reversible            Generate numbered session placeholders ([ANTHROPIC_API_KEY_1])
  -o, --output <file>         Write sanitized content to target file instead of stdout
  -i, --inplace               Modify input file in-place
  -j, --json                  Output result and leak metadata as JSON
  --config <path>             Path to configuration file (.agentredactrc or json)
  --entropy                   Enable Shannon entropy detection for generic secrets
  --check, --fail-on-leak     Exit with code 1 if any secrets are detected (CI/pre-commit)
  --vault-out <file>          Save generated session vault mappings to JSON file
  --vault-key-env <VAR>       Encrypt/decrypt the vault with the passphrase in env var VAR
  --vault-in <file>           Continue an existing vault (numbering carries over between runs)
  --preset <a,b>              Enable opt-in pattern presets (e.g. vn-pii)
  --unmask <vaultFile>        Restore previously masked file using saved vault file
  --stats                     Display leak statistics breakdown table
  -h, --help                  Show this help message
  -v, --version               Show current version

${colors.bold}EXAMPLES:${colors.reset}
  ${colors.dim}# 1. Pipe and sanitize on the fly:${colors.reset}
  cat server.log | npx agent-redact

  ${colors.dim}# 2. Reversibly mask .env and save vault:${colors.reset}
  npx agent-redact .env -r -o .env.safe --vault-out session.vault.json

  ${colors.dim}# 3. Restore masked file after agent completes:${colors.reset}
  npx agent-redact .env.safe --unmask session.vault.json -o .env.restored
`;
  console.log(helpText.trim());
}
async function readStdin() {
  return new Promise((resolve5) => {
    let data = "";
    process.stdin.setEncoding("utf-8");
    process.stdin.on("data", (chunk) => {
      data += chunk;
    });
    process.stdin.on("end", () => {
      resolve5(data);
    });
  });
}
async function main() {
  const args = process.argv.slice(2);
  if (args[0] === "mcp") {
    const { runMcpServer: runMcpServer2 } = await Promise.resolve().then(() => (init_server(), server_exports));
    await runMcpServer2(args.slice(1));
    return;
  }
  if (args[0] === "hook") {
    process.exit(await runHook(args.slice(1)));
  }
  if (args[0] === "proxy") {
    process.exitCode = await runProxyCli(args.slice(1));
    return;
  }
  if (args[0] === "serve") {
    process.exitCode = await runServe(args.slice(1));
    return;
  }
  if (args.includes("-h") || args.includes("--help")) {
    printHelp();
    process.exit(0);
  }
  if (args.includes("-v") || args.includes("--version")) {
    console.log(`agent-redact v${VERSION2}`);
    process.exit(0);
  }
  const VALUE_FLAGS2 = /* @__PURE__ */ new Set([
    "-o",
    "--output",
    "--vault-out",
    "--unmask",
    "--config",
    "--format",
    "--report",
    "--baseline",
    "--write-baseline",
    "--vault-key-env",
    "--vault-in",
    "--preset"
  ]);
  const BOOLEAN_FLAGS = /* @__PURE__ */ new Set([
    "-r",
    "--reversible",
    "-j",
    "--json",
    "--stats",
    "-i",
    "--inplace",
    "--entropy",
    "--check",
    "--fail-on-leak",
    "--staged",
    "-h",
    "--help",
    "-v",
    "--version"
  ]);
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg.startsWith("-")) {
      if (VALUE_FLAGS2.has(arg)) {
        const val = args[i + 1];
        if (!val || val.startsWith("-")) {
          console.error(`${colors.red}Error:${colors.reset} Flag "${arg}" requires a file argument.`);
          process.exit(2);
        }
        i++;
      } else if (!BOOLEAN_FLAGS.has(arg)) {
        console.error(`${colors.red}Error:${colors.reset} Unknown flag "${arg}". Use --help for available options.`);
        process.exit(2);
      }
    }
  }
  const isReversible = args.includes("-r") || args.includes("--reversible");
  const isJson = args.includes("-j") || args.includes("--json");
  const showStats = args.includes("--stats");
  const isInplace = args.includes("-i") || args.includes("--inplace");
  const detectEntropy = args.includes("--entropy");
  const failOnLeak = args.includes("--check") || args.includes("--fail-on-leak");
  const outputIdx = args.findIndex((a) => a === "-o" || a === "--output");
  const outputFile = outputIdx !== -1 && args[outputIdx + 1] ? args[outputIdx + 1] : void 0;
  const vaultOutIdx = args.indexOf("--vault-out");
  const vaultOutFile = vaultOutIdx !== -1 && args[vaultOutIdx + 1] ? args[vaultOutIdx + 1] : void 0;
  const unmaskIdx = args.indexOf("--unmask");
  const unmaskVaultFile = unmaskIdx !== -1 && args[unmaskIdx + 1] ? args[unmaskIdx + 1] : void 0;
  const configIdx = args.indexOf("--config");
  const configPath = configIdx !== -1 && args[configIdx + 1] ? args[configIdx + 1] : void 0;
  const valueAfter = (flag) => {
    const index = args.indexOf(flag);
    return { index, value: index !== -1 ? args[index + 1] : void 0 };
  };
  const formatArg = valueAfter("--format");
  const reportArg = valueAfter("--report");
  const baselineArg = valueAfter("--baseline");
  const writeBaselineArg = valueAfter("--write-baseline");
  const vaultKeyArg = valueAfter("--vault-key-env");
  const vaultKeyEnv = vaultKeyArg.value;
  const vaultInArg = valueAfter("--vault-in");
  const presetArg = valueAfter("--preset");
  const isStaged = args.includes("--staged");
  const skipIndices = /* @__PURE__ */ new Set();
  if (outputIdx !== -1) skipIndices.add(outputIdx + 1);
  if (vaultOutIdx !== -1) skipIndices.add(vaultOutIdx + 1);
  if (unmaskIdx !== -1) skipIndices.add(unmaskIdx + 1);
  if (configIdx !== -1) skipIndices.add(configIdx + 1);
  for (const a of [formatArg, reportArg, baselineArg, writeBaselineArg, vaultKeyArg, vaultInArg, presetArg]) {
    if (a.index !== -1) skipIndices.add(a.index + 1);
  }
  const format = formatArg.value;
  if (format !== void 0 && !["text", "json", "sarif"].includes(format)) {
    console.error(`${colors.red}Error:${colors.reset} --format must be one of: text, json, sarif.`);
    process.exit(2);
  }
  let loadedConfig = null;
  try {
    loadedConfig = loadConfig(configPath);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`${colors.red}Configuration Error:${colors.reset} ${msg}`);
    process.exit(1);
  }
  const fileArgs = args.filter(
    (a, i) => !a.startsWith("-") && !skipIndices.has(i)
  );
  const effectiveReversible = isReversible || (loadedConfig?.reversible ?? false);
  const effectivePresets = [
    ...loadedConfig?.presets ?? [],
    ...(presetArg.value ?? "").split(",").map((s) => s.trim()).filter(Boolean)
  ];
  try {
    resolvePresets(effectivePresets);
  } catch (err) {
    console.error(`${colors.red}Error:${colors.reset} ${err instanceof Error ? err.message : String(err)}`);
    process.exit(2);
  }
  const vault = effectiveReversible ? vaultInArg.value ? loadVault(vaultInArg.value, vaultKeyEnv) : new Vault() : void 0;
  if (effectiveReversible && isInplace && !vaultOutFile && !unmaskVaultFile) {
    console.error(
      `${colors.red}Error:${colors.reset} reversible in-place masking requires --vault-out <file>; otherwise the original values cannot be restored.`
    );
    process.exit(2);
  }
  const isDirectoryArg = (p) => {
    try {
      return fs.statSync(p).isDirectory();
    } catch {
      return false;
    }
  };
  const hasDirectory = fileArgs.some(isDirectoryArg);
  const multiInput = fileArgs.length > 1 || hasDirectory;
  if (multiInput && (unmaskVaultFile || outputFile || isJson)) {
    console.error(
      `${colors.red}Error:${colors.reset} Flags -o/--output, --unmask, and -j/--json cannot be used with multiple input files.`
    );
    process.exit(2);
  }
  const scanMode = isStaged || format !== void 0 || baselineArg.index !== -1 || writeBaselineArg.index !== -1 || multiInput && !isInplace;
  if (scanMode) {
    if (isInplace || isReversible || outputFile || unmaskVaultFile || isJson) {
      console.error(
        `${colors.red}Error:${colors.reset} -i, -r, -o, --unmask and --json cannot be combined with scan mode (directories, --staged, --format, --baseline, --write-baseline).`
      );
      process.exit(2);
    }
    if (!isStaged && fileArgs.length === 0) {
      console.error(`${colors.red}Error:${colors.reset} scan mode needs at least one file or directory (or --staged).`);
      process.exit(2);
    }
    let outcome;
    try {
      outcome = runScan({
        targets: fileArgs,
        staged: isStaged,
        baselineFile: writeBaselineArg.index !== -1 ? void 0 : baselineArg.value,
        cwd: process.cwd(),
        options: {
          include: loadedConfig?.include,
          exclude: loadedConfig?.exclude,
          allowlist: loadedConfig?.allowlist,
          customPatterns: loadedConfig?.customPatterns,
          detectHighEntropy: detectEntropy || (loadedConfig?.detectHighEntropy ?? false),
          presets: effectivePresets,
          entropy: loadedConfig?.entropy
        }
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`${colors.red}Error:${colors.reset} ${msg}`);
      process.exit(1);
    }
    if (writeBaselineArg.value) {
      writeScanBaseline(writeBaselineArg.value, outcome);
      console.error(
        `${colors.green}\u2714${colors.reset} Baseline with ${outcome.findings.length} finding(s) written to ${writeBaselineArg.value}`
      );
      process.exit(0);
    }
    if (format === "json" || format === "sarif") {
      const report = formatReport(outcome, format);
      if (reportArg.value) fs.writeFileSync(reportArg.value, report, "utf-8");
      else process.stdout.write(report);
    }
    console.error(formatText(outcome, colors));
    process.exit(outcome.findings.length > 0 ? 1 : 0);
  }
  if (multiInput) {
    let totalLeaksAcrossFiles = 0;
    let inPlaceFiles;
    try {
      inPlaceFiles = expandTargets(fileArgs, process.cwd());
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`${colors.red}Error:${colors.reset} ${msg}`);
      process.exit(1);
    }
    const inputs = [];
    for (const file of inPlaceFiles) {
      const read = readTextForScan(file);
      if (read.ok) {
        inputs.push({ file, content: read.content });
      } else if (read.reason === "unreadable" || !hasDirectory) {
        console.error(`${colors.red}Error:${colors.reset} Cannot read file: ${path.relative(process.cwd(), file) || file}`);
        process.exit(1);
      }
    }
    const results = inputs.map(({ file, content: fileContent }) => ({
      file,
      res: redact(fileContent, {
        reversible: effectiveReversible,
        vault,
        include: loadedConfig?.include,
        exclude: loadedConfig?.exclude,
        allowlist: loadedConfig?.allowlist,
        customPatterns: loadedConfig?.customPatterns,
        detectHighEntropy: detectEntropy || (loadedConfig?.detectHighEntropy ?? false),
        presets: effectivePresets,
        entropy: loadedConfig?.entropy
      })
    }));
    if (vaultOutFile && vault) {
      saveVault(vaultOutFile, vault, vaultKeyEnv);
    }
    for (const { file, res } of results) {
      const shown = path.relative(process.cwd(), file) || file;
      if (res.hasLeaks) {
        fs.writeFileSync(file, res.text, "utf-8");
        totalLeaksAcrossFiles += res.totalLeaks;
        console.error(`${colors.yellow}\u2716 [LEAK]${colors.reset} ${shown}: ${res.totalLeaks} secret(s) redacted in place`);
      } else {
        console.error(`${colors.green}\u2714 [CLEAN]${colors.reset} ${shown}`);
      }
    }
    if (totalLeaksAcrossFiles > 0 && failOnLeak) {
      console.error(
        `
${colors.red}[agent-redact] Audit failed: detected ${totalLeaksAcrossFiles} secret(s) across ${results.length} files.${colors.reset}`
      );
      process.exit(1);
    }
    console.error(`
${colors.green}[agent-redact] All ${results.length} files sanitized.${colors.reset}`);
    process.exit(0);
  }
  const fileArg = fileArgs[0];
  let content = "";
  if (fileArg) {
    try {
      content = fs.readFileSync(fileArg, "utf-8");
    } catch {
      console.error(`${colors.red}Error:${colors.reset} Cannot read file: ${fileArg}`);
      process.exit(1);
    }
  } else if (!process.stdin.isTTY) {
    content = await readStdin();
  } else {
    printHelp();
    process.exit(0);
  }
  if (unmaskVaultFile) {
    const vault2 = loadVault(unmaskVaultFile, vaultKeyEnv);
    try {
      const restoredText = unmask(content, vault2);
      if (outputFile) {
        fs.writeFileSync(outputFile, restoredText, "utf-8");
        console.error(`${colors.green}\u2714${colors.reset} Restored output written to ${outputFile}`);
      } else if (isInplace && fileArg) {
        fs.writeFileSync(fileArg, restoredText, "utf-8");
        console.error(`${colors.green}\u2714${colors.reset} Unmasked in-place: ${fileArg}`);
      } else {
        process.stdout.write(restoredText);
      }
      return;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`${colors.red}Error during unmasking:${colors.reset} ${msg}`);
      process.exit(1);
    }
  }
  const result = redact(content, {
    reversible: effectiveReversible,
    vault,
    include: loadedConfig?.include,
    exclude: loadedConfig?.exclude,
    allowlist: loadedConfig?.allowlist,
    customPatterns: loadedConfig?.customPatterns,
    detectHighEntropy: detectEntropy || (loadedConfig?.detectHighEntropy ?? false),
    presets: effectivePresets,
    entropy: loadedConfig?.entropy
  });
  if (vaultOutFile && vault) {
    saveVault(vaultOutFile, vault, vaultKeyEnv);
  }
  if (isJson) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    if (outputFile) {
      fs.writeFileSync(outputFile, result.text, "utf-8");
      console.error(`${colors.green}\u2714${colors.reset} Sanitized output written to ${outputFile}`);
    } else if (isInplace && fileArg) {
      fs.writeFileSync(fileArg, result.text, "utf-8");
      console.error(`${colors.green}\u2714${colors.reset} Sanitized in-place: ${fileArg}`);
    } else if (!failOnLeak) {
      process.stdout.write(result.text);
    }
    if (result.hasLeaks || showStats) {
      console.error(
        `
${colors.cyan}[agent-redact]${colors.reset} ${result.hasLeaks ? `${colors.yellow}Detected & masked ${result.totalLeaks} secret(s)${colors.reset}` : `${colors.green}No leaks detected${colors.reset}`} ${colors.gray}in ${result.durationMs}ms${colors.reset}`
      );
      if (showStats && result.hasLeaks) {
        console.error(`${colors.bold}Leak Breakdown:${colors.reset}`);
        for (const [patternId, count] of Object.entries(result.stats)) {
          console.error(`  ${colors.dim}\u2022${colors.reset} ${patternId.padEnd(25)} ${count} occurrence(s)`);
        }
      }
    }
  }
  if (result.hasLeaks && failOnLeak) {
    process.exit(1);
  }
}
main().catch((err) => {
  console.error("Unexpected error:", err);
  process.exit(1);
});
//# sourceMappingURL=index.cjs.map
//# sourceMappingURL=index.cjs.map