#!/usr/bin/env node
'use strict';

var mcp_js = require('@modelcontextprotocol/sdk/server/mcp.js');
var stdio_js = require('@modelcontextprotocol/sdk/server/stdio.js');
var zod = require('zod');
var fs = require('fs');
var path = require('path');
var os = require('os');

var __defProp = Object.defineProperty;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// src/patterns/credentials.ts
var anthropicApiKeyPattern, openaiApiKeyPattern, awsAccessKeyPattern, awsSecretKeyPattern, githubTokenPattern, stripeKeyPattern, jwtTokenPattern, privateKeyPattern, googleApiKeyPattern, slackTokenPattern, databaseUrlPattern, basicAuthUrlPattern, huggingFaceTokenPattern, gitlabTokenPattern, discordTokenPattern, npmTokenPattern, sendgridApiKeyPattern, twilioAccountSidPattern, supabaseKeyPattern, telegramBotTokenPattern, twilioApiKeyPattern, azureStorageKeyPattern, gcpOauthSecretPattern, digitalOceanTokenPattern, mailgunApiKeyPattern, CREDENTIAL_PATTERNS;
var init_credentials = __esm({
  "src/patterns/credentials.ts"() {
    anthropicApiKeyPattern = {
      id: "anthropic-api-key",
      name: "Anthropic API Key",
      category: "credential",
      severity: "critical",
      regex: /\bsk-ant-(?:api03|admin01)-[A-Za-z0-9_\-]{80,120}\b|\bsk-ant-[A-Za-z0-9_\-]{20,}\b/g,
      placeholder: "ANTHROPIC_API_KEY",
      description: "Anthropic Claude API key or Admin key"
    };
    openaiApiKeyPattern = {
      id: "openai-api-key",
      name: "OpenAI API Key",
      category: "credential",
      severity: "critical",
      regex: /\bsk-(?:proj|svcacct)-[A-Za-z0-9_\-]{40,}\b|\bsk-[a-zA-Z0-9]{20,}\b/g,
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
      regex: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-]{10,}\b/g,
      placeholder: "JWT_TOKEN",
      description: "JSON Web Token (JWT) in header.payload.signature format"
    };
    privateKeyPattern = {
      id: "private-key",
      name: "Private Key",
      category: "credential",
      severity: "critical",
      regex: /-----BEGIN (?:(?:RSA |OPENSSH |DSA |EC |ENCRYPTED )?PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----[\s\S]*?-----END (?:(?:RSA |OPENSSH |DSA |EC |ENCRYPTED )?PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----/g,
      placeholder: "PRIVATE_KEY",
      description: "RSA, OpenSSH, DSA, EC, Encrypted, or PGP private key certificate"
    };
    googleApiKeyPattern = {
      id: "google-api-key",
      name: "Google API Key",
      category: "credential",
      severity: "high",
      regex: /\bAIza[0-9A-Za-z\-_]{35}\b/g,
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
      regex: /\bglpat-[0-9a-zA-Z\-_]{20,}\b/g,
      placeholder: "GITLAB_TOKEN",
      description: "GitLab Personal Access Token"
    };
    discordTokenPattern = {
      id: "discord-token",
      name: "Discord Bot Token",
      category: "credential",
      severity: "high",
      regex: /\b[MNO][a-zA-Z0-9_-]{23,25}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27,38}\b/g,
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
      regex: /\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b/g,
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
      regex: /\b\d{8,10}:[A-Za-z0-9_-]{35}\b/g,
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
      regex: /\bGOCSPX-[A-Za-z0-9_-]{28}\b/g,
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
      mailgunApiKeyPattern
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
      regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
      placeholder: "EMAIL_ADDRESS",
      description: "Standard RFC 5322 email address"
    };
    ipv4Pattern = {
      id: "ipv4-address",
      name: "IPv4 Address",
      category: "network",
      severity: "low",
      regex: /(?<![vV])\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b/g,
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

// src/patterns/index.ts
var DEFAULT_PATTERNS;
var init_patterns = __esm({
  "src/patterns/index.ts"() {
    init_credentials();
    init_pii();
    init_credentials();
    init_pii();
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
function calculateShannonEntropy(str) {
  if (!str || str.length === 0) {
    return 0;
  }
  const frequencies = /* @__PURE__ */ new Map();
  for (let i = 0; i < str.length; i++) {
    const char = str[i];
    frequencies.set(char, (frequencies.get(char) ?? 0) + 1);
  }
  let entropy = 0;
  const len = str.length;
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
var Vault;
var init_vault = __esm({
  "src/core/vault.ts"() {
    Vault = class _Vault {
      placeholderToEntry = /* @__PURE__ */ new Map();
      placeholderToEntries = /* @__PURE__ */ new Map();
      originalToPlaceholder = /* @__PURE__ */ new Map();
      counters = /* @__PURE__ */ new Map();
      maxEntries;
      constructor(options) {
        this.maxEntries = options?.maxEntries;
      }
      evictOldestIfNeeded() {
        if (this.maxEntries && this.originalToPlaceholder.size >= this.maxEntries) {
          const oldestPlaceholder = this.placeholderToEntry.keys().next().value;
          if (oldestPlaceholder) {
            const oldEntry = this.placeholderToEntry.get(oldestPlaceholder);
            if (oldEntry) {
              this.originalToPlaceholder.delete(oldEntry.original);
            }
            this.placeholderToEntry.delete(oldestPlaceholder);
            this.placeholderToEntries.delete(oldestPlaceholder);
          }
        }
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
          while (existingText.includes(`[${pattern.placeholder}_${count}]`)) {
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
       */
      unmask(text) {
        if (this.placeholderToEntries.size === 0 || !text) {
          return text;
        }
        const placeholders = Array.from(this.placeholderToEntries.keys()).sort(
          (a, b) => b.length - a.length
        );
        const escaped = placeholders.map((p) => p.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
        const regex = new RegExp(escaped.join("|"), "g");
        const occurrences = /* @__PURE__ */ new Map();
        return text.replace(regex, (matched) => {
          const list = this.placeholderToEntries.get(matched);
          if (!list || list.length === 0) {
            return matched;
          }
          if (list.length === 1) {
            return list[0].original;
          }
          const idx = occurrences.get(matched) ?? 0;
          occurrences.set(matched, idx + 1);
          const entry = list[idx % list.length];
          return entry.original;
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
        let activePatterns = options?.customPatterns ? [...this.patterns, ...options.customPatterns] : [...this.patterns];
        if (options?.detectHighEntropy) {
          activePatterns.push(createHighEntropyPattern(options.entropy));
        }
        if (options?.include && options.include.length > 0) {
          const includeSet = new Set(options.include);
          const customIds = new Set((options.customPatterns ?? []).map((p) => p.id));
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
        for (const candidate of rawMatches) {
          const hasOverlap = accepted.some(
            (acc) => candidate.startIndex < acc.endIndex && acc.startIndex < candidate.endIndex
          );
          if (!hasOverlap) {
            accepted.push(candidate);
          }
        }
        accepted.sort((a, b) => a.startIndex - b.startIndex);
        const matches = [];
        const stats = {};
        let redactedText = "";
        let cursor = 0;
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
            replacement = vault.getOrCreate(m.secret, m.pattern, text);
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

// src/mcp/server.ts
var server_exports = {};
__export(server_exports, {
  createMcpServer: () => createMcpServer,
  runMcpServer: () => runMcpServer
});
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
  const sessionVault = new Vault({ maxEntries: 1e4 });
  const allowedRoots = (options.allowedRoots ?? defaultAllowedRoots()).map(realpathOrNearest);
  const server = new mcp_js.McpServer({
    name: "agent-redact",
    version: "0.1.4"
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
        return {
          content: [
            {
              type: "text",
              text: `Successfully restored content to ${outputFilePath}. Plaintext secrets were safely written to disk and remain isolated from model context.`
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
      const MAX_SCAN_BYTES = 5 * 1024 * 1024;
      const fileStat = fs.statSync(resolvedFile);
      if (fileStat.size > MAX_SCAN_BYTES) {
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
        const checkBytes = Math.min(8192, fileStat.size);
        const buf = Buffer.alloc(checkBytes);
        const fd = fs.openSync(resolvedFile, "r");
        try {
          fs.readSync(fd, buf, 0, checkBytes, 0);
        } finally {
          fs.closeSync(fd);
        }
        if (buf.includes(0)) {
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
async function runMcpServer() {
  const server = createMcpServer();
  const transport = new stdio_js.StdioServerTransport();
  await server.connect(transport);
}
var SAFE_WRITE_FLAGS;
var init_server = __esm({
  "src/mcp/server.ts"() {
    init_engine();
    init_vault();
    init_patterns();
    SAFE_WRITE_FLAGS = fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_TRUNC | (fs.constants.O_NOFOLLOW ?? 0);
  }
});

// src/cli/index.ts
init_engine();
init_vault();
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
function writeSecureFile(filePath, content) {
  fs.writeFileSync(filePath, content, { encoding: "utf-8", mode: 384 });
  try {
    fs.chmodSync(filePath, 384);
  } catch {
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
${colors.bold}${colors.cyan}agent-redact${colors.reset} ${colors.gray}v0.1.4${colors.reset}
${colors.dim}Universal zero-latency, zero-leak secret & PII redactor for ALL AI Agents${colors.reset}

${colors.bold}USAGE:${colors.reset}
  npx agent-redact <file> [options]         Redact secrets in a file
  cat log.txt | npx agent-redact [options]  Redact secrets from standard input (stdin)
  npx agent-redact mcp                      Start Model Context Protocol (MCP) server

${colors.bold}OPTIONS:${colors.reset}
  -r, --reversible            Generate numbered session placeholders ([ANTHROPIC_API_KEY_1])
  -o, --output <file>         Write sanitized content to target file instead of stdout
  -i, --inplace               Modify input file in-place
  -j, --json                  Output result and leak metadata as JSON
  --config <path>             Path to configuration file (.agentredactrc or json)
  --entropy                   Enable Shannon entropy detection for generic secrets
  --check, --fail-on-leak     Exit with code 1 if any secrets are detected (CI/pre-commit)
  --vault-out <file>          Save generated session vault mappings to JSON file
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
  return new Promise((resolve3) => {
    let data = "";
    process.stdin.setEncoding("utf-8");
    process.stdin.on("data", (chunk) => {
      data += chunk;
    });
    process.stdin.on("end", () => {
      resolve3(data);
    });
  });
}
async function main() {
  const args = process.argv.slice(2);
  if (args[0] === "mcp") {
    const { runMcpServer: runMcpServer2 } = await Promise.resolve().then(() => (init_server(), server_exports));
    await runMcpServer2();
    return;
  }
  if (args.includes("-h") || args.includes("--help")) {
    printHelp();
    process.exit(0);
  }
  if (args.includes("-v") || args.includes("--version")) {
    console.log("agent-redact v0.1.4");
    process.exit(0);
  }
  const VALUE_FLAGS = /* @__PURE__ */ new Set(["-o", "--output", "--vault-out", "--unmask", "--config"]);
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
    "-h",
    "--help",
    "-v",
    "--version"
  ]);
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg.startsWith("-")) {
      if (VALUE_FLAGS.has(arg)) {
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
  const skipIndices = /* @__PURE__ */ new Set();
  if (outputIdx !== -1) skipIndices.add(outputIdx + 1);
  if (vaultOutIdx !== -1) skipIndices.add(vaultOutIdx + 1);
  if (unmaskIdx !== -1) skipIndices.add(unmaskIdx + 1);
  if (configIdx !== -1) skipIndices.add(configIdx + 1);
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
  const vault = effectiveReversible ? new Vault() : void 0;
  if (effectiveReversible && isInplace && !vaultOutFile && !unmaskVaultFile) {
    console.error(
      `${colors.red}Error:${colors.reset} reversible in-place masking requires --vault-out <file>; otherwise the original values cannot be restored.`
    );
    process.exit(2);
  }
  if (fileArgs.length > 1) {
    if (unmaskVaultFile || outputFile || isJson) {
      console.error(
        `${colors.red}Error:${colors.reset} Flags -o/--output, --unmask, and -j/--json cannot be used with multiple input files.`
      );
      process.exit(2);
    }
    let totalLeaksAcrossFiles = 0;
    const inputs = [];
    for (const file of fileArgs) {
      try {
        inputs.push({ file, content: fs.readFileSync(file, "utf-8") });
      } catch {
        console.error(`${colors.red}Error:${colors.reset} Cannot read file: ${file}`);
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
        entropy: loadedConfig?.entropy
      })
    }));
    if (vaultOutFile && vault) {
      writeSecureFile(vaultOutFile, vault.toJSON());
      console.error(`${colors.green}\u2714${colors.reset} Session vault saved to ${vaultOutFile}`);
    }
    for (const { file, res } of results) {
      if (isInplace && res.hasLeaks) {
        fs.writeFileSync(file, res.text, "utf-8");
      }
      if (res.hasLeaks) {
        totalLeaksAcrossFiles += res.totalLeaks;
        console.error(
          `${colors.yellow}\u2716 [LEAK]${colors.reset} ${file}: ${res.totalLeaks} secret(s) detected`
        );
      } else {
        console.error(`${colors.green}\u2714 [CLEAN]${colors.reset} ${file}`);
      }
    }
    if (totalLeaksAcrossFiles > 0 && (failOnLeak || !isInplace)) {
      console.error(
        `
${colors.red}[agent-redact] Audit failed: detected ${totalLeaksAcrossFiles} secret(s) across ${fileArgs.length} files.${colors.reset}`
      );
      process.exit(1);
    } else {
      console.error(
        `
${colors.green}[agent-redact] All ${fileArgs.length} files ${isInplace ? "sanitized" : "are clean"}.${colors.reset}`
      );
      process.exit(0);
    }
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
    try {
      const rawVault = fs.readFileSync(unmaskVaultFile, "utf-8");
      const vault2 = Vault.fromJSON(rawVault);
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
    entropy: loadedConfig?.entropy
  });
  if (vaultOutFile && vault) {
    writeSecureFile(vaultOutFile, vault.toJSON());
    console.error(`${colors.green}\u2714${colors.reset} Session vault saved to ${vaultOutFile}`);
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