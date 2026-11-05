#!/usr/bin/env node
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { resolve, join } from 'path';

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
var anthropicApiKeyPattern, openaiApiKeyPattern, awsAccessKeyPattern, awsSecretKeyPattern, githubTokenPattern, stripeKeyPattern, jwtTokenPattern, privateKeyPattern, googleApiKeyPattern, slackTokenPattern, databaseUrlPattern, huggingFaceTokenPattern, gitlabTokenPattern, discordTokenPattern, npmTokenPattern, sendgridApiKeyPattern, twilioAccountSidPattern, supabaseKeyPattern, CREDENTIAL_PATTERNS;
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
      regex: /\b(?:sk|pk|rk)_(?:live|test)_[0-9a-zA-Z]{24,99}\b/g,
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
      regex: /\b(?:xoxb|xoxp|xoxr|xoxa)-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}\b|\bxapp-[0-9]{1,}-[a-zA-Z0-9]{10,32}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}\b/g,
      placeholder: "SLACK_TOKEN",
      description: "Slack Bot, User, or App token"
    };
    databaseUrlPattern = {
      id: "database-url",
      name: "Database Connection URL",
      category: "credential",
      severity: "critical",
      regex: /\b(?:postgres|postgresql|mysql|mariadb|mongodb|mongodb\+srv|redis|rediss):\/\/[^\s:]*:[^\s@]+@[^\s/:]+(?::\d+)?(?:\/[^\s?"']*)?(?:\?[^\s"']*)?\b/g,
      placeholder: "DATABASE_URL",
      description: "Database connection URL containing user and password credentials"
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
      huggingFaceTokenPattern,
      gitlabTokenPattern,
      discordTokenPattern,
      npmTokenPattern,
      sendgridApiKeyPattern,
      twilioAccountSidPattern,
      supabaseKeyPattern
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
var emailPattern, ipv4Pattern, ssnPattern, creditCardPattern, ipv6Pattern, phonePattern, PII_PATTERNS;
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
      regex: /\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b/g,
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
      regex: /\b(?:4[0-9]{3}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{1,4}|5[1-5][0-9]{2}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}|2[2-7][0-9]{2}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}|3[47][0-9]{2}[-\s]?[0-9]{6}[-\s]?[0-9]{5}|6(?:011|5[0-9]{2})[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4})\b/g,
      placeholder: "CREDIT_CARD",
      description: "Major credit card numbers (Visa, MasterCard, Amex, Discover)",
      validator: isValidLuhn
    };
    ipv6Pattern = {
      id: "ipv6-address",
      name: "IPv6 Address",
      category: "network",
      severity: "low",
      regex: /\b(?:(?:[0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|:(?::[0-9a-fA-F]{1,4}){1,7}|fe80::[0-9a-fA-F:]+|::1)\b/g,
      placeholder: "IPV6_ADDRESS",
      description: "Standard or compressed 128-bit IPv6 address"
    };
    phonePattern = {
      id: "phone-number",
      name: "Phone Number",
      category: "pii",
      severity: "medium",
      regex: /(?:(?<![\w$])\+\d{1,3}[-.\s]?(?:\(?\d{1,4}\)?[-.\s]?)?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9}\b|(?:\(\d{3}\)|\b\d{3})[-.\s]\d{3}[-.\s]\d{4}\b)/g,
      placeholder: "PHONE_NUMBER",
      description: "Telephone number in formatted local or international E.164 format"
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
  const minLength = config.minLength ?? 20;
  const maxLength = config.maxLength ?? 120;
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
  const min = config.minLength ?? 16;
  const max = config.maxLength ?? 120;
  return {
    id: "generic-high-entropy-secret",
    name: "Generic High-Entropy Secret",
    category: "credential",
    severity: "high",
    regex: new RegExp(
      `(?:api[_-]?key|secret|token|password|auth[_-]?key|access[_-]?key)[\\s=:'"]+([^\\s"';,\\n]{${min},${max}})`,
      "gi"
    ),
    placeholder: "GENERIC_SECRET",
    description: "High-entropy random token detected in sensitive assignment context"
  };
}
var init_entropy = __esm({
  "src/core/entropy.ts"() {
  }
});

// src/core/vault.ts
var Vault;
var init_vault = __esm({
  "src/core/vault.ts"() {
    Vault = class _Vault {
      placeholderToEntry = /* @__PURE__ */ new Map();
      originalToPlaceholder = /* @__PURE__ */ new Map();
      counters = /* @__PURE__ */ new Map();
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
       * in a deterministic, collision-free single regex pass.
       */
      unmask(text) {
        if (this.placeholderToEntry.size === 0 || !text) {
          return text;
        }
        const placeholders = Array.from(this.placeholderToEntry.keys()).sort(
          (a, b) => b.length - a.length
        );
        const escaped = placeholders.map((p) => p.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
        const regex = new RegExp(escaped.join("|"), "g");
        return text.replace(regex, (matched) => {
          const entry = this.placeholderToEntry.get(matched);
          return entry ? entry.original : matched;
        });
      }
      /**
       * Directly restores an entry into the vault without altering placeholder names.
       */
      restoreEntry(entry) {
        this.placeholderToEntry.set(entry.placeholder, entry);
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
        if (Array.isArray(list)) {
          vault.restoreEntries(list);
        }
        return vault;
      }
      /**
       * Returns list of all entries currently in the vault.
       */
      entries() {
        return Array.from(this.placeholderToEntry.values());
      }
      /**
       * Number of unique secrets stored.
       */
      get size() {
        return this.placeholderToEntry.size;
      }
      /**
       * Wipes all secrets from memory.
       */
      clear() {
        this.placeholderToEntry.clear();
        this.originalToPlaceholder.clear();
        this.counters.clear();
      }
    };
  }
});

// src/core/engine.ts
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
          activePatterns = activePatterns.filter((p) => includeSet.has(p.id));
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
            let secret;
            let startIndex;
            let endIndex;
            if (match[1] !== void 0 && match[1].length > 0) {
              secret = match[1];
              const indices = match.indices;
              if (indices && indices[1]) {
                startIndex = indices[1][0];
                endIndex = indices[1][1];
              } else {
                const offsetInMatch = match[0].indexOf(secret);
                startIndex = match.index + offsetInMatch;
                endIndex = startIndex + secret.length;
              }
            } else {
              secret = match[0];
              startIndex = match.index;
              endIndex = startIndex + secret.length;
            }
            if (allowlist.length > 0 && allowlist.some((al) => typeof al === "string" && al.length > 0 && secret === al)) {
              continue;
            }
            if (pattern.validator && !pattern.validator(secret)) {
              continue;
            }
            if (pattern.id === "generic-high-entropy-secret" && !isHighEntropyToken(secret, options?.entropy)) {
              continue;
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
          durationMs,
          vault
        };
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
function createMcpServer() {
  const sessionVault = new Vault();
  const server = new McpServer({
    name: "agent-redact",
    version: "0.1.0"
  });
  server.tool(
    "redact_text",
    "Scans and redacts sensitive credentials (Anthropic keys, OpenAI keys, AWS tokens, GitHub PATs, JWTs, Stripe keys, SSH keys, database URIs) and PII from a given prompt or text payload.",
    {
      text: z.string().describe("The raw text/prompt to scan and sanitize"),
      reversible: z.boolean().default(true).describe(
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
    "Restores masked session placeholders (e.g. [ANTHROPIC_API_KEY_1]) in agent response back to original secret values using the secure in-memory vault. If outputFilePath is specified, writes to disk directly to isolate credentials from chat context.",
    {
      text: z.string().describe("The text containing session placeholders to restore"),
      outputFilePath: z.string().optional().describe(
        "Optional path to file where restored content should be written without leaking plaintext secrets in context"
      )
    },
    async ({ text, outputFilePath }) => {
      const restored = unmask(text, sessionVault);
      if (outputFilePath) {
        writeFileSync(outputFilePath, restored, "utf-8");
        return {
          content: [
            {
              type: "text",
              text: `Successfully restored content to ${outputFilePath}. Plaintext secrets were not exposed in context.`
            }
          ]
        };
      }
      return {
        content: [
          {
            type: "text",
            text: restored
          }
        ]
      };
    }
  );
  server.tool(
    "scan_file",
    "Scans a local file (.env, config, logs) for credentials before importing into agent context window.",
    {
      filePath: z.string().describe("Relative or absolute file path to inspect"),
      reversible: z.boolean().default(false).describe("Whether to generate reversible placeholders (default: false for one-way safe scan)"),
      inPlace: z.boolean().default(false).describe("If true, sanitizes the file directly in-place on disk"),
      outputFilePath: z.string().optional().describe("Optional destination path to write sanitized content")
    },
    async ({ filePath, reversible, inPlace, outputFilePath }) => {
      if (!existsSync(filePath)) {
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
      try {
        const rawContent = readFileSync(filePath, "utf-8");
        const result = redact(rawContent, { reversible, vault: sessionVault });
        if (inPlace) {
          writeFileSync(filePath, result.text, "utf-8");
        } else if (outputFilePath) {
          writeFileSync(outputFilePath, result.text, "utf-8");
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
                  writtenTo: inPlace ? filePath : outputFilePath ?? null
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
          content: [{ type: "text", text: `Failed reading file ${filePath}: ${errorMsg}` }]
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
  const transport = new StdioServerTransport();
  await server.connect(transport);
}
var init_server = __esm({
  "src/mcp/server.ts"() {
    init_engine();
    init_vault();
    init_patterns();
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
  return {
    id: cfg.id,
    name: cfg.name,
    category: cfg.category ?? "custom",
    severity: cfg.severity ?? "high",
    regex: parseRegexString(cfg.regex),
    placeholder: cfg.placeholder,
    description: cfg.description ?? cfg.name
  };
}
function loadConfig(explicitPath, searchDir = process.cwd()) {
  let targetPath;
  if (explicitPath) {
    const resolved = resolve(searchDir, explicitPath);
    if (!existsSync(resolved)) {
      throw new Error(`Config file not found at: ${resolved}`);
    }
    targetPath = resolved;
  } else {
    for (const filename of DEFAULT_CONFIG_FILENAMES) {
      const candidate = join(searchDir, filename);
      if (existsSync(candidate)) {
        targetPath = candidate;
        break;
      }
    }
  }
  if (!targetPath) {
    return null;
  }
  try {
    const raw = readFileSync(targetPath, "utf-8");
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
${colors.bold}${colors.cyan}agent-redact${colors.reset} ${colors.gray}v0.1.2${colors.reset}
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
  return new Promise((resolve2) => {
    let data = "";
    process.stdin.setEncoding("utf-8");
    process.stdin.on("data", (chunk) => {
      data += chunk;
    });
    process.stdin.on("end", () => {
      resolve2(data);
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
    console.log("agent-redact v0.1.2");
    process.exit(0);
  }
  const isReversible = args.includes("-r") || args.includes("--reversible");
  const isJson = args.includes("-j") || args.includes("--json");
  const showStats = args.includes("--stats");
  const isInplace = args.includes("-i") || args.includes("--inplace");
  const detectEntropy = args.includes("--entropy");
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
  if (fileArgs.length > 1) {
    let totalLeaksAcrossFiles = 0;
    for (const file of fileArgs) {
      try {
        const fileContent = readFileSync(file, "utf-8");
        const res = redact(fileContent, {
          reversible: effectiveReversible,
          vault,
          include: loadedConfig?.include,
          exclude: loadedConfig?.exclude,
          allowlist: loadedConfig?.allowlist,
          customPatterns: loadedConfig?.customPatterns,
          detectHighEntropy: detectEntropy || (loadedConfig?.detectHighEntropy ?? false),
          entropy: loadedConfig?.entropy
        });
        if (isInplace) {
          writeFileSync(file, res.text, "utf-8");
        }
        if (res.hasLeaks) {
          totalLeaksAcrossFiles += res.totalLeaks;
          console.error(
            `${colors.yellow}\u2716 [LEAK]${colors.reset} ${file}: ${res.totalLeaks} secret(s) detected`
          );
        } else {
          console.error(`${colors.green}\u2714 [CLEAN]${colors.reset} ${file}`);
        }
      } catch {
        console.error(`${colors.red}Error:${colors.reset} Cannot read file: ${file}`);
        process.exit(1);
      }
    }
    if (vaultOutFile && vault) {
      writeFileSync(vaultOutFile, vault.toJSON(), "utf-8");
      console.error(`${colors.green}\u2714${colors.reset} Session vault saved to ${vaultOutFile}`);
    }
    if (totalLeaksAcrossFiles > 0) {
      console.error(
        `
${colors.red}[agent-redact] Audit failed: detected ${totalLeaksAcrossFiles} secret(s) across ${fileArgs.length} files.${colors.reset}`
      );
      process.exit(1);
    } else {
      console.error(
        `
${colors.green}[agent-redact] All ${fileArgs.length} files are clean.${colors.reset}`
      );
      process.exit(0);
    }
  }
  const fileArg = fileArgs[0];
  let content = "";
  if (fileArg) {
    try {
      content = readFileSync(fileArg, "utf-8");
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
      const rawVault = readFileSync(unmaskVaultFile, "utf-8");
      const vault2 = Vault.fromJSON(rawVault);
      const restoredText = unmask(content, vault2);
      if (outputFile) {
        writeFileSync(outputFile, restoredText, "utf-8");
        console.error(`${colors.green}\u2714${colors.reset} Restored output written to ${outputFile}`);
      } else if (isInplace && fileArg) {
        writeFileSync(fileArg, restoredText, "utf-8");
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
    writeFileSync(vaultOutFile, vault.toJSON(), "utf-8");
    console.error(`${colors.green}\u2714${colors.reset} Session vault saved to ${vaultOutFile}`);
  }
  if (isJson) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    if (outputFile) {
      writeFileSync(outputFile, result.text, "utf-8");
      console.error(`${colors.green}\u2714${colors.reset} Sanitized output written to ${outputFile}`);
    } else if (isInplace && fileArg) {
      writeFileSync(fileArg, result.text, "utf-8");
      console.error(`${colors.green}\u2714${colors.reset} Sanitized in-place: ${fileArg}`);
    } else {
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
  if (result.hasLeaks && !outputFile && !effectiveReversible && !isInplace) {
    process.exit(1);
  }
}
main().catch((err) => {
  console.error("Unexpected error:", err);
  process.exit(1);
});
//# sourceMappingURL=index.js.map
//# sourceMappingURL=index.js.map