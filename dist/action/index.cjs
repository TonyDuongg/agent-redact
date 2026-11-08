'use strict';

var fs = require('fs');
var path = require('path');
var crypto = require('crypto');

// src/action/index.ts
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
var DEFAULT_MAX_SCAN_BYTES = 5 * 1024 * 1024;
var KNOWN_BINARY_EXTENSIONS = /* @__PURE__ */ new Set([
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
function readTextForScan(path, maxBytes = DEFAULT_MAX_SCAN_BYTES) {
  try {
    const { size } = fs.statSync(path);
    if (size > maxBytes) return { ok: false, reason: "too-large", size };
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

// src/patterns/credentials.ts
var anthropicApiKeyPattern = {
  id: "anthropic-api-key",
  name: "Anthropic API Key",
  category: "credential",
  severity: "critical",
  regex: /\bsk-ant-(?:api03|admin01)-[A-Za-z0-9_\-]{80,120}(?![A-Za-z0-9_])|\bsk-ant-[A-Za-z0-9_\-]{20,}(?![A-Za-z0-9_])/g,
  placeholder: "ANTHROPIC_API_KEY",
  description: "Anthropic Claude API key or Admin key"
};
var openaiApiKeyPattern = {
  id: "openai-api-key",
  name: "OpenAI API Key",
  category: "credential",
  severity: "critical",
  regex: /\bsk-(?:proj|svcacct)-[A-Za-z0-9_\-]{40,}(?![A-Za-z0-9_])|\bsk-[a-zA-Z0-9]{20,}\b/g,
  placeholder: "OPENAI_API_KEY",
  description: "OpenAI API key (standard, project, or service account)"
};
var awsAccessKeyPattern = {
  id: "aws-access-key-id",
  name: "AWS Access Key ID",
  category: "credential",
  severity: "high",
  regex: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g,
  placeholder: "AWS_ACCESS_KEY_ID",
  description: "Amazon Web Services 20-character Access Key ID"
};
var awsSecretKeyPattern = {
  id: "aws-secret-access-key",
  name: "AWS Secret Access Key",
  category: "credential",
  severity: "critical",
  regex: /(?:aws_secret_access_key|aws_secret_key|secret_access_key)[\s=:'"]+([A-Za-z0-9\/+=]{40})(?:\s|$|['",;])/gi,
  secretGroup: 1,
  placeholder: "AWS_SECRET_ACCESS_KEY",
  description: "Amazon Web Services 40-character Secret Access Key"
};
var githubTokenPattern = {
  id: "github-token",
  name: "GitHub Token",
  category: "credential",
  severity: "critical",
  regex: /\b(?:ghp_[A-Za-z0-9]{36,40}|github_pat_[A-Za-z0-9_]{60,100}|gho_[A-Za-z0-9]{36,40}|ghu_[A-Za-z0-9]{36,40}|ghs_[A-Za-z0-9]{36,40}|ghr_[A-Za-z0-9]{36,40})\b/g,
  placeholder: "GITHUB_TOKEN",
  description: "GitHub Personal Access Token, OAuth token, or App token"
};
var stripeKeyPattern = {
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
var jwtTokenPattern = {
  id: "jwt-token",
  name: "JSON Web Token (JWT)",
  category: "credential",
  severity: "critical",
  regex: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-]{10,}(?![A-Za-z0-9_])/g,
  placeholder: "JWT_TOKEN",
  description: "JSON Web Token (JWT) in header.payload.signature format"
};
var privateKeyPattern = {
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
var googleApiKeyPattern = {
  id: "google-api-key",
  name: "Google API Key",
  category: "credential",
  severity: "high",
  regex: /\bAIza[0-9A-Za-z\-_]{35}(?![A-Za-z0-9_])/g,
  placeholder: "GOOGLE_API_KEY",
  description: "Google Cloud or Gemini AI Studio API key"
};
var slackTokenPattern = {
  id: "slack-token",
  name: "Slack Token",
  category: "credential",
  severity: "high",
  // Bot tokens have two numeric segments, user/refresh tokens have three
  regex: /\b(?:xoxb|xoxp|xoxr|xoxa|xoxe|xoxs)-[0-9]{10,13}(?:-[0-9]{10,13}){1,2}-[a-zA-Z0-9]{24,34}\b|\bxapp-[0-9]{1,}-[a-zA-Z0-9]{10,32}-[0-9]{10,13}-[a-zA-Z0-9]{24,64}\b/g,
  placeholder: "SLACK_TOKEN",
  description: "Slack Bot, User, or App token"
};
var databaseUrlPattern = {
  id: "database-url",
  name: "Database Connection URL",
  category: "credential",
  severity: "critical",
  regex: /\b(?:postgres|postgresql|mysql|mariadb|mongodb|mongodb\+srv|redis|rediss):\/\/[^\s:/@]*:[^\s/@]+@[^\s/:]+(?::\d+)?(?:\/[^\s?"']*)?(?:\?[^\s"']*)?\b/g,
  placeholder: "DATABASE_URL",
  description: "Database connection URL containing user and password credentials"
};
var basicAuthUrlPattern = {
  id: "basic-auth-url",
  name: "HTTP Basic Auth URL",
  category: "credential",
  severity: "critical",
  regex: /\bhttps?:\/\/[^\s:/@]+:[^\s/@]+@[^\s/:]+(?::\d+)?(?:\/[^\s?"']*)?(?:\?[^\s"']*)?\b/g,
  placeholder: "BASIC_AUTH_URL",
  description: "HTTP/HTTPS URL containing username and password credentials"
};
var huggingFaceTokenPattern = {
  id: "huggingface-token",
  name: "Hugging Face Token",
  category: "credential",
  severity: "high",
  regex: /\bhf_[a-zA-Z0-9]{34}\b/g,
  placeholder: "HUGGINGFACE_TOKEN",
  description: "Hugging Face User Access Token"
};
var gitlabTokenPattern = {
  id: "gitlab-token",
  name: "GitLab Token",
  category: "credential",
  severity: "high",
  regex: /\bglpat-[0-9a-zA-Z\-_]{20,}(?![A-Za-z0-9_])/g,
  placeholder: "GITLAB_TOKEN",
  description: "GitLab Personal Access Token"
};
var discordTokenPattern = {
  id: "discord-token",
  name: "Discord Bot Token",
  category: "credential",
  severity: "high",
  regex: /\b[MNO][a-zA-Z0-9_-]{23,25}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27,38}(?![A-Za-z0-9_])/g,
  placeholder: "DISCORD_TOKEN",
  description: "Discord Bot Authentication Token"
};
var npmTokenPattern = {
  id: "npm-token",
  name: "NPM Access Token",
  category: "credential",
  severity: "critical",
  regex: /\bnpm_[A-Za-z0-9]{36}\b/g,
  placeholder: "NPM_TOKEN",
  description: "Node Package Manager (npm) access token"
};
var sendgridApiKeyPattern = {
  id: "sendgrid-api-key",
  name: "SendGrid API Key",
  category: "credential",
  severity: "high",
  regex: /\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}(?![A-Za-z0-9_])/g,
  placeholder: "SENDGRID_API_KEY",
  description: "SendGrid Email API key"
};
var twilioAccountSidPattern = {
  id: "twilio-account-sid",
  name: "Twilio Account SID",
  category: "credential",
  severity: "high",
  regex: /\bAC[0-9a-fA-F]{32}\b/g,
  placeholder: "TWILIO_ACCOUNT_SID",
  description: "Twilio Account Identifier"
};
var supabaseKeyPattern = {
  id: "supabase-key",
  name: "Supabase Key",
  category: "credential",
  severity: "critical",
  regex: /\bsbp_[a-zA-Z0-9]{40}\b/g,
  placeholder: "SUPABASE_KEY",
  description: "Supabase Project or Management API key"
};
var telegramBotTokenPattern = {
  id: "telegram-bot-token",
  name: "Telegram Bot Token",
  category: "credential",
  severity: "critical",
  regex: /\b\d{8,10}:[A-Za-z0-9_-]{35}(?![A-Za-z0-9_])/g,
  placeholder: "TELEGRAM_BOT_TOKEN",
  description: "Telegram Bot API authentication token"
};
var twilioApiKeyPattern = {
  id: "twilio-api-key",
  name: "Twilio API Key",
  category: "credential",
  severity: "critical",
  regex: /\bSK[0-9a-fA-F]{32}\b/g,
  placeholder: "TWILIO_API_KEY",
  description: "Twilio API Key starting with SK prefix"
};
var azureStorageKeyPattern = {
  id: "azure-storage-key",
  name: "Azure Storage Key",
  category: "credential",
  severity: "critical",
  regex: /\bAccountKey=[A-Za-z0-9+/]{86}==|\bAccountKey=[A-Za-z0-9+/=]{88}\b/g,
  placeholder: "AZURE_STORAGE_KEY",
  description: "Azure Storage Account access key"
};
var gcpOauthSecretPattern = {
  id: "gcp-oauth-client-secret",
  name: "GCP OAuth Client Secret",
  category: "credential",
  severity: "critical",
  regex: /\bGOCSPX-[A-Za-z0-9_-]{28}(?![A-Za-z0-9_])/g,
  placeholder: "GCP_OAUTH_CLIENT_SECRET",
  description: "Google Cloud Platform OAuth 2.0 client secret"
};
var digitalOceanTokenPattern = {
  id: "digitalocean-token",
  name: "DigitalOcean Token",
  category: "credential",
  severity: "critical",
  regex: /\bdop_v1_[a-f0-9]{64}\b/g,
  placeholder: "DIGITALOCEAN_TOKEN",
  description: "DigitalOcean Personal Access Token"
};
var mailgunApiKeyPattern = {
  id: "mailgun-api-key",
  name: "Mailgun API Key",
  category: "credential",
  severity: "high",
  regex: /\bkey-[0-9a-zA-Z]{32}\b/g,
  placeholder: "MAILGUN_API_KEY",
  description: "Mailgun API authentication key"
};
var CREDENTIAL_PATTERNS = [
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

// src/patterns/pii.ts
var emailPattern = {
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
var ipv4Pattern = {
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
var ssnPattern = {
  id: "us-ssn",
  name: "US Social Security Number",
  category: "pii",
  severity: "critical",
  regex: /\b\d{3}-\d{2}-\d{4}\b/g,
  placeholder: "US_SSN",
  description: "US Social Security Number in AAA-GG-SSSS format"
};
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
var creditCardPattern = {
  id: "credit-card",
  name: "Credit Card Number",
  category: "pii",
  severity: "critical",
  regex: /\b(?:4[0-9]{3}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{1,4}|5[1-5][0-9]{2}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}|2[2-7][0-9]{2}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}|3[47][0-9]{2}[- ]?[0-9]{6}[- ]?[0-9]{5}|6(?:011|5[0-9]{2})[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4})\b/g,
  placeholder: "CREDIT_CARD",
  description: "Major credit card numbers (Visa, MasterCard, Amex, Discover)",
  validator: isValidLuhn
};
var ipv6Pattern = {
  id: "ipv6-address",
  name: "IPv6 Address",
  category: "network",
  severity: "low",
  regex: /(?<![a-zA-Z0-9_:])(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|:(?::[0-9a-fA-F]{1,4}){1,7}|(?:[0-9a-fA-F]{1,4}:){1,6}:(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}|::[1])(?![a-zA-Z0-9_:])/gi,
  placeholder: "IPV6_ADDRESS",
  description: "Standard or compressed 128-bit IPv6 address",
  validator: isLikelyIpv6
};
var IPV6_LOOPBACK = ["", "", "1"].join(":");
function isLikelyIpv6(candidate) {
  if (candidate === IPV6_LOOPBACK) return true;
  const groups = candidate.split(":").filter((g) => g.length > 0);
  if (groups.length < 2) return false;
  if (!/[0-9]/.test(candidate)) return false;
  if (groups.length === 2 && candidate.includes("::") && groups[0].length < 3) return false;
  return true;
}
var phonePattern = {
  id: "phone-number",
  name: "Phone Number",
  category: "pii",
  severity: "medium",
  regex: /(?:(?<![\w$])\+(?:[0-9]{1,4}[-.\s](?:\([0-9]{1,4}\)[-.\s]?)?[0-9]{1,4}[-.\s]?[0-9]{1,4}[-.\s]?[0-9]{1,9}|[0-9]{7,15})\b|(?:\([0-9]{3}\)|\b[0-9]{3})[-.\s][0-9]{3}[-.\s][0-9]{4}\b|(?<![\w$])\b0[35789](?:[0-9]{8}|[0-9]{2}[-.\s][0-9]{3}[-.\s][0-9]{3}|[0-9][-.\s][0-9]{3}[-.\s][0-9]{4})\b|(?<![\w$])\b02(?:[48][-.\s]?[0-9]{4}[-.\s]?[0-9]{4}|[0-35-79][0-9][-.\s]?[0-9]{3}[-.\s]?[0-9]{3,4})\b)/g,
  placeholder: "PHONE_NUMBER",
  description: "Telephone number in formatted local, international E.164, or domestic VN format"
};
var PII_PATTERNS = [
  emailPattern,
  ipv4Pattern,
  ipv6Pattern,
  phonePattern,
  ssnPattern,
  creditCardPattern
];

// src/patterns/index.ts
var DEFAULT_PATTERNS = [
  ...CREDENTIAL_PATTERNS,
  ...PII_PATTERNS
];
new Map([
  ...DEFAULT_PATTERNS.map((p) => [p.id, p]),
  ["database-uri", databaseUrlPattern]
  // Alias for backwards compatibility
]);

// src/core/entropy.ts
var DEFAULT_ENTROPY_MIN_LENGTH = 20;
var DEFAULT_ENTROPY_MAX_LENGTH = 120;
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

// src/core/vault.ts
function collectPlaceholderLiterals(text) {
  const found = /* @__PURE__ */ new Set();
  for (const m of text.matchAll(/\[[^[\]\r\n]{1,256}_\d+\]/g)) {
    found.add(m[0]);
  }
  return found;
}
var Vault = class _Vault {
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

// src/core/engine.ts
var SEVERITY_WEIGHT = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1
};
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
var RedactEngine = class {
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
var defaultEngine = new RedactEngine();
function redact(text, options) {
  return defaultEngine.redact(text, options);
}

// src/core/scan.ts
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

// src/version.ts
var VERSION = "0.1.5";

// src/action/index.ts
function getInput(name, fallback = "") {
  const keyWithUnderscore = `INPUT_${name.replace(/-/g, "_").toUpperCase()}`;
  const keyWithHyphen = `INPUT_${name.toUpperCase()}`;
  const val = process.env[keyWithHyphen] ?? process.env[keyWithUnderscore];
  return val !== void 0 && val.trim().length > 0 ? val.trim() : fallback;
}
function setOutput(name, value) {
  const outputFile = process.env.GITHUB_OUTPUT;
  if (outputFile && fs.existsSync(outputFile)) {
    fs.appendFileSync(outputFile, `${name}=${value}
`, "utf-8");
  }
}
function writeSummary(markdown) {
  const summaryFile = process.env.GITHUB_STEP_SUMMARY;
  if (summaryFile && fs.existsSync(summaryFile)) {
    fs.appendFileSync(summaryFile, markdown + "\n\n", "utf-8");
  }
}
function escapeCommandData(value) {
  return value.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
}
function escapeCommandProperty(value) {
  return escapeCommandData(value).replace(/:/g, "%3A").replace(/,/g, "%2C");
}
async function runAction() {
  const scanPath = getInput("scan-path", ".");
  const failOnLeak = getInput("fail-on-leak", "true").toLowerCase() === "true";
  const detectEntropy = getInput("detect-entropy", "false").toLowerCase() === "true";
  const configPath = getInput("config-path") || void 0;
  const excludeInput = getInput(
    "exclude",
    "node_modules,dist,build,.git,coverage,.turbo"
  );
  const excludeDirs = new Set(
    excludeInput.split(",").map((s) => s.trim()).filter(Boolean)
  );
  const maxFileSizeMb = Number(getInput("max-file-size", "5"));
  const maxBytes = Number.isFinite(maxFileSizeMb) && maxFileSizeMb > 0 ? Math.floor(maxFileSizeMb * 1024 * 1024) : DEFAULT_MAX_SCAN_BYTES;
  console.log(`[agent-redact] Starting security scan on: ${scanPath}`);
  console.log(`[agent-redact] Fail on leak: ${failOnLeak} | Entropy detection: ${detectEntropy}`);
  const loadedConfig = loadConfig(configPath);
  const baselinePath = getInput("baseline") || void 0;
  const baseline = baselinePath ? loadBaseline(baselinePath) : void 0;
  const sarifPath = getInput("sarif-file") || void 0;
  const filesToScan = [];
  const stat = fs.statSync(scanPath);
  if (stat.isFile()) {
    filesToScan.push(scanPath);
  } else {
    walkFiles(scanPath, excludeDirs, filesToScan);
  }
  console.log(`[agent-redact] Discovered ${filesToScan.length} text files to analyze.`);
  const allLeaks = [];
  const suppressed = { inline: 0, baseline: 0 };
  const skipped = {
    binary: 0,
    "too-large": 0,
    unreadable: 0
  };
  const startTime = performance.now();
  for (const filePath of filesToScan) {
    const read = readTextForScan(filePath, maxBytes);
    if (!read.ok) {
      skipped[read.reason]++;
      continue;
    }
    const relPath = path.relative(process.cwd(), filePath).replace(/\\/g, "/");
    const result = scanContent(read.content, relPath, {
      include: loadedConfig?.include,
      exclude: loadedConfig?.exclude,
      allowlist: loadedConfig?.allowlist,
      customPatterns: loadedConfig?.customPatterns,
      detectHighEntropy: detectEntropy || (loadedConfig?.detectHighEntropy ?? false),
      entropy: loadedConfig?.entropy,
      respectInlineIgnore: true,
      baseline
    });
    suppressed.inline += result.suppressed.inline;
    suppressed.baseline += result.suppressed.baseline;
    for (const finding of result.findings) {
      allLeaks.push(finding);
      const annotationPath = escapeCommandProperty(finding.file);
      const message = escapeCommandData(
        `[agent-redact] Leaked ${finding.patternName} (${finding.severity.toUpperCase()}) detected!`
      );
      console.log(`::error file=${annotationPath},line=${finding.line},col=${finding.column}::${message}`);
    }
  }
  if (sarifPath) {
    fs.writeFileSync(sarifPath, JSON.stringify(toSarif(allLeaks, VERSION), null, 2) + "\n", "utf-8");
    console.log(`[agent-redact] SARIF report written to ${sarifPath}`);
  }
  if (suppressed.inline + suppressed.baseline > 0) {
    console.log(
      `[agent-redact] Suppressed ${suppressed.inline} finding(s) by inline comment and ${suppressed.baseline} by baseline.`
    );
  }
  const durationMs = Math.round((performance.now() - startTime) * 100) / 100;
  const totalLeaks = allLeaks.length;
  const hasLeaks = totalLeaks > 0;
  const skippedTotal = skipped.binary + skipped["too-large"] + skipped.unreadable;
  const skippedSummary = `Skipped ${skippedTotal} file(s): ${skipped.binary} binary, ${skipped["too-large"]} larger than ${(maxBytes / (1024 * 1024)).toFixed(2)} MB, ${skipped.unreadable} unreadable.`;
  if (skippedTotal > 0) {
    console.log(`[agent-redact] ${skippedSummary}`);
  }
  setOutput("has-leaks", String(hasLeaks));
  setOutput("total-leaks", String(totalLeaks));
  let summaryMd = `## \u{1F6E1}\uFE0F agent-redact Security Scan Report

`;
  summaryMd += `* **Status**: ${hasLeaks ? "\u274C **Secrets Detected**" : "\u2705 **No Leaks Found**"}
`;
  summaryMd += `* **Files Scanned**: ${filesToScan.length - skippedTotal}
`;
  if (skippedTotal > 0) {
    summaryMd += `* **Files Skipped**: ${skippedSummary}
`;
  }
  summaryMd += `* **Total Leaks Detected**: ${totalLeaks}
`;
  summaryMd += `* **Scan Duration**: ${durationMs}ms

`;
  if (hasLeaks) {
    summaryMd += `### \u{1F6A8} Detected Secret Leaks

`;
    summaryMd += `| File | Line | Secret Type | Severity | Category |
`;
    summaryMd += `| :--- | :---: | :--- | :---: | :---: |
`;
    for (const leak of allLeaks) {
      summaryMd += `| \`${leak.file}\` | ${leak.line} | **${leak.patternName}** | \`${leak.severity.toUpperCase()}\` | ${leak.category} |
`;
    }
  } else {
    summaryMd += `\u{1F389} All scanned files are clean and safe from credentials & PII leaks!
`;
  }
  writeSummary(summaryMd);
  console.log(`
[agent-redact] Scan complete in ${durationMs}ms. Found ${totalLeaks} leak(s).`);
  if (hasLeaks && failOnLeak) {
    console.error(`
\u274C [agent-redact] Build failed due to detected sensitive credentials in repository.`);
    process.exit(1);
  }
}
var isEntryPoint = process.argv[1] && (process.argv[1].endsWith("action/index.js") || process.argv[1].endsWith("action\\index.js") || process.env.RUN_AGENT_REDACT_ACTION === "true");
if (isEntryPoint) {
  runAction().catch((err) => {
    console.error("Fatal error in agent-redact action:", err);
    process.exit(1);
  });
}

exports.runAction = runAction;
//# sourceMappingURL=index.cjs.map
//# sourceMappingURL=index.cjs.map