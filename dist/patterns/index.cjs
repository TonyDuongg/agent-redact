'use strict';

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
var databaseUriPattern = databaseUrlPattern;
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
var openrouterApiKeyPattern = {
  id: "openrouter-api-key",
  name: "OpenRouter API Key",
  category: "credential",
  severity: "critical",
  regex: /\bsk-or-v1-[a-f0-9]{40,}(?![A-Za-z0-9_])/g,
  placeholder: "OPENROUTER_API_KEY",
  description: "OpenRouter API key (sk-or-v1-...)"
};
var groqApiKeyPattern = {
  id: "groq-api-key",
  name: "Groq API Key",
  category: "credential",
  severity: "critical",
  regex: /\bgsk_[A-Za-z0-9]{40,}(?![A-Za-z0-9_])/g,
  placeholder: "GROQ_API_KEY",
  description: "Groq API key (gsk_...)"
};
var xaiApiKeyPattern = {
  id: "xai-api-key",
  name: "xAI API Key",
  category: "credential",
  severity: "critical",
  regex: /\bxai-[A-Za-z0-9_]{60,}(?![A-Za-z0-9_])/g,
  placeholder: "XAI_API_KEY",
  description: "xAI (Grok) API key (xai-...)"
};
var perplexityApiKeyPattern = {
  id: "perplexity-api-key",
  name: "Perplexity API Key",
  category: "credential",
  severity: "critical",
  regex: /\bpplx-[A-Za-z0-9]{32,}(?![A-Za-z0-9_])/g,
  placeholder: "PERPLEXITY_API_KEY",
  description: "Perplexity API key (pplx-...)"
};
var replicateApiTokenPattern = {
  id: "replicate-api-token",
  name: "Replicate API Token",
  category: "credential",
  severity: "critical",
  regex: /\br8_[A-Za-z0-9_-]{30,}(?![A-Za-z0-9_-])/g,
  placeholder: "REPLICATE_API_TOKEN",
  description: "Replicate API token (r8_...)"
};
var huggingFaceOrgTokenPattern = {
  id: "huggingface-org-token",
  name: "Hugging Face Organization Token",
  category: "credential",
  severity: "high",
  regex: /\bapi_org_[A-Za-z0-9]{30,}(?![A-Za-z0-9_])/g,
  placeholder: "HUGGINGFACE_ORG_TOKEN",
  description: "Hugging Face organization API token (api_org_...)"
};
var langsmithApiKeyPattern = {
  id: "langsmith-api-key",
  name: "LangSmith API Key",
  category: "credential",
  severity: "high",
  regex: /\blsv2_(?:pt|sk)_[a-f0-9]{32}_[a-f0-9]{10}(?![A-Za-z0-9_])/g,
  placeholder: "LANGSMITH_API_KEY",
  description: "LangSmith / LangChain personal or service key (lsv2_pt_ / lsv2_sk_)"
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
  mailgunApiKeyPattern,
  openrouterApiKeyPattern,
  groqApiKeyPattern,
  xaiApiKeyPattern,
  perplexityApiKeyPattern,
  replicateApiTokenPattern,
  huggingFaceOrgTokenPattern,
  langsmithApiKeyPattern
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

// src/patterns/vn.ts
function hasValidProvinceCode(id) {
  const province = Number(id.slice(0, 3));
  return province >= 1 && province <= 96;
}
var vnCitizenIdPattern = {
  id: "vn-citizen-id",
  name: "Vietnamese Citizen ID (CCCD)",
  category: "pii",
  severity: "high",
  regex: /(?<![\w$])0\d{11}(?!\d)/g,
  placeholder: "VN_CITIZEN_ID",
  description: "12-digit Vietnamese citizen identity card number (CCCD) with a valid province code",
  validator: hasValidProvinceCode
};
var vnIdNumberPattern = {
  id: "vn-id-number",
  name: "Vietnamese ID Number (CMND/CCCD, with context)",
  category: "pii",
  severity: "high",
  regex: /(?:CMND|CCCD|CMT|căn cước|can cuoc|chứng minh|chung minh)(?:\s+(?:số|so|no\.?))?[\s:#.=-]*(\d{9}|\d{12})(?!\d)/giu,
  secretGroup: 1,
  placeholder: "VN_ID_NUMBER",
  description: "9-digit CMND or 12-digit CCCD number preceded by an ID keyword"
};
var vnTaxCodePattern = {
  id: "vn-tax-code",
  name: "Vietnamese Tax Code (MST)",
  category: "pii",
  severity: "medium",
  regex: /(?:MST|mã số thuế|ma so thue|tax\s*code)[\s:#.=-]*(\d{10}(?:-\d{3})?)(?!\d)/giu,
  secretGroup: 1,
  placeholder: "VN_TAX_CODE",
  description: "10- or 13-digit Vietnamese tax code preceded by MST / m\xE3 s\u1ED1 thu\u1EBF"
};
var vnBankAccountPattern = {
  id: "vn-bank-account",
  name: "Vietnamese Bank Account Number",
  category: "pii",
  severity: "high",
  regex: /(?:STK|số tài khoản|so tai khoan|tài khoản số|tai khoan so|account\s*(?:no\.?|number))[\s:#.=-]*(\d{6,20})(?!\d)/giu,
  secretGroup: 1,
  placeholder: "VN_BANK_ACCOUNT",
  description: "Bank account number preceded by STK / s\u1ED1 t\xE0i kho\u1EA3n / account number"
};
var VN_PII_PATTERNS = [
  vnCitizenIdPattern,
  vnIdNumberPattern,
  vnTaxCodePattern,
  vnBankAccountPattern
];

// src/patterns/presets.ts
var PATTERN_PRESETS = {
  "vn-pii": VN_PII_PATTERNS
};
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

// src/patterns/index.ts
var DEFAULT_PATTERNS = [
  ...CREDENTIAL_PATTERNS,
  ...PII_PATTERNS
];
var PATTERN_MAP = new Map([
  ...DEFAULT_PATTERNS.map((p) => [p.id, p]),
  ["database-uri", databaseUrlPattern]
  // Alias for backwards compatibility
]);

exports.CREDENTIAL_PATTERNS = CREDENTIAL_PATTERNS;
exports.DEFAULT_PATTERNS = DEFAULT_PATTERNS;
exports.PATTERN_MAP = PATTERN_MAP;
exports.PATTERN_PRESETS = PATTERN_PRESETS;
exports.PII_PATTERNS = PII_PATTERNS;
exports.VN_PII_PATTERNS = VN_PII_PATTERNS;
exports.anthropicApiKeyPattern = anthropicApiKeyPattern;
exports.awsAccessKeyPattern = awsAccessKeyPattern;
exports.awsSecretKeyPattern = awsSecretKeyPattern;
exports.azureStorageKeyPattern = azureStorageKeyPattern;
exports.basicAuthUrlPattern = basicAuthUrlPattern;
exports.creditCardPattern = creditCardPattern;
exports.databaseUriPattern = databaseUriPattern;
exports.databaseUrlPattern = databaseUrlPattern;
exports.digitalOceanTokenPattern = digitalOceanTokenPattern;
exports.discordTokenPattern = discordTokenPattern;
exports.emailPattern = emailPattern;
exports.gcpOauthSecretPattern = gcpOauthSecretPattern;
exports.githubTokenPattern = githubTokenPattern;
exports.gitlabTokenPattern = gitlabTokenPattern;
exports.googleApiKeyPattern = googleApiKeyPattern;
exports.groqApiKeyPattern = groqApiKeyPattern;
exports.huggingFaceOrgTokenPattern = huggingFaceOrgTokenPattern;
exports.huggingFaceTokenPattern = huggingFaceTokenPattern;
exports.ipv4Pattern = ipv4Pattern;
exports.ipv6Pattern = ipv6Pattern;
exports.jwtTokenPattern = jwtTokenPattern;
exports.langsmithApiKeyPattern = langsmithApiKeyPattern;
exports.mailgunApiKeyPattern = mailgunApiKeyPattern;
exports.npmTokenPattern = npmTokenPattern;
exports.openaiApiKeyPattern = openaiApiKeyPattern;
exports.openrouterApiKeyPattern = openrouterApiKeyPattern;
exports.perplexityApiKeyPattern = perplexityApiKeyPattern;
exports.phonePattern = phonePattern;
exports.privateKeyPattern = privateKeyPattern;
exports.replicateApiTokenPattern = replicateApiTokenPattern;
exports.resolvePresets = resolvePresets;
exports.sendgridApiKeyPattern = sendgridApiKeyPattern;
exports.slackTokenPattern = slackTokenPattern;
exports.ssnPattern = ssnPattern;
exports.stripeKeyPattern = stripeKeyPattern;
exports.supabaseKeyPattern = supabaseKeyPattern;
exports.telegramBotTokenPattern = telegramBotTokenPattern;
exports.twilioAccountSidPattern = twilioAccountSidPattern;
exports.twilioApiKeyPattern = twilioApiKeyPattern;
exports.vnBankAccountPattern = vnBankAccountPattern;
exports.vnCitizenIdPattern = vnCitizenIdPattern;
exports.vnIdNumberPattern = vnIdNumberPattern;
exports.vnTaxCodePattern = vnTaxCodePattern;
exports.xaiApiKeyPattern = xaiApiKeyPattern;
//# sourceMappingURL=index.cjs.map
//# sourceMappingURL=index.cjs.map