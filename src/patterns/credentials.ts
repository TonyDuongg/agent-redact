import type { RedactPattern } from '../core/types.js';

/*
 * Token alphabets that include '-' end with `(?![A-Za-z0-9_])` instead of `\b`.
 * `\b` cannot match between a final '-' and a following space or punctuation, so a
 * token whose last character is '-' (about 1 in 64 for base64url) was skipped entirely
 * by fixed-length patterns. The lookahead is identical to `\b` for every other ending.
 */

/**
 * Anthropic Claude API Key (standard API key or Admin API key)
 * e.g. sk-ant-api03-... or sk-ant-admin01-...
 */
export const anthropicApiKeyPattern: RedactPattern = {
  id: 'anthropic-api-key',
  name: 'Anthropic API Key',
  category: 'credential',
  severity: 'critical',
  regex: /\bsk-ant-(?:api03|admin01)-[A-Za-z0-9_\-]{80,120}(?![A-Za-z0-9_])|\bsk-ant-[A-Za-z0-9_\-]{20,}(?![A-Za-z0-9_])/g,
  placeholder: 'ANTHROPIC_API_KEY',
  description: 'Anthropic Claude API key or Admin key'
};

/**
 * OpenAI API Key (Standard sk-... or project sk-proj-...)
 */
export const openaiApiKeyPattern: RedactPattern = {
  id: 'openai-api-key',
  name: 'OpenAI API Key',
  category: 'credential',
  severity: 'critical',
  regex: /\bsk-(?:proj|svcacct)-[A-Za-z0-9_\-]{40,}(?![A-Za-z0-9_])|\bsk-[a-zA-Z0-9]{20,}\b/g,
  placeholder: 'OPENAI_API_KEY',
  description: 'OpenAI API key (standard, project, or service account)'
};

/**
 * AWS Access Key ID (AKIA / ASIA / ABIA / ACCA)
 */
export const awsAccessKeyPattern: RedactPattern = {
  id: 'aws-access-key-id',
  name: 'AWS Access Key ID',
  category: 'credential',
  severity: 'high',
  regex: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g,
  placeholder: 'AWS_ACCESS_KEY_ID',
  description: 'Amazon Web Services 20-character Access Key ID'
};

/**
 * AWS Secret Access Key (with assignment context)
 */
export const awsSecretKeyPattern: RedactPattern = {
  id: 'aws-secret-access-key',
  name: 'AWS Secret Access Key',
  category: 'credential',
  severity: 'critical',
  regex: /(?:aws_secret_access_key|aws_secret_key|secret_access_key)[\s=:'"]+([A-Za-z0-9\/+=]{40})(?:\s|$|['",;])/gi,
  secretGroup: 1,
  placeholder: 'AWS_SECRET_ACCESS_KEY',
  description: 'Amazon Web Services 40-character Secret Access Key'
};

/**
 * GitHub Tokens (Personal access tokens, OAuth, App tokens)
 */
export const githubTokenPattern: RedactPattern = {
  id: 'github-token',
  name: 'GitHub Token',
  category: 'credential',
  severity: 'critical',
  regex: /\b(?:ghp_[A-Za-z0-9]{36,40}|github_pat_[A-Za-z0-9_]{60,100}|gho_[A-Za-z0-9]{36,40}|ghu_[A-Za-z0-9]{36,40}|ghs_[A-Za-z0-9]{36,40}|ghr_[A-Za-z0-9]{36,40})\b/g,
  placeholder: 'GITHUB_TOKEN',
  description: 'GitHub Personal Access Token, OAuth token, or App token'
};

/**
 * Stripe API Keys (Secret, Publishable, Restricted, Test)
 */
export const stripeKeyPattern: RedactPattern = {
  id: 'stripe-api-key',
  name: 'Stripe API Key',
  category: 'credential',
  severity: 'critical',
  // Unbounded: Stripe documents that key length may grow, and a bounded
  // quantifier followed by \b silently skips longer keys entirely.
  regex: /\b(?:sk|pk|rk)_(?:live|test)_[0-9a-zA-Z]{24,}\b/g,
  placeholder: 'STRIPE_API_KEY',
  description: 'Stripe API key (live or test, secret or publishable)'
};

/**
 * JSON Web Token (JWT)
 */
export const jwtTokenPattern: RedactPattern = {
  id: 'jwt-token',
  name: 'JSON Web Token (JWT)',
  category: 'credential',
  severity: 'critical',
  regex: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-]{10,}(?![A-Za-z0-9_])/g,
  placeholder: 'JWT_TOKEN',
  description: 'JSON Web Token (JWT) in header.payload.signature format'
};

/**
 * Private Keys (PEM / OpenSSH / RSA / DSA / EC / PGP)
 */
export const privateKeyPattern: RedactPattern = {
  id: 'private-key',
  name: 'Private Key',
  category: 'credential',
  severity: 'critical',
  // The body may not run past another BEGIN marker: without that, every unterminated
  // BEGIN rescanned to the end of the input (quadratic on many BEGINs without END).
  regex: /-----BEGIN (?:(?:RSA |OPENSSH |DSA |EC |ENCRYPTED )?PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----(?:(?!-----BEGIN )[\s\S])*?-----END (?:(?:RSA |OPENSSH |DSA |EC |ENCRYPTED )?PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----/g,
  placeholder: 'PRIVATE_KEY',
  description: 'RSA, OpenSSH, DSA, EC, Encrypted, or PGP private key certificate'
};

/**
 * Google Cloud / Gemini API Key
 */
export const googleApiKeyPattern: RedactPattern = {
  id: 'google-api-key',
  name: 'Google API Key',
  category: 'credential',
  severity: 'high',
  regex: /\bAIza[0-9A-Za-z\-_]{35}(?![A-Za-z0-9_])/g,
  placeholder: 'GOOGLE_API_KEY',
  description: 'Google Cloud or Gemini AI Studio API key'
};

/**
 * Slack Token (bot, user, app)
 */
export const slackTokenPattern: RedactPattern = {
  id: 'slack-token',
  name: 'Slack Token',
  category: 'credential',
  severity: 'high',
  // Bot tokens have two numeric segments, user/refresh tokens have three
  regex: /\b(?:xoxb|xoxp|xoxr|xoxa|xoxe|xoxs)-[0-9]{10,13}(?:-[0-9]{10,13}){1,2}-[a-zA-Z0-9]{24,34}\b|\bxapp-[0-9]{1,}-[a-zA-Z0-9]{10,32}-[0-9]{10,13}-[a-zA-Z0-9]{24,64}\b/g,
  placeholder: 'SLACK_TOKEN',
  description: 'Slack Bot, User, or App token'
};

/**
 * Database Connection URL (PostgreSQL, MySQL, MongoDB, Redis with credentials)
 */
export const databaseUrlPattern: RedactPattern = {
  id: 'database-url',
  name: 'Database Connection URL',
  category: 'credential',
  severity: 'critical',
  regex: /\b(?:postgres|postgresql|mysql|mariadb|mongodb|mongodb\+srv|redis|rediss):\/\/[^\s:/@]*:[^\s/@]+@[^\s/:]+(?::\d+)?(?:\/[^\s?"']*)?(?:\?[^\s"']*)?\b/g,
  placeholder: 'DATABASE_URL',
  description: 'Database connection URL containing user and password credentials'
};

/**
 * Backward-compatibility alias for databaseUrlPattern
 */
export const databaseUriPattern: RedactPattern = databaseUrlPattern;

/**
 * HTTP Basic Authentication URL containing user and password credentials
 */
export const basicAuthUrlPattern: RedactPattern = {
  id: 'basic-auth-url',
  name: 'HTTP Basic Auth URL',
  category: 'credential',
  severity: 'critical',
  regex: /\bhttps?:\/\/[^\s:/@]+:[^\s/@]+@[^\s/:]+(?::\d+)?(?:\/[^\s?"']*)?(?:\?[^\s"']*)?\b/g,
  placeholder: 'BASIC_AUTH_URL',
  description: 'HTTP/HTTPS URL containing username and password credentials'
};

/**
 * Hugging Face Token
 */
export const huggingFaceTokenPattern: RedactPattern = {
  id: 'huggingface-token',
  name: 'Hugging Face Token',
  category: 'credential',
  severity: 'high',
  regex: /\bhf_[a-zA-Z0-9]{34}\b/g,
  placeholder: 'HUGGINGFACE_TOKEN',
  description: 'Hugging Face User Access Token'
};

/**
 * GitLab Personal Access Token
 */
export const gitlabTokenPattern: RedactPattern = {
  id: 'gitlab-token',
  name: 'GitLab Token',
  category: 'credential',
  severity: 'high',
  regex: /\bglpat-[0-9a-zA-Z\-_]{20,}(?![A-Za-z0-9_])/g,
  placeholder: 'GITLAB_TOKEN',
  description: 'GitLab Personal Access Token'
};

/**
 * Discord Bot Token
 */
export const discordTokenPattern: RedactPattern = {
  id: 'discord-token',
  name: 'Discord Bot Token',
  category: 'credential',
  severity: 'high',
  regex: /\b[MNO][a-zA-Z0-9_-]{23,25}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27,38}(?![A-Za-z0-9_])/g,
  placeholder: 'DISCORD_TOKEN',
  description: 'Discord Bot Authentication Token'
};

/**
 * NPM Access Token (Automation or granular token)
 */
export const npmTokenPattern: RedactPattern = {
  id: 'npm-token',
  name: 'NPM Access Token',
  category: 'credential',
  severity: 'critical',
  regex: /\bnpm_[A-Za-z0-9]{36}\b/g,
  placeholder: 'NPM_TOKEN',
  description: 'Node Package Manager (npm) access token'
};

/**
 * SendGrid API Key
 */
export const sendgridApiKeyPattern: RedactPattern = {
  id: 'sendgrid-api-key',
  name: 'SendGrid API Key',
  category: 'credential',
  severity: 'high',
  regex: /\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}(?![A-Za-z0-9_])/g,
  placeholder: 'SENDGRID_API_KEY',
  description: 'SendGrid Email API key'
};

/**
 * Twilio Account SID
 */
export const twilioAccountSidPattern: RedactPattern = {
  id: 'twilio-account-sid',
  name: 'Twilio Account SID',
  category: 'credential',
  severity: 'high',
  regex: /\bAC[0-9a-fA-F]{32}\b/g,
  placeholder: 'TWILIO_ACCOUNT_SID',
  description: 'Twilio Account Identifier'
};

/**
 * Supabase Service/Secret Key
 */
export const supabaseKeyPattern: RedactPattern = {
  id: 'supabase-key',
  name: 'Supabase Key',
  category: 'credential',
  severity: 'critical',
  regex: /\bsbp_[a-zA-Z0-9]{40}\b/g,
  placeholder: 'SUPABASE_KEY',
  description: 'Supabase Project or Management API key'
};

/**
 * Telegram Bot Token (<bot-id>:<35-char-token>)
 */
export const telegramBotTokenPattern: RedactPattern = {
  id: 'telegram-bot-token',
  name: 'Telegram Bot Token',
  category: 'credential',
  severity: 'critical',
  regex: /\b\d{8,10}:[A-Za-z0-9_-]{35}(?![A-Za-z0-9_])/g,
  placeholder: 'TELEGRAM_BOT_TOKEN',
  description: 'Telegram Bot API authentication token'
};

/**
 * Twilio API Key (SK...)
 */
export const twilioApiKeyPattern: RedactPattern = {
  id: 'twilio-api-key',
  name: 'Twilio API Key',
  category: 'credential',
  severity: 'critical',
  regex: /\bSK[0-9a-fA-F]{32}\b/g,
  placeholder: 'TWILIO_API_KEY',
  description: 'Twilio API Key starting with SK prefix'
};

/**
 * Azure Storage Connection String / AccountKey
 */
export const azureStorageKeyPattern: RedactPattern = {
  id: 'azure-storage-key',
  name: 'Azure Storage Key',
  category: 'credential',
  severity: 'critical',
  regex: /\bAccountKey=[A-Za-z0-9+/]{86}==|\bAccountKey=[A-Za-z0-9+/=]{88}\b/g,
  placeholder: 'AZURE_STORAGE_KEY',
  description: 'Azure Storage Account access key'
};

/**
 * GCP OAuth Client Secret (GOCSPX-...)
 */
export const gcpOauthSecretPattern: RedactPattern = {
  id: 'gcp-oauth-client-secret',
  name: 'GCP OAuth Client Secret',
  category: 'credential',
  severity: 'critical',
  regex: /\bGOCSPX-[A-Za-z0-9_-]{28}(?![A-Za-z0-9_])/g,
  placeholder: 'GCP_OAUTH_CLIENT_SECRET',
  description: 'Google Cloud Platform OAuth 2.0 client secret'
};

/**
 * DigitalOcean Personal Access Token (dop_v1_...)
 */
export const digitalOceanTokenPattern: RedactPattern = {
  id: 'digitalocean-token',
  name: 'DigitalOcean Token',
  category: 'credential',
  severity: 'critical',
  regex: /\bdop_v1_[a-f0-9]{64}\b/g,
  placeholder: 'DIGITALOCEAN_TOKEN',
  description: 'DigitalOcean Personal Access Token'
};

/**
 * Mailgun API Key (key-...)
 */
export const mailgunApiKeyPattern: RedactPattern = {
  id: 'mailgun-api-key',
  name: 'Mailgun API Key',
  category: 'credential',
  severity: 'high',
  regex: /\bkey-[0-9a-zA-Z]{32}\b/g,
  placeholder: 'MAILGUN_API_KEY',
  description: 'Mailgun API authentication key'
};

/*
 * AI / LLM provider keys commonly handled by agents. Length quantifiers are lower bounds
 * (not exact lengths) so a provider lengthening its keys does not silently stop detection.
 */

export const openrouterApiKeyPattern: RedactPattern = {
  id: 'openrouter-api-key',
  name: 'OpenRouter API Key',
  category: 'credential',
  severity: 'critical',
  regex: /\bsk-or-v1-[a-f0-9]{40,}(?![A-Za-z0-9_])/g,
  placeholder: 'OPENROUTER_API_KEY',
  description: 'OpenRouter API key (sk-or-v1-...)'
};

export const groqApiKeyPattern: RedactPattern = {
  id: 'groq-api-key',
  name: 'Groq API Key',
  category: 'credential',
  severity: 'critical',
  regex: /\bgsk_[A-Za-z0-9]{40,}(?![A-Za-z0-9_])/g,
  placeholder: 'GROQ_API_KEY',
  description: 'Groq API key (gsk_...)'
};

export const xaiApiKeyPattern: RedactPattern = {
  id: 'xai-api-key',
  name: 'xAI API Key',
  category: 'credential',
  severity: 'critical',
  regex: /\bxai-[A-Za-z0-9]{60,}(?![A-Za-z0-9_])/g,
  placeholder: 'XAI_API_KEY',
  description: 'xAI (Grok) API key (xai-...)'
};

export const perplexityApiKeyPattern: RedactPattern = {
  id: 'perplexity-api-key',
  name: 'Perplexity API Key',
  category: 'credential',
  severity: 'critical',
  regex: /\bpplx-[A-Za-z0-9]{32,}(?![A-Za-z0-9_])/g,
  placeholder: 'PERPLEXITY_API_KEY',
  description: 'Perplexity API key (pplx-...)'
};

export const replicateApiTokenPattern: RedactPattern = {
  id: 'replicate-api-token',
  name: 'Replicate API Token',
  category: 'credential',
  severity: 'critical',
  regex: /\br8_[A-Za-z0-9]{30,}(?![A-Za-z0-9_])/g,
  placeholder: 'REPLICATE_API_TOKEN',
  description: 'Replicate API token (r8_...)'
};

export const huggingFaceOrgTokenPattern: RedactPattern = {
  id: 'huggingface-org-token',
  name: 'Hugging Face Organization Token',
  category: 'credential',
  severity: 'high',
  regex: /\bapi_org_[A-Za-z0-9]{30,}(?![A-Za-z0-9_])/g,
  placeholder: 'HUGGINGFACE_ORG_TOKEN',
  description: 'Hugging Face organization API token (api_org_...)'
};

export const langsmithApiKeyPattern: RedactPattern = {
  id: 'langsmith-api-key',
  name: 'LangSmith API Key',
  category: 'credential',
  severity: 'high',
  regex: /\blsv2_(?:pt|sk)_[a-f0-9]{32}_[a-f0-9]{10}(?![A-Za-z0-9_])/g,
  placeholder: 'LANGSMITH_API_KEY',
  description: 'LangSmith / LangChain personal or service key (lsv2_pt_ / lsv2_sk_)'
};

/**
 * Export array of all built-in credential patterns
 */
export const CREDENTIAL_PATTERNS: RedactPattern[] = [
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
