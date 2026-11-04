import type { RedactPattern } from '../core/types.js';

/**
 * Anthropic Claude API Key (standard API key or Admin API key)
 * e.g. sk-ant-api03-... or sk-ant-admin01-...
 */
export const anthropicApiKeyPattern: RedactPattern = {
  id: 'anthropic-api-key',
  name: 'Anthropic API Key',
  category: 'credential',
  severity: 'critical',
  regex: /\bsk-ant-(?:api03|admin01)-[A-Za-z0-9_\-]{80,120}\b|\bsk-ant-[A-Za-z0-9_\-]{20,}\b/g,
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
  regex: /\bsk-(?:proj|svcacct)-[A-Za-z0-9_\-]{40,160}\b|\bsk-[a-zA-Z0-9]{20,64}\b/g,
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
  regex: /(?:aws_secret_access_key|aws_secret_key|secret_access_key)[\s=:'"]+([A-Za-z0-9\/+=]{40})(?:\s|$|['",])/gi,
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
  regex: /\b(?:sk|pk|rk)_(?:live|test)_[0-9a-zA-Z]{24,99}\b/g,
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
  severity: 'high',
  regex: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-]{10,}\b/g,
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
  regex: /-----BEGIN (?:RSA |OPENSSH |DSA |EC |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |OPENSSH |DSA |EC |PGP )?PRIVATE KEY-----/g,
  placeholder: 'PRIVATE_KEY',
  description: 'RSA, OpenSSH, DSA, EC, or PGP private key certificate'
};

/**
 * Google Cloud / Gemini API Key
 */
export const googleApiKeyPattern: RedactPattern = {
  id: 'google-api-key',
  name: 'Google API Key',
  category: 'credential',
  severity: 'high',
  regex: /\bAIza[0-9A-Za-z\-_]{35}\b/g,
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
  regex: /\b(?:xoxb|xoxp|xoxr|xoxa)-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}\b|\bxapp-[0-9]{1,}-[a-zA-Z0-9]{10,32}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}\b/g,
  placeholder: 'SLACK_TOKEN',
  description: 'Slack Bot, User, or App token'
};

/**
 * Database Connection URI (PostgreSQL, MySQL, MongoDB, Redis with credentials)
 */
export const databaseUriPattern: RedactPattern = {
  id: 'database-uri',
  name: 'Database Connection URI',
  category: 'credential',
  severity: 'critical',
  regex: /\b(?:postgres|postgresql|mysql|mongodb|mongodb\+srv|redis|rediss):\/\/[^\s:]+:[^\s@]+@[^\s/:]+(?::\d+)?\/[^\s?"']+\b/g,
  placeholder: 'DATABASE_URI',
  description: 'Database connection URI containing user and password credentials'
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
  regex: /\bglpat-[0-9a-zA-Z\-_]{20,}\b/g,
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
  regex: /\b[MNO][a-zA-Z0-9_-]{23,25}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27,38}\b/g,
  placeholder: 'DISCORD_TOKEN',
  description: 'Discord Bot Authentication Token'
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
  databaseUriPattern,
  huggingFaceTokenPattern,
  gitlabTokenPattern,
  discordTokenPattern
];
