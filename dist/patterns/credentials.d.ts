import type { RedactPattern } from '../core/types.js';
/**
 * Anthropic Claude API Key (standard API key or Admin API key)
 * e.g. sk-ant-api03-... or sk-ant-admin01-...
 */
export declare const anthropicApiKeyPattern: RedactPattern;
/**
 * OpenAI API Key (Standard sk-... or project sk-proj-...)
 */
export declare const openaiApiKeyPattern: RedactPattern;
/**
 * AWS Access Key ID (AKIA / ASIA / ABIA / ACCA)
 */
export declare const awsAccessKeyPattern: RedactPattern;
/**
 * AWS Secret Access Key (with assignment context)
 */
export declare const awsSecretKeyPattern: RedactPattern;
/**
 * GitHub Tokens (Personal access tokens, OAuth, App tokens)
 */
export declare const githubTokenPattern: RedactPattern;
/**
 * Stripe API Keys (Secret, Publishable, Restricted, Test)
 */
export declare const stripeKeyPattern: RedactPattern;
/**
 * JSON Web Token (JWT)
 */
export declare const jwtTokenPattern: RedactPattern;
/**
 * Private Keys (PEM / OpenSSH / RSA / DSA / EC / PGP)
 */
export declare const privateKeyPattern: RedactPattern;
/**
 * Google Cloud / Gemini API Key
 */
export declare const googleApiKeyPattern: RedactPattern;
/**
 * Slack Token (bot, user, app)
 */
export declare const slackTokenPattern: RedactPattern;
/**
 * Database Connection URL (PostgreSQL, MySQL, MongoDB, Redis with credentials)
 */
export declare const databaseUrlPattern: RedactPattern;
/**
 * Backward-compatibility alias for databaseUrlPattern
 */
export declare const databaseUriPattern: RedactPattern;
/**
 * HTTP Basic Authentication URL containing user and password credentials
 */
export declare const basicAuthUrlPattern: RedactPattern;
/**
 * Hugging Face Token
 */
export declare const huggingFaceTokenPattern: RedactPattern;
/**
 * GitLab Personal Access Token
 */
export declare const gitlabTokenPattern: RedactPattern;
/**
 * Discord Bot Token
 */
export declare const discordTokenPattern: RedactPattern;
/**
 * NPM Access Token (Automation or granular token)
 */
export declare const npmTokenPattern: RedactPattern;
/**
 * SendGrid API Key
 */
export declare const sendgridApiKeyPattern: RedactPattern;
/**
 * Twilio Account SID
 */
export declare const twilioAccountSidPattern: RedactPattern;
/**
 * Supabase Service/Secret Key
 */
export declare const supabaseKeyPattern: RedactPattern;
/**
 * Telegram Bot Token (<bot-id>:<35-char-token>)
 */
export declare const telegramBotTokenPattern: RedactPattern;
/**
 * Twilio API Key (SK...)
 */
export declare const twilioApiKeyPattern: RedactPattern;
/**
 * Azure Storage Connection String / AccountKey
 */
export declare const azureStorageKeyPattern: RedactPattern;
/**
 * GCP OAuth Client Secret (GOCSPX-...)
 */
export declare const gcpOauthSecretPattern: RedactPattern;
/**
 * DigitalOcean Personal Access Token (dop_v1_...)
 */
export declare const digitalOceanTokenPattern: RedactPattern;
/**
 * Mailgun API Key (key-...)
 */
export declare const mailgunApiKeyPattern: RedactPattern;
export declare const openrouterApiKeyPattern: RedactPattern;
export declare const groqApiKeyPattern: RedactPattern;
export declare const xaiApiKeyPattern: RedactPattern;
export declare const perplexityApiKeyPattern: RedactPattern;
export declare const replicateApiTokenPattern: RedactPattern;
export declare const huggingFaceOrgTokenPattern: RedactPattern;
export declare const langsmithApiKeyPattern: RedactPattern;
/**
 * Export array of all built-in credential patterns
 */
export declare const CREDENTIAL_PATTERNS: RedactPattern[];
