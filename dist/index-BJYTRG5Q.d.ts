interface EntropyConfig {
    /** Minimum token length to analyze (default: 20) */
    minLength?: number;
    /** Maximum token length to analyze (default: 120) */
    maxLength?: number;
    /** Shannon entropy threshold for Base64/Alphanumeric strings (default: 4.3) */
    base64Threshold?: number;
    /** Shannon entropy threshold for Hex strings (default: 3.2) */
    hexThreshold?: number;
}
/**
 * Calculates the Shannon Entropy of a string:
 * H(X) = -sum(P(x) * log2(P(x)))
 * Higher entropy means higher randomness / unpredictability (characteristic of cryptographic keys).
 */
declare function calculateShannonEntropy(str: string): number;
/**
 * Determines whether a candidate string exhibits high entropy (randomness)
 * typical of generated API keys or secrets.
 */
declare function isHighEntropyToken(token: string, config?: EntropyConfig): boolean;
/**
 * Pattern definition to detect generic high-entropy secrets preceded by key/token/secret context
 */
declare function createHighEntropyPattern(config?: EntropyConfig): RedactPattern;

type SecretCategory = 'credential' | 'pii' | 'network' | 'custom';
type Severity = 'critical' | 'high' | 'medium' | 'low';
interface RedactPattern {
    /** Unique identifier for the pattern (e.g., 'anthropic-api-key') */
    id: string;
    /** Human-readable name */
    name: string;
    /** Classification category */
    category: SecretCategory;
    /** Risk severity if leaked */
    severity: Severity;
    /** Regular expression used for detection */
    regex: RegExp;
    /** Default token placeholder label (e.g., 'ANTHROPIC_API_KEY') */
    placeholder: string;
    /** Short description of the matched token */
    description: string;
    /** Optional secondary validation function (e.g., Luhn check) */
    validator?: (match: string) => boolean;
    /**
     * Capturing group that holds the secret (number or group name), e.g. for
     * `key=(value)` assignments. When omitted, a named group `(?<secret>...)` is
     * used if present, otherwise the WHOLE match is redacted. Plain capturing
     * groups used only for alternation no longer cause partial redaction.
     */
    secretGroup?: number | string;
}
interface RedactMatch {
    patternId: string;
    patternName: string;
    category: SecretCategory;
    severity: Severity;
    matchedText?: string;
    startIndex: number;
    endIndex: number;
    replacement: string;
}
interface VaultEntry {
    placeholder: string;
    original: string;
    patternId: string;
    category: SecretCategory;
    timestamp: number;
}
interface RedactOptions {
    /**
     * If true, generates sequential session placeholders (e.g., [ANTHROPIC_API_KEY_1])
     * that can be reversibly unmasked using `unmask(text, vault)`.
     * If false, one-way redaction is used (e.g., [REDACTED_ANTHROPIC_API_KEY]).
     * @default false
     */
    reversible?: boolean;
    /**
     * List of specific pattern IDs to include.
     * If not specified, all active patterns are used.
     */
    include?: string[];
    /**
     * List of specific pattern IDs to exclude.
     */
    exclude?: string[];
    /**
     * Custom list of patterns to use (overriding or supplementing defaults).
     */
    customPatterns?: RedactPattern[];
    /**
     * Whitelist of exact strings or substrings that should NEVER be redacted.
     */
    allowlist?: string[];
    /**
     * If true, enables Shannon entropy analysis to detect generic high-entropy
     * cryptographic secrets that lack fixed vendor prefixes.
     * @default false
     */
    detectHighEntropy?: boolean;
    /**
     * Custom entropy parameters (thresholds, min/max length).
     */
    entropy?: EntropyConfig;
    /**
     * Optional custom replacement formatting function.
     */
    customFormatter?: (info: {
        pattern: RedactPattern;
        matchedText: string;
        index: number;
        reversible: boolean;
    }) => string;
    /**
     * If true, includes the raw matched secret text in match results.
     * By default false for security to prevent secrets leaking in JSON serialization.
     * @default false
     */
    includeMatchedText?: boolean;
}
interface RedactResult {
    /** The sanitized text with all secrets redacted or masked */
    text: string;
    /** Details of all detected leaks */
    matches: RedactMatch[];
    /** True if any sensitive token was detected and redacted */
    hasLeaks: boolean;
    /** Total count of leaked tokens detected */
    totalLeaks: number;
    /** Breakdown count by pattern ID */
    stats: Record<string, number>;
    /** Execution time in milliseconds */
    durationMs: number;
}

/**
 * Anthropic Claude API Key (standard API key or Admin API key)
 * e.g. sk-ant-api03-... or sk-ant-admin01-...
 */
declare const anthropicApiKeyPattern: RedactPattern;
/**
 * OpenAI API Key (Standard sk-... or project sk-proj-...)
 */
declare const openaiApiKeyPattern: RedactPattern;
/**
 * AWS Access Key ID (AKIA / ASIA / ABIA / ACCA)
 */
declare const awsAccessKeyPattern: RedactPattern;
/**
 * AWS Secret Access Key (with assignment context)
 */
declare const awsSecretKeyPattern: RedactPattern;
/**
 * GitHub Tokens (Personal access tokens, OAuth, App tokens)
 */
declare const githubTokenPattern: RedactPattern;
/**
 * Stripe API Keys (Secret, Publishable, Restricted, Test)
 */
declare const stripeKeyPattern: RedactPattern;
/**
 * JSON Web Token (JWT)
 */
declare const jwtTokenPattern: RedactPattern;
/**
 * Private Keys (PEM / OpenSSH / RSA / DSA / EC / PGP)
 */
declare const privateKeyPattern: RedactPattern;
/**
 * Google Cloud / Gemini API Key
 */
declare const googleApiKeyPattern: RedactPattern;
/**
 * Slack Token (bot, user, app)
 */
declare const slackTokenPattern: RedactPattern;
/**
 * Database Connection URL (PostgreSQL, MySQL, MongoDB, Redis with credentials)
 */
declare const databaseUrlPattern: RedactPattern;
/**
 * Backward-compatibility alias for databaseUrlPattern
 */
declare const databaseUriPattern: RedactPattern;
/**
 * HTTP Basic Authentication URL containing user and password credentials
 */
declare const basicAuthUrlPattern: RedactPattern;
/**
 * Hugging Face Token
 */
declare const huggingFaceTokenPattern: RedactPattern;
/**
 * GitLab Personal Access Token
 */
declare const gitlabTokenPattern: RedactPattern;
/**
 * Discord Bot Token
 */
declare const discordTokenPattern: RedactPattern;
/**
 * NPM Access Token (Automation or granular token)
 */
declare const npmTokenPattern: RedactPattern;
/**
 * SendGrid API Key
 */
declare const sendgridApiKeyPattern: RedactPattern;
/**
 * Twilio Account SID
 */
declare const twilioAccountSidPattern: RedactPattern;
/**
 * Supabase Service/Secret Key
 */
declare const supabaseKeyPattern: RedactPattern;
/**
 * Export array of all built-in credential patterns
 */
declare const CREDENTIAL_PATTERNS: RedactPattern[];

/**
 * Email Address
 */
declare const emailPattern: RedactPattern;
/**
 * IPv4 Address (Public / Private)
 */
declare const ipv4Pattern: RedactPattern;
/**
 * US Social Security Number (SSN)
 */
declare const ssnPattern: RedactPattern;
/**
 * Credit Card Number (Visa, MasterCard, Amex, Discover)
 */
declare const creditCardPattern: RedactPattern;
/**
 * IPv6 Address
 */
declare const ipv6Pattern: RedactPattern;
/**
 * Phone Number (US & International E.164 formats with separators or + prefix)
 */
declare const phonePattern: RedactPattern;
/**
 * Export array of all built-in PII patterns
 */
declare const PII_PATTERNS: RedactPattern[];

/**
 * All default patterns included in agent-redact
 */
declare const DEFAULT_PATTERNS: RedactPattern[];
/**
 * Map pattern ID to RedactPattern for fast lookup
 */
declare const PATTERN_MAP: ReadonlyMap<string, RedactPattern>;

export { phonePattern as A, privateKeyPattern as B, CREDENTIAL_PATTERNS as C, DEFAULT_PATTERNS as D, type EntropyConfig as E, sendgridApiKeyPattern as F, slackTokenPattern as G, ssnPattern as H, stripeKeyPattern as I, supabaseKeyPattern as J, twilioAccountSidPattern as K, PATTERN_MAP as P, type RedactPattern as R, type SecretCategory as S, type VaultEntry as V, type RedactOptions as a, type RedactResult as b, type Severity as c, PII_PATTERNS as d, type RedactMatch as e, anthropicApiKeyPattern as f, awsAccessKeyPattern as g, awsSecretKeyPattern as h, basicAuthUrlPattern as i, calculateShannonEntropy as j, createHighEntropyPattern as k, creditCardPattern as l, databaseUriPattern as m, databaseUrlPattern as n, discordTokenPattern as o, emailPattern as p, githubTokenPattern as q, gitlabTokenPattern as r, googleApiKeyPattern as s, huggingFaceTokenPattern as t, ipv4Pattern as u, ipv6Pattern as v, isHighEntropyToken as w, jwtTokenPattern as x, npmTokenPattern as y, openaiApiKeyPattern as z };
