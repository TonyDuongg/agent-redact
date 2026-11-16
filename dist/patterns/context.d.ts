import type { RedactPattern } from '../core/types.js';
/**
 * True when `value` could be a real secret: at least 8 characters, and not a reference
 * (`${VAR}`, `$VAR`, `process.env.X`, `os.environ[...]`), a template (`{{ ... }}`), a
 * placeholder (`<your-key>`, `changeme`, `xxxx`, `****`, `...`) or a literal like `null`.
 */
export declare function isPlausibleSecretValue(value: string): boolean;
/**
 * Values of .npmrc `_authToken`, `_auth` and `_password` (registry-scoped or global).
 */
export declare const npmrcAuthPattern: RedactPattern;
/**
 * Password of a .netrc entry (`machine <host> login <user> password <secret>`), on one line or
 * several. Keywords are lowercase, as netrc requires.
 */
export declare const netrcPasswordPattern: RedactPattern;
/**
 * Docker / Podman config.json registry credentials: `"auth": "<base64 user:password>"`.
 */
export declare const dockerConfigAuthPattern: RedactPattern;
/**
 * .env style lines whose UPPERCASE key ends in PASSWORD, PASSWD, SECRET, TOKEN, API_KEY or
 * SECRET_KEY (optionally followed by a short number): `DB_PASSWORD=...`, `export JWT_SECRET="..."`,
 * docker-compose `- POSTGRES_PASSWORD=...`, Dockerfile `ENV APP_TOKEN=...`.
 * Unquoted values must follow `=` directly, so code such as `API_TOKEN = get_token()` is skipped.
 * Like dotenv, an unquoted value runs to the end of the line or a ` #` comment, spaces included,
 * so no word of it is left visible.
 */
export declare const dotenvSecretPattern: RedactPattern;
/**
 * Quoted values assigned to password-like keys in code and config (JSON, YAML, TOML, XML
 * attributes, Python/JS/PHP/Go): `password: "..."`, `"client_secret": "..."`, `db_pass = '...'`.
 * Also matches JSON embedded in a JSON string (`\"password\": \"...\"`). Backslash escapes and
 * YAML's '' escape stay inside the value. Unquoted values are never matched, so
 * `password = get_pw()` is not a finding.
 */
export declare const quotedSecretAssignmentPattern: RedactPattern;
/**
 * Values under `data:` / `stringData:` of YAML documents with `kind: Secret`, including
 * Secrets inside a `kind: List` (`kubectl get secrets -o yaml`). Templated values
 * (`{{ .Values.x }}`) are skipped.
 */
export declare const kubernetesSecretPattern: RedactPattern;
/**
 * Context-aware patterns, on by default. Order matters only for ties (same severity and span):
 * vendor patterns come first in DEFAULT_PATTERNS, then .env keys before quoted assignments.
 */
export declare const CONTEXT_PATTERNS: RedactPattern[];
