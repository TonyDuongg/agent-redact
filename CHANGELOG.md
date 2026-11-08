# Changelog

All notable changes to `agent-redact` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.3.0] - 2026-11-08

Node.js 22.18+ is now required, and the toolchain moves to Vitest 5, tsup 9 and TypeScript 7. The xAI and Replicate patterns now catch keys they used to miss, and a script checks real provider keys locally. The Python package is on PyPI, published through Trusted Publishing.

### ⚠️ Upgrade notes (behavior changes)
- **Node.js 22.18 or newer is required** (`engines.node: ">=22.18.0"`). Node.js 20 reached end-of-life in April 2026, and the build toolchain no longer runs on it (Vitest 5 needs ≥ 22.12, tsup 9 needs ≥ 22.18). The code does not use Node 22-only APIs, but Node 20 is no longer tested or supported. This also applies to the Python package, which runs the Node.js CLI.
- **xAI and Replicate patterns are broader:** keys containing `_` (xAI) or `-`/`_` (Replicate) are now detected and fully masked, so scans and baselines may report new findings.
- **Type declarations are no longer bundled.** `dist/` now ships one `.d.ts` per source file, emitted by `tsc`, and no longer ships the `.d.cts` copies. The `exports` map already pointed `types` at the `.d.ts` files, and the public API is unchanged: a compiler-API dump of all 149 exports and their members is identical. ESM and CJS consumers type-check against the new package with TypeScript 5.9 and 7.0, with `skipLibCheck: false`.

### 🔧 Tooling
- **CI matrix:** Node.js 22, 24 and 26 (was 20, 22, 24). The secret-scan workflow moved from Node 20 to 22.
- **Vitest 4.1 → 5.1, tsup 8 → 9.** The esbuild `overrides` entry is gone, because tsup 9 depends on esbuild ^0.28.2 itself (`npm audit`: 0 vulnerabilities). Build target `node20` → `node22`, which changes no emitted JavaScript.
- **TypeScript 6.0 → 7.0 (native compiler)** for type checking and declaration emit. tsup 9 still cannot emit declarations with TS 7, because its bundled `rollup-plugin-dts` needs the JavaScript compiler API that TS 7 does not ship. Declarations are therefore emitted by `tsc -p tsconfig.build.json` (`emitDeclarationOnly`) after tsup builds the JavaScript, and tsup's `dts` is off. `ignoreDeprecations: "6.0"` is removed: it was only needed for the `baseUrl` that tsup's old d.ts step passed.
- Timing-based performance tests keep their thresholds: on Vitest 5 the slowest runs are 4–22× below them.
- New `tests/node-support.test.ts` keeps `engines`, every workflow's Node version, the build target and the docs on the same minimum version.

### 🐍 Python package
- **On PyPI** as `agent-redact` (`pip install agent-redact`). The new workflow published 0.2.0 there on 2026-11-08. Node.js is still required (22.18+ from this release), because the package wraps the Node.js CLI.
- **New `release-python.yml` workflow** using PyPI Trusted Publishing (OIDC, no API token):
  - a `vX.Y.Z` tag builds and tests the sdist and wheel, checks that the tag, `pyproject.toml`, `__init__.py` and `package.json` agree and that the tagged commit is on `main`, waits until the same version is on npm (the wrapper installs it from there on first use), and then publishes from the `pypi` environment;
  - a manual run publishes to TestPyPI by default. Publishing to PyPI manually works only from `main`, for a version whose tag already exists and whose `python/src` and `pyproject.toml` are unchanged since that tag;
  - only the publish jobs get `id-token: write`, and they run no repository code.

### 🎯 Detection
- **AI provider keys checked against public scanners** (trufflehog, gitleaks) and vendor docs. OpenRouter, Groq, Perplexity, Hugging Face org and LangSmith already matched. Two patterns were too narrow and **missed keys completely** (fail open):
  - **xAI:** the key body may contain `_` (`xai-` + `[A-Za-z0-9_]`). Before, a key with `_` was not detected at all.
  - **Replicate:** the token body may contain `-` and `_` (`r8_` + `[A-Za-z0-9_-]`; the docs give 40 characters in total). Before, a `_` hid the whole token, and a `-` after the first 30 characters left the rest of the token unmasked.
- Each trailing lookahead now excludes the pattern's full character set, so a key is never matched only in part. Lengths remain lower bounds.
- **`scripts/verify-provider-keys.mjs`:** checks real provider keys against the built `dist/`, reading them from environment variables only (`OPENROUTER_KEY`, `GROQ_KEY`, `XAI_KEY`, `PERPLEXITY_KEY`, `REPLICATE_KEY`, `HF_ORG_KEY`, `LANGSMITH_KEY`, plus the usual SDK names). Each key must be found with its full span in `.env`, JSON, prose and `Authorization` header contexts. The output is only `provider: PASS/FAIL/SKIPPED`; `--explain` adds non-secret hints (reason, length, character classes). Keys are never printed.

---

## [0.2.0] - 2026-11-08

Linear-time scanning, streaming unmask for LLM SDKs, repository scanning with SARIF and baselines, a Claude Code hook, encrypted vaults, Vietnamese PII preset, more AI provider keys and a Python package.

### ⚠️ Upgrade notes (behavior changes)
- **`wrapAgent`** now deep-unmasks plain-object responses (returning a restored **copy**, not the same reference) and stream-unmasks `async function*` responses. Class instances are still returned untouched.
- **Tool-call inputs stay masked by default** (`tool_use.input`, `function.arguments`, …) in `unmaskDeep`, the stream adapters and `wrapAgent`. Opt in per tool with `unmaskToolInputs`.
- **CLI:** passing directories or several files now runs **scan mode**, which reports findings without values and exits 1 when any are found. Scan mode cannot be combined with `-r`, `-o`, `--unmask` or `--json`. Multi-file `-i` only rewrites files that contain secrets.
- **Email pattern:** RFC 5321 length limits apply (local part ≤ 64, domain ≤ 253, TLD ≤ 63).
- **npm package:** no longer ships source maps, the GitHub Action bundle or the CJS CLI.
- **Python package:** requires Python 3.10+.

### 🔧 Tooling
- **TypeScript 5.9 → 6.0.3:** `tsconfig.json` now lists `"types": ["node"]` explicitly, because TS 6 no longer auto-includes `@types`. It also sets `ignoreDeprecations: "6.0"`, because tsup's d.ts step passes the deprecated `baseUrl`. TypeScript 7 (native) is not usable yet: tsup's `rollup-plugin-dts` needs the JS compiler API that TS 7 does not ship.
- **Vitest 3 → 4.1.** Vitest 5 and tsup 9 require Node ≥ 22.12 / 22.18, so they would drop the Node 20 CI leg. They are left for a separate decision.
- **esbuild pinned to ^0.28.1 via `overrides`:** this fixes GHSA-g7r4-m6w7-qqqr (low, dev server only), which tsup 8's range could not reach. The only output difference is esbuild's lazy-init helper.

### 🐍 Python package (`python/`)
- **`agent-redact` for Python:** a dependency-free wrapper around the CLI, so it uses exactly the same engine.
  - `redact()` returns text plus matches, without secret values.
  - `scan()` covers paths or the git index.
  - `Session` provides reversible masking across calls. Its vault is encrypted with a random per-session passphrase that never touches disk, and is deleted on close.
- **CLI discovery** (hardened after automated security review): an absolute `AGENT_REDACT_CLI`, then a global `agent-redact` resolved to its JS entry, then a one-time `npm install --ignore-scripts` of the same version into a private user cache. The CLI is always started as `node <absolute path>`. `.cmd`/`.bat` shims and `npx` are never used, and executables are never taken from the current directory or relative `PATH` entries, so a scanned repository cannot plant a binary or an `.npmrc`. Python 3.10+ (3.9 is EOL and no longer available on CI runners).
- **CI:** new Python job (Ubuntu and Windows, Python 3.10 and 3.13). A test keeps the Python version in sync with `package.json`.
- **New CLI flags:** `--vault-in <file>` continues an existing (encrypted) vault, so numbering carries over between runs; `--preset <a,b>` enables presets from the command line.

### 🎯 Detection
- **New AI/LLM provider keys:** OpenRouter (`sk-or-v1-`), Groq (`gsk_`), xAI (`xai-`), Perplexity (`pplx-`), Replicate (`r8_`), Hugging Face org tokens (`api_org_`), LangSmith (`lsv2_pt_` / `lsv2_sk_`). Lengths are lower bounds, so longer future keys are still caught.
- **`vn-pii` preset (opt-in):** Vietnamese CCCD (with province-code validation), CMND/CCCD after an ID keyword, tax code (MST) and bank account numbers after their keywords. Enable it with `presets: ['vn-pii']` (option or config). Unknown preset names throw.
- **Labelled corpus test:** positive samples for every built-in pattern (enforced) and a negative corpus of realistic non-secret text (0 false positives).

### 🔐 Encrypted vaults
- **`--vault-key-env <VAR>`** (or `AGENT_REDACT_VAULT_KEY`) encrypts `--vault-out` files with AES-256-GCM, using a scrypt-derived key and an authenticated header. `--unmask` decrypts them and refuses encrypted vaults without a key. Writing an unencrypted vault prints a warning.
- **Library helpers:** `encryptVaultJson`, `decryptVaultJson`, `isEncryptedVault`.

### ✨ Repository scanning & CI
- **Scan mode:** `agent-redact <dir|files...>` reports findings (file:line:column, never values) and exits 1 when any are found. Inside git it uses `git ls-files --cached --others --exclude-standard`, so `.gitignore` is honoured exactly; outside git, common build and dependency directories are skipped. Binary and oversized files are skipped.
- **`--staged`:** scans the git index, i.e. exactly what is about to be committed.
- **`--format json|sarif` and `--report <file>`:** SARIF 2.1.0 with `security-severity`, for GitHub code scanning.
- **Baselines:** `--write-baseline` / `--baseline` store fingerprints only (`sha256(pattern, file, value)`).
- **Inline ignore:** `agent-redact-ignore` (same line) and `agent-redact-ignore-next-line`. Honoured only in scan/audit modes, never for redaction, and never by the Claude Code hook.
- **GitHub Action:**
  - new `baseline` and `sarif-file` inputs;
  - annotations now carry the column;
  - line numbers come from a line-start index instead of re-splitting the file for every finding.
- **Multi-file in-place mode** accepts directories, skips binaries and rewrites only files that contain secrets.

### 🛡️ Claude Code hook
- **`agent-redact hook [--block-writes] [--config <path>]`** reads the hook event JSON on stdin and exits 2 to block. It covers:
  - prompts containing secrets;
  - `Read` of files with secrets;
  - `Grep` in any output mode when the searched files include a secret file. The regex is never evaluated (no ripgrep/JS differential, no ReDoS), and only simple globs narrow the check;
  - `Bash` commands that contain secrets or print secret files;
  - other tools whose input contains secrets or whose path arguments point at a secret file.

  Messages name secret types, never values.
- **Fail closed:**
  - large files are scanned in full, and reads above 64 MB are refused;
  - UTF-16 is decoded, and printable strings in binaries are scanned;
  - unexpected errors block;
  - inline ignore comments are not honoured;
  - from the agent-writable project config, only additive settings are used (`allowlist`/`include`/`exclude` require an explicit `--config`).

### 🔒 Git hardening
- Scan mode runs git with `core.fsmonitor=false` (no untracked cache, no pager, and no `core.excludesFile`, so a repo-local exclude cannot hide files). It descends into submodules. A test showed that a scanned directory's own `.git/config` could otherwise execute a command through `git ls-files`.
- Staged content is read with `git cat-file blob`, which applies no textconv or filters.

### 🔧 Internal
- **Single version source:** `src/version.ts`, used by the CLI, MCP server and SARIF reports; a test keeps it equal to `package.json`.

### ✨ Streaming & SDK round-trips
- **`StreamingUnmasker`, `unmaskTextStream`, `createUnmaskStream`:** restore placeholders in streamed LLM output even when one is split across chunks. A chunk tail is held back only while it is the start of a placeholder that exists in the vault, so ordinary `[` text is never delayed.
- **`unmaskAnthropicStream` / `unmaskOpenAIStream`:** adapters for the Messages and Chat Completions event streams, covering text deltas and tool-call JSON (restored secrets are JSON-escaped, so `partial_json` / `arguments` stay valid).
- **`redactDeep` / `unmaskDeep`:** sanitize or restore every string in a request/response object with one shared vault, including `tool_use` inputs. Base64 payloads and `data:` URLs are skipped. Inputs are never mutated.
- **`wrapAgent`:** now also deep-unmasks plain-object responses and stream-unmasks `async function*` responses; class instances are still returned untouched. ⚠️ Object responses are now returned as a restored deep copy, no longer the same reference.
- **Exfiltration guard (deny by default):** model-generated tool-call inputs are **not** unmasked by default, because a prompt-injected model could otherwise route a secret into a network-bound tool argument. Covered shapes:
  - Anthropic `tool_use` / `server_tool_use` / `mcp_tool_use` `input`, and `partial_json`;
  - OpenAI `arguments`, with or without `name`;
  - Responses API `function_call_arguments` events;
  - Gemini and LangChain `args`, and Vercel AI SDK `input`.

  Opt in with `unmaskToolInputs: true` or a per-tool predicate (`unmaskDeep`, both stream adapters, `wrapAgent`). The stream adapters pass unrecognised event/chunk shapes through unchanged (fail closed).
- **Base64 fails closed in `redactDeep`:** content that is not actually base64 is redacted normally, and text documents encoded as base64 are decoded, redacted and re-encoded. Only genuine binary is skipped.
- **`Vault.unmask(text, encode?)`:** optional `encode` for restored secrets. The unmask regex is cached between calls instead of being rebuilt every time.
- README: removed the claim of Fastify/Next.js middleware (only Express/Connect middleware exists).

### ⚡ Performance (quadratic → linear)
- **Overlap resolution** used a nested scan over accepted matches (O(m²)): a 2 MB log with 100k IP addresses took 18.8 s although the regexes ran in 17 ms. A coverage bitmap now makes it linear (~0.3 s).
- **Reversible placeholder allocation** rescanned the whole document for every new secret: 40k emails took 11 s, now ~0.2 s.
- **Email pattern ReDoS:** unbounded quantifiers backtracked quadratically, so 80 KB of `a-a-a-…` took 10 s, which is a denial-of-service vector through the Express middleware and the MCP server. RFC 5321 length limits make it linear with identical matches on normal text.
- **Private key pattern:** many `BEGIN` markers without `END` rescanned to the end of input (1.3 MB took 4.3 s); the body can no longer run past another `BEGIN`.
- New `tests/perf.test.ts` guards these cases with generous time thresholds.

### 🔍 GitHub Action
- Binary files are skipped by content sniffing (NUL byte in the first 8 KB, like git), not only by extension. Fonts, videos, jars and extensionless binaries previously produced false findings.
- New `max-file-size` input (MB, default 5); oversized files are skipped and reported in the log and step summary.
- File selection is shared with the MCP server through `src/core/files.ts`.

### 📦 Packaging
- The npm tarball no longer ships source maps, the GitHub Action bundle or the unused CJS CLI: 329.5 kB → 93.7 kB.

### 📝 Docs
- Pattern matrix lists all built-in patterns (basic-auth URLs, Telegram, Twilio API key, Azure, GCP OAuth, DigitalOcean, Mailgun, Vietnamese phones); JWT severity corrected to CRITICAL.
- Replaced inaccurate "zero-latency", "O(1) memory" and "zero runtime dependencies" claims with measured numbers. The core engine is dependency-free, but the MCP server and CLI use `@modelcontextprotocol/sdk` and `zod`.

---

## [0.1.5] - 2026-11-05

### 🔒 Leak fixes
- **Tokens whose last character is `-` were skipped.** Patterns over a base64url alphabet ended with `\b`, which cannot match between a final `-` and a following space or punctuation. Fixed-length patterns therefore missed the whole token (Telegram, GCP `GOCSPX-`, Google `AIza`, SendGrid, GitLab), about 1 token in 64. Variable-length ones (Anthropic, OpenAI project keys, Discord, JWT) left the final `-` visible. These patterns now end with `(?![A-Za-z0-9_])`, which behaves exactly like `\b` for every other ending.

### 🎯 Accuracy
- IPv4: four-part version numbers after `v` / `ver` / `version` (any case, optional `:`/`=`) are no longer redacted. The previous `(?<![vV])` lookbehind had no effect.

### 🧰 Vault / MCP
- `Vault.findEvictedPlaceholders(text)` lists placeholders (names only) that the `maxEntries` cap evicted.
- MCP `unmask_text` now warns when placeholders could not be restored because they were evicted, instead of silently leaving them in the output file.
- Eviction now drops every secret mapped to the evicted placeholder.
- `createMcpServer({ vaultMaxEntries })` makes the session vault cap configurable (default 10,000).

---

## [0.1.4] - 2026-11-05

### ⚠️ Behavior Change
- **Capturing groups no longer cause partial redaction.** Previously, any regex with a capturing group redacted only group 1, so a custom pattern like `(acme|corp)_[A-Za-z0-9]{32}` left the token body visible. The whole match is now redacted unless the pattern declares `secretGroup` (number or name) or uses a named `(?<secret>...)` group. Built-in assignment patterns (AWS secret key, generic entropy) declare `secretGroup: 1` and are unchanged. Custom patterns that relied on implicit group 1 now redact more, never less.

### 🔒 Leak Fixes & New Providers
- **Added missing security providers:**
  - Telegram bot tokens (`<digits>:<35 chars>`) -> `[REDACTED_TELEGRAM_BOT_TOKEN]`
  - Twilio API keys (`SK...`) -> `[REDACTED_TWILIO_API_KEY]`
  - Azure Storage Connection strings / AccountKeys -> `[REDACTED_AZURE_STORAGE_KEY]`
  - GCP OAuth client secrets (`GOCSPX-...`) -> `[REDACTED_GCP_OAUTH_CLIENT_SECRET]`
  - DigitalOcean Personal Access Tokens (`dop_v1_...`) -> `[REDACTED_DIGITALOCEAN_TOKEN]`
  - Mailgun API keys (`key-...`) -> `[REDACTED_MAILGUN_API_KEY]`
- **Pattern precision improvements:**
  - Added Vietnamese landlines (`024`, `028`, and provincial `02x` codes) to phone pattern.
  - Restricted credit card number separators to spaces and hyphens (`[- ]`), preventing digits split across lines in markdown tables from being falsely merged.
  - Added lookbehind guard to IPv4 pattern (`(?<![vV])`) to prevent matching software version strings like `v1.0.0.1`.
- **Stripe keys longer than 99 characters** were skipped entirely (bounded quantifier + `\b`); the pattern is now unbounded.
- **Slack user/refresh tokens** (`xoxp-`/`xoxe-` with three numeric segments) were not detected.
- **High-entropy secrets longer than `maxLength`** were cut at 120 characters, leaving the tail visible; the whole token is now redacted (entropy is judged on the first `maxLength` characters).
- **Stream: oversized private key blocks** (>1 MB without END) leaked body lines that arrived in later chunks; the stream now keeps discarding until the END marker, including one split across chunks.

### 🛡️ MCP Server Hardening
- **File size cap (5 MB):** `scan_file` refuses files exceeding 5 MB to prevent context explosion and server timeouts.
- **Binary file protection:** `scan_file` inspects the initial byte header and rejects binary files containing null bytes.
- **Bounded session vault:** Session vault capped at 10,000 entries with automatic oldest entry eviction to prevent unbounded memory growth.
- **Default root protection:** Does not default to filesystem root or user home directory without explicit `AGENT_REDACT_ALLOWED_DIR`.
- **Preserved file permissions:** `scan_file({ inPlace })` preserves existing executable permissions on POSIX.

### 🧯 CLI Hardening & Validation
- **CLI `-r -i` without `--vault-out`** destroyed the original values (placeholders could never be restored); it now exits with code 2.
- **CLI multi-file mode** rewrote earlier files and then aborted on an unreadable file before saving the vault; all inputs are now read first and the vault is written before any file is modified. Files without leaks are no longer rewritten.
- **Strict CLI argument validation:** Rejects unknown flags (e.g. `--ouput`) and value flags missing arguments with exit code 2.
- **Multi-file flag incompatibility check:** Refuses combinations of multiple input files with `-o`, `--unmask`, or `-j` with exit code 2.

### 🧰 Validation & Tooling
- Custom patterns missing `id`/`name`/`regex`/`placeholder` now fail with a clear error instead of producing `[REDACTED_undefined]`.
- Engine `include` option preserves custom patterns and entropy detector.
- `Vault.fromJSON` validates entries and reports the failing index without echoing secret values.
- GitHub Action annotations escape `%`, `,`, `:` and newlines in file paths/messages per the workflow-command spec.
- Entropy regex and `isHighEntropyToken` share one default `minLength` (20).
- Added `.gitattributes` (`eol=lf`) so `dist/` source maps build identically on Windows and Linux CI.
- README: documented `AGENT_REDACT_ALLOWED_DIR`, `.bak` backups, `secretGroup`, exact-match allowlist and fail-closed PEM streaming.

---

## [0.1.3] - 2026-11-05

### 🔒 Security & Sandbox Hardening
- **MCP Symlink & Junction Resolution**: Sandbox verification now checks real canonical targets (`realpathSync.native`), completely preventing sandbox escapes via planted symlinks, junctions, or NTFS alternate data streams.
- **VCS Hook Protection**: Refused all write operations targeting `.git` directory trees (including `.git.` / `.git ` and 8.3 short name `GIT~1`), preventing malicious prompt injections from overwriting Git hooks.
- **Backup File Preservation**: `scan_file({ inPlace: true })` uses atomic unique allocation (`.bak`, `.bak.1`, ...) with `wx` flag and never overwrites an existing backup.
- **Strict File Permissions**: Enforced `0600` permissions (`rw-------`) via `fchmodSync` on open file descriptors and existing vault files.
- **Release Workflow Fix**: Gated npm publish on job-level token boolean, failing loudly if `NPM_TOKEN` is missing, and enforcing git tag version parity with `package.json`.

### 🎯 Pattern Precision
- **IPv6 Code Protection**: Added validator to distinguish real IPv6 addresses from Python slice indices (`arr[::2]`, `arr[1::2]`) and C++/Rust hex namespaces (`db::add`, `dead::beef`).
- **URL Path Disambiguation**: Excluded path slashes from userinfo in database and basic-auth URL regexes, eliminating false positives on `http://localhost:5173/@vite/client` and npm registry scopes (`@types/node`).
- **Domestic Vietnamese Phone Numbers**: Added support for 10-digit Vietnamese local mobile numbers (`0912 345 678`, `0912345678`, `03...`, `05...`, `07...`, `08...`, `09...`).

### ⚡ Vault & Stream Hardening
- **Reversible Custom Formatter Invariant**: Custom formatters that return identical placeholders for different secrets now fail fast with an informative error rather than silently returning corrupted credentials.
- **Idempotent Vault Restoration**: `Vault.restoreEntry` is now idempotent and `Vault.size` accurately counts distinct secrets.
- **Stream Unclosed PEM Redaction**: Incomplete private key PEM blocks exceeding stream buffers or reaching EOF are masked as `[REDACTED_PRIVATE_KEY]`, preventing raw key body lines from leaking unredacted.
- **CLI Quiet Check**: Running `--check` on a single file suppresses stdout streaming of the entire file, keeping pre-commit hooks clean and concise.

---

## [0.1.2] - 2026-11-05

### ⚠️ Breaking Changes
- **`RedactMatch.matchedText` is now optional (`matchedText?: string`)**: To guarantee zero credential leakage when serializing scan results to JSON, logging, or passing outputs between tools, `matchedText` is omitted by default from all match objects. If your application explicitly requires the raw matched secret string, pass `{ includeMatchedText: true }` in `RedactOptions`.

### 🔒 Security Fixes
- **JSON Leak Prevention**: Added custom non-enumerable `toJSON` serializer to `RedactResult` that excludes raw `vault` and unmasked credentials from `JSON.stringify()`.
- **Object Spread Protection**: `vault` property on `RedactResult` is defined with `enumerable: false` so that object spreading (`{ ...result }`) never copies the raw secret store into serialized outputs.
- **MCP Context Isolation**: `unmask_text` in Model Context Protocol (MCP) server requires `outputFilePath` and writes restored secrets directly to disk with mode `0600` without exposing plaintext secrets in the LLM conversation context.
- **MCP Path Sandboxing**: Restricted all MCP file operations (`scan_file`, `unmask_text`) to the active workspace or OS temp directory to eliminate arbitrary file write / path traversal risks.
- **In-Place File Backup**: `scan_file` with `inPlace: true` automatically creates a `${filePath}.bak` backup before modifying files on disk.
- **Vault File Permissions**: CLI `--vault-out` and MCP disk writes now enforce `0600` permissions (`rw-------`) on POSIX environments to protect vault files.
- **Allowlist Exact Matching**: Allowlist verification now enforces exact equality (`secret === al && al.length > 0`), eliminating vulnerabilities where substring matching or empty strings (`""`) exempted secrets from being redacted.
- **Zero-Width Regex Loop Protection**: The redaction engine now advances `regex.lastIndex` on zero-length matches (e.g., lookahead expressions like `(?=a)`), preventing infinite execution loops.

### 🎯 Pattern Enhancements
- **IPv6 High Fidelity**: Re-engineered IPv6 regex to eliminate severe false positives on log timestamps (`10:45:30`), JavaScript code/ternaries (`{a:1, b:2}`, `x ? a:b`), and MAC addresses (`aa:bb:cc:dd:ee:ff`) by requiring at least 3 colons or `::` compression; added exact loopback (`::1`) detection with non-word lookarounds.
- **Phone Numbers**: Enforced international phone number structure and length constraints to prevent false positives on arithmetic or variable offsets (`n = n +1000;`).
- **HTTP Basic Authentication URL**: Added dedicated `basicAuthUrlPattern` (`https://user:pass@host/path`) with `CRITICAL` priority to prevent basic-auth credentials from being erroneously matched as email addresses.
- **Database URLs**: Added support for IP hostnames without paths (`postgres://user:pass@10.0.0.5:5432`), Redis connections with empty usernames (`redis://:pass@host:6379/0`), and MongoDB SRV URLs with query parameters.
- **OpenAI API Keys**: Extended regex length `{40,}` to match long project keys (`sk-proj-...`) exceeding 160 characters.
- **Private Keys**: Added full support for PGP Private Key blocks (`-----BEGIN PGP PRIVATE KEY BLOCK-----`) and Encrypted PKCS#8 private keys (`-----BEGIN ENCRYPTED PRIVATE KEY-----`).
- **Credit Cards**: Added support for hyphen and space groupings (`4111 1111...`, `4111-1111...`) combined with Luhn checksum validation.

### ⚡ Stream Engine Improvements
- **UTF-8 Multibyte Protection**: Switched to `StringDecoder('utf8')` to prevent corruption of multi-byte UTF-8 characters (Vietnamese diacritics, emoji, CJK) across streaming chunk boundaries.
- **Certificate & Key Demuxing**: Stream engine pairs specific `PEM_BEGIN_PATTERN` and `PEM_END_PATTERN` types, preventing public certificates from prematurely flushing private keys across chunk boundaries.

### 🛠️ CLI & Pre-Commit
- **Pipe Mode Exit Code**: Piping stdin (`echo "key" | agent-redact`) and single-file redactions now return exit code `0` by default, ensuring compatibility with Python `subprocess.run(check=True)` and shell pipelines.
- **Explicit Check Flags**: Added `--check` and `--fail-on-leak` flags to exit with code `1` when secrets are detected.
- **Multi-File Pre-commit**: CLI supports scanning multiple file arguments sequentially and exits with code `1` if any file contains unmasked secrets.

### 🌐 Ecosystem & CI/CD
- **GitHub Action Node 24**: Upgraded `action.yml` to `node24` runner and bundled pre-built `dist/` directly in git.
- **Multi-OS CI Matrix**: CI workflows now test all 79 test cases across **Ubuntu**, **Windows**, and **macOS** on **Node 20, 22, and 24**.

---

## [0.1.1] - 2026-11-04
- Official public publishing to npm registry.
- Zero runtime dependencies for core scanning engine.
- 23+ security regex patterns.
- Model Context Protocol (MCP) server integration (`agent-redact-mcp`).
- Bidirectional session vault with reversible placeholder masking.

---

## [0.1.0] - 2026-11-04
- Initial release and architecture prototype.

