# Changelog

All notable changes to `agent-redact` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### ⚠️ Behavior change
- **Capturing groups no longer cause partial redaction.** Previously, any regex with a capturing group redacted only group 1, so a custom pattern like `(acme|corp)_[A-Za-z0-9]{32}` left the token body visible. The whole match is now redacted unless the pattern declares `secretGroup` (number or name) or uses a named `(?<secret>...)` group. Built-in assignment patterns (AWS secret key, generic entropy) declare `secretGroup: 1` and are unchanged. Custom patterns that relied on implicit group 1 now redact more, never less.

### 🔒 Leak fixes
- **Stripe keys longer than 99 characters** were skipped entirely (bounded quantifier + `\b`); the pattern is now unbounded.
- **Slack user/refresh tokens** (`xoxp-`/`xoxe-` with three numeric segments) were not detected.
- **High-entropy secrets longer than `maxLength`** were cut at 120 characters, leaving the tail visible; the whole token is now redacted (entropy is judged on the first `maxLength` characters).
- **Stream: oversized private key blocks** (>1 MB without END) leaked body lines that arrived in later chunks; the stream now keeps discarding until the END marker, including one split across chunks.

### 🧯 Data-loss fixes
- **CLI `-r -i` without `--vault-out`** destroyed the original values (placeholders could never be restored); it now exits with code 2.
- **CLI multi-file mode** rewrote earlier files and then aborted on an unreadable file before saving the vault; all inputs are now read first and the vault is written before any file is modified. Files without leaks are no longer rewritten.
- **MCP `scan_file({ inPlace })`** reset the sanitized file's permissions to `0644` (scripts lost their executable bit); existing permissions are now preserved. Restored-secret files from `unmask_text` are still forced to `0600`.

### 🧰 Validation & tooling
- Custom patterns missing `id`/`name`/`regex`/`placeholder` now fail with a clear error instead of producing `[REDACTED_undefined]`.
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

