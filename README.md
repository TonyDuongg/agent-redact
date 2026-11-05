# agent-redact 🛡️

[![CI](https://github.com/TonyDuongg/agent-redact/actions/workflows/ci.yml/badge.svg)](https://github.com/TonyDuongg/agent-redact/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/agent-redact.svg?style=flat&color=3178c6)](https://www.npmjs.com/package/agent-redact)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)](package.json)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D20.0.0-blue)](package.json)

> **Universal zero-latency, zero-leak secret & PII redactor for ALL AI Agents, LLMs, and Multi-Agent Workflows.**

Developers and autonomous AI agents (**Claude Code, Cursor, OpenAI, DeepSeek, Google Gemini, Ollama, LangChain, AutoGen, CrewAI**) frequently pipe local logs, source code, `.env` files, and database dumps directly into model prompt contexts. Unintentional leaks of credentials (Anthropic keys, OpenAI tokens, AWS keys, Stripe secrets, JWTs, database URLs) are catastrophic.

`agent-redact` is a universal privacy and secret firewall designed to protect **ANY** agentic architecture:
* Intercepts prompts before network transmission to any cloud or local LLM.
* Reversibly masks sensitive tokens (`[API_KEY_1]`).
* Restores values in generated agent responses without ever leaking secrets to external servers or monitoring tools.
* First-class integration via **CLI**, **Universal TypeScript Wrapper (`wrapAgent`)**, **Model Context Protocol (MCP)**, and **Web Middlewares (Express / Fastify / Next.js)**.

---

## ⚡ Highlights

* **Zero-Latency Performance**: Optimized single-pass regex compilation executes in under **2ms** even for large prompt payloads.
* **Zero Runtime Dependencies**: Pure TypeScript/JavaScript with zero third-party packages at runtime, eliminating supply-chain vulnerabilities.
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

#### Continuous Stream Processing (O(1) Memory for Huge Files)
```typescript
import { createReadStream, createWriteStream } from 'node:fs';
import { createRedactStream } from 'agent-redact';

// Pipe gigabytes of logs without high memory consumption:
createReadStream('system-audit.log')
  .pipe(createRedactStream({ reversible: true }))
  .pipe(createWriteStream('sanitized-audit.log'));
```

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

---

### 4. Express / Fastify / Node.js HTTP Middleware

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
    }
  ]
}
```

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

---

### 8. Multi-Language & Python Agents (LangChain, AutoGen, CrewAI)

For Python, Go, Rust, or any non-Node environment, `agent-redact` integrates seamlessly via CLI subprocess or stdin pipes:

```python
import subprocess
import sys

def sanitize_prompt_for_agent(raw_prompt: str) -> str:
    """Pipes sensitive prompts through agent-redact before sending to any LLM."""
    cmd = ["npx.cmd" if sys.platform == "win32" else "npx", "-y", "agent-redact", "-r"]
    proc = subprocess.run(
        cmd,
        input=raw_prompt,
        text=True,
        encoding="utf-8",
        capture_output=True,
        check=True,
        shell=(sys.platform == "win32")
    )
    return proc.stdout

# Safe to send to LangChain, AutoGen, or CrewAI:
clean_prompt = sanitize_prompt_for_agent("My API key is sk-ant-api03-xxx and DB is postgres://...")
print(clean_prompt)
# => "My API key is [ANTHROPIC_API_KEY_1] and DB is [DATABASE_URL_1]"
```

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
      - uses: actions/checkout@v4
      - name: Scan repository for secrets
        uses: TonyDuongg/agent-redact@main
        with:
          scan-path: '.'
          fail-on-leak: 'true'
          detect-entropy: 'true'
          exclude: 'node_modules,dist,build,.git,coverage'
```

#### GitHub Action Features
* **In-PR Error Annotations**: Pinpoints exact file and line numbers directly on the GitHub PR Diff view.
* **Rich Markdown Step Summary**: Renders an audit table in GitHub Actions summary with detected categories, threat severities, and timestamps.
* **Zero Runtime Overhead**: Executes in milliseconds with native Node.js.

---

### 11. Pre-commit Git Hook

Prevent accidental credential commits locally using [pre-commit](https://pre-commit.com):

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/TonyDuongg/agent-redact
    rev: v0.1.2
    hooks:
      - id: agent-redact
```

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
| **JSON Web Token (JWT)** | `eyJ... . eyJ... . ...` | `HIGH` | `[JWT_TOKEN]` |
| **Database URLs** | `postgres://`, `mongodb://`, `mysql://`, `redis://` | `CRITICAL` | `[DATABASE_URL]` |
| **Google Cloud / Gemini** | `AIza[0-9A-Za-z_-]{35}` | `HIGH` | `[GOOGLE_API_KEY]` |
| **Slack Tokens** | `xoxb-...`, `xoxp-...`, `xapp-...` | `HIGH` | `[SLACK_TOKEN]` |
| **Hugging Face Token** | `hf_[a-zA-Z0-9]{34}` | `HIGH` | `[HUGGINGFACE_TOKEN]` |
| **GitLab PAT** | `glpat-[0-9a-zA-Z-_]{20,}` | `HIGH` | `[GITLAB_TOKEN]` |
| **NPM Access Token** | `npm_[A-Za-z0-9]{36}` | `CRITICAL` | `[NPM_TOKEN]` |
| **SendGrid API Key** | `SG.[A-Za-z0-9_-]{22}.[A-Za-z0-9_-]{43}` | `HIGH` | `[SENDGRID_API_KEY]` |
| **Twilio SID** | `AC[0-9a-fA-F]{32}` | `HIGH` | `[TWILIO_ACCOUNT_SID]` |
| **Supabase Key** | `sbp_[a-zA-Z0-9]{40}` | `CRITICAL` | `[SUPABASE_KEY]` |
| **PII: Emails & IPv4/IPv6** | RFC 5322 emails, IPv4 & IPv6 network addrs | `MEDIUM` | `[EMAIL_ADDRESS]`, `[IPV4_ADDRESS]`, `[IPV6_ADDRESS]` |
| **PII: Phone Numbers** | US & International E.164 formats | `MEDIUM` | `[PHONE_NUMBER]` |
| **PII: SSN & Cards** | US SSN, Major Credit Cards | `CRITICAL` | `[US_SSN]`, `[CREDIT_CARD]` |

---

## ⚡ Benchmark & Performance

Tested with Node.js 24 on realistic multi-agent payloads (~4KB containing code, env tokens, and system logs across 1,000 continuous iterations):

| Metric | Result | Impact |
| :--- | :---: | :--- |
| **Average Latency** | **`0.087 ms`** / scan | Invisible latency overhead in LLM inference loops |
| **Throughput** | **`11,510 scans / sec`** | Easily handles high-concurrency multi-agent servers |
| **Memory Footprint** | `< 25 MB` | Stream processing mode with $O(1)$ memory usage |
| **Supply Chain Risk** | **Zero** | Zero external dependencies for core scanning |

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
  * `createRedactStream`: Node.js Transform stream for continuous log sanitization with $O(1)$ memory.
* [x] **v1.4 (Customization & Shannon Entropy Heuristics)**:
  * `.agentredactrc` / `agent-redact.config.json` configuration file loader.
  * Custom regex patterns and allowlist/whitelist exemption engine.
  * Shannon Entropy calculator ($H \ge 4.3$) for zero-day generic cryptographic keys.
* [x] **v1.5 (CI/CD Ecosystem & GitHub Action)**:
  * Official GitHub Action (`action.yml`) with in-PR file & line annotations.
  * Markdown Step Summary table in GitHub Actions runner.
  * `.pre-commit-hooks.yaml` for pre-commit git hooks.
* [x] **v1.6 (NPM Public Distribution & Multi-OS CI)**:
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

