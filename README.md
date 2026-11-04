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
// DATABASE_URL=[REDACTED_DATABASE_URI]

console.log(`Detected ${result.totalLeaks} leak(s) in ${result.durationMs}ms`);
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

### 5. Model Context Protocol (MCP) Server (Claude, Cursor, Zed, Windsurf)

`agent-redact` includes a native Model Context Protocol (MCP) server that empowers Claude Desktop and Claude Code to sanitize user input and file content on-the-fly before ingesting it into context.

#### Claude Desktop Configuration
Add `agent-redact` to your `claude_desktop_config.json`:

* **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
* **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

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
| `unmask_text` | Restores `[ANTHROPIC_API_KEY_1]` placeholders in Claude's output back to real keys in local session |
| `scan_file` | Audits and redacts sensitive content in `.env`, config, or log files before Claude reads them |
| `get_vault_status` | Inspects currently vaulted placeholders and timestamps without exposing plaintext secrets |
| `clear_vault` | Wipes in-memory vault when session concludes |
| `list_supported_patterns` | Queries all active secret definitions and threat levels |

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
| **Database URIs** | `postgres://`, `mongodb://`, `mysql://`, `redis://` | `CRITICAL` | `[DATABASE_URI]` |
| **Google Cloud / Gemini** | `AIza[0-9A-Za-z_-]{35}` | `HIGH` | `[GOOGLE_API_KEY]` |
| **Slack Tokens** | `xoxb-...`, `xoxp-...`, `xapp-...` | `HIGH` | `[SLACK_TOKEN]` |
| **Hugging Face Token** | `hf_[a-zA-Z0-9]{34}` | `HIGH` | `[HUGGINGFACE_TOKEN]` |
| **GitLab PAT** | `glpat-[0-9a-zA-Z-_]{20,}` | `HIGH` | `[GITLAB_TOKEN]` |
| **PII: Emails & IPv4** | RFC 5322 emails, public/private IPs | `MEDIUM` | `[EMAIL_ADDRESS]`, `[IPV4_ADDRESS]` |
| **PII: SSN & Cards** | US SSN, Major Credit Cards | `CRITICAL` | `[US_SSN]`, `[CREDIT_CARD]` |

---

## 🗺️ Roadmap & Milestones

* [x] **v1.0 (Core Engine & CLI)**:
  * High-performance single-pass regex scanner for 20+ secret categories.
  * Conflict resolution algorithm based on token severity.
  * Dual ESM/CJS build targeting Node.js 20+.
  * Zero runtime dependencies.
* [x] **v1.1 (Reversible Session Vault)**:
  * In-memory Vault with bidirectional placeholder substitution.
  * Batch unmasking with token integrity preservation.
* [x] **v1.2 (Model Context Protocol Integration)**:
  * Official **Model Context Protocol (MCP)** server for Claude Desktop & Claude Code.
  * 6 dedicated tools: `redact_text`, `unmask_text`, `scan_file`, `get_vault_status`, `clear_vault`, `list_supported_patterns`.
* [ ] **v1.3 (Framework Adapters)**:
  * Express / Fastify / Next.js middleware adapters.
  * GitHub Action for CI/CD pre-commit secret screening.

---

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) and submit PRs with corresponding unit tests.

```bash
# Run test suite
npm test

# Type checking
npm run typecheck

# Build bundle
npm run build
```

---

## 📄 License

[MIT](LICENSE) © 2025-2026 Agent Redact Contributors.

