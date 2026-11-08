# Contributing to agent-redact 🛡️

First off, thank you for considering contributing to `agent-redact`! It's people like you who make this tool a powerful, zero-leak defense layer for the open-source AI community.

---

## 🛠️ Development Setup

### Prerequisites
* **Node.js**: `v22.18.0` or higher
* **npm**: `v10.0.0` or higher
* **git**

### Getting Started

1. **Fork and clone** the repository:
   ```bash
   git clone https://github.com/TonyDuongg/agent-redact.git
   cd agent-redact
   ```

2. **Install dependencies**:
   ```bash
   npm install
   ```

3. **Run unit tests**:
   ```bash
   npm test
   ```

4. **Run TypeScript typecheck**:
   ```bash
   npm run typecheck
   ```

5. **Build bundles**:
   ```bash
   npm run build
   ```

---

## 🔍 How to Add a New Secret or PII Pattern

We welcome contributions expanding secret pattern coverage! To add a new pattern:

1. Open `src/patterns/credentials.ts` (for API keys, tokens, certificates) or `src/patterns/pii.ts` (for personal data).
2. Define a new `RedactPattern`:
   ```typescript
   export const myProviderTokenPattern: RedactPattern = {
     id: 'myprovider-token',
     name: 'MyProvider Token',
     category: 'credential',
     severity: 'critical', // 'critical' | 'high' | 'medium' | 'low'
     regex: /\bmyprov_[A-Za-z0-9]{32}\b/g,
     placeholder: 'MYPROVIDER_TOKEN',
     description: 'Authentication token for MyProvider service'
   };
   ```
3. Add the pattern to the exported `CREDENTIAL_PATTERNS` or `PII_PATTERNS` array.
4. **Write unit tests** in `tests/`:
   * Verify positive matches on realistic dummy tokens (use `sampleKey(...)` dynamic assembly to avoid tripping static Git push protection scanners).
   * Verify negative matches (no false positives on normal text).
5. Ensure all tests pass (`npm test`) and type checking passes (`npm run typecheck`).

### Checking AI provider patterns with real keys

`scripts/verify-provider-keys.mjs` runs the built patterns (`npm run build` first) against **real** keys taken from environment variables, and prints only `provider: PASS/FAIL/SKIPPED`. Never paste real keys into issues, PRs or chats, and never commit them.

```powershell
# PowerShell: take the key from the clipboard so it never lands in shell history
$env:GROQ_KEY = Get-Clipboard; node scripts/verify-provider-keys.mjs --explain; Remove-Item Env:GROQ_KEY
```

```bash
# bash / zsh: read the key without echoing it
read -rs GROQ_KEY && export GROQ_KEY && node scripts/verify-provider-keys.mjs --explain; unset GROQ_KEY
```

Variables: `OPENROUTER_KEY`, `GROQ_KEY`, `XAI_KEY`, `PERPLEXITY_KEY`, `REPLICATE_KEY`, `HF_ORG_KEY`, `LANGSMITH_KEY` (the usual SDK names such as `GROQ_API_KEY` work too). `--explain` adds non-secret hints to failures: the reason, the length, and which character classes occur.

---

## 📐 Coding Conventions

* **Zero Runtime Dependencies**: The core scanning engine (`src/core/`) must remain pure TypeScript with zero third-party packages at runtime.
* **Strict Type Safety**: All TypeScript code must compile under `strict: true` and `noUncheckedIndexedAccess: true`.
* **Sub-Millisecond Performance**: Regexes must avoid catastrophic backtracking (`evil regexes`). Test complex regexes against worst-case inputs.

---

## 📬 Pull Request Guidelines

1. Create a feature branch: `git checkout -b feat/my-new-pattern`.
2. Commit with conventional commit messages: `feat: add support for XYZ token pattern`.
3. Push to your branch and open a PR against `main`.
4. Ensure all GitHub Actions CI checks pass.

---

## 🚀 Releasing (maintainers)

1. Open a PR that bumps the version in all five places (`package.json`, `package-lock.json`, `src/version.ts`, `python/pyproject.toml`, `python/src/agent_redact/__init__.py`) and turns `[Unreleased]` in `CHANGELOG.md` into `[x.y.z] - date`.
2. Merge it with a merge commit.
3. Push an annotated tag `vX.Y.Z` on the merge commit. Two workflows start:
   * `release.yml` checks the version and publishes to npm;
   * `release-python.yml` builds and tests the Python package, checks that the tagged commit is on `main`, waits until the same version is on npm, and publishes to PyPI through Trusted Publishing (environment `pypi`).
4. Create the GitHub Release from the `CHANGELOG.md` entry.

`release-python.yml` can also be run manually: the default target is TestPyPI (a dry run). Choosing `pypi` publishes a version that is already tagged, and only from `main` when `python/src` and `pyproject.toml` are unchanged since that tag.

