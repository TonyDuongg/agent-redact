# agent-redact (Python)

Python bindings for [agent-redact](https://github.com/TonyDuongg/agent-redact). This is a thin, dependency-free wrapper around the Node.js CLI, so Python agents get exactly the same detection engine as the npm package.

```bash
pip install agent-redact
```

> **Node.js 22.18+ is still required.** This package contains only the Python wrapper; the detection engine is the Node.js CLI (see below for how it is found).

**Requirements:**
- Python 3.10+
- Node.js 22.18+
- the CLI, from one of these (checked in order):
  1. `AGENT_REDACT_CLI` set to the **absolute** path of `dist/cli/index.js`;
  2. a global `npm install -g agent-redact`;
  3. npm next to `node`: the matching version is installed once into a private user cache (`--ignore-scripts`) and reused.

The CLI is always started as `node <absolute path>`. It is never run through `.cmd`/`.bat` shims, through `npx`, or from a binary found in the current directory, so scanning an untrusted repository cannot hijack it.

```python
from agent_redact import redact, scan, Session

# One-way redaction
result = redact("deploy with AKIA...")       # result.text, result.matches (no secret values)
redact(text, presets=["vn-pii"])             # opt-in presets

# Reversible masking across a whole conversation
with Session() as s:
    safe_prompt = s.redact(user_prompt)      # [AWS_ACCESS_KEY_ID_1] …
    answer = llm(safe_prompt)
    print(s.unmask(answer))                  # placeholders restored locally

# Repository / staged-changes audit
findings = scan(["."])                       # honours .gitignore in git repos
findings = scan(staged=True)                 # what is about to be committed
```

`Session` keeps its vault in a private temporary directory, **encrypted** with a random per-session passphrase that is never written to disk, and deletes it on `close()` or when the `with` block ends.
