# agent-redact (Python)

Python bindings for [agent-redact](https://github.com/TonyDuongg/agent-redact). This is a thin, dependency-free wrapper around the Node.js CLI, so Python agents get exactly the same detection engine as the npm package.

**Requirements:**
- Python 3.9+
- Node.js 20+
- the CLI, from one of these (checked in order):
  1. `AGENT_REDACT_CLI` pointing at it;
  2. `npm install -g agent-redact`;
  3. `npx` on `PATH`, which fetches the matching version.

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
