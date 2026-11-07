"""Python bindings for agent-redact.

This package is a thin, dependency-free wrapper around the agent-redact Node.js CLI, so
Python agents (LangChain, CrewAI, AutoGen, plain SDK code) get exactly the same detection
engine as the npm package. It needs Node.js 20+ and one of:

* ``AGENT_REDACT_CLI`` pointing at the CLI (an executable, or ``dist/cli/index.js``),
* ``agent-redact`` on ``PATH`` (``npm install -g agent-redact``), or
* ``npx`` on ``PATH`` (the matching version is fetched on first use).

Secret values are never written to disk in plaintext: :class:`Session` keeps its vault
encrypted with a random per-session passphrase that only lives in this process.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Iterable, Mapping, Sequence

__version__ = "0.1.5"

__all__ = [
    "AgentRedactError",
    "Finding",
    "Match",
    "RedactResult",
    "Session",
    "redact",
    "scan",
    "__version__",
]


class AgentRedactError(RuntimeError):
    """Raised when the CLI cannot be found or exits with an error."""


@dataclass(frozen=True)
class Match:
    """One redacted span. The secret value itself is never included."""

    pattern_id: str
    pattern_name: str
    category: str
    severity: str
    start: int
    end: int
    replacement: str


@dataclass(frozen=True)
class RedactResult:
    text: str
    matches: list[Match] = field(default_factory=list)
    stats: dict[str, int] = field(default_factory=dict)

    @property
    def total_leaks(self) -> int:
        return len(self.matches)

    @property
    def has_leaks(self) -> bool:
        return bool(self.matches)


@dataclass(frozen=True)
class Finding:
    """A finding from :func:`scan`, without the secret value."""

    file: str
    line: int
    column: int
    pattern_id: str
    pattern_name: str
    severity: str
    category: str
    fingerprint: str


def _cli_command() -> list[str]:
    explicit = os.environ.get("AGENT_REDACT_CLI")
    if explicit:
        if explicit.endswith((".js", ".mjs", ".cjs")):
            node = shutil.which("node")
            if not node:
                raise AgentRedactError("AGENT_REDACT_CLI points at a .js file but `node` is not on PATH")
            return [node, explicit]
        return [explicit]
    installed = shutil.which("agent-redact")
    if installed:
        return [installed]
    npx = shutil.which("npx")
    if npx:
        # Pin the CLI to this package's version so results are reproducible
        return [npx, "--yes", f"agent-redact@{__version__}"]
    raise AgentRedactError(
        "agent-redact CLI not found. Install Node.js 20+ and run `npm install -g agent-redact`, "
        "or set AGENT_REDACT_CLI to the CLI path."
    )


def _run(
    args: Sequence[str],
    *,
    stdin: str | None = None,
    env: Mapping[str, str] | None = None,
    ok_codes: Iterable[int] = (0,),
    cwd: str | None = None,
) -> subprocess.CompletedProcess[str]:
    command = [*_cli_command(), *args]
    try:
        proc = subprocess.run(
            command,
            input=stdin if stdin is not None else "",
            capture_output=True,
            text=True,
            encoding="utf-8",
            env=dict(env) if env is not None else None,
            cwd=cwd,
            check=False,
        )
    except OSError as exc:  # e.g. the executable disappeared
        raise AgentRedactError(f"could not start agent-redact: {exc}") from exc
    if proc.returncode not in tuple(ok_codes):
        message = (proc.stderr or proc.stdout or "").strip() or f"exit code {proc.returncode}"
        raise AgentRedactError(message)
    return proc


def _common_flags(presets: Sequence[str], entropy: bool, config: str | None) -> list[str]:
    flags: list[str] = []
    if presets:
        flags += ["--preset", ",".join(presets)]
    if entropy:
        flags.append("--entropy")
    if config:
        flags += ["--config", config]
    return flags


def redact(
    text: str,
    *,
    presets: Sequence[str] = (),
    entropy: bool = False,
    config: str | None = None,
) -> RedactResult:
    """One-way redaction: secrets become ``[REDACTED_<TYPE>]`` placeholders."""
    proc = _run(["--json", *_common_flags(presets, entropy, config)], stdin=text)
    data = json.loads(proc.stdout)
    matches = [
        Match(
            pattern_id=m["patternId"],
            pattern_name=m["patternName"],
            category=m["category"],
            severity=m["severity"],
            start=m["startIndex"],
            end=m["endIndex"],
            replacement=m["replacement"],
        )
        for m in data.get("matches", [])
    ]
    return RedactResult(text=data["text"], matches=matches, stats=data.get("stats", {}))


def scan(
    paths: Sequence[str] = (),
    *,
    staged: bool = False,
    presets: Sequence[str] = (),
    entropy: bool = False,
    config: str | None = None,
    baseline: str | None = None,
    cwd: str | None = None,
) -> list[Finding]:
    """Scan files/directories (honouring .gitignore inside git repos) or the git index."""
    if not paths and not staged:
        raise ValueError("pass at least one path, or staged=True")
    args = [*paths, "--format", "json", *_common_flags(presets, entropy, config)]
    if staged:
        args.append("--staged")
    if baseline:
        args += ["--baseline", baseline]
    proc = _run(args, ok_codes=(0, 1), cwd=cwd)  # exit 1 means "findings present"
    data = json.loads(proc.stdout)
    return [
        Finding(
            file=f["file"],
            line=f["line"],
            column=f["column"],
            pattern_id=f["patternId"],
            pattern_name=f["patternName"],
            severity=f["severity"],
            category=f["category"],
            fingerprint=f["fingerprint"],
        )
        for f in data.get("findings", [])
    ]


class Session:
    """Reversible masking across several calls, e.g. one LLM conversation.

    Placeholders are numbered consistently across calls (``[AWS_ACCESS_KEY_ID_1]``,
    ``[AWS_ACCESS_KEY_ID_2]`` …) and :meth:`unmask` restores them. The vault lives in a
    private temporary directory, encrypted with a random passphrase that is passed to the
    CLI through an environment variable and never written anywhere. Use as a context
    manager (or call :meth:`close`) to delete it.

    >>> with Session() as s:                                    # doctest: +SKIP
    ...     safe = s.redact(user_prompt)
    ...     answer = call_llm(safe)
    ...     print(s.unmask(answer))
    """

    _KEY_ENV = "AGENT_REDACT_PY_SESSION_KEY"

    def __init__(self, *, presets: Sequence[str] = (), entropy: bool = False, config: str | None = None) -> None:
        self._dir = tempfile.mkdtemp(prefix="agent-redact-")
        self._vault = os.path.join(self._dir, "vault.json")
        self._env = {**os.environ, self._KEY_ENV: secrets.token_urlsafe(32)}
        self._flags = _common_flags(presets, entropy, config)
        self._closed = False

    def _vault_flags(self) -> list[str]:
        return ["--vault-key-env", self._KEY_ENV]

    def redact(self, text: str) -> str:
        """Mask secrets with reversible, session-wide numbered placeholders."""
        self._ensure_open()
        args = ["-r", "--vault-out", self._vault, *self._vault_flags(), *self._flags]
        if os.path.exists(self._vault):
            args += ["--vault-in", self._vault]
        return _run(args, stdin=text, env=self._env).stdout

    def unmask(self, text: str) -> str:
        """Restore placeholders produced by this session (unknown ones are left as is)."""
        self._ensure_open()
        if not os.path.exists(self._vault):
            return text
        return _run(["--unmask", self._vault, *self._vault_flags()], stdin=text, env=self._env).stdout

    def close(self) -> None:
        if not self._closed:
            shutil.rmtree(self._dir, ignore_errors=True)
            self._closed = True

    def _ensure_open(self) -> None:
        if self._closed:
            raise AgentRedactError("this Session is closed")

    def __enter__(self) -> "Session":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def __del__(self) -> None:  # best effort cleanup
        try:
            self.close()
        except Exception:
            pass
