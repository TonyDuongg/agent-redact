"""The long-lived worker transport (``agent-redact serve --stdio``), the default since 0.4."""

from __future__ import annotations

import os
import threading
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
os.environ.setdefault("AGENT_REDACT_CLI", str(REPO / "dist" / "cli" / "index.js"))

import agent_redact  # noqa: E402
from agent_redact import AgentRedactError, Session, redact  # noqa: E402

AWS = "AKIA" + "IOSFODNN7EXAMPLE"
AWS2 = "AKIA" + "ABCDEFGHIJKLMNOP"


@pytest.fixture(autouse=True)
def fresh_worker(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("AGENT_REDACT_TRANSPORT", raising=False)
    agent_redact._shutdown_worker()  # noqa: SLF001
    yield
    agent_redact._shutdown_worker()  # noqa: SLF001


def _worker():
    return agent_redact._current_worker()  # noqa: SLF001


def test_redact_uses_one_worker_and_matches_the_subprocess_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    text = f"key {AWS} and café ✓"
    first = redact(text)
    worker = _worker()
    assert worker is not None and worker.alive
    second = redact(text)
    assert _worker() is worker  # reused, not restarted

    monkeypatch.setenv("AGENT_REDACT_TRANSPORT", "subprocess")
    via_subprocess = redact(text)
    assert first.text == second.text == via_subprocess.text == "key [REDACTED_AWS_ACCESS_KEY_ID] and café ✓"
    assert first.matches == via_subprocess.matches and first.stats == via_subprocess.stats


def test_worker_calls_are_fast() -> None:
    redact("warm up")
    started = time.perf_counter()
    for _ in range(50):
        redact(f"key {AWS}")
    per_call_ms = (time.perf_counter() - started) / 50 * 1000
    # Spawning Node per call costs ~100-600 ms; the worker is well under this generous bound.
    assert per_call_ms < 50, per_call_ms


def test_session_vault_stays_in_memory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    monkeypatch.setenv("TEMP", str(tmp_path))
    monkeypatch.setenv("TMP", str(tmp_path))
    import tempfile

    monkeypatch.setattr(tempfile, "tempdir", None)
    with Session() as s:
        assert s.redact(f"first {AWS}") == "first [AWS_ACCESS_KEY_ID_1]"
        assert s.redact(f"second {AWS2} and {AWS}") == "second [AWS_ACCESS_KEY_ID_2] and [AWS_ACCESS_KEY_ID_1]"
        assert s.unmask("[AWS_ACCESS_KEY_ID_2]") == AWS2
        assert list(tmp_path.iterdir()) == []  # nothing written to disk


def test_sessions_are_independent_and_closed_sessions_raise() -> None:
    with Session() as a, Session() as b:
        assert a.redact(AWS) == "[AWS_ACCESS_KEY_ID_1]"
        assert b.redact(AWS2) == "[AWS_ACCESS_KEY_ID_1]"
        assert a.unmask("[AWS_ACCESS_KEY_ID_1]") == AWS
        assert b.unmask("[AWS_ACCESS_KEY_ID_1]") == AWS2
    with pytest.raises(AgentRedactError, match="closed"):
        a.redact("x")


def test_dead_worker_fails_closed_then_recovers_for_one_way_redaction() -> None:
    s = Session()
    s.redact(f"first {AWS}")
    _worker().kill()  # simulate a crash

    # One-way redaction transparently starts a new worker
    assert redact(f"k {AWS}").text == "k [REDACTED_AWS_ACCESS_KEY_ID]"
    # The session's vault died with the old worker: never return unmasked or mis-numbered text
    with pytest.raises(AgentRedactError, match="restarted"):
        s.redact(f"second {AWS2}")
    with pytest.raises(AgentRedactError, match="restarted"):
        s.unmask("[AWS_ACCESS_KEY_ID_1]")
    s.close()


def test_unresponsive_worker_times_out(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    hang = tmp_path / "hang.js"
    hang.write_text("process.stdin.resume(); setInterval(() => {}, 1000);\n", encoding="utf-8")
    monkeypatch.setenv("AGENT_REDACT_CLI", str(hang))
    monkeypatch.setattr(agent_redact, "_WORKER_TIMEOUT", 1.0)
    started = time.perf_counter()
    with pytest.raises(AgentRedactError, match="did not respond"):
        redact("x")
    assert time.perf_counter() - started < 10


def test_version_mismatch_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent_redact, "__version__", "9.9.9")
    with pytest.raises(AgentRedactError, match="does not match"):
        redact("x")


def test_oversized_input_is_refused_before_sending(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent_redact, "_MAX_MESSAGE_BYTES", 1024)
    with pytest.raises(AgentRedactError, match="too large"):
        redact("a" * 4096)
    assert redact("small").text == "small"  # the worker is still usable


def test_concurrent_calls_from_threads() -> None:
    errors: list[BaseException] = []

    def work(i: int) -> None:
        try:
            for _ in range(10):
                assert redact(f"t{i} {AWS}").text == f"t{i} [REDACTED_AWS_ACCESS_KEY_ID]"
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=work, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []


def test_changing_the_cli_restarts_the_worker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    redact("x")
    first = _worker()
    monkeypatch.setenv("AGENT_REDACT_CLI", "relative/index.js")
    with pytest.raises(AgentRedactError, match="absolute path"):
        redact("x")
    assert not first.alive


def test_unknown_transport_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_REDACT_TRANSPORT", "tcp")
    with pytest.raises(AgentRedactError, match="AGENT_REDACT_TRANSPORT"):
        redact("x")
