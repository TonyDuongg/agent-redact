"""Tests run against the repository's built CLI (dist/cli/index.js) unless
AGENT_REDACT_CLI is already set. Build it first with `npm run build`."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
os.environ.setdefault("AGENT_REDACT_CLI", str(REPO / "dist" / "cli" / "index.js"))

import agent_redact  # noqa: E402
from agent_redact import AgentRedactError, Session, redact, scan  # noqa: E402

# Token-shaped fixtures are assembled at runtime so they never appear verbatim in the repo
AWS = "AKIA" + "IOSFODNN7EXAMPLE"
AWS2 = "AKIA" + "ABCDEFGHIJKLMNOP"


def test_version_matches_npm_package() -> None:
    pkg = json.loads((REPO / "package.json").read_text(encoding="utf-8"))
    assert agent_redact.__version__ == pkg["version"]


def test_redact_returns_text_and_matches_without_values() -> None:
    result = redact(f"key {AWS} end")
    assert result.text == "key [REDACTED_AWS_ACCESS_KEY_ID] end"
    assert result.total_leaks == 1 and result.has_leaks
    assert result.matches[0].pattern_id == "aws-access-key-id"
    assert AWS not in repr(result)


def test_redact_handles_unicode_and_presets() -> None:
    cccd = "079" + "2" + "03" + "012345"
    assert redact(f"Xin chào {AWS} ổn").text == "Xin chào [REDACTED_AWS_ACCESS_KEY_ID] ổn"
    assert cccd in redact(f"CCCD {cccd}").text  # opt-in only
    assert redact(f"CCCD {cccd}", presets=["vn-pii"]).text == "CCCD [REDACTED_VN_CITIZEN_ID]"


def test_unknown_preset_raises() -> None:
    with pytest.raises(AgentRedactError, match="Unknown preset"):
        redact("x", presets=["nope"])


def test_session_numbers_consistently_and_unmasks(tmp_path: Path) -> None:
    with Session() as s:
        first = s.redact(f"first {AWS}")
        second = s.redact(f"second {AWS2} and again {AWS}")
        assert first == "first [AWS_ACCESS_KEY_ID_1]"
        assert second == "second [AWS_ACCESS_KEY_ID_2] and again [AWS_ACCESS_KEY_ID_1]"
        assert s.unmask("use [AWS_ACCESS_KEY_ID_2] then [AWS_ACCESS_KEY_ID_1]") == f"use {AWS2} then {AWS}"

        vault = Path(s._vault)  # noqa: SLF001 - verify the on-disk format
        content = vault.read_text(encoding="utf-8")
        assert json.loads(content)["format"] == "agent-redact-vault"  # encrypted
        assert AWS not in content and AWS2 not in content
        vault_dir = vault.parent
    assert not vault_dir.exists()  # deleted on exit


def test_session_unmask_before_redact_is_identity() -> None:
    with Session() as s:
        assert s.unmask("nothing [AWS_ACCESS_KEY_ID_1]") == "nothing [AWS_ACCESS_KEY_ID_1]"


def test_closed_session_raises() -> None:
    s = Session()
    s.close()
    with pytest.raises(AgentRedactError, match="closed"):
        s.redact("x")


def test_scan_reports_findings_without_values(tmp_path: Path) -> None:
    (tmp_path / "app.env").write_text(f"\nKEY={AWS}\n", encoding="utf-8")
    (tmp_path / "clean.txt").write_text("nothing here", encoding="utf-8")
    findings = scan(["."], cwd=str(tmp_path))
    assert [(f.file, f.line, f.pattern_id) for f in findings] == [("app.env", 2, "aws-access-key-id")]
    assert AWS not in repr(findings)


def test_scan_requires_a_target() -> None:
    with pytest.raises(ValueError):
        scan()


def test_missing_cli_raises_helpful_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_REDACT_CLI", raising=False)
    monkeypatch.setattr(agent_redact, "_safe_which", lambda _name: None)
    with pytest.raises(AgentRedactError, match="not found"):
        redact("x")


def test_relative_cli_override_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_REDACT_CLI", "dist/cli/index.js")
    with pytest.raises(AgentRedactError, match="absolute path"):
        redact("x")


def test_safe_which_ignores_cwd_and_relative_path_entries(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    planted = tmp_path / ("agent-redact.exe" if os.name == "nt" else "agent-redact")
    planted.write_text("#!/bin/sh\necho pwned\n", encoding="utf-8")
    planted.chmod(0o755)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PATH", os.pathsep.join([".", "", str(tmp_path)]))
    assert agent_redact._safe_which("agent-redact") is None  # noqa: SLF001


def test_cli_command_never_uses_shims_or_npx() -> None:
    cmd = agent_redact._cli_command()  # noqa: SLF001
    assert os.path.basename(cmd[0]).lower().startswith("node")
    assert cmd[1].endswith("index.js") and os.path.isabs(cmd[1])
