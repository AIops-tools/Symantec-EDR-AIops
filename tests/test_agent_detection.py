"""Agent identity environment markers remain stable during product renames."""

from symantec_edr_aiops.governance.audit import detect_agent


def test_codex_session_marker(monkeypatch):
    monkeypatch.setenv("CODEX_SESSION", "test")
    assert detect_agent() == "codex"
