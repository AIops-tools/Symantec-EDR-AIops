"""CLI delegates to the same governed MCP tool."""

from typer.testing import CliRunner


def test_cli_delegates(monkeypatch):
    from symantec_edr_aiops import cli

    calls = []

    def fake(*args):
        calls.append(args)
        return {"data": {"ok": True}}

    monkeypatch.setattr(cli.edr, "edr_appliances", fake)
    result = CliRunner().invoke(cli.app, ["appliances"])
    assert result.exit_code == 0
    assert len(calls) == 1


def test_cli_error_exits_one(monkeypatch):
    from symantec_edr_aiops import cli

    monkeypatch.setattr(cli.edr, "edr_appliances", lambda *args: {"error": "HTTP 503"})
    result = CliRunner().invoke(cli.app, ["appliances"])
    assert result.exit_code == 1
