"""Release shape and governance invariants."""

import asyncio
import tomllib
from pathlib import Path

from typer.testing import CliRunner


def test_version_matches_project_metadata():
    import symantec_edr_aiops

    project = tomllib.loads((Path(__file__).parents[1] / "pyproject.toml").read_text())
    assert symantec_edr_aiops.__version__ == project["project"]["version"]


def test_cli_and_mcp_tools_are_governed():
    from symantec_edr_aiops.cli import app
    from symantec_edr_aiops.mcp_server.server import mcp

    assert CliRunner().invoke(app, ["--help"]).exit_code == 0
    assert len(asyncio.run(mcp.list_tools())) == 20
    assert len(app.registered_commands) == 20
    for name, tool in mcp._tool_manager._tools.items():
        assert tool.fn._is_governed_tool, name
        assert tool.fn._risk_level == "low", name
        assert (tool.fn.__doc__ or "").lstrip().startswith("[READ]"), name
