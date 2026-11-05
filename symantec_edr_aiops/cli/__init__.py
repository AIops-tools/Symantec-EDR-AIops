"""CLI commands delegate to governed EDR MCP tools."""

from __future__ import annotations

import json

import typer

from symantec_edr_aiops.governance import BudgetExceeded
from symantec_edr_aiops.mcp_server.tools import edr

app = typer.Typer(name="symantec-edr-aiops", no_args_is_help=True)


def governed(result: dict) -> dict:
    if result.get("outcomeUnknown"):
        typer.echo(json.dumps(result, ensure_ascii=False), err=True)
        raise typer.Exit(2)
    if result.get("error"):
        typer.echo(json.dumps(result, ensure_ascii=False), err=True)
        raise typer.Exit(1)
    return result


def _emit(result: dict) -> None:
    typer.echo(json.dumps(governed(result), ensure_ascii=False, indent=2))


@app.command("appliances")
def appliances() -> None:
    _emit(edr.edr_appliances())


@app.command("incidents")
def incidents(
    start_time: str, end_time: str, limit: int = 100, query: str = "", next_cursor: str = ""
) -> None:
    _emit(edr.edr_incidents(start_time, end_time, limit, query, next_cursor))


@app.command("events")
def events(
    start_time: str, end_time: str, limit: int = 100, query: str = "", next_cursor: str = ""
) -> None:
    _emit(edr.edr_events(start_time, end_time, limit, query, next_cursor))


@app.command("audit-events")
def audit_events(
    start_time: str, end_time: str, limit: int = 100, query: str = "", next_cursor: str = ""
) -> None:
    _emit(edr.edr_audit_events(start_time, end_time, limit, query, next_cursor))


def main() -> None:
    try:
        app()
    except BudgetExceeded as exc:
        typer.echo(f"Budget stopped the operation: {exc}", err=True)
        raise typer.Exit(1) from exc
