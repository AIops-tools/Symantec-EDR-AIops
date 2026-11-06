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


@app.command("incident-events")
def incident_events(
    start_time: str, end_time: str, limit: int = 100, query: str = "", next_cursor: str = ""
) -> None:
    _emit(edr.edr_incident_events(start_time, end_time, limit, query, next_cursor))


@app.command("incident-lineage-events")
def incident_lineage_events(
    start_time: str, end_time: str, limit: int = 100, query: str = "", next_cursor: str = ""
) -> None:
    _emit(edr.edr_incident_lineage_events(start_time, end_time, limit, query, next_cursor))


@app.command("system-activities")
def system_activities(
    start_time: str, end_time: str, limit: int = 100, query: str = "", next_cursor: str = ""
) -> None:
    _emit(edr.edr_system_activities(start_time, end_time, limit, query, next_cursor))


@app.command("entities")
def entities(query: str, limit: int = 100, next_cursor: str = "") -> None:
    _emit(edr.edr_entities(query, limit, next_cursor))


@app.command("file-entities")
def file_entities(query: str, limit: int = 100, next_cursor: str = "") -> None:
    _emit(edr.edr_file_entities(query, limit, next_cursor))


@app.command("adversary-actors")
def adversary_actors(query: str, limit: int = 100, next_cursor: str = "") -> None:
    _emit(edr.edr_adversary_actors(query, limit, next_cursor))


@app.command("adversary-files")
def adversary_files(query: str, limit: int = 100, next_cursor: str = "") -> None:
    _emit(edr.edr_adversary_files(query, limit, next_cursor))


@app.command("adversary-networks")
def adversary_networks(query: str, limit: int = 100, next_cursor: str = "") -> None:
    _emit(edr.edr_adversary_networks(query, limit, next_cursor))


@app.command("file-entity")
def file_entity(sha2: str) -> None:
    _emit(edr.edr_file_entity(sha2))


@app.command("sandbox-command")
def sandbox_command(command_id: str) -> None:
    _emit(edr.edr_sandbox_command(command_id))


@app.command("sandbox-verdict")
def sandbox_verdict(sha2: str) -> None:
    _emit(edr.edr_sandbox_verdict(sha2))


@app.command("allow-list")
def allow_list(limit: int = 50, next_cursor: str = "") -> None:
    _emit(edr.edr_allow_list(limit, next_cursor))


@app.command("deny-list")
def deny_list(limit: int = 50, next_cursor: str = "") -> None:
    _emit(edr.edr_deny_list(limit, next_cursor))


@app.command("sandbox-activities")
def sandbox_activities(sha2: str, limit: int = 30, next_cursor: str = "") -> None:
    _emit(edr.edr_sandbox_activities(sha2, limit, next_cursor))


@app.command("sandbox-events")
def sandbox_events(sha2: str, limit: int = 30, next_cursor: str = "") -> None:
    _emit(edr.edr_sandbox_events(sha2, limit, next_cursor))


@app.command("sandbox-patterns")
def sandbox_patterns(sha2: str, limit: int = 30, next_cursor: str = "") -> None:
    _emit(edr.edr_sandbox_patterns(sha2, limit, next_cursor))
