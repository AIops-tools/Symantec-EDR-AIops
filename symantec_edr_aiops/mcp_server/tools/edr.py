"""Governed on-prem EDR read tools."""

from symantec_edr_aiops import ops
from symantec_edr_aiops.connection import get_connection
from symantec_edr_aiops.governance import governed_tool
from symantec_edr_aiops.mcp_server._shared import mcp, tool_errors


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors()
def edr_appliances() -> dict:
    """[READ] Read EDR management appliance metadata."""
    return ops.appliances(get_connection())


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["query", "next_cursor"])
@tool_errors()
def edr_incidents(
    start_time: str, end_time: str, limit: int = 100, query: str = "", next_cursor: str = ""
) -> dict:
    """[READ] Search incidents over at most 30 days."""
    return ops.incidents(get_connection(), start_time, end_time, limit, query, next_cursor)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["query", "next_cursor"])
@tool_errors()
def edr_events(
    start_time: str, end_time: str, limit: int = 100, query: str = "", next_cursor: str = ""
) -> dict:
    """[READ] Search events over at most 30 days."""
    return ops.events(get_connection(), start_time, end_time, limit, query, next_cursor)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["query", "next_cursor"])
@tool_errors()
def edr_audit_events(
    start_time: str, end_time: str, limit: int = 100, query: str = "", next_cursor: str = ""
) -> dict:
    """[READ] Search audit events over at most 7 days."""
    return ops.audit_events(get_connection(), start_time, end_time, limit, query, next_cursor)
