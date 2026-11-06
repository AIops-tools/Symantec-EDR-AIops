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


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["query", "next_cursor"])
@tool_errors()
def edr_incident_events(
    start_time: str, end_time: str, limit: int = 100, query: str = "", next_cursor: str = ""
) -> dict:
    """[READ] Search incident events over at most 30 days."""
    return ops.incident_events(get_connection(), start_time, end_time, limit, query, next_cursor)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["query", "next_cursor"])
@tool_errors()
def edr_incident_lineage_events(
    start_time: str, end_time: str, limit: int = 100, query: str = "", next_cursor: str = ""
) -> dict:
    """[READ] Search incident lineage events."""
    return ops.incident_lineage_events(
        get_connection(), start_time, end_time, limit, query, next_cursor
    )


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["query", "next_cursor"])
@tool_errors()
def edr_system_activities(
    start_time: str, end_time: str, limit: int = 100, query: str = "", next_cursor: str = ""
) -> dict:
    """[READ] Search system activities over at most 7 days."""
    return ops.system_activities(get_connection(), start_time, end_time, limit, query, next_cursor)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["query", "next_cursor"])
@tool_errors()
def edr_entities(query: str, limit: int = 100, next_cursor: str = "") -> dict:
    """[READ] Search EDR entities."""
    return ops.entities(get_connection(), query, limit, next_cursor)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["query", "next_cursor"])
@tool_errors()
def edr_file_entities(query: str, limit: int = 100, next_cursor: str = "") -> dict:
    """[READ] Search file entities."""
    return ops.file_entities(get_connection(), query, limit, next_cursor)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["query", "next_cursor"])
@tool_errors()
def edr_adversary_actors(query: str, limit: int = 100, next_cursor: str = "") -> dict:
    """[READ] Search adversary actor feed."""
    return ops.adversary_actors(get_connection(), query, limit, next_cursor)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["query", "next_cursor"])
@tool_errors()
def edr_adversary_files(query: str, limit: int = 100, next_cursor: str = "") -> dict:
    """[READ] Search adversary file feed."""
    return ops.adversary_files(get_connection(), query, limit, next_cursor)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["query", "next_cursor"])
@tool_errors()
def edr_adversary_networks(query: str, limit: int = 100, next_cursor: str = "") -> dict:
    """[READ] Search adversary network feed."""
    return ops.adversary_networks(get_connection(), query, limit, next_cursor)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["sha2"])
@tool_errors()
def edr_file_entity(sha2: str) -> dict:
    """[READ] Read one file entity by SHA-256."""
    return ops.file_entity(get_connection(), sha2)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["command_id"])
@tool_errors()
def edr_sandbox_command(command_id: str) -> dict:
    """[READ] Read sandbox command status."""
    return ops.sandbox_command(get_connection(), command_id)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["sha2"])
@tool_errors()
def edr_sandbox_verdict(sha2: str) -> dict:
    """[READ] Read sandbox verdict by SHA-256."""
    return ops.sandbox_verdict(get_connection(), sha2)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["next_cursor"])
@tool_errors()
def edr_allow_list(limit: int = 50, next_cursor: str = "") -> dict:
    """[READ] List allow policies."""
    return ops.allow_list(get_connection(), limit, next_cursor)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["next_cursor"])
@tool_errors()
def edr_deny_list(limit: int = 50, next_cursor: str = "") -> dict:
    """[READ] List deny policies."""
    return ops.deny_list(get_connection(), limit, next_cursor)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["sha2", "next_cursor"])
@tool_errors()
def edr_sandbox_activities(sha2: str, limit: int = 30, next_cursor: str = "") -> dict:
    """[READ] Read sandbox activities."""
    return ops.sandbox_activities(get_connection(), sha2, limit, next_cursor)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["sha2", "next_cursor"])
@tool_errors()
def edr_sandbox_events(sha2: str, limit: int = 30, next_cursor: str = "") -> dict:
    """[READ] Read sandbox events."""
    return ops.sandbox_events(get_connection(), sha2, limit, next_cursor)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["sha2", "next_cursor"])
@tool_errors()
def edr_sandbox_patterns(sha2: str, limit: int = 30, next_cursor: str = "") -> dict:
    """[READ] Read sandbox patterns."""
    return ops.sandbox_patterns(get_connection(), sha2, limit, next_cursor)
