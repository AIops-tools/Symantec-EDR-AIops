"""Governed on-prem EDR read tools."""

from typing import Annotated

from pydantic import Field

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
    start_time: Annotated[
        str, Field(description=("ISO 8601 start time with UTC offset for the bounded EDR search."))
    ],
    end_time: Annotated[
        str, Field(description=("ISO 8601 end time with UTC offset; must be after start_time."))
    ],
    limit: Annotated[
        int,
        Field(description=("Maximum rows to return (1–500); follow nextCursor for another page.")),
    ] = 100,
    query: Annotated[
        str,
        Field(
            description=(
                "EDR search expression (at most 10240 characters); "
                "required for entity/feed searches."
            )
        ),
    ] = "",
    next_cursor: Annotated[
        str,
        Field(
            description=(
                "Opaque continuation token from the previous nextCursor; empty starts a search."
            )
        ),
    ] = "",
) -> dict:
    """[READ] Search incidents over at most 30 days.

    Result: items, returned, limit, truncated, nextCursor and totalReported; an absent cursor
    ends continuation.
    """
    return ops.incidents(get_connection(), start_time, end_time, limit, query, next_cursor)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["query", "next_cursor"])
@tool_errors()
def edr_events(
    start_time: Annotated[
        str, Field(description=("ISO 8601 start time with UTC offset for the bounded EDR search."))
    ],
    end_time: Annotated[
        str, Field(description=("ISO 8601 end time with UTC offset; must be after start_time."))
    ],
    limit: Annotated[
        int,
        Field(description=("Maximum rows to return (1–500); follow nextCursor for another page.")),
    ] = 100,
    query: Annotated[
        str,
        Field(
            description=(
                "EDR search expression (at most 10240 characters); "
                "required for entity/feed searches."
            )
        ),
    ] = "",
    next_cursor: Annotated[
        str,
        Field(
            description=(
                "Opaque continuation token from the previous nextCursor; empty starts a search."
            )
        ),
    ] = "",
) -> dict:
    """[READ] Search events over at most 30 days.

    Result: items, returned, limit, truncated, nextCursor and totalReported; an absent cursor
    ends continuation.
    """
    return ops.events(get_connection(), start_time, end_time, limit, query, next_cursor)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["query", "next_cursor"])
@tool_errors()
def edr_audit_events(
    start_time: Annotated[
        str, Field(description=("ISO 8601 start time with UTC offset for the bounded EDR search."))
    ],
    end_time: Annotated[
        str, Field(description=("ISO 8601 end time with UTC offset; must be after start_time."))
    ],
    limit: Annotated[
        int,
        Field(description=("Maximum rows to return (1–500); follow nextCursor for another page.")),
    ] = 100,
    query: Annotated[
        str,
        Field(
            description=(
                "EDR search expression (at most 10240 characters); "
                "required for entity/feed searches."
            )
        ),
    ] = "",
    next_cursor: Annotated[
        str,
        Field(
            description=(
                "Opaque continuation token from the previous nextCursor; empty starts a search."
            )
        ),
    ] = "",
) -> dict:
    """[READ] Search audit events over at most 7 days.

    Result: items, returned, limit, truncated, nextCursor and totalReported; an absent cursor
    ends continuation.
    """
    return ops.audit_events(get_connection(), start_time, end_time, limit, query, next_cursor)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["query", "next_cursor"])
@tool_errors()
def edr_incident_events(
    start_time: Annotated[
        str, Field(description=("ISO 8601 start time with UTC offset for the bounded EDR search."))
    ],
    end_time: Annotated[
        str, Field(description=("ISO 8601 end time with UTC offset; must be after start_time."))
    ],
    limit: Annotated[
        int,
        Field(description=("Maximum rows to return (1–500); follow nextCursor for another page.")),
    ] = 100,
    query: Annotated[
        str,
        Field(
            description=(
                "EDR search expression (at most 10240 characters); "
                "required for entity/feed searches."
            )
        ),
    ] = "",
    next_cursor: Annotated[
        str,
        Field(
            description=(
                "Opaque continuation token from the previous nextCursor; empty starts a search."
            )
        ),
    ] = "",
) -> dict:
    """[READ] Search incident events over at most 30 days.

    Result: items, returned, limit, truncated, nextCursor and totalReported; an absent cursor
    ends continuation.
    """
    return ops.incident_events(get_connection(), start_time, end_time, limit, query, next_cursor)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["query", "next_cursor"])
@tool_errors()
def edr_incident_lineage_events(
    start_time: Annotated[
        str, Field(description=("ISO 8601 start time with UTC offset for the bounded EDR search."))
    ],
    end_time: Annotated[
        str, Field(description=("ISO 8601 end time with UTC offset; must be after start_time."))
    ],
    limit: Annotated[
        int,
        Field(description=("Maximum rows to return (1–500); follow nextCursor for another page.")),
    ] = 100,
    query: Annotated[
        str,
        Field(
            description=(
                "EDR search expression (at most 10240 characters); "
                "required for entity/feed searches."
            )
        ),
    ] = "",
    next_cursor: Annotated[
        str,
        Field(
            description=(
                "Opaque continuation token from the previous nextCursor; empty starts a search."
            )
        ),
    ] = "",
) -> dict:
    """[READ] Search incident lineage events.

    Use for lineage-linked incident events; use edr_incident_events for the broader
    incident-event feed.

    Result: items, returned, limit, truncated, nextCursor and totalReported; an absent cursor
    ends continuation.
    """
    return ops.incident_lineage_events(
        get_connection(), start_time, end_time, limit, query, next_cursor
    )


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["query", "next_cursor"])
@tool_errors()
def edr_system_activities(
    start_time: Annotated[
        str, Field(description=("ISO 8601 start time with UTC offset for the bounded EDR search."))
    ],
    end_time: Annotated[
        str, Field(description=("ISO 8601 end time with UTC offset; must be after start_time."))
    ],
    limit: Annotated[
        int,
        Field(description=("Maximum rows to return (1–500); follow nextCursor for another page.")),
    ] = 100,
    query: Annotated[
        str,
        Field(
            description=(
                "EDR search expression (at most 10240 characters); "
                "required for entity/feed searches."
            )
        ),
    ] = "",
    next_cursor: Annotated[
        str,
        Field(
            description=(
                "Opaque continuation token from the previous nextCursor; empty starts a search."
            )
        ),
    ] = "",
) -> dict:
    """[READ] Search system activities over at most 7 days.

    Result: items, returned, limit, truncated, nextCursor and totalReported; an absent cursor
    ends continuation.
    """
    return ops.system_activities(get_connection(), start_time, end_time, limit, query, next_cursor)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["query", "next_cursor"])
@tool_errors()
def edr_entities(
    query: Annotated[
        str,
        Field(
            description=(
                "EDR search expression (at most 10240 characters); "
                "required for entity/feed searches."
            )
        ),
    ],
    limit: Annotated[
        int,
        Field(description=("Maximum rows to return (1–100); follow nextCursor for another page.")),
    ] = 100,
    next_cursor: Annotated[
        str,
        Field(
            description=(
                "Opaque continuation token from the previous nextCursor; empty starts a search."
            )
        ),
    ] = "",
) -> dict:
    """[READ] Search EDR entities.

    Use for general entity search; use edr_file_entities to restrict the search to file
    entities.

    Result: items, returned, limit, truncated, nextCursor and totalReported; an absent cursor
    ends continuation.
    """
    return ops.entities(get_connection(), query, limit, next_cursor)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["query", "next_cursor"])
@tool_errors()
def edr_file_entities(
    query: Annotated[
        str,
        Field(
            description=(
                "EDR search expression (at most 10240 characters); "
                "required for entity/feed searches."
            )
        ),
    ],
    limit: Annotated[
        int,
        Field(description=("Maximum rows to return (1–100); follow nextCursor for another page.")),
    ] = 100,
    next_cursor: Annotated[
        str,
        Field(
            description=(
                "Opaque continuation token from the previous nextCursor; empty starts a search."
            )
        ),
    ] = "",
) -> dict:
    """[READ] Search file entities.

    Use for file-entity search; use edr_file_entity when a SHA-256 is already known.

    Result: items, returned, limit, truncated, nextCursor and totalReported; an absent cursor
    ends continuation.
    """
    return ops.file_entities(get_connection(), query, limit, next_cursor)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["query", "next_cursor"])
@tool_errors()
def edr_adversary_actors(
    query: Annotated[
        str,
        Field(
            description=(
                "EDR search expression (at most 10240 characters); "
                "required for entity/feed searches."
            )
        ),
    ],
    limit: Annotated[
        int,
        Field(description=("Maximum rows to return (1–100); follow nextCursor for another page.")),
    ] = 100,
    next_cursor: Annotated[
        str,
        Field(
            description=(
                "Opaque continuation token from the previous nextCursor; empty starts a search."
            )
        ),
    ] = "",
) -> dict:
    """[READ] Search adversary actor feed.

    Result: items, returned, limit, truncated, nextCursor and totalReported; an absent cursor
    ends continuation.
    """
    return ops.adversary_actors(get_connection(), query, limit, next_cursor)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["query", "next_cursor"])
@tool_errors()
def edr_adversary_files(
    query: Annotated[
        str,
        Field(
            description=(
                "EDR search expression (at most 10240 characters); "
                "required for entity/feed searches."
            )
        ),
    ],
    limit: Annotated[
        int,
        Field(description=("Maximum rows to return (1–100); follow nextCursor for another page.")),
    ] = 100,
    next_cursor: Annotated[
        str,
        Field(
            description=(
                "Opaque continuation token from the previous nextCursor; empty starts a search."
            )
        ),
    ] = "",
) -> dict:
    """[READ] Search adversary file feed.

    Result: items, returned, limit, truncated, nextCursor and totalReported; an absent cursor
    ends continuation.
    """
    return ops.adversary_files(get_connection(), query, limit, next_cursor)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["query", "next_cursor"])
@tool_errors()
def edr_adversary_networks(
    query: Annotated[
        str,
        Field(
            description=(
                "EDR search expression (at most 10240 characters); "
                "required for entity/feed searches."
            )
        ),
    ],
    limit: Annotated[
        int,
        Field(description=("Maximum rows to return (1–100); follow nextCursor for another page.")),
    ] = 100,
    next_cursor: Annotated[
        str,
        Field(
            description=(
                "Opaque continuation token from the previous nextCursor; empty starts a search."
            )
        ),
    ] = "",
) -> dict:
    """[READ] Search adversary network feed.

    Result: items, returned, limit, truncated, nextCursor and totalReported; an absent cursor
    ends continuation.
    """
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
def edr_sandbox_command(
    command_id: Annotated[str, Field(description="Sandbox command ID returned by the appliance.")],
) -> dict:
    """[READ] Read sandbox command status.

    Result: structured data or an explicit, sanitized operation error.
    """
    return ops.sandbox_command(get_connection(), command_id)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["sha2"])
@tool_errors()
def edr_sandbox_verdict(
    sha2: Annotated[
        str,
        Field(
            description=(
                "64-character hexadecimal SHA-256 identifying the sandbox result."
            )
        ),
    ],
) -> dict:
    """[READ] Read sandbox verdict by SHA-256.

    Result: structured data or an explicit, sanitized operation error.
    """
    return ops.sandbox_verdict(get_connection(), sha2)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["next_cursor"])
@tool_errors()
def edr_allow_list(
    limit: Annotated[
        int,
        Field(description=("Maximum rows to return (10–50); follow nextCursor for another page.")),
    ] = 50,
    next_cursor: Annotated[
        str,
        Field(
            description=(
                "Opaque continuation token from the previous nextCursor; empty starts a search."
            )
        ),
    ] = "",
) -> dict:
    """[READ] List allow policies.

    Result: items, returned, limit, truncated, nextCursor and totalReported; an absent cursor
    ends continuation.
    """
    return ops.allow_list(get_connection(), limit, next_cursor)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["next_cursor"])
@tool_errors()
def edr_deny_list(
    limit: Annotated[
        int,
        Field(description=("Maximum rows to return (10–50); follow nextCursor for another page.")),
    ] = 50,
    next_cursor: Annotated[
        str,
        Field(
            description=(
                "Opaque continuation token from the previous nextCursor; empty starts a search."
            )
        ),
    ] = "",
) -> dict:
    """[READ] List deny policies.

    Result: items, returned, limit, truncated, nextCursor and totalReported; an absent cursor
    ends continuation.
    """
    return ops.deny_list(get_connection(), limit, next_cursor)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["sha2", "next_cursor"])
@tool_errors()
def edr_sandbox_activities(
    sha2: Annotated[
        str,
        Field(
            description=(
                "64-character hexadecimal SHA-256 identifying the sandbox result."
            )
        ),
    ],
    limit: Annotated[
        int,
        Field(description=("Maximum rows to return (10–50); follow nextCursor for another page.")),
    ] = 30,
    next_cursor: Annotated[
        str,
        Field(
            description=(
                "Opaque continuation token from the previous nextCursor; empty starts a search."
            )
        ),
    ] = "",
) -> dict:
    """[READ] Read sandbox activities.

    Use after edr_sandbox_verdict to inspect activity records for the same SHA-256; use the
    events or patterns tools for those record types.

    Result: items, returned, limit, truncated, nextCursor and totalReported; an absent cursor
    ends continuation.
    """
    return ops.sandbox_activities(get_connection(), sha2, limit, next_cursor)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["sha2", "next_cursor"])
@tool_errors()
def edr_sandbox_events(
    sha2: Annotated[
        str,
        Field(
            description=(
                "64-character hexadecimal SHA-256 identifying the sandbox result."
            )
        ),
    ],
    limit: Annotated[
        int,
        Field(description=("Maximum rows to return (10–50); follow nextCursor for another page.")),
    ] = 30,
    next_cursor: Annotated[
        str,
        Field(
            description=(
                "Opaque continuation token from the previous nextCursor; empty starts a search."
            )
        ),
    ] = "",
) -> dict:
    """[READ] Read sandbox events.

    Use after edr_sandbox_verdict to inspect event records for the same SHA-256; use the
    activities or patterns tools for those record types.

    Result: items, returned, limit, truncated, nextCursor and totalReported; an absent cursor
    ends continuation.
    """
    return ops.sandbox_events(get_connection(), sha2, limit, next_cursor)


@mcp.tool()
@governed_tool(risk_level="low", sensitive_params=["sha2", "next_cursor"])
@tool_errors()
def edr_sandbox_patterns(
    sha2: Annotated[
        str,
        Field(
            description=(
                "64-character hexadecimal SHA-256 identifying the sandbox result."
            )
        ),
    ],
    limit: Annotated[
        int,
        Field(description=("Maximum rows to return (10–50); follow nextCursor for another page.")),
    ] = 30,
    next_cursor: Annotated[
        str,
        Field(
            description=(
                "Opaque continuation token from the previous nextCursor; empty starts a search."
            )
        ),
    ] = "",
) -> dict:
    """[READ] Read sandbox patterns.

    Use after edr_sandbox_verdict to inspect pattern records for the same SHA-256; use the
    activities or events tools for those record types.

    Result: items, returned, limit, truncated, nextCursor and totalReported; an absent cursor
    ends continuation.
    """
    return ops.sandbox_patterns(get_connection(), sha2, limit, next_cursor)
