"""Documented, bounded Symantec on-prem EDR read operations."""

from __future__ import annotations

import re
from datetime import datetime
from urllib.parse import quote

from symantec_edr_aiops.connection import EdrConnection, EdrError


def appliances(conn: EdrConnection) -> dict:
    data = conn.get("/api/atpapi/v2/appliances")
    if (
        not isinstance(data, dict)
        or not isinstance(data.get("appliance_list"), list)
        or any(not isinstance(row, dict) for row in data["appliance_list"])
    ):
        raise EdrError("EDR returned an unexpected appliance response")
    return {
        "items": data["appliance_list"],
        "returned": len(data["appliance_list"]),
        "paginationKnown": False,
    }


def _time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("time must be ISO 8601 with an offset") from exc
    if parsed.tzinfo is None:
        raise ValueError("time must have an offset")
    return parsed


def _query(
    conn: EdrConnection,
    kind: str,
    start_time: str,
    end_time: str,
    limit: int = 100,
    query: str = "",
    next_cursor: str = "",
) -> dict:
    if kind not in {
        "incidents",
        "events",
        "auditevents",
        "incidentevents",
        "incidentlineageevents",
        "systemactivities",
    }:
        raise ValueError("Unknown EDR query")
    start, end = _time(start_time), _time(end_time)
    max_days = 7 if kind in {"auditevents", "systemactivities"} else 30
    if not 0 < (end - start).total_seconds() <= max_days * 86400:
        raise ValueError(f"{kind} time window must be 0–{max_days} days")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
        raise ValueError("limit must be 1–500")
    if len(query) > 10240 or len(next_cursor) > 4096:
        raise ValueError("query or cursor exceeds bound")
    body = {
        "verb": "query",
        "start_time": start_time,
        "end_time": end_time,
        "limit": limit,
        "query": query,
    }
    if next_cursor:
        body["next"] = next_cursor
    data = conn.query(f"/api/atpapi/v2/{kind}", body)
    if not isinstance(data, dict) or not isinstance(data.get("result"), list):
        raise EdrError(f"EDR returned an unexpected {kind} page")
    rows = data["result"]
    if any(not isinstance(row, dict) for row in rows) or len(rows) > limit:
        raise EdrError(f"EDR returned invalid {kind} rows")
    cursor = data.get("next")
    if cursor is not None and not isinstance(cursor, str):
        raise EdrError(f"EDR returned invalid {kind} cursor")
    total = data.get("total")
    if total is not None and (isinstance(total, bool) or not isinstance(total, int)):
        raise EdrError(f"EDR returned invalid {kind} total")
    return {
        "items": rows,
        "returned": len(rows),
        "limit": limit,
        "truncated": bool(cursor),
        "nextCursor": cursor or None,
        "totalReported": total,
    }


def incidents(
    conn: EdrConnection,
    start_time: str,
    end_time: str,
    limit: int = 100,
    query: str = "",
    next_cursor: str = "",
) -> dict:
    return _query(conn, "incidents", start_time, end_time, limit, query, next_cursor)


def events(
    conn: EdrConnection,
    start_time: str,
    end_time: str,
    limit: int = 100,
    query: str = "",
    next_cursor: str = "",
) -> dict:
    return _query(conn, "events", start_time, end_time, limit, query, next_cursor)


def audit_events(
    conn: EdrConnection,
    start_time: str,
    end_time: str,
    limit: int = 100,
    query: str = "",
    next_cursor: str = "",
) -> dict:
    return _query(conn, "auditevents", start_time, end_time, limit, query, next_cursor)


def incident_events(
    conn: EdrConnection,
    start_time: str,
    end_time: str,
    limit: int = 100,
    query: str = "",
    next_cursor: str = "",
) -> dict:
    return _query(conn, "incidentevents", start_time, end_time, limit, query, next_cursor)


def incident_lineage_events(
    conn: EdrConnection,
    start_time: str,
    end_time: str,
    limit: int = 100,
    query: str = "",
    next_cursor: str = "",
) -> dict:
    return _query(conn, "incidentlineageevents", start_time, end_time, limit, query, next_cursor)


def system_activities(
    conn: EdrConnection,
    start_time: str,
    end_time: str,
    limit: int = 100,
    query: str = "",
    next_cursor: str = "",
) -> dict:
    return _query(conn, "systemactivities", start_time, end_time, limit, query, next_cursor)


def _search(
    conn: EdrConnection, path: str, query: str, limit: int = 100, next_cursor: str = ""
) -> dict:
    if not isinstance(query, str) or not query or len(query) > 10240:
        raise ValueError("A bounded search query is required")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
        raise ValueError("limit must be 1–100")
    if len(next_cursor) > 4096:
        raise ValueError("next_cursor exceeds bound")
    body = {"verb": "query", "query": query, "limit": limit}
    if next_cursor:
        body["next"] = next_cursor
    data = conn.query(path, body)
    return _result_page(data, path, limit)


def _result_page(data: object, path: str, limit: int) -> dict:
    if not isinstance(data, dict) or not isinstance(data.get("result"), list):
        raise EdrError(f"EDR returned an unexpected page for {path}")
    rows = data["result"]
    if any(not isinstance(row, dict) for row in rows) or len(rows) > limit:
        raise EdrError(f"EDR returned invalid rows for {path}")
    cursor = data.get("next")
    if cursor is not None and not isinstance(cursor, str):
        raise EdrError(f"EDR returned an invalid cursor for {path}")
    total = data.get("total")
    if total is not None and (isinstance(total, bool) or not isinstance(total, int)):
        raise EdrError(f"EDR returned an invalid total for {path}")
    return {
        "items": rows,
        "returned": len(rows),
        "limit": limit,
        "truncated": bool(cursor),
        "nextCursor": cursor or None,
        "totalReported": total,
    }


def entities(conn: EdrConnection, query: str, limit: int = 100, next_cursor: str = "") -> dict:
    return _search(conn, "/api/atpapi/v2/entities", query, limit, next_cursor)


def file_entities(conn: EdrConnection, query: str, limit: int = 100, next_cursor: str = "") -> dict:
    return _search(conn, "/api/atpapi/v2/entities/files", query, limit, next_cursor)


def adversary_actors(
    conn: EdrConnection, query: str, limit: int = 100, next_cursor: str = ""
) -> dict:
    return _search(conn, "/api/atpapi/v2/datafeeds/adversary/actors", query, limit, next_cursor)


def adversary_files(
    conn: EdrConnection, query: str, limit: int = 100, next_cursor: str = ""
) -> dict:
    return _search(conn, "/api/atpapi/v2/datafeeds/adversary/files", query, limit, next_cursor)


def adversary_networks(
    conn: EdrConnection, query: str, limit: int = 100, next_cursor: str = ""
) -> dict:
    return _search(conn, "/api/atpapi/v2/datafeeds/adversary/networks", query, limit, next_cursor)


def _sha2(value: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[A-Fa-f0-9]{64}", value) is None:
        raise ValueError("sha2 must be a 64-character hexadecimal digest")
    return value


def _id(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 200:
        raise ValueError("ID must be a non-empty bounded string")
    return quote(value, safe="")


def file_entity(conn: EdrConnection, sha2: str) -> dict:
    data = conn.get(f"/api/atpapi/v2/entities/files/{_sha2(sha2)}")
    if not isinstance(data, dict) or not data:
        raise EdrError("EDR returned an unexpected file entity")
    return {"file": data}


def sandbox_command(conn: EdrConnection, command_id: str) -> dict:
    data = conn.get(f"/api/atpapi/v2/sandbox/commands/{_id(command_id)}")
    if not isinstance(data, dict) or not isinstance(data.get("status"), list):
        raise EdrError("EDR returned an unexpected sandbox command status")
    return {"status": data["status"]}


def sandbox_verdict(conn: EdrConnection, sha2: str) -> dict:
    data = conn.get(f"/api/atpapi/v2/sandbox/results/{_sha2(sha2)}/verdict")
    if not isinstance(data, dict) or "verdict" not in data:
        raise EdrError("EDR returned an unexpected sandbox verdict")
    return {"verdict": data}


def _get_page(
    conn: EdrConnection, path: str, limit: int = 50, next_cursor: str = "", minimum: int = 10
) -> dict:
    if isinstance(limit, bool) or not isinstance(limit, int) or not minimum <= limit <= 50:
        raise ValueError(f"limit must be {minimum}–50")
    if len(next_cursor) > 4096:
        raise ValueError("next_cursor exceeds bound")
    params = {"limit": limit}
    if next_cursor:
        params["next"] = next_cursor
    return _result_page(conn.get(path, params=params), path, limit)


def allow_list(conn: EdrConnection, limit: int = 50, next_cursor: str = "") -> dict:
    return _get_page(conn, "/api/atpapi/v2/policies/allow_list", limit, next_cursor)


def deny_list(conn: EdrConnection, limit: int = 50, next_cursor: str = "") -> dict:
    return _get_page(conn, "/api/atpapi/v2/policies/deny_list", limit, next_cursor)


def sandbox_activities(
    conn: EdrConnection, sha2: str, limit: int = 30, next_cursor: str = ""
) -> dict:
    return _get_page(
        conn, f"/api/atpapi/v2/sandbox/results/{_sha2(sha2)}/activities", limit, next_cursor
    )


def sandbox_events(conn: EdrConnection, sha2: str, limit: int = 30, next_cursor: str = "") -> dict:
    return _get_page(
        conn, f"/api/atpapi/v2/sandbox/results/{_sha2(sha2)}/events", limit, next_cursor
    )


def sandbox_patterns(
    conn: EdrConnection, sha2: str, limit: int = 30, next_cursor: str = ""
) -> dict:
    return _get_page(
        conn, f"/api/atpapi/v2/sandbox/results/{_sha2(sha2)}/patterns", limit, next_cursor
    )
