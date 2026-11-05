"""Documented, bounded Symantec on-prem EDR read operations."""

from __future__ import annotations

from datetime import datetime

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
    if kind not in {"incidents", "events", "auditevents"}:
        raise ValueError("Unknown EDR query")
    start, end = _time(start_time), _time(end_time)
    max_days = 7 if kind == "auditevents" else 30
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
