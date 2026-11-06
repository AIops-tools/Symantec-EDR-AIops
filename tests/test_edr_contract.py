"""On-prem EDR OAuth and query-only cursor contracts."""

import httpx
import pytest

from symantec_edr_aiops import ops
from symantec_edr_aiops.connection import EdrConnection


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setenv("SYMANTEC_EDR_URL", "https://edr.example")
    monkeypatch.setenv("SYMANTEC_EDR_CLIENT_ID", "client")
    monkeypatch.setenv("SYMANTEC_EDR_CLIENT_SECRET", "secret")


def test_auth_and_incident_cursor():
    seen = []

    def handler(request):
        seen.append(request)
        if request.url.path == "/api/oauth2/tokens":
            return httpx.Response(200, json={"token": {"access_token": "t", "expires_in": "3600"}})
        return httpx.Response(200, json={"result": [{"uuid": "u"}], "next": "cursor", "total": 8})

    conn = EdrConnection(
        httpx.Client(base_url="https://edr.example", transport=httpx.MockTransport(handler))
    )
    page = ops.incidents(conn, "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z", 20)
    assert page["truncated"] and page["nextCursor"] == "cursor"
    assert seen[0].headers["authorization"].startswith("Basic ")
    assert seen[0].url.params["grant_type"] == "client_credentials"
    assert seen[1].headers["authorization"] == "Bearer t"


def test_time_limit_and_query_only_transport():
    with pytest.raises(ValueError, match="0–7 days"):
        ops.audit_events(None, "2026-01-01T00:00:00Z", "2026-01-10T00:00:00Z")
    conn = EdrConnection(
        httpx.Client(base_url="https://edr.example", transport=httpx.MockTransport(lambda _: None))
    )
    with pytest.raises(ValueError, match="query-only"):
        conn.query("/api/atpapi/v2/incidents", {"verb": "update"})


def test_appliance_shape_is_not_assumed_healthy():
    from symantec_edr_aiops.connection import EdrError

    def handler(request):
        if request.url.path == "/api/oauth2/tokens":
            return httpx.Response(200, json={"token": {"access_token": "t", "expires_in": 3600}})
        return httpx.Response(200, json={"wrong": []})

    conn = EdrConnection(
        httpx.Client(base_url="https://edr.example", transport=httpx.MockTransport(handler))
    )
    with pytest.raises(EdrError, match="unexpected appliance"):
        ops.appliances(conn)


def test_entity_search_is_query_only_and_cursor_is_preserved():
    seen = []

    def handler(request):
        if request.url.path == "/api/oauth2/tokens":
            return httpx.Response(200, json={"token": {"access_token": "t", "expires_in": 3600}})
        seen.append(request)
        return httpx.Response(200, json={"result": [{"sha2": "a"}], "next": "opaque", "total": 3})

    conn = EdrConnection(
        httpx.Client(base_url="https://edr.example", transport=httpx.MockTransport(handler))
    )
    page = ops.file_entities(conn, "sha2:abc", 25)
    assert page["nextCursor"] == "opaque" and page["truncated"]
    assert seen[0].url.path == "/api/atpapi/v2/entities/files"
    assert b'"verb":"query"' in seen[0].content
    with pytest.raises(ValueError, match="read operations"):
        conn.query("/api/atpapi/v2/sandbox/commands", {"verb": "query"})


def test_sandbox_sha_is_strict_and_paged_result_is_validated():
    sha = "a" * 64

    def handler(request):
        if request.url.path == "/api/oauth2/tokens":
            return httpx.Response(200, json={"token": {"access_token": "t", "expires_in": 3600}})
        return httpx.Response(200, json={"result": [{"name": "pattern"}], "next": "n", "total": 2})

    conn = EdrConnection(
        httpx.Client(base_url="https://edr.example", transport=httpx.MockTransport(handler))
    )
    assert ops.sandbox_patterns(conn, sha, 10)["nextCursor"] == "n"
    with pytest.raises(ValueError, match="sha2"):
        ops.sandbox_patterns(conn, "../bad")
