"""Bounded, tenant-scoped EDR transport. Only documented read requests are exposed."""

from __future__ import annotations

import json
import os
import threading
import time
from typing import Any
from urllib.parse import urlsplit

import httpx

_MAX_RESPONSE_BYTES = 16 * 1024 * 1024


class EdrError(RuntimeError):
    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class EdrConnection:
    def __init__(self, client: httpx.Client | None = None) -> None:
        url = os.environ.get("SYMANTEC_EDR_URL", "").rstrip("/")
        parts = urlsplit(url)
        if (
            parts.scheme != "https"
            or not parts.netloc
            or parts.path
            or parts.query
            or parts.fragment
            or parts.username
            or parts.password
        ):
            raise EdrError("Set SYMANTEC_EDR_URL to the API HTTPS origin")
        try:
            timeout = float(os.environ.get("SYMANTEC_EDR_TIMEOUT", "30"))
        except ValueError as exc:
            raise EdrError("SYMANTEC_EDR_TIMEOUT must be positive") from exc
        if timeout <= 0:
            raise EdrError("SYMANTEC_EDR_TIMEOUT must be positive")
        client_id = os.environ.get("SYMANTEC_EDR_CLIENT_ID", "")
        client_secret = os.environ.get("SYMANTEC_EDR_CLIENT_SECRET", "")
        if not client_id or not client_secret:
            raise EdrError("Set SYMANTEC_EDR_CLIENT_ID and SYMANTEC_EDR_CLIENT_SECRET")
        self._credentials = (client_id, client_secret)
        verify = os.environ.get("SYMANTEC_EDR_CA_BUNDLE") or True
        self._client = client or httpx.Client(base_url=url, timeout=timeout, verify=verify)
        self._token: str | None = None
        self._expires_at = 0.0
        self._auth_retry_at = 0.0
        self._lock = threading.RLock()

    def close(self) -> None:
        self._client.close()

    def _bounded_request(self, method: str, path: str, **kwargs: Any) -> tuple[int, bytearray]:
        with self._client.stream(method, path, **kwargs) as response:
            status = response.status_code
            if status >= 400:
                return status, bytearray()
            body = bytearray()
            for chunk in response.iter_bytes(chunk_size=64 * 1024):
                if len(body) + len(chunk) > _MAX_RESPONSE_BYTES:
                    raise EdrError("EDR response exceeds 16 MiB; narrow the query")
                body.extend(chunk)
            return status, body

    def _authenticate(self) -> None:
        if time.monotonic() < self._auth_retry_at:
            raise EdrError("EDR login was rejected recently; wait before retrying credentials")
        try:
            status, body = self._bounded_request(
                "POST",
                "/api/oauth2/tokens",
                params={"grant_type": "client_credentials"},
                auth=self._credentials,
                headers={"Accept": "application/json"},
            )
        except httpx.TimeoutException as exc:
            raise EdrError("EDR login timed out; check URL and timeout") from exc
        except httpx.HTTPError as exc:
            raise EdrError("Cannot reach EDR login; check URL and TLS") from exc
        if status in (400, 401, 403):
            self._auth_retry_at = time.monotonic() + 30
            raise EdrError("EDR rejected credentials or client privileges")
        if status >= 400:
            raise EdrError(f"EDR login returned HTTP {status}")
        try:
            data = json.loads(body)
        except ValueError as exc:
            raise EdrError("EDR login returned non-JSON data") from exc
        if not isinstance(data, dict):
            raise EdrError("EDR login returned an unexpected response")
        token_data = data.get("token")
        if not isinstance(token_data, dict):
            raise EdrError("EDR login response has no token object")
        token = token_data.get("access_token")
        raw_expiry = token_data.get("expires_in")
        if not isinstance(token, str) or not token:
            raise EdrError("EDR login response has no token")
        if isinstance(raw_expiry, bool) or not isinstance(raw_expiry, (int, str)):
            raise EdrError("EDR login response has invalid expires_in")
        try:
            expiry = int(raw_expiry)
        except ValueError as exc:
            raise EdrError("EDR login response has invalid expires_in") from exc
        if expiry <= 0:
            raise EdrError("EDR login response has invalid expires_in")
        self._token = token
        self._expires_at = time.monotonic() + max(1, expiry - 60)
        self._auth_retry_at = 0.0

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        payload: dict[str, Any] | None = None,
    ) -> Any:
        if path.startswith("//") or not (path.startswith("/api/atpapi/v2/")):
            raise ValueError("Undocumented EDR resource path")
        query_routes = {
            "/api/atpapi/v2/incidents",
            "/api/atpapi/v2/events",
            "/api/atpapi/v2/auditevents",
            "/api/atpapi/v2/incidentevents",
            "/api/atpapi/v2/incidentlineageevents",
            "/api/atpapi/v2/systemactivities",
            "/api/atpapi/v2/entities",
            "/api/atpapi/v2/entities/files",
            "/api/atpapi/v2/datafeeds/adversary/actors",
            "/api/atpapi/v2/datafeeds/adversary/files",
            "/api/atpapi/v2/datafeeds/adversary/networks",
        }
        if method != "GET" and (method != "POST" or path not in query_routes):
            raise ValueError("EDR transport only exposes documented read operations")
        if method == "POST" and (not isinstance(payload, dict) or payload.get("verb") != "query"):
            raise ValueError("EDR POST must be a query-only request")
        with self._lock:
            if self._token is None or time.monotonic() >= self._expires_at:
                self._authenticate()
            for attempt in range(2):
                try:
                    status, body = self._bounded_request(
                        method,
                        path,
                        params=params,
                        json=payload,
                        headers={
                            "Authorization": f"Bearer {self._token}",
                            "Accept": "application/json",
                        },
                    )
                except httpx.TimeoutException as exc:
                    raise EdrError(f"EDR timed out on {path}") from exc
                except httpx.HTTPError as exc:
                    raise EdrError(f"Cannot reach EDR on {path}; check URL and TLS") from exc
                if status == 401 and attempt == 0:
                    self._token = None
                    self._authenticate()
                    continue
                if status >= 400:
                    hint = "Check client privilege and resource ID."
                    if status == 429:
                        hint = "API quota exceeded; retry after the server limit resets."
                    elif status >= 500:
                        hint = "Check service health before retrying."
                    raise EdrError(
                        f"EDR returned HTTP {status} for {path}. {hint}",
                        status_code=status,
                    )
                if not body:
                    raise EdrError(f"EDR returned an empty response for {path}")
                try:
                    return json.loads(body)
                except ValueError as exc:
                    raise EdrError(f"EDR returned non-JSON data for {path}") from exc
            raise EdrError("EDR authentication retry failed")

    def get(self, path: str, *, params: dict[str, Any] | None = None) -> Any:
        return self._request("GET", path, params=params)

    def query(self, path: str, payload: dict[str, Any]) -> Any:
        return self._request("POST", path, payload=payload)


_connection: EdrConnection | None = None
_connection_lock = threading.Lock()


def get_connection() -> EdrConnection:
    global _connection
    with _connection_lock:
        if _connection is None:
            _connection = EdrConnection()
        return _connection
