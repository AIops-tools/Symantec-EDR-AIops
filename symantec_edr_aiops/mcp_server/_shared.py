"""Shared MCP registration and sanitized EDR errors."""

from __future__ import annotations

import functools
import logging
from collections.abc import Callable
from typing import Any

from mcp.server import MCPServer

from symantec_edr_aiops import __version__
from symantec_edr_aiops.connection import EdrError
from symantec_edr_aiops.governance import sanitize

logger = logging.getLogger(__name__)
_ERROR_MAX = 800


def tool_errors() -> Callable:
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                return func(*args, **kwargs)
            except (EdrError, ValueError) as exc:
                logger.warning("Tool %s failed: %s", func.__name__, type(exc).__name__)
                return {"error": sanitize(str(exc), _ERROR_MAX)}
            except Exception:
                logger.exception("Tool %s failed", func.__name__)
                return {"error": "Unexpected EDR operation failure; check server logs."}

        return wrapper

    return decorator


mcp = MCPServer(
    "symantec-edr-aiops",
    version=__version__,
    instructions=(
        "Audited EDR tenant, application, connector and policy read tools. "
        "No state-changing tools in this preview."
    ),
)
