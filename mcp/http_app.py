"""HTTP transport for the AD LDAP MCP server (permanent-container deployment).

Mounts the FastMCP streamable-HTTP ASGI app under
``/mcp``, guards it with a bearer-token middleware, and exposes an unauthenticated
``/healthz`` liveness probe for the Docker healthcheck.

Refuse-to-start policy: :func:`create_app` raises :class:`RuntimeError` when
``MCP_BEARER_TOKEN`` is unset/empty so the HTTP transport never serves
unauthenticated. As defence-in-depth the middleware also rejects every ``/mcp``
request with 401 if the token is somehow empty at request time. Bearer
comparison is constant-time (:func:`hmac.compare_digest`) against the full
``Authorization`` header value.

The AD connection itself is built lazily on first tool call (see ``app.get_client``),
so importing this module never forces an environment read or a DC bind.
"""

from __future__ import annotations

import hmac
import os

from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

from app import mcp

# Importing the tool modules registers their tools on the shared FastMCP app.
import tools_read  # noqa: E402,F401
import tools_write_user  # noqa: E402,F401
import tools_write_computer_group  # noqa: E402,F401
import tools_bulk  # noqa: E402,F401

ENV_BEARER_TOKEN = "MCP_BEARER_TOKEN"
ENV_HTTP_HOST = "HTTP_HOST"
ENV_HTTP_PORT = "HTTP_PORT"

# Path under which the MCP ASGI app is mounted; all requests here are guarded.
_MCP_MOUNT = "/mcp"


def _bearer_token() -> str:
    return (os.environ.get(ENV_BEARER_TOKEN) or "").strip()


def http_host() -> str:
    return (os.environ.get(ENV_HTTP_HOST) or "0.0.0.0").strip()


def http_port() -> int:
    raw = (os.environ.get(ENV_HTTP_PORT) or "8000").strip()
    try:
        return int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{ENV_HTTP_PORT} must be an integer (got {raw!r})") from exc


class _BearerAuthMiddleware(BaseHTTPMiddleware):
    """Reject any ``/mcp`` request that does not carry the exact bearer token."""

    def __init__(self, app, expected: str) -> None:
        super().__init__(app)
        self._expected = expected

    async def dispatch(self, request: Request, call_next):
        if request.url.path.startswith(_MCP_MOUNT):
            provided = request.headers.get("authorization", "")
            if not self._expected or not hmac.compare_digest(
                provided, f"Bearer {self._expected}"
            ):
                return JSONResponse(
                    {"detail": "Unauthorized"},
                    status_code=401,
                    headers={"WWW-Authenticate": "Bearer"},
                )
        return await call_next(request)


async def _healthz(_request: Request) -> JSONResponse:
    """Unauthenticated liveness probe (used by the Docker healthcheck)."""
    return JSONResponse({"ok": True})


def create_app() -> Starlette:
    """Build the bearer-protected Starlette app hosting the MCP HTTP transport.

    :raises RuntimeError: if ``MCP_BEARER_TOKEN`` is unset/empty (refuse-to-start).
    """
    expected = _bearer_token()
    if not expected:
        raise RuntimeError(
            f"{ENV_BEARER_TOKEN} not configured: the HTTP transport refuses to "
            "start without a bearer token. Set MCP_BEARER_TOKEN, or run the stdio "
            "transport (python mcp/server.py --transport stdio) for local use."
        )

    # FastMCP 3.x streamable-HTTP ASGI app; carries its own session-manager lifespan.
    mcp_app = mcp.http_app(path="/")

    app = Starlette(
        routes=[
            Route("/healthz", _healthz, methods=["GET"]),
            Mount(_MCP_MOUNT, app=mcp_app),
        ],
        lifespan=mcp_app.lifespan,
    )
    app.add_middleware(_BearerAuthMiddleware, expected=expected)
    return app
