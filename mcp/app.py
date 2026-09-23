"""Shared FastMCP instance and lazy AD client accessor.

The FastMCP app is defined once here; tool modules (``tools_read`` and, in later
stories, the write modules) import ``mcp`` from this module and register their
tools against it. ``server.py`` imports those modules and runs the stdio loop.

The AD client is created lazily on first use so that importing this module (e.g.
during tests or tool discovery) never forces an environment read or a DC bind.
"""

from __future__ import annotations

from fastmcp import FastMCP

from ad_client import ADClient
from config import ADConfig

mcp = FastMCP(name="ad-ldap-mcp")

_client: ADClient | None = None


def get_client() -> ADClient:
    """Return the process-wide :class:`ADClient`, building it on first use."""
    global _client
    if _client is None:
        _client = ADClient(ADConfig.from_env())
    return _client


def set_client(client: ADClient | None) -> None:
    """Override (or reset) the cached client — used by tests."""
    global _client
    _client = client
