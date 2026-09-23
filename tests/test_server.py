"""Tests for the FastMCP scaffold and the ad_check_connection tool (story-001)."""

import asyncio

import pytest
from ldap3 import MOCK_SYNC, OFFLINE_AD_2012_R2, Connection, Server

from fastmcp.exceptions import ToolError

import app
import tools_read  # noqa: F401 — registers read tools on import
from ad_client import ADClient
from config import ADConfig

BASE_DN = "DC=lab,DC=example,DC=com"
BIND_DN = "CN=svc_ldap,OU=Service,DC=lab,DC=example,DC=com"


def _mock_client():
    server = Server("fake-dc", get_info=OFFLINE_AD_2012_R2)
    conn = Connection(server, user=BIND_DN, password="s3cret", client_strategy=MOCK_SYNC)
    conn.strategy.add_entry(BIND_DN, {"objectClass": ["user"], "userPassword": "s3cret"})
    conn.bind()
    env = {
        "AD_SERVER": "dc01.lab.example.com",
        "AD_BASE_DN": BASE_DN,
        "AD_BIND_USER": BIND_DN,
        "AD_BIND_PASSWORD": "s3cret",
    }
    return ADClient(ADConfig.from_env(env), connection=conn)


@pytest.fixture(autouse=True)
def _reset_client():
    yield
    app.set_client(None)  # don't leak a mock into other tests


def test_check_connection_tool_is_registered_read_only():
    tool = asyncio.run(app.mcp.get_tool("ad_check_connection"))
    assert tool.name == "ad_check_connection"
    assert tool.annotations.readOnlyHint is True
    assert len(tool.name) <= 64
    assert tool.description  # describes, present


def test_check_connection_tool_returns_structured_content():
    app.set_client(_mock_client())
    result = asyncio.run(app.mcp.call_tool("ad_check_connection", {}))
    assert result.is_error is False
    data = result.structured_content
    assert data["connected"] is True
    assert data["server"] == "dc01.lab.example.com"
    assert data["base_dn"] == BASE_DN
    assert data["tls_validate"] is True


def test_check_connection_tool_raises_clean_toolerror_on_config_error(monkeypatch):
    # No client cached and required env missing. The tool must raise a ToolError
    # (which FastMCP converts to an isError response at the transport boundary)
    # rather than leaking a raw exception/traceback.
    app.set_client(None)
    for var in ("AD_SERVER", "AD_BASE_DN", "AD_BIND_USER", "AD_BIND_PASSWORD"):
        monkeypatch.delenv(var, raising=False)
    with pytest.raises(ToolError) as exc:
        asyncio.run(app.mcp.call_tool("ad_check_connection", {}))
    assert "Configuration error" in str(exc.value)
