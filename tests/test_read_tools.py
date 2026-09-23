"""Unit tests for story-002 read tools and helpers.

Runs fully offline against ldap3's MOCK_SYNC strategy with the bundled offline
AD schema. Covers user/computer attribute mapping, password-expiry computation
(expired, not expired, never-expires UAC bit, pwdLastSet=0), paging that honours
AD_PAGE_SIZE, and group member DN resolution. Live-DC coverage lives in
scripts/smoke_read.py.
"""

import asyncio

import pytest
from ldap3 import MOCK_SYNC, OFFLINE_AD_2012_R2, Connection, Server
from ldap3.protocol.rfc4512 import AttributeTypeInfo

import app
import tools_read  # noqa: F401 — registers read tools on import
from ad_client import (
    ADClient,
    COMPUTER_READ_ATTRIBUTES,
    USER_READ_ATTRIBUTES,
    _TICKS_PER_DAY,
    compute_password_expiry,
)
from config import ADConfig

BASE_DN = "DC=lab,DC=example,DC=com"
BIND_DN = "CN=svc_ldap,OU=Service,DC=lab,DC=example,DC=com"

# A fixed "now" expressed as a FILETIME so expiry tests are deterministic.
# 2021-01-01T00:00:00Z == 132539328000000000 ticks since 1601-01-01.
NOW_FILETIME = 132_539_328_000_000_000
DAY = _TICKS_PER_DAY
# maxPwdAge is stored negative in AD: 90 days.
MAX_PWD_AGE_90D = -(90 * DAY)


def _env(**overrides):
    base = {
        "AD_SERVER": "dc01.lab.example.com",
        "AD_BASE_DN": BASE_DN,
        "AD_BIND_USER": BIND_DN,
        "AD_BIND_PASSWORD": "s3cret",
    }
    base.update(overrides)
    return base


# The bundled offline AD 2012 schema predates the Exchange extensionAttribute*
# attributes that our agreed user set requires, so register them on the mock
# schema (they exist on every real Exchange-extended DC).
_EXCHANGE_ATTRS = (
    ("extensionAttribute1", "1.2.840.113556.1.4.1100"),
    ("extensionAttribute10", "1.2.840.113556.1.4.1109"),
)


def _augment_schema(server):
    defs = [
        f"( {oid} NAME '{name}' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' SINGLE-VALUE )"
        for name, oid in _EXCHANGE_ATTRS
    ]
    for key, value in AttributeTypeInfo.from_definition(defs).items():
        server.schema.attribute_types[key] = value


def _build_conn(*, max_pwd_age=MAX_PWD_AGE_90D):
    server = Server("fake-dc", get_info=OFFLINE_AD_2012_R2)
    _augment_schema(server)
    conn = Connection(server, user=BIND_DN, password="s3cret", client_strategy=MOCK_SYNC)
    conn.strategy.add_entry(BIND_DN, {"objectClass": ["user"], "userPassword": "s3cret"})
    # Domain root carries maxPwdAge.
    conn.strategy.add_entry(
        BASE_DN,
        {"objectClass": ["domain"], "maxPwdAge": [str(max_pwd_age)]},
        validate=False,
    )
    return conn


def _client(conn, **env_overrides):
    return ADClient(ADConfig.from_env(_env(**env_overrides)), connection=conn)


@pytest.fixture(autouse=True)
def _reset_client():
    yield
    app.set_client(None)


# --------------------------------------------------------------------------- #
# compute_password_expiry — pure function
# --------------------------------------------------------------------------- #

def test_expiry_not_expired():
    # Set 10 days ago, 90-day policy → ~80 days remaining, not expired.
    pwd_last_set = NOW_FILETIME - 10 * DAY
    result = compute_password_expiry(
        pwd_last_set, MAX_PWD_AGE_90D, 512, now_filetime=NOW_FILETIME
    )
    assert result["password_expired"] is False
    assert result["days_until_expiry"] == 80


def test_expiry_expired():
    # Set 100 days ago, 90-day policy → expired, negative days remaining.
    pwd_last_set = NOW_FILETIME - 100 * DAY
    result = compute_password_expiry(
        pwd_last_set, MAX_PWD_AGE_90D, 512, now_filetime=NOW_FILETIME
    )
    assert result["password_expired"] is True
    assert result["days_until_expiry"] == -10


def test_expiry_never_expires_uac_bit():
    # DONT_EXPIRE_PASSWORD (0x10000) set; even an ancient pwdLastSet is fine.
    uac = 512 | 0x10000
    result = compute_password_expiry(
        NOW_FILETIME - 1000 * DAY, MAX_PWD_AGE_90D, uac, now_filetime=NOW_FILETIME
    )
    assert result["password_expired"] is False
    assert result["days_until_expiry"] is None


def test_expiry_pwd_last_set_zero_must_change():
    result = compute_password_expiry(0, MAX_PWD_AGE_90D, 512, now_filetime=NOW_FILETIME)
    assert result["password_expired"] is True
    assert result["days_until_expiry"] is None


def test_expiry_domain_never_expires():
    # maxPwdAge == 0 means passwords never expire domain-wide.
    result = compute_password_expiry(
        NOW_FILETIME - 1000 * DAY, 0, 512, now_filetime=NOW_FILETIME
    )
    assert result["password_expired"] is False
    assert result["days_until_expiry"] is None


# --------------------------------------------------------------------------- #
# get_user — attribute mapping + computed expiry
# --------------------------------------------------------------------------- #

def _add_user(conn, cn="jdoe", **attrs):
    dn = f"CN={cn},OU=Users,{BASE_DN}"
    base = {
        "objectClass": ["user", "person"],
        "cn": [cn],
        "sAMAccountName": [cn],
        "displayName": [f"{cn} display"],
        "userPrincipalName": [f"{cn}@lab.example.com"],
        "mail": [f"{cn}@lab.example.com"],
        "department": ["IT"],
        "title": ["Engineer"],
        "userAccountControl": ["512"],
    }
    base.update(attrs)
    conn.strategy.add_entry(dn, base, validate=False)
    return dn


def test_get_user_returns_all_agreed_attributes_plus_expiry():
    conn = _build_conn()
    _add_user(conn, pwdLastSet=[str(NOW_FILETIME)])
    conn.bind()
    client = _client(conn)

    user = client.get_user("jdoe")
    # All 22 agreed attributes present.
    for attr in USER_READ_ATTRIBUTES:
        assert attr in user, f"missing {attr}"
    # Plus the two computed fields.
    assert "password_expired" in user
    assert "days_until_expiry" in user
    assert user["sAMAccountName"] == ["jdoe"]
    assert user["department"] == ["IT"]


def test_get_user_by_dn():
    conn = _build_conn()
    dn = _add_user(conn, cn="bsmith", pwdLastSet=[str(NOW_FILETIME)])
    conn.bind()
    client = _client(conn)
    user = client.get_user(dn)
    assert user["sAMAccountName"] == ["bsmith"]


def test_get_user_password_expiry_wired_from_entry_and_domain():
    conn = _build_conn(max_pwd_age=MAX_PWD_AGE_90D)
    # pwdLastSet far in the past → expired under a 90-day policy.
    _add_user(conn, cn="olduser", pwdLastSet=["131000000000000000"])
    conn.bind()
    client = _client(conn)
    user = client.get_user("olduser")
    assert user["password_expired"] is True


def test_get_user_not_found_raises_lookup_error():
    conn = _build_conn()
    conn.bind()
    client = _client(conn)
    with pytest.raises(LookupError):
        client.get_user("ghost")


# --------------------------------------------------------------------------- #
# get_computer — attribute mapping
# --------------------------------------------------------------------------- #

def _add_computer(conn, name="PC01", **attrs):
    dn = f"CN={name},OU=Computers,{BASE_DN}"
    base = {
        "objectClass": ["computer"],
        "cn": [name],
        "name": [name],
        "sAMAccountName": [f"{name}$"],
        "dNSHostName": [f"{name.lower()}.lab.example.com"],
        "description": ["Owned by Jane Doe"],
        "operatingSystem": ["Windows 11 Pro"],
        "managedBy": [f"CN=jdoe,OU=Users,{BASE_DN}"],
    }
    base.update(attrs)
    conn.strategy.add_entry(dn, base, validate=False)
    return dn


def test_get_computer_returns_agreed_attributes_incl_managedby():
    conn = _build_conn()
    _add_computer(conn)
    conn.bind()
    client = _client(conn)
    comp = client.get_computer("PC01")
    for attr in COMPUTER_READ_ATTRIBUTES:
        assert attr in comp, f"missing {attr}"
    assert comp["description"] == ["Owned by Jane Doe"]
    assert comp["managedBy"] == [f"CN=jdoe,OU=Users,{BASE_DN}"]


def test_get_computer_strips_trailing_dollar():
    conn = _build_conn()
    _add_computer(conn, name="PC02")
    conn.bind()
    client = _client(conn)
    comp = client.get_computer("PC02$")
    assert comp["name"] == ["PC02"]


# --------------------------------------------------------------------------- #
# Paging — honours AD_PAGE_SIZE
# --------------------------------------------------------------------------- #

def test_find_users_paging_honours_page_size(monkeypatch):
    conn = _build_conn()
    for i in range(12):
        _add_user(conn, cn=f"pageuser{i}", pwdLastSet=[str(NOW_FILETIME)])
    conn.bind()
    client = _client(conn, AD_PAGE_SIZE="5")
    assert client.config.page_size == 5

    captured = {}
    real = conn.extend.standard.paged_search

    def spy(*args, **kwargs):
        captured["paged_size"] = kwargs.get("paged_size")
        return real(*args, **kwargs)

    monkeypatch.setattr(conn.extend.standard, "paged_search", spy)

    # include_disabled=True so the bitwise disabled-exclusion clause (which
    # MOCK_SYNC cannot evaluate) is omitted and the real search runs on the mock.
    out = client.find_users("pageuser", limit=100, include_disabled=True)
    assert captured["paged_size"] == 5  # AD_PAGE_SIZE wired into the control
    assert out["page_size"] == 5
    assert out["count"] == 12  # all pages collected across the 5-per-page control


def test_find_users_respects_limit():
    conn = _build_conn()
    for i in range(10):
        _add_user(conn, cn=f"limuser{i}", pwdLastSet=[str(NOW_FILETIME)])
    conn.bind()
    client = _client(conn, AD_PAGE_SIZE="500")
    # include_disabled=True so the bitwise clause (unsupported by MOCK_SYNC) is
    # omitted and the search runs on the mock.
    out = client.find_users("limuser", limit=3, include_disabled=True)
    assert out["count"] == 3


def test_find_computers_returns_matches():
    conn = _build_conn()
    _add_computer(conn, name="WS01")
    _add_computer(conn, name="WS02")
    conn.bind()
    client = _client(conn)
    out = client.find_computers("WS0")
    names = sorted(c["name"] for c in out["computers"])
    assert names == ["WS01", "WS02"]


# --------------------------------------------------------------------------- #
# Disabled-account exclusion (Feature 1)
#
# MOCK CAVEAT: ldap3's MOCK_SYNC strategy does NOT implement the AD bitwise
# extensible matching rule (1.2.840.113556.1.4.803) — searching with that clause
# raises LDAPAttributeError. So the default-path tests assert the *generated
# filter string* via a paged_search spy (without executing it against the mock),
# and the result-mapping path is exercised with include_disabled=True (clause
# omitted). Real AD evaluates the rule correctly.
# --------------------------------------------------------------------------- #

_DISABLED_CLAUSE = "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"


def _filter_spy(conn, monkeypatch, *, returns=None):
    """Spy on paged_search: capture search_filter/search_base and short-circuit
    the call (returning a canned generator) so the unsupported bitwise rule is
    never actually evaluated by the mock."""
    captured = {}

    def spy(*args, **kwargs):
        captured["search_filter"] = kwargs.get("search_filter")
        captured["search_base"] = kwargs.get("search_base")
        return iter(returns or [])

    monkeypatch.setattr(conn.extend.standard, "paged_search", spy)
    return captured


def test_find_users_filter_excludes_disabled_by_default(monkeypatch):
    conn = _build_conn()
    conn.bind()
    client = _client(conn)
    captured = _filter_spy(conn, monkeypatch)

    client.find_users("alice")  # default include_disabled=False
    assert _DISABLED_CLAUSE in captured["search_filter"]


def test_find_users_filter_omits_clause_with_include_disabled(monkeypatch):
    conn = _build_conn()
    conn.bind()
    client = _client(conn)
    captured = _filter_spy(conn, monkeypatch)

    client.find_users("alice", include_disabled=True)
    assert _DISABLED_CLAUSE not in captured["search_filter"]


def test_find_users_include_disabled_maps_results():
    # Exercise result-shape mapping via the include_disabled=True path (no bitwise
    # clause, so the mock can run the search). Both enabled and disabled users
    # are returned and mapped.
    conn = _build_conn()
    _add_user(conn, cn="abled_on", userAccountControl=["512"], pwdLastSet=[str(NOW_FILETIME)])
    _add_user(conn, cn="abled_off", userAccountControl=["514"], pwdLastSet=[str(NOW_FILETIME)])
    conn.bind()
    client = _client(conn)
    out = client.find_users("abled", include_disabled=True)
    sams = sorted(u["sAMAccountName"] for u in out["users"])
    assert sams == ["abled_off", "abled_on"]


def test_get_user_account_disabled_true():
    conn = _build_conn()
    _add_user(conn, cn="gone", userAccountControl=["514"], pwdLastSet=[str(NOW_FILETIME)])
    conn.bind()
    client = _client(conn)
    user = client.get_user("gone")
    assert user["account_disabled"] is True


def test_get_user_account_disabled_false():
    conn = _build_conn()
    _add_user(conn, cn="here", userAccountControl=["512"], pwdLastSet=[str(NOW_FILETIME)])
    conn.bind()
    client = _client(conn)
    user = client.get_user("here")
    assert user["account_disabled"] is False


# --------------------------------------------------------------------------- #
# Scoped search bases (Feature 2)
# --------------------------------------------------------------------------- #

def test_find_users_uses_user_search_base_when_set(monkeypatch):
    user_base = f"OU=_Users,{BASE_DN}"
    conn = _build_conn()
    conn.bind()
    client = _client(conn, AD_USER_SEARCH_BASE=user_base)
    captured = _filter_spy(conn, monkeypatch)
    client.find_users("alice", include_disabled=True)
    assert captured["search_base"] == user_base


def test_find_users_falls_back_to_base_dn(monkeypatch):
    conn = _build_conn()
    conn.bind()
    client = _client(conn)  # no scoped base
    captured = _filter_spy(conn, monkeypatch)
    client.find_users("alice", include_disabled=True)
    assert captured["search_base"] == BASE_DN


def test_find_computers_uses_computer_search_base_when_set(monkeypatch):
    comp_base = f"OU=_Computers,{BASE_DN}"
    conn = _build_conn()
    conn.bind()
    client = _client(conn, AD_COMPUTER_SEARCH_BASE=comp_base)
    captured = _filter_spy(conn, monkeypatch)
    client.find_computers("WS0")
    assert captured["search_base"] == comp_base


def test_find_computers_falls_back_to_base_dn(monkeypatch):
    conn = _build_conn()
    conn.bind()
    client = _client(conn)
    captured = _filter_spy(conn, monkeypatch)
    client.find_computers("WS0")
    assert captured["search_base"] == BASE_DN


# --------------------------------------------------------------------------- #
# Group member DN resolution
# --------------------------------------------------------------------------- #

def test_list_group_members_resolves_dns():
    conn = _build_conn()
    u1 = _add_user(conn, cn="alice", pwdLastSet=[str(NOW_FILETIME)])
    u2 = _add_user(conn, cn="bob", pwdLastSet=[str(NOW_FILETIME)])
    group_dn = f"CN=Engineers,OU=Groups,{BASE_DN}"
    conn.strategy.add_entry(
        group_dn,
        {
            "objectClass": ["group"],
            "cn": ["Engineers"],
            "sAMAccountName": ["Engineers"],
            "member": [u1, u2],
        },
        validate=False,
    )
    conn.bind()
    client = _client(conn)

    out = client.list_group_members("Engineers")
    assert out["count"] == 2
    names = sorted(m["name"] for m in out["members"])
    assert names == ["alice", "bob"]
    assert all(m["resolved"] for m in out["members"])
    sams = sorted(m["sAMAccountName"] for m in out["members"])
    assert sams == ["alice", "bob"]


def test_list_group_members_empty_group():
    conn = _build_conn()
    group_dn = f"CN=Empty,OU=Groups,{BASE_DN}"
    conn.strategy.add_entry(
        group_dn,
        {"objectClass": ["group"], "cn": ["Empty"], "sAMAccountName": ["Empty"]},
        validate=False,
    )
    conn.bind()
    client = _client(conn)
    out = client.list_group_members("Empty")
    assert out["count"] == 0
    assert out["members"] == []


# --------------------------------------------------------------------------- #
# Tool registration + dispatch through FastMCP
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "tool_name",
    [
        "ad_find_users",
        "ad_get_user",
        "ad_find_computers",
        "ad_get_computer",
        "ad_list_group_members",
    ],
)
def test_read_tools_registered_read_only(tool_name):
    tool = asyncio.run(app.mcp.get_tool(tool_name))
    assert tool.name == tool_name
    assert tool.annotations.readOnlyHint is True
    assert len(tool.name) <= 64
    assert tool.description


def test_get_user_tool_dispatch_returns_structured_content():
    conn = _build_conn()
    _add_user(conn, pwdLastSet=[str(NOW_FILETIME)])
    conn.bind()
    app.set_client(_client(conn))

    result = asyncio.run(app.mcp.call_tool("ad_get_user", {"identifier": "jdoe"}))
    assert result.is_error is False
    data = result.structured_content
    assert data["sAMAccountName"] == ["jdoe"]
    assert "password_expired" in data
    assert "days_until_expiry" in data


def test_get_user_tool_not_found_is_clean_toolerror():
    from fastmcp.exceptions import ToolError

    conn = _build_conn()
    conn.bind()
    app.set_client(_client(conn))
    with pytest.raises(ToolError):
        asyncio.run(app.mcp.call_tool("ad_get_user", {"identifier": "nobody"}))
