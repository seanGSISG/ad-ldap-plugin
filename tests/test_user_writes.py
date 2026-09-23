"""Unit tests for story-003 user write tools and ADClient write methods.

Runs fully offline against ldap3's MOCK_SYNC strategy with the bundled offline
AD schema (the same harness as test_read_tools). Covers:

- whitelist enforcement: only the six permitted attributes pass; everything
  else (incl. ``manager``) is rejected, and an empty string clears an attribute;
- ``ad_reset_password``: the unicodePwd MODIFY_REPLACE path produces ldap3's
  quoted UTF-16-LE encoding, and force_change_at_logon sets pwdLastSet=0;
- ``ad_set_account_status``: disabling sets the ACCOUNTDISABLE bit while
  preserving every other userAccountControl flag, and is idempotent;
- the dry-run contract: every write tool defaults to dry_run=true, returns a
  before/after diff, and commits nothing;
- tool registration + annotations (destructive / idempotent hints).

MOCK_SYNC note: ldap3's MockBaseStrategy DOES support ``connection.modify`` and
the Microsoft extended ``modify_password`` (which is itself implemented on top
of a unicodePwd ``connection.modify``). So ad_reset_password is exercised
through its real ``ad_modify_password`` path against the mock — no monkeypatch —
and we assert on the quoted-UTF-16-LE bytes the mock actually stores.
"""

import asyncio

import pytest
from ldap3 import MOCK_SYNC, OFFLINE_AD_2012_R2, Connection, Server
from ldap3.protocol.rfc4512 import AttributeTypeInfo

import app
import tools_write_user  # noqa: F401 — registers user write tools on import
from ad_client import ADClient, USER_WRITABLE_ATTRIBUTES, _UAC_ACCOUNTDISABLE
from config import ADConfig

BASE_DN = "DC=lab,DC=example,DC=com"
BIND_DN = "CN=svc_ldap,OU=Service,DC=lab,DC=example,DC=com"


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
# attributes our whitelist requires, so register them on the mock schema.
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


def _build_conn():
    server = Server("fake-dc", get_info=OFFLINE_AD_2012_R2)
    _augment_schema(server)
    conn = Connection(server, user=BIND_DN, password="s3cret", client_strategy=MOCK_SYNC)
    conn.strategy.add_entry(BIND_DN, {"objectClass": ["user"], "userPassword": "s3cret"})
    return conn


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


def _client(conn, **env_overrides):
    return ADClient(ADConfig.from_env(_env(**env_overrides)), connection=conn)


def _bound_client():
    conn = _build_conn()
    dn = _add_user(conn)
    conn.bind()
    return _client(conn), conn, dn


@pytest.fixture(autouse=True)
def _reset_client():
    yield
    app.set_client(None)


def _read(conn, dn, attr):
    conn.search(dn, "(objectClass=*)", attributes=[attr])
    entry = conn.entries[0]
    try:
        return entry[attr].value
    except Exception:  # noqa: BLE001
        return None


def _read_raw(conn, dn, attr):
    conn.search(dn, "(objectClass=*)", attributes=[attr])
    entry = conn.entries[0]
    try:
        return list(entry[attr].raw_values)
    except Exception:  # noqa: BLE001
        return []


# --------------------------------------------------------------------------- #
# Tool registration + annotations
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "tool_name,destructive,idempotent",
    [
        ("ad_set_user_attributes", True, True),
        ("ad_set_user_manager", True, True),
        ("ad_reset_password", True, False),
        ("ad_set_account_status", True, True),
        ("ad_unlock_account", False, True),
    ],
)
def test_write_tools_registered_with_expected_annotations(tool_name, destructive, idempotent):
    tool = asyncio.run(app.mcp.get_tool(tool_name))
    assert tool.name == tool_name
    assert len(tool.name) <= 64
    assert tool.description
    assert tool.annotations.destructiveHint is destructive
    assert tool.annotations.idempotentHint is idempotent


@pytest.mark.parametrize(
    "tool_name",
    [
        "ad_set_user_attributes",
        "ad_set_user_manager",
        "ad_reset_password",
        "ad_set_account_status",
        "ad_unlock_account",
    ],
)
def test_write_tools_default_dry_run_true(tool_name):
    tool = asyncio.run(app.mcp.get_tool(tool_name))
    schema = tool.parameters
    assert schema["properties"]["dry_run"]["default"] is True


# --------------------------------------------------------------------------- #
# ad_set_user_attributes — whitelist enforcement
# --------------------------------------------------------------------------- #
def test_whitelist_exactly_six_attributes():
    assert USER_WRITABLE_ATTRIBUTES == (
        "department",
        "title",
        "physicalDeliveryOfficeName",
        "telephoneNumber",
        "extensionAttribute1",
        "extensionAttribute10",
    )


def test_set_user_attributes_rejects_non_whitelisted():
    client, _, _ = _bound_client()
    with pytest.raises(ValueError, match="not permitted"):
        client.set_user_attributes("jdoe", {"description": "nope"}, dry_run=True)


def test_set_user_attributes_rejects_manager():
    # manager has its own tool; it must not slip through the attribute setter.
    client, _, _ = _bound_client()
    with pytest.raises(ValueError, match="manager"):
        client.set_user_attributes("jdoe", {"manager": f"CN=x,{BASE_DN}"}, dry_run=True)


def test_set_user_attributes_accepts_whitelisted_dry_run_diff():
    client, conn, dn = _bound_client()
    result = client.set_user_attributes("jdoe", {"title": "Director"}, dry_run=True)
    assert result["dry_run"] is True
    assert result["committed"] is False
    assert result["changes"]["title"] == {"before": ["Engineer"], "after": ["Director"]}
    # Nothing was written.
    assert _read(conn, dn, "title") == "Engineer"


def test_set_user_attributes_commit_writes():
    client, conn, dn = _bound_client()
    result = client.set_user_attributes("jdoe", {"title": "Director"}, dry_run=False)
    assert result["committed"] is True
    assert _read(conn, dn, "title") == "Director"


def test_set_user_attributes_empty_string_clears():
    client, conn, dn = _bound_client()
    result = client.set_user_attributes("jdoe", {"department": ""}, dry_run=False)
    assert result["changes"]["department"] == {"before": ["IT"], "after": []}
    assert result["committed"] is True
    assert _read(conn, dn, "department") in (None, [], "")


def test_set_user_attributes_rejects_empty_payload():
    client, _, _ = _bound_client()
    with pytest.raises(ValueError):
        client.set_user_attributes("jdoe", {}, dry_run=True)


# --------------------------------------------------------------------------- #
# ad_set_user_manager
# --------------------------------------------------------------------------- #
def test_set_user_manager_sets_validated_dn():
    conn = _build_conn()
    udn = _add_user(conn, cn="jdoe")
    mdn = _add_user(conn, cn="boss")
    conn.bind()
    client = _client(conn)
    result = client.set_user_manager("jdoe", "boss", dry_run=False)
    assert result["committed"] is True
    assert result["changes"]["manager"]["after"] == [mdn]
    assert _read(conn, udn, "manager") == mdn


def test_set_user_manager_unresolvable_manager_raises():
    client, _, _ = _bound_client()
    with pytest.raises(LookupError):
        client.set_user_manager("jdoe", "ghostmanager", dry_run=True)


def test_set_user_manager_clear_with_none():
    conn = _build_conn()
    mdn = _add_user(conn, cn="boss")
    udn = _add_user(conn, cn="jdoe", manager=[mdn])
    conn.bind()
    client = _client(conn)
    result = client.set_user_manager("jdoe", None, dry_run=False)
    assert result["changes"]["manager"]["after"] == []
    assert _read(conn, udn, "manager") in (None, [], "")


# --------------------------------------------------------------------------- #
# ad_reset_password — unicodePwd encoding + force change
# --------------------------------------------------------------------------- #
def test_reset_password_dry_run_does_not_contact_dc():
    client, conn, dn = _bound_client()
    result = client.reset_password("jdoe", "S3cret!Pass", dry_run=True)
    assert result["dry_run"] is True
    assert result["committed"] is False
    # Cleartext password is never echoed back.
    assert "S3cret!Pass" not in str(result)
    assert _read_raw(conn, dn, "unicodePwd") == []


def test_reset_password_commit_sets_quoted_utf16le_unicodepwd():
    client, conn, dn = _bound_client()
    result = client.reset_password("jdoe", "S3cret!Pass", dry_run=False)
    assert result["committed"] is True
    stored = _read_raw(conn, dn, "unicodePwd")
    assert stored, "unicodePwd was not written"
    expected = ('"%s"' % "S3cret!Pass").encode("utf-16-le")
    assert stored[0] == expected


def test_reset_password_force_change_sets_pwdlastset_zero():
    client, conn, dn = _bound_client()
    result = client.reset_password(
        "jdoe", "S3cret!Pass", force_change_at_logon=True, dry_run=False
    )
    assert result["committed"] is True
    assert result["force_change_at_logon"] is True
    assert result["pwdLastSet_committed"] is True
    # pwdLastSet has the AD time syntax (ldap3 decodes .value to a datetime), so
    # assert on the raw wire value, which is the literal "0".
    assert _read_raw(conn, dn, "pwdLastSet") == [b"0"]


def test_reset_password_without_force_leaves_pwdlastset_untouched():
    client, conn, dn = _bound_client()
    result = client.reset_password("jdoe", "S3cret!Pass", dry_run=False)
    assert "pwdLastSet_committed" not in result


# --------------------------------------------------------------------------- #
# ad_set_account_status — ACCOUNTDISABLE bit handling
# --------------------------------------------------------------------------- #
def test_disable_sets_only_accountdisable_bit():
    # Start with a UAC carrying an extra flag (DONT_EXPIRE_PASSWORD 0x10000).
    conn = _build_conn()
    start = 0x200 | 0x10000  # NORMAL_ACCOUNT + DONT_EXPIRE_PASSWORD = 66048
    dn = _add_user(conn, cn="jdoe", userAccountControl=[str(start)])
    conn.bind()
    client = _client(conn)
    result = client.set_account_status("jdoe", enabled=False, dry_run=False)
    new_uac = int(_read(conn, dn, "userAccountControl"))
    # ACCOUNTDISABLE now set; every other bit preserved.
    assert new_uac & _UAC_ACCOUNTDISABLE
    assert new_uac == start | _UAC_ACCOUNTDISABLE
    assert new_uac & 0x10000  # DONT_EXPIRE_PASSWORD untouched
    assert result["committed"] is True


def test_enable_clears_only_accountdisable_bit():
    conn = _build_conn()
    start = 0x200 | 0x2 | 0x10000  # disabled + dont-expire
    dn = _add_user(conn, cn="jdoe", userAccountControl=[str(start)])
    conn.bind()
    client = _client(conn)
    client.set_account_status("jdoe", enabled=True, dry_run=False)
    new_uac = int(_read(conn, dn, "userAccountControl"))
    assert not (new_uac & _UAC_ACCOUNTDISABLE)
    assert new_uac == start & ~_UAC_ACCOUNTDISABLE
    assert new_uac & 0x10000  # other bits preserved


def test_set_account_status_idempotent_noop():
    # Already enabled (512) → enabling again is a no-op: empty diff, no commit.
    client, conn, dn = _bound_client()
    result = client.set_account_status("jdoe", enabled=True, dry_run=False)
    assert result["changes"] == {}
    assert result["committed"] is False


def test_set_account_status_reads_object_once():
    # Consolidated read: set_account_status passes its raw read to diff_modify as
    # ``before`` so the toggle + diff share a single object read (no double-read).
    conn = _build_conn()
    dn = _add_user(conn, cn="jdoe")
    conn.bind()
    client = _client(conn)

    calls = {"n": 0}
    real_read_raw = client.read_raw_attributes

    def _counting_read_raw(read_dn, attrs):
        if read_dn == dn and list(attrs) == ["userAccountControl"]:
            calls["n"] += 1
        return real_read_raw(read_dn, attrs)

    client.read_raw_attributes = _counting_read_raw
    client.set_account_status("jdoe", enabled=False, dry_run=False)
    assert calls["n"] == 1


def test_set_account_status_dry_run_diff_no_write():
    client, conn, dn = _bound_client()
    result = client.set_account_status("jdoe", enabled=False, dry_run=True)
    assert result["dry_run"] is True
    assert result["committed"] is False
    assert result["changes"]["userAccountControl"] == {"before": ["512"], "after": ["514"]}
    assert str(_read(conn, dn, "userAccountControl")) == "512"


# --------------------------------------------------------------------------- #
# ad_unlock_account
# --------------------------------------------------------------------------- #
def test_unlock_account_sets_lockouttime_zero():
    conn = _build_conn()
    dn = _add_user(conn, cn="jdoe", lockoutTime=["132539328000000000"])
    conn.bind()
    client = _client(conn)
    result = client.unlock_account("jdoe", dry_run=False)
    assert result["committed"] is True
    assert result["changes"]["lockoutTime"]["after"] == ["0"]
    # lockoutTime uses the AD time syntax; assert on the raw wire value.
    assert _read_raw(conn, dn, "lockoutTime") == [b"0"]


def test_unlock_account_idempotent_when_already_zero():
    conn = _build_conn()
    _add_user(conn, cn="jdoe", lockoutTime=["0"])
    conn.bind()
    client = _client(conn)
    result = client.unlock_account("jdoe", dry_run=False)
    assert result["changes"] == {}
    assert result["committed"] is False


# --------------------------------------------------------------------------- #
# Tool dispatch through FastMCP
# --------------------------------------------------------------------------- #
def test_set_user_attributes_tool_dispatch_dry_run():
    client, _, _ = _bound_client()
    app.set_client(client)
    result = asyncio.run(
        app.mcp.call_tool(
            "ad_set_user_attributes",
            {"identifier": "jdoe", "attributes": {"title": "Director"}},
        )
    )
    assert result.is_error is False
    data = result.structured_content
    assert data["dry_run"] is True
    assert data["committed"] is False


def test_set_user_attributes_tool_rejects_bad_attribute_as_toolerror():
    from fastmcp.exceptions import ToolError

    client, _, _ = _bound_client()
    app.set_client(client)
    with pytest.raises(ToolError):
        asyncio.run(
            app.mcp.call_tool(
                "ad_set_user_attributes",
                {"identifier": "jdoe", "attributes": {"description": "x"}},
            )
        )
