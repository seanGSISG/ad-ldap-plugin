"""Unit tests for story-004 computer/group write tools and ADClient methods.

Runs fully offline against ldap3's MOCK_SYNC strategy with the bundled offline
AD schema (same harness as test_read_tools / test_user_writes). Covers:

- ``ad_set_computer_attributes``: managedBy validation (a valid user DN, a valid
  group DN, and a nonexistent principal that is rejected), a description edit,
  the empty-string clear, and whitelist rejection of any other attribute;
- ``ad_add_group_member`` / ``ad_remove_group_member``: the happy-path member
  add/remove diffs, and their idempotent no-ops (adding an existing member /
  removing a non-member commit nothing);
- the dry-run contract: every write tool defaults to dry_run=true, returns a
  before/after diff, and modifies nothing on disk;
- tool registration + annotations (destructive / idempotent hints).
"""

import asyncio

import pytest
from ldap3 import MOCK_SYNC, OFFLINE_AD_2012_R2, Connection, Server

import app
import tools_write_computer_group  # noqa: F401 — registers computer/group write tools
from ad_client import ADClient, COMPUTER_WRITABLE_ATTRIBUTES
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


def _build_conn():
    server = Server("fake-dc", get_info=OFFLINE_AD_2012_R2)
    conn = Connection(server, user=BIND_DN, password="s3cret", client_strategy=MOCK_SYNC)
    conn.strategy.add_entry(BIND_DN, {"objectClass": ["user"], "userPassword": "s3cret"})
    return conn


def _add_user(conn, cn="jdoe", **attrs):
    dn = f"CN={cn},OU=Users,{BASE_DN}"
    base = {
        "objectClass": ["user", "person"],
        "cn": [cn],
        "sAMAccountName": [cn],
        "userPrincipalName": [f"{cn}@lab.example.com"],
        "mail": [f"{cn}@lab.example.com"],
        "userAccountControl": ["512"],
    }
    base.update(attrs)
    conn.strategy.add_entry(dn, base, validate=False)
    return dn


def _add_group(conn, cn="Admins", members=None, **attrs):
    dn = f"CN={cn},OU=Groups,{BASE_DN}"
    base = {
        "objectClass": ["group", "top"],
        "cn": [cn],
        "sAMAccountName": [cn],
    }
    if members:
        base["member"] = list(members)
    base.update(attrs)
    conn.strategy.add_entry(dn, base, validate=False)
    return dn


def _add_computer(conn, name="PC01", **attrs):
    dn = f"CN={name},OU=Computers,{BASE_DN}"
    base = {
        "objectClass": ["computer", "top"],
        "cn": [name],
        "name": [name],
        "sAMAccountName": [f"{name}$"],
        "dNSHostName": [f"{name.lower()}.lab.example.com"],
        "description": ["initial desc"],
    }
    base.update(attrs)
    conn.strategy.add_entry(dn, base, validate=False)
    return dn


def _client(conn, **env_overrides):
    return ADClient(ADConfig.from_env(_env(**env_overrides)), connection=conn)


def _read_raw(conn, dn, attr):
    conn.search(dn, "(objectClass=*)", attributes=[attr])
    entry = conn.entries[0]
    try:
        return list(entry[attr].raw_values)
    except Exception:  # noqa: BLE001
        return []


@pytest.fixture(autouse=True)
def _reset_client():
    yield
    app.set_client(None)


def _scenario():
    """Build a populated mock directory: a user, a group, and a computer."""
    conn = _build_conn()
    user_dn = _add_user(conn, cn="jdoe")
    group_dn = _add_group(conn, cn="Owners")
    comp_dn = _add_computer(conn, name="PC01")
    conn.bind()
    return conn, user_dn, group_dn, comp_dn


# --------------------------------------------------------------------------- #
# Tool registration + annotations
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "tool_name,destructive,idempotent",
    [
        ("ad_set_computer_attributes", True, True),
        ("ad_add_group_member", False, True),
        ("ad_remove_group_member", True, True),
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
    ["ad_set_computer_attributes", "ad_add_group_member", "ad_remove_group_member"],
)
def test_write_tools_default_dry_run_true(tool_name):
    tool = asyncio.run(app.mcp.get_tool(tool_name))
    schema = tool.parameters
    assert schema["properties"]["dry_run"]["default"] is True


# --------------------------------------------------------------------------- #
# ad_set_computer_attributes — managedBy validation
# --------------------------------------------------------------------------- #
def test_set_computer_managedby_to_valid_user_dn():
    conn, user_dn, _group_dn, comp_dn = _scenario()
    client = _client(conn)
    out = client.set_computer_attributes("PC01", {"managedBy": "jdoe"}, dry_run=False)
    assert out["committed"] is True
    assert out["changes"]["managedBy"]["after"] == [user_dn]
    assert _read_raw(conn, comp_dn, "managedBy") == [user_dn.encode()]


def test_set_computer_managedby_to_valid_group_dn():
    conn, _user_dn, group_dn, comp_dn = _scenario()
    client = _client(conn)
    # A group (not a user) is an equally valid managedBy principal.
    out = client.set_computer_attributes("PC01", {"managedBy": group_dn}, dry_run=False)
    assert out["committed"] is True
    assert out["changes"]["managedBy"]["after"] == [group_dn]
    assert _read_raw(conn, comp_dn, "managedBy") == [group_dn.encode()]


def test_set_computer_managedby_nonexistent_principal_rejected():
    conn, _user_dn, _group_dn, _comp_dn = _scenario()
    client = _client(conn)
    with pytest.raises(LookupError):
        client.set_computer_attributes("PC01", {"managedBy": "ghost"}, dry_run=True)


# --------------------------------------------------------------------------- #
# ad_set_computer_attributes — description + clear + whitelist
# --------------------------------------------------------------------------- #
def test_set_computer_description_edit():
    conn, _user_dn, _group_dn, comp_dn = _scenario()
    client = _client(conn)
    out = client.set_computer_attributes("PC01", {"description": "Owned by IT"}, dry_run=False)
    assert out["committed"] is True
    assert out["changes"]["description"] == {"before": ["initial desc"], "after": ["Owned by IT"]}
    assert _read_raw(conn, comp_dn, "description") == [b"Owned by IT"]


def test_set_computer_empty_string_clears_description():
    conn, _user_dn, _group_dn, comp_dn = _scenario()
    client = _client(conn)
    out = client.set_computer_attributes("PC01", {"description": ""}, dry_run=False)
    assert out["committed"] is True
    assert out["changes"]["description"]["after"] == []
    assert _read_raw(conn, comp_dn, "description") == []


def test_set_computer_rejects_attribute_outside_whitelist():
    conn, _user_dn, _group_dn, _comp_dn = _scenario()
    client = _client(conn)
    with pytest.raises(ValueError):
        client.set_computer_attributes("PC01", {"operatingSystem": "Win"}, dry_run=True)


def test_set_computer_rejects_empty_payload():
    conn, _user_dn, _group_dn, _comp_dn = _scenario()
    client = _client(conn)
    with pytest.raises(ValueError):
        client.set_computer_attributes("PC01", {}, dry_run=True)


def test_set_computer_dry_run_returns_diff_without_modifying():
    conn, user_dn, _group_dn, comp_dn = _scenario()
    client = _client(conn)
    out = client.set_computer_attributes("PC01", {"managedBy": "jdoe"}, dry_run=True)
    assert out["dry_run"] is True
    assert out["committed"] is False
    assert out["changes"]["managedBy"]["after"] == [user_dn]
    # Nothing written: the computer still has no managedBy.
    assert _read_raw(conn, comp_dn, "managedBy") == []


# --------------------------------------------------------------------------- #
# Whitelist constant
# --------------------------------------------------------------------------- #
def test_computer_writable_attributes_is_exactly_description_and_managedby():
    assert set(COMPUTER_WRITABLE_ATTRIBUTES) == {"description", "managedBy"}


# --------------------------------------------------------------------------- #
# Group membership — add
# --------------------------------------------------------------------------- #
def test_add_group_member_happy_path():
    conn, user_dn, group_dn, _comp_dn = _scenario()
    client = _client(conn)
    out = client.add_group_member("Owners", "jdoe", dry_run=False)
    assert out["committed"] is True
    assert out["no_op"] is False
    assert out["member_dn"] == user_dn
    assert out["changes"]["member"]["after"] == [user_dn]
    assert _read_raw(conn, group_dn, "member") == [user_dn.encode()]


def test_add_group_member_dry_run_does_not_modify():
    conn, _user_dn, group_dn, _comp_dn = _scenario()
    client = _client(conn)
    out = client.add_group_member("Owners", "jdoe", dry_run=True)
    assert out["dry_run"] is True
    assert out["committed"] is False
    assert "member" in out["changes"]
    assert _read_raw(conn, group_dn, "member") == []


def test_add_group_member_existing_is_idempotent_noop():
    conn = _build_conn()
    user_dn = _add_user(conn, cn="jdoe")
    group_dn = _add_group(conn, cn="Owners", members=[user_dn])
    conn.bind()
    client = _client(conn)
    out = client.add_group_member("Owners", "jdoe", dry_run=False)
    assert out["no_op"] is True
    assert out["committed"] is False
    assert out["changes"] == {}
    # Member list unchanged (still exactly the one member).
    assert _read_raw(conn, group_dn, "member") == [user_dn.encode()]


def test_add_group_member_accepts_computer():
    conn = _build_conn()
    group_dn = _add_group(conn, cn="Owners")
    comp_dn = _add_computer(conn, name="PC01")
    conn.bind()
    client = _client(conn)
    out = client.add_group_member("Owners", "PC01", dry_run=False)
    assert out["committed"] is True
    assert out["member_dn"] == comp_dn
    assert _read_raw(conn, group_dn, "member") == [comp_dn.encode()]


# --------------------------------------------------------------------------- #
# Group membership — remove
# --------------------------------------------------------------------------- #
def test_remove_group_member_happy_path():
    conn = _build_conn()
    user_dn = _add_user(conn, cn="jdoe")
    group_dn = _add_group(conn, cn="Owners", members=[user_dn])
    conn.bind()
    client = _client(conn)
    out = client.remove_group_member("Owners", "jdoe", dry_run=False)
    assert out["committed"] is True
    assert out["no_op"] is False
    assert out["changes"]["member"]["after"] == []
    assert _read_raw(conn, group_dn, "member") == []


def test_remove_group_member_nonmember_is_idempotent_noop():
    conn, _user_dn, group_dn, _comp_dn = _scenario()
    client = _client(conn)
    out = client.remove_group_member("Owners", "jdoe", dry_run=False)
    assert out["no_op"] is True
    assert out["committed"] is False
    assert out["changes"] == {}
    assert _read_raw(conn, group_dn, "member") == []


def test_remove_group_member_dry_run_does_not_modify():
    conn = _build_conn()
    user_dn = _add_user(conn, cn="jdoe")
    group_dn = _add_group(conn, cn="Owners", members=[user_dn])
    conn.bind()
    client = _client(conn)
    out = client.remove_group_member("Owners", "jdoe", dry_run=True)
    assert out["dry_run"] is True
    assert out["committed"] is False
    assert out["changes"]["member"]["after"] == []
    assert _read_raw(conn, group_dn, "member") == [user_dn.encode()]


# --------------------------------------------------------------------------- #
# Tool dispatch through FastMCP
# --------------------------------------------------------------------------- #
def test_set_computer_attributes_tool_dispatch_dry_run():
    conn, _user_dn, _group_dn, _comp_dn = _scenario()
    app.set_client(_client(conn))
    result = asyncio.run(
        app.mcp.call_tool(
            "ad_set_computer_attributes",
            {"identifier": "PC01", "attributes": {"description": "x"}},
        )
    )
    assert result.is_error is False
    data = result.structured_content
    assert data["dry_run"] is True
    assert data["committed"] is False


def test_set_computer_attributes_tool_rejects_bad_attribute_as_toolerror():
    from fastmcp.exceptions import ToolError

    conn, _user_dn, _group_dn, _comp_dn = _scenario()
    app.set_client(_client(conn))
    with pytest.raises(ToolError):
        asyncio.run(
            app.mcp.call_tool(
                "ad_set_computer_attributes",
                {"identifier": "PC01", "attributes": {"operatingSystem": "Win"}},
            )
        )


def test_add_group_member_tool_dispatch_idempotent_noop():
    conn = _build_conn()
    user_dn = _add_user(conn, cn="jdoe")
    _add_group(conn, cn="Owners", members=[user_dn])
    conn.bind()
    app.set_client(_client(conn))
    result = asyncio.run(
        app.mcp.call_tool(
            "ad_add_group_member",
            {"group": "Owners", "member": "jdoe", "dry_run": False},
        )
    )
    assert result.is_error is False
    data = result.structured_content
    assert data["no_op"] is True
    assert data["committed"] is False


# --------------------------------------------------------------------------- #
# DN-form resolver hardening (cleanup-lows)
# --------------------------------------------------------------------------- #
def test_malformed_dn_identifier_raises_clear_lookuperror():
    # A DN-form identifier (contains '=') that is not a valid DN yields a clear
    # LookupError("not a valid DN: ...") up front rather than an opaque search miss.
    conn, _user_dn, _group_dn, _comp_dn = _scenario()
    client = _client(conn)
    with pytest.raises(LookupError, match="not a valid DN"):
        client._resolve_user_dn("=garbage,,,")


def test_dn_form_lookup_uses_base_scope_not_subtree():
    # A container DN must NOT resolve to a same-class descendant: with BASE scope
    # the container itself has no matching objectClass, so resolution fails even
    # though a matching computer lives beneath it.
    conn = _build_conn()
    container_dn = f"OU=Computers,{BASE_DN}"
    conn.strategy.add_entry(
        container_dn, {"objectClass": ["organizationalUnit", "top"], "ou": ["Computers"]},
        validate=False,
    )
    _add_computer(conn, name="PC01")  # descendant of the container
    conn.bind()
    client = _client(conn)
    with pytest.raises(LookupError):
        client._resolve_computer_dn(container_dn)


def test_membership_noop_canonicalizes_attribute_type_case():
    # The stored member DN differs only by attribute-type case (lower-case
    # cn=/ou=/dc=) from the resolved member DN. The canonicalized _dn_equal
    # comparison treats them as the same object, so an add is a no-op rather
    # than appending a duplicate member.
    conn = _build_conn()
    user_dn = _add_user(conn, cn="jdoe")
    lowered = user_dn.replace("CN=", "cn=").replace("OU=", "ou=").replace("DC=", "dc=")
    assert lowered != user_dn
    group_dn = _add_group(conn, cn="Owners", members=[lowered])
    conn.bind()
    client = _client(conn)
    out = client.add_group_member("Owners", "jdoe", dry_run=False)
    assert out["no_op"] is True
    assert out["committed"] is False
    # Unchanged: no duplicate member appended.
    assert _read_raw(conn, group_dn, "member") == [lowered.encode()]
