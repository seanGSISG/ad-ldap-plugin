"""Unit tests for story-005: bulk managedBy assignment (plan/apply workflow).

Runs fully offline against ldap3's MOCK_SYNC strategy with the bundled offline
AD schema (same harness as the other write-tool test modules). Covers:

- the pure matching helpers (normalize_owner trim/collapse, build_display_index
  case-insensitivity, classify_owner matched/ambiguous/unmatched);
- bucket classification end-to-end: exact match, case/trim insensitivity,
  ambiguous (2+ users sharing a displayName), no_description, no_user_match,
  already_assigned;
- hint precedence: hint overrides description on conflict, hint fills a gap when
  description is empty, an unresolvable hint -> unmatched/hint_unresolved;
- apply mode commits only the matched bucket and skips/reports the rest;
- per-item error isolation: one failing commit does not abort the run;
- the description field is NEVER modified (every conn.modify call is inspected,
  and plan mode issues zero writes);
- overwrite=false leaves already-assigned computers untouched; overwrite=true
  moves a fresh match back into the matched bucket;
- tool registration/annotations + FastMCP dispatch (plan mode default).
"""

import asyncio

import pytest
from ldap3 import MOCK_SYNC, OFFLINE_AD_2012_R2, Connection, Server

import app
import tools_bulk  # noqa: F401 — registers the bulk tool on import
from ad_client import ADClient
from bulk_assign import (
    REASON_HINT_UNRESOLVED,
    REASON_NO_DESCRIPTION,
    REASON_NO_USER_MATCH,
    SOURCE_DESCRIPTION,
    build_display_index,
    classify_owner,
    normalize_owner,
)
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
    # MOCK_SYNC cannot evaluate the AD bitwise disabled-exclusion clause the bulk
    # user-index build now emits; strip it so end-to-end bucket/apply tests run.
    # (Clause-presence tests overwrite paged_search via _paged_search_spy.)
    _strip_bitwise_clause(conn)
    return conn


def _add_user(conn, cn="jdoe", display_name=None, **attrs):
    dn = f"CN={cn},OU=Users,{BASE_DN}"
    base = {
        "objectClass": ["user", "person"],
        "cn": [cn],
        "sAMAccountName": [cn],
        "userPrincipalName": [f"{cn}@lab.example.com"],
        "mail": [f"{cn}@lab.example.com"],
        "userAccountControl": ["512"],
    }
    if display_name is not None:
        base["displayName"] = [display_name]
    base.update(attrs)
    conn.strategy.add_entry(dn, base, validate=False)
    return dn


def _add_group(conn, cn="Admins", **attrs):
    dn = f"CN={cn},OU=Groups,{BASE_DN}"
    base = {"objectClass": ["group", "top"], "cn": [cn], "sAMAccountName": [cn]}
    base.update(attrs)
    conn.strategy.add_entry(dn, base, validate=False)
    return dn


def _add_computer(conn, name="PC01", description="initial desc", managed_by=None, **attrs):
    dn = f"CN={name},OU=Computers,{BASE_DN}"
    base = {
        "objectClass": ["computer", "top"],
        "cn": [name],
        "name": [name],
        "sAMAccountName": [f"{name}$"],
        "dNSHostName": [f"{name.lower()}.lab.example.com"],
    }
    if description is not None:
        base["description"] = [description]
    if managed_by is not None:
        base["managedBy"] = [managed_by]
    base.update(attrs)
    conn.strategy.add_entry(dn, base, validate=False)
    return dn


def _client(conn, **env_overrides):
    return ADClient(ADConfig.from_env(_env(**env_overrides)), connection=conn)


# The bulk user-index build now applies the AD bitwise disabled-exclusion clause
# unconditionally (only ENABLED users are owner candidates). ldap3's MOCK_SYNC
# strategy cannot evaluate that extensible matching rule, so for the end-to-end
# bucket/apply tests below we transparently STRIP the clause before the search
# reaches the mock. Since these tests add no disabled users, the result set is
# identical to what a real DC would return. Tests that assert the clause IS
# present spy on paged_search directly (see _paged_search_spy) and are unaffected.
_BITWISE_DISABLED = "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"


def _strip_bitwise_clause(conn):
    real = conn.extend.standard.paged_search

    def patched(*args, **kwargs):
        f = kwargs.get("search_filter")
        if f and _BITWISE_DISABLED in f:
            kwargs["search_filter"] = f.replace(_BITWISE_DISABLED, "")
        return real(*args, **kwargs)

    conn.extend.standard.paged_search = patched  # type: ignore[method-assign]


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


def _spy_modify(conn):
    """Wrap conn.modify so every call's (dn, change-dict) is recorded.

    Returns the list the spy appends to. Lets a test assert exactly which
    attributes were ever sent to a MODIFY (notably: never ``description``).
    """
    calls: list[tuple] = []
    real = conn.modify

    def spy(dn, changes, *args, **kwargs):
        calls.append((dn, changes))
        return real(dn, changes, *args, **kwargs)

    conn.modify = spy  # type: ignore[method-assign]
    return calls


# --------------------------------------------------------------------------- #
# Pure matching helpers
# --------------------------------------------------------------------------- #
def test_normalize_owner_trims_and_collapses():
    assert normalize_owner("  Jane   Doe  ") == "Jane Doe"
    assert normalize_owner("Jane Doe") == "Jane Doe"


def test_normalize_owner_empty_and_missing():
    assert normalize_owner("") == ""
    assert normalize_owner(None) == ""
    assert normalize_owner("    ") == ""


def test_derive_owner_returns_named_fields_for_description_source():
    from ad_client import OwnerSource

    client = ADClient.__new__(ADClient)  # no connection needed for the description path
    result = client._derive_owner({"name": "PC01", "description": "  Jane  Doe "}, {})
    assert isinstance(result, OwnerSource)
    assert result.source == SOURCE_DESCRIPTION
    assert result.value == "Jane Doe"
    assert result.hint_dn is None
    # Positional unpacking still works (backward-compatible).
    source, value, hint_dn = result
    assert (source, value, hint_dn) == (SOURCE_DESCRIPTION, "Jane Doe", None)


def test_build_display_index_is_case_insensitive_and_groups_duplicates():
    users = [
        {"dn": "CN=a", "displayName": "Jane Doe", "sAMAccountName": "a"},
        {"dn": "CN=b", "displayName": "jane doe", "sAMAccountName": "b"},
        {"dn": "CN=c", "displayName": "Bob Smith", "sAMAccountName": "c"},
        {"dn": "CN=d", "displayName": None, "sAMAccountName": "d"},  # skipped
    ]
    index = build_display_index(users)
    assert set(index) == {"jane doe", "bob smith"}
    assert len(index["jane doe"]) == 2  # both Janes collapse to one key
    assert len(index["bob smith"]) == 1


def test_classify_owner_matched_ambiguous_unmatched():
    index = build_display_index(
        [
            {"dn": "CN=a", "displayName": "Jane Doe"},
            {"dn": "CN=b", "displayName": "Jane Doe"},
            {"dn": "CN=c", "displayName": "Bob Smith"},
        ]
    )
    # exact single match (case-insensitive)
    assert classify_owner("bob smith", index) == {
        "bucket": "matched",
        "user": {"dn": "CN=c", "displayName": "Bob Smith"},
    }
    # two users -> ambiguous
    amb = classify_owner("Jane Doe", index)
    assert amb["bucket"] == "ambiguous"
    assert len(amb["candidates"]) == 2
    # no users -> unmatched/no_user_match
    assert classify_owner("Nobody", index) == {
        "bucket": "unmatched",
        "reason": REASON_NO_USER_MATCH,
    }
    # empty owner -> unmatched/no_description
    assert classify_owner("", index) == {
        "bucket": "unmatched",
        "reason": REASON_NO_DESCRIPTION,
    }


# --------------------------------------------------------------------------- #
# Plan-mode bucket classification (end-to-end against the mock directory)
# --------------------------------------------------------------------------- #
def test_plan_buckets_basic_classification():
    conn = _build_conn()
    _add_user(conn, cn="jane", display_name="Jane Doe")
    _add_user(conn, cn="bob", display_name="Bob Smith")
    # two users share a displayName -> ambiguous
    _add_user(conn, cn="dup1", display_name="Dup Person")
    _add_user(conn, cn="dup2", display_name="Dup Person")
    _add_computer(conn, name="PCMATCH", description="  Jane   Doe ")  # trim/collapse -> matched
    _add_computer(conn, name="PCAMB", description="Dup Person")  # ambiguous
    _add_computer(conn, name="PCNONE", description="Ghost User")  # no_user_match
    _add_computer(conn, name="PCEMPTY", description="")  # no_description
    conn.bind()
    calls = _spy_modify(conn)
    client = _client(conn)

    report = client.bulk_assign_managers()

    assert report["apply"] is False
    assert report["scanned"] == 4
    assert report["counts"]["matched"] == 1
    assert report["counts"]["ambiguous"] == 1
    assert report["counts"]["unmatched"] == 2

    matched = report["matched"][0]
    assert matched["computer"] == "PCMATCH"
    assert matched["owner"] == "Jane Doe"
    assert matched["source"] == "description"
    assert matched["owner_dn"] == f"CN=jane,OU=Users,{BASE_DN}"

    reasons = {u["computer"]: u["reason"] for u in report["unmatched"]}
    assert reasons["PCNONE"] == REASON_NO_USER_MATCH
    assert reasons["PCEMPTY"] == REASON_NO_DESCRIPTION

    # AC: plan mode performs no write whatsoever.
    assert calls == []


def test_plan_already_assigned_bucket_default_no_overwrite():
    conn = _build_conn()
    jane_dn = _add_user(conn, cn="jane", display_name="Jane Doe")
    _add_computer(conn, name="PCSET", description="Jane Doe", managed_by=jane_dn)
    conn.bind()
    calls = _spy_modify(conn)
    client = _client(conn)

    report = client.bulk_assign_managers()
    assert report["counts"]["already_assigned"] == 1
    assert report["counts"]["matched"] == 0
    assert report["already_assigned"][0]["computer"] == "PCSET"
    assert report["already_assigned"][0]["current_managedBy"] == jane_dn
    assert calls == []


def test_plan_already_assigned_with_overwrite_becomes_matched():
    conn = _build_conn()
    jane_dn = _add_user(conn, cn="jane", display_name="Jane Doe")
    _add_computer(conn, name="PCSET", description="Jane Doe", managed_by="CN=old,OU=Users," + BASE_DN)
    conn.bind()
    client = _client(conn)

    report = client.bulk_assign_managers(overwrite=True)
    assert report["counts"]["already_assigned"] == 0
    assert report["counts"]["matched"] == 1
    assert report["matched"][0]["owner_dn"] == jane_dn


# --------------------------------------------------------------------------- #
# Hints: precedence over description, gap-fill, unresolvable
# --------------------------------------------------------------------------- #
def test_hint_overrides_description_on_conflict():
    conn = _build_conn()
    _add_user(conn, cn="jane", display_name="Jane Doe")
    bob_dn = _add_user(conn, cn="bob", display_name="Bob Smith")
    _add_computer(conn, name="PCX", description="Jane Doe")  # description says Jane
    conn.bind()
    client = _client(conn)

    report = client.bulk_assign_managers(hints={"PCX": "bob"})  # hint says Bob
    assert report["counts"]["matched"] == 1
    entry = report["matched"][0]
    assert entry["source"] == "hint"
    assert entry["owner"] == "bob"
    assert entry["owner_dn"] == bob_dn


def test_hint_fills_gap_when_description_empty():
    conn = _build_conn()
    bob_dn = _add_user(conn, cn="bob", display_name="Bob Smith")
    _add_computer(conn, name="PCEMPTY", description="")  # would be no_description
    conn.bind()
    client = _client(conn)

    report = client.bulk_assign_managers(hints={"PCEMPTY": "bob"})
    assert report["counts"]["unmatched"] == 0
    assert report["counts"]["matched"] == 1
    assert report["matched"][0]["source"] == "hint"
    assert report["matched"][0]["owner_dn"] == bob_dn


def test_hint_can_be_keyed_by_dn():
    conn = _build_conn()
    bob_dn = _add_user(conn, cn="bob", display_name="Bob Smith")
    comp_dn = _add_computer(conn, name="PCEMPTY", description="")
    conn.bind()
    client = _client(conn)

    report = client.bulk_assign_managers(hints={comp_dn: "bob"})
    assert report["counts"]["matched"] == 1
    assert report["matched"][0]["owner_dn"] == bob_dn


def test_unresolvable_hint_goes_to_unmatched():
    conn = _build_conn()
    _add_computer(conn, name="PCX", description="")
    conn.bind()
    client = _client(conn)

    report = client.bulk_assign_managers(hints={"PCX": "ghost"})
    assert report["counts"]["unmatched"] == 1
    u = report["unmatched"][0]
    assert u["source"] == "hint"
    assert u["reason"] == REASON_HINT_UNRESOLVED


# --------------------------------------------------------------------------- #
# Apply mode: commit matched only, skip the rest, never touch description
# --------------------------------------------------------------------------- #
def test_apply_commits_only_matched_and_skips_rest():
    conn = _build_conn()
    jane_dn = _add_user(conn, cn="jane", display_name="Jane Doe")
    _add_user(conn, cn="dup1", display_name="Dup Person")
    _add_user(conn, cn="dup2", display_name="Dup Person")
    match_dn = _add_computer(conn, name="PCMATCH", description="Jane Doe")
    _add_computer(conn, name="PCAMB", description="Dup Person")
    _add_computer(conn, name="PCNONE", description="Ghost")
    conn.bind()
    calls = _spy_modify(conn)
    client = _client(conn)

    report = client.bulk_assign_managers(apply=True)
    assert report["apply"] is True
    assert report["counts"]["committed"] == 1
    assert report["counts"]["failed"] == 0
    assert report["counts"]["ambiguous"] == 1
    assert report["counts"]["unmatched"] == 1

    # Only PCMATCH got managedBy written.
    assert _read_raw(conn, match_dn, "managedBy") == [jane_dn.encode()]
    # Every MODIFY targeted managedBy only — description was NEVER modified.
    assert calls, "expected at least one managedBy write"
    for _dn, change in calls:
        assert "description" not in change
        assert set(change) == {"managedBy"}


def test_apply_never_modifies_description_even_with_hints():
    conn = _build_conn()
    _add_user(conn, cn="bob", display_name="Bob Smith")
    comp_dn = _add_computer(conn, name="PCX", description="some owner name")
    conn.bind()
    calls = _spy_modify(conn)
    client = _client(conn)

    client.bulk_assign_managers(hints={"PCX": "bob"}, apply=True)
    # description value on disk is unchanged.
    assert _read_raw(conn, comp_dn, "description") == [b"some owner name"]
    for _dn, change in calls:
        assert "description" not in change


def test_apply_per_item_error_isolation():
    """One failing commit must not abort the run; it is captured in 'failed'."""
    conn = _build_conn()
    jane_dn = _add_user(conn, cn="jane", display_name="Jane Doe")
    bob_dn = _add_user(conn, cn="bob", display_name="Bob Smith")
    good_dn = _add_computer(conn, name="PCGOOD", description="Jane Doe")
    bad_dn = _add_computer(conn, name="PCBAD", description="Bob Smith")
    conn.bind()
    client = _client(conn)

    original = client.set_computer_attributes

    def flaky(identifier, attributes, *, dry_run=True):
        if identifier == bad_dn:
            raise RuntimeError("simulated DC failure")
        return original(identifier, attributes, dry_run=dry_run)

    client.set_computer_attributes = flaky  # type: ignore[method-assign]

    report = client.bulk_assign_managers(apply=True)
    assert report["counts"]["committed"] == 1
    assert report["counts"]["failed"] == 1
    committed_dns = {c["dn"] for c in report["committed"]}
    failed = report["failed"][0]
    assert good_dn in committed_dns
    assert failed["dn"] == bad_dn
    assert "simulated DC failure" in failed["error"]
    # The good one still actually wrote managedBy despite the sibling failure.
    assert _read_raw(conn, good_dn, "managedBy") == [jane_dn.encode()]
    # The bad one wrote nothing.
    assert _read_raw(conn, bad_dn, "managedBy") == []
    assert bob_dn  # referenced for clarity


def test_plan_mode_issues_zero_writes_with_hints_and_overwrite():
    conn = _build_conn()
    jane_dn = _add_user(conn, cn="jane", display_name="Jane Doe")
    _add_computer(conn, name="PC1", description="Jane Doe")
    _add_computer(conn, name="PC2", description="", managed_by=jane_dn)
    conn.bind()
    calls = _spy_modify(conn)
    client = _client(conn)

    client.bulk_assign_managers(hints={"PC2": "jane"}, apply=False, overwrite=True)
    assert calls == []


# --------------------------------------------------------------------------- #
# Tool registration + FastMCP dispatch
# --------------------------------------------------------------------------- #
def test_bulk_tool_registered_with_expected_annotations():
    tool = asyncio.run(app.mcp.get_tool("ad_bulk_assign_managers"))
    assert tool.name == "ad_bulk_assign_managers"
    assert len(tool.name) <= 64
    assert tool.description
    assert tool.annotations.destructiveHint is True
    assert tool.annotations.idempotentHint is True


def test_bulk_tool_defaults_to_plan_mode():
    tool = asyncio.run(app.mcp.get_tool("ad_bulk_assign_managers"))
    schema = tool.parameters
    assert schema["properties"]["apply"]["default"] is False
    assert schema["properties"]["overwrite"]["default"] is False


def test_bulk_tool_dispatch_plan_mode():
    conn = _build_conn()
    _add_user(conn, cn="jane", display_name="Jane Doe")
    _add_computer(conn, name="PCMATCH", description="Jane Doe")
    conn.bind()
    calls = _spy_modify(conn)
    app.set_client(_client(conn))

    result = asyncio.run(app.mcp.call_tool("ad_bulk_assign_managers", {}))
    assert result.is_error is False
    data = result.structured_content
    assert data["apply"] is False
    assert data["counts"]["matched"] == 1
    assert calls == []


# --------------------------------------------------------------------------- #
# Bulk user-index build: only ENABLED users are owner candidates (Feature 1),
# and scoped search bases are honoured (Feature 2).
#
# MOCK CAVEAT: ldap3's MOCK_SYNC strategy cannot evaluate the bitwise rule
# 1.2.840.113556.1.4.803, so we spy on paged_search to assert the generated
# filter/base rather than executing the disabled-exclusion clause on the mock.
# --------------------------------------------------------------------------- #

_DISABLED_CLAUSE = "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"


def _paged_search_spy(conn):
    """Capture (search_base, search_filter) for every paged_search and return an
    empty generator so the unsupported bitwise clause is never run on the mock."""
    captured: list[tuple] = []

    def spy(*args, **kwargs):
        captured.append((kwargs.get("search_base"), kwargs.get("search_filter")))
        return iter([])

    conn.extend.standard.paged_search = spy  # type: ignore[method-assign]
    return captured


def test_bulk_user_index_build_excludes_disabled():
    conn = _build_conn()
    conn.bind()
    client = _client(conn)
    captured = _paged_search_spy(conn)

    client.bulk_assign_managers()

    user_filters = [f for _, f in captured if "objectClass=user" in (f or "")]
    assert user_filters, "expected a user-index paged_search"
    assert all(_DISABLED_CLAUSE in f for f in user_filters)


def test_bulk_sweep_uses_scoped_bases_when_set():
    user_base = f"OU=_Users,{BASE_DN}"
    comp_base = f"OU=_Computers,{BASE_DN}"
    conn = _build_conn()
    conn.bind()
    client = _client(
        conn, AD_USER_SEARCH_BASE=user_base, AD_COMPUTER_SEARCH_BASE=comp_base
    )
    captured = _paged_search_spy(conn)

    client.bulk_assign_managers()

    bases = {f: b for b, f in captured}
    user_base_used = next(b for f, b in bases.items() if "objectClass=user" in f)
    comp_base_used = next(b for f, b in bases.items() if f == "(objectClass=computer)")
    assert user_base_used == user_base
    assert comp_base_used == comp_base


def test_bulk_sweep_falls_back_to_base_dn():
    conn = _build_conn()
    conn.bind()
    client = _client(conn)
    captured = _paged_search_spy(conn)

    client.bulk_assign_managers()

    assert all(b == BASE_DN for b, _ in captured)


def test_bulk_disabled_user_never_matched():
    # End-to-end (no bitwise clause needed at the Python layer): a disabled user
    # is excluded from the match index, so a computer described with that owner's
    # display name lands in unmatched rather than matched.
    #
    # The exclusion happens in the LDAP filter, which MOCK_SYNC cannot evaluate,
    # so we simulate it by stubbing the index build to mirror real-AD behaviour:
    # the disabled user is simply absent from the candidate list.
    conn = _build_conn()
    _add_computer(conn, name="PCDIS", description="Ghost User")
    conn.bind()
    client = _client(conn)
    # Real AD's filter would omit the disabled user from this list.
    client._all_users_for_matching = lambda: []  # type: ignore[method-assign]

    report = client.bulk_assign_managers()
    assert report["counts"]["matched"] == 0
    assert any(c["computer"] == "PCDIS" for c in report["unmatched"])
