"""ldap3 connection management and safe LDAP primitives.

Responsibilities for story-001:
- Build an LDAPS ``Server``/``Connection`` from :class:`config.ADConfig`, with TLS
  validation on by default and a documented self-signed lab opt-out.
- ``check_connection`` — bind diagnostic returning whoami + server info.
- The shared **dry-run/diff** write framework (:meth:`ADClient.diff_modify`):
  every mutation reads the current values, computes a before/after diff, and
  commits only when ``dry_run=False``.
"""

from __future__ import annotations

import ssl
from datetime import datetime, timezone
from typing import Any, Mapping, NamedTuple, Sequence

from ldap3 import (
    ALL,
    BASE,
    MODIFY_ADD,
    MODIFY_DELETE,
    MODIFY_REPLACE,
    SIMPLE,
    SUBTREE,
    Connection,
    Server,
    Tls,
)
from ldap3.extend.microsoft.modifyPassword import ad_modify_password
from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import parse_dn, safe_dn

from bulk_assign import (
    REASON_HINT_UNRESOLVED,
    SOURCE_DESCRIPTION,
    SOURCE_HINT,
    build_display_index,
    classify_owner,
    normalize_owner,
)
from config import ADConfig

# Default number of computers committed per chunk in bulk apply mode. Chunking
# bounds the blast radius of a single run; per-item errors are captured so one
# failure never aborts the chunk or the run.
_BULK_APPLY_CHUNK_SIZE = 50


class OwnerSource(NamedTuple):
    """Result of :meth:`ADClient._derive_owner` — where one computer's owner came
    from. ``source`` is ``"hint"`` or ``"description"``; ``value`` is the raw hint
    identifier or the normalized description owner string; ``hint_dn`` is the
    resolved principal DN for a hint (``None`` for a description, or when a hint
    is unresolvable).
    """

    source: str
    value: str
    hint_dn: str | None

# ldap3 raises LDAPKeyError when an attribute is absent from an Entry; build a
# flat tuple of "attribute missing" exceptions to catch on reads.
try:
    from ldap3.core.exceptions import LDAPKeyError as _LDAPKeyError

    _ATTR_MISSING_ERRORS: tuple = (_LDAPKeyError, KeyError)
except Exception:  # pragma: no cover - defensive import shim
    _ATTR_MISSING_ERRORS = (KeyError,)

# Seconds before a dead DC fails fast instead of hanging.
_CONNECT_TIMEOUT = 10
_RECEIVE_TIMEOUT = 30

# userAccountControl bit: password never expires.
_UAC_DONT_EXPIRE_PASSWORD = 0x10000
# userAccountControl bit: the account is disabled (ACCOUNTDISABLE).
_UAC_ACCOUNTDISABLE = 0x2
# LDAP filter clause that excludes disabled accounts using the AD bitwise
# (LDAP_MATCHING_RULE_BIT_AND) matching rule: matches only users whose
# ACCOUNTDISABLE (0x2) bit is NOT set. NOTE: ldap3's MOCK_SYNC strategy does not
# implement this extensible matching rule (it raises LDAPAttributeError), so the
# offline test suite asserts the *generated filter string* for the default path
# and exercises result mapping with include_disabled=True. Real AD evaluates the
# rule correctly.
_FILTER_EXCLUDE_DISABLED = "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
# Default userAccountControl for a normal enabled account (NORMAL_ACCOUNT) when a
# user object somehow carries no userAccountControl value to read-modify-write.
_UAC_NORMAL_ACCOUNT = 0x200

# The exact attributes ad_set_user_attributes is permitted to MODIFY_REPLACE.
# Anything outside this whitelist is rejected. manager is handled by its own
# tool (ad_set_user_manager) and is deliberately NOT included here.
USER_WRITABLE_ATTRIBUTES: tuple[str, ...] = (
    "department",
    "title",
    "physicalDeliveryOfficeName",
    "telephoneNumber",
    "extensionAttribute1",
    "extensionAttribute10",
)

# The exact attributes ad_set_computer_attributes is permitted to MODIFY_REPLACE.
# Anything outside this whitelist is rejected. ``managedBy`` is validated to
# resolve to an existing user OR group object before it is set; an empty string
# clears it (MODIFY_REPLACE []).
COMPUTER_WRITABLE_ATTRIBUTES: tuple[str, ...] = (
    "description",
    "managedBy",
)
# 100-nanosecond intervals per day (AD stores time deltas/FILETIME in 100ns ticks).
_TICKS_PER_DAY = 864_000_000_000
# Difference between the Windows FILETIME epoch (1601-01-01) and the Unix epoch.
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

# Agreed read attribute sets (authoritative — see spec.md / DESIGN.md).
USER_READ_ATTRIBUTES: tuple[str, ...] = (
    "cn",
    "company",
    "department",
    "displayName",
    "distinguishedName",
    "employeeID",
    "extensionAttribute1",
    "extensionAttribute10",
    "facsimileTelephoneNumber",
    "givenName",
    "initials",
    "lastLogon",
    "mail",
    "manager",
    "name",
    "physicalDeliveryOfficeName",
    "pwdLastSet",
    "sAMAccountName",
    "sn",
    "telephoneNumber",
    "title",
    "userPrincipalName",
)

COMPUTER_READ_ATTRIBUTES: tuple[str, ...] = (
    "cn",
    "description",
    "distinguishedName",
    "lastLogon",
    "name",
    "operatingSystem",
    "whenCreated",
    "managedBy",
)


def _as_list(value: Any) -> list:
    """Normalise an ldap3 attribute value into a plain list."""
    if value is None:
        return []
    if isinstance(value, (str, bytes)):
        return [value]
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def _first(values: Sequence) -> Any:
    """Return the first element of a list, or None when empty."""
    return values[0] if values else None


def _validate_dn(identifier: str) -> None:
    """Raise ``LookupError`` if an identifier in DN form is not a syntactically
    valid DN.

    Used by the resolvers' ``"=" in identifier`` (DN) branch so a malformed DN
    yields a clear error up front instead of an opaque "no object matched"
    search failure.
    """
    try:
        parse_dn(identifier)
    except Exception as exc:  # noqa: BLE001 — ldap3 raises LDAPInvalidDnError subtypes
        raise LookupError(f"not a valid DN: {identifier!r} ({exc})") from exc


def _dn_normalize(dn: str) -> str:
    """Canonicalize a DN for equality comparison.

    Uses ldap3's :func:`safe_dn` to normalize RDN ordering of components,
    whitespace, and attribute-value escaping, then casefolds, so two DNs that
    denote the same object compare equal despite cosmetic encoding differences.
    Falls back to a plain casefold if the value cannot be parsed as a DN.
    """
    try:
        return safe_dn(dn).casefold()
    except Exception:  # noqa: BLE001 — non-DN value; fall back to plain casefold
        return dn.casefold()


def _dn_equal(a: str, b: str) -> bool:
    """Return True if two DN strings denote the same object (canonicalized)."""
    return _dn_normalize(a) == _dn_normalize(b)


def _raw_values(entry, attr: str) -> list:
    """Return an Entry's raw (undecoded) values for an attribute, or []."""
    try:
        return list(entry[attr].raw_values)
    except _ATTR_MISSING_ERRORS:
        return []


def compute_diff(before: Mapping[str, Sequence], after: Mapping[str, Sequence]) -> dict:
    """Return ``{attr: {"before": [...], "after": [...]}}`` for changed attrs only.

    Pure function — the heart of the before/after diff. Attributes whose value is
    unchanged are omitted so the diff shows only what a write would actually do.
    """
    diff: dict[str, dict[str, list]] = {}
    for attr, new_vals in after.items():
        old = _as_list(before.get(attr))
        new = _as_list(new_vals)
        if old != new:
            diff[attr] = {"before": old, "after": new}
    return diff


def _raw_int(raw_values: Sequence) -> int | None:
    """Parse the first raw attribute value (bytes/str) as an int, or None."""
    if not raw_values:
        return None
    value = raw_values[0]
    if isinstance(value, bytes):
        value = value.decode("ascii", "ignore")
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _now_filetime() -> int:
    """Current time as a Windows FILETIME (100ns ticks since 1601-01-01 UTC)."""
    delta = datetime.now(timezone.utc) - _FILETIME_EPOCH
    return int(delta.total_seconds() * 10_000_000)


def compute_password_expiry(
    pwd_last_set: int | None,
    max_pwd_age: int | None,
    user_account_control: int | None,
    *,
    now_filetime: int | None = None,
) -> dict:
    """Derive password expiry status from raw AD values.

    All time arguments are raw AD integers:
    - ``pwd_last_set`` — FILETIME of the last password set. ``0`` means the user
      must change their password at next logon (treated as already expired).
    - ``max_pwd_age`` — the domain ``maxPwdAge`` delta in 100ns ticks (AD stores
      it negative; ``0`` or ``None`` means passwords never expire domain-wide).
    - ``user_account_control`` — when the DONT_EXPIRE_PASSWORD bit is set, the
      password never expires for this account.

    Returns ``{"password_expired": bool, "days_until_expiry": int | None}``.
    ``days_until_expiry`` is ``None`` whenever expiry does not apply (never
    expires) or cannot be determined (missing pwdLastSet).
    """
    # Account-level "never expires" wins.
    if user_account_control is not None and user_account_control & _UAC_DONT_EXPIRE_PASSWORD:
        return {"password_expired": False, "days_until_expiry": None}

    # pwdLastSet == 0 → must change at next logon (effectively expired now).
    if pwd_last_set == 0:
        return {"password_expired": True, "days_until_expiry": None}

    if pwd_last_set is None:
        return {"password_expired": False, "days_until_expiry": None}

    # Domain-wide "never expires" (maxPwdAge 0 or unset).
    max_age_ticks = abs(max_pwd_age) if max_pwd_age else 0
    if not max_age_ticks:
        return {"password_expired": False, "days_until_expiry": None}

    now = _now_filetime() if now_filetime is None else now_filetime
    expires_at = pwd_last_set + max_age_ticks
    remaining_ticks = expires_at - now
    days = remaining_ticks // _TICKS_PER_DAY
    return {
        "password_expired": remaining_ticks <= 0,
        "days_until_expiry": int(days),
    }


def _entry_attributes(entry, attributes: Sequence[str]) -> dict[str, list]:
    """Collapse an ldap3 Entry into ``{attr: [values]}`` for the named attrs."""
    result: dict[str, list] = {}
    for attr in attributes:
        try:
            result[attr] = _as_list(entry[attr].value)
        except _ATTR_MISSING_ERRORS:
            result[attr] = []
    return result


class ADClient:
    """Manages an ldap3 connection to AD and exposes safe primitives."""

    def __init__(self, config: ADConfig, *, connection: Connection | None = None) -> None:
        self.config = config
        self._conn = connection

    # ------------------------------------------------------------------ #
    # Connection construction
    # ------------------------------------------------------------------ #
    def build_tls(self) -> Tls:
        """Build the TLS context. Validation defaults on; lab opt-out via config."""
        if self.config.tls_validate:
            return Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=self.config.ca_certs)
        # Lab-only: self-signed DC, validation disabled. Never for production.
        return Tls(validate=ssl.CERT_NONE)

    def build_server(self) -> Server:
        return Server(
            host=self.config.server,
            port=self.config.port,
            use_ssl=self.config.use_ssl,
            tls=self.build_tls(),
            get_info=ALL,
            connect_timeout=_CONNECT_TIMEOUT,
        )

    def _make_connection(self) -> Connection:
        return Connection(
            self.build_server(),
            user=self.config.bind_user,
            password=self.config.bind_password,
            authentication=SIMPLE,
            auto_referrals=False,  # never chase referrals against AD
            receive_timeout=_RECEIVE_TIMEOUT,
            raise_exceptions=False,
        )

    @property
    def conn(self) -> Connection:
        """The live connection, bound on first access and rebound if stale."""
        if self._conn is None:
            self._conn = self._make_connection()
        if not self._conn.bound:
            self._conn.bind()
        return self._conn

    # ------------------------------------------------------------------ #
    # Diagnostics
    # ------------------------------------------------------------------ #
    def _safe_whoami(self) -> str | None:
        try:
            return self.conn.extend.standard.who_am_i()
        except Exception:  # noqa: BLE001 — diagnostic only; mock/older DCs may not answer
            return None

    def _server_info(self) -> dict | None:
        info = getattr(self.conn.server, "info", None)
        if info is None:
            return None
        naming = list(getattr(info, "naming_contexts", None) or [])
        return {
            "naming_contexts": naming,
            "supported_ldap_versions": list(getattr(info, "supported_ldap_versions", None) or []),
            "vendor_name": getattr(info, "vendor_name", None),
        }

    def check_connection(self) -> dict:
        """Bind to the DC and report identity + server info (read-only diagnostic)."""
        conn = self.conn  # triggers bind
        return {
            "connected": bool(conn.bound),
            "server": self.config.server,
            "port": self.config.port,
            "use_ssl": self.config.use_ssl,
            "tls_validate": self.config.tls_validate,
            "base_dn": self.config.base_dn,
            "bind_user": self.config.bind_user,
            "whoami": self._safe_whoami(),
            "server_info": self._server_info(),
        }

    # ------------------------------------------------------------------ #
    # Reads
    # ------------------------------------------------------------------ #
    def read_attributes(self, dn: str, attributes: Sequence[str]) -> dict[str, list]:
        """Read the named attributes of a single object as ``{attr: [values]}``."""
        attrs = list(attributes)
        self.conn.search(dn, "(objectClass=*)", search_scope=BASE, attributes=attrs)
        if not self.conn.entries:
            raise LookupError(f"Object not found: {dn}")
        entry = self.conn.entries[0]
        result: dict[str, list] = {}
        for attr in attrs:
            try:
                result[attr] = _as_list(entry[attr].value)
            except _ATTR_MISSING_ERRORS:
                result[attr] = []
        return result

    def read_raw_attributes(self, dn: str, attributes: Sequence[str]) -> dict[str, list]:
        """Read the named attributes as decoded **raw** (wire) string values.

        Unlike :meth:`read_attributes`, this bypasses ldap3's per-syntax value
        decoding (which turns AD time attributes such as ``lockoutTime`` /
        ``pwdLastSet`` into ``datetime`` objects). Returning the raw octet form as
        ``str`` makes before/after diffs comparable to the string values writes
        send, regardless of attribute syntax (time, int, DN, or text).
        """
        attrs = list(attributes)
        self.conn.search(dn, "(objectClass=*)", search_scope=BASE, attributes=attrs)
        if not self.conn.entries:
            raise LookupError(f"Object not found: {dn}")
        entry = self.conn.entries[0]
        result: dict[str, list] = {}
        for attr in attrs:
            raw = _raw_values(entry, attr)
            result[attr] = [v.decode("utf-8", "surrogateescape") if isinstance(v, bytes) else str(v) for v in raw]
        return result

    def paged_search(
        self,
        base_dn: str,
        ldap_filter: str,
        attributes: Sequence[str],
        *,
        limit: int | None = None,
    ) -> list[dict]:
        """Run a subtree search paged by ``AD_PAGE_SIZE``; return entry dicts.

        Honours the configured ``page_size`` for the LDAP paged-results control
        and stops collecting once ``limit`` matches have been gathered. Only
        actual ``searchResEntry`` rows are returned (referrals are skipped).
        """
        attrs = list(attributes)
        entries = self.conn.extend.standard.paged_search(
            search_base=base_dn,
            search_filter=ldap_filter,
            search_scope=SUBTREE,
            attributes=attrs,
            paged_size=self.config.page_size,
            generator=True,
        )
        results: list[dict] = []
        for row in entries:
            if row.get("type") != "searchResEntry":
                continue
            attr_map = row.get("attributes") or {}
            record = {attr: _as_list(attr_map.get(attr)) for attr in attrs}
            record["dn"] = row.get("dn")
            results.append(record)
            if limit is not None and len(results) >= limit:
                break
        return results

    def _find_one(
        self, base_dn: str, ldap_filter: str, attributes: Sequence[str], *, scope=SUBTREE
    ):
        """Return the single matching ldap3 Entry, or raise LookupError."""
        self.conn.search(base_dn, ldap_filter, search_scope=scope, attributes=list(attributes))
        if not self.conn.entries:
            raise LookupError(f"No object matched: {ldap_filter}")
        return self.conn.entries[0]

    def _find_by_dn(self, dn: str, ldap_filter: str, attributes: Sequence[str]):
        """Resolve a DN-form identifier to its single Entry of the expected class.

        Validates DN syntax up front (clear ``LookupError`` on a malformed DN)
        and searches with ``BASE`` scope so a supplied DN resolves only to that
        exact object — a container DN can never silently resolve to a same-class
        descendant the way a ``SUBTREE`` search would.
        """
        _validate_dn(dn)
        return self._find_one(dn, ldap_filter, attributes, scope=BASE)

    # ------------------------------------------------------------------ #
    # Users
    # ------------------------------------------------------------------ #
    def find_users(self, query: str, *, limit: int = 100, include_disabled: bool = False) -> dict:
        """Search users by sAMAccountName / UPN / mail / displayName substring.

        Disabled accounts (ACCOUNTDISABLE bit set) are excluded by default via the
        AD bitwise matching rule; pass ``include_disabled=True`` to include them
        (the exclusion clause is omitted).
        """
        term = escape_filter_chars(query)
        disabled_clause = "" if include_disabled else _FILTER_EXCLUDE_DISABLED
        ldap_filter = (
            "(&(objectClass=user)(!(objectClass=computer))"
            f"{disabled_clause}(|"
            f"(sAMAccountName=*{term}*)"
            f"(userPrincipalName=*{term}*)"
            f"(mail=*{term}*)"
            f"(displayName=*{term}*)"
            "))"
        )
        brief_attrs = ("sAMAccountName", "displayName", "userPrincipalName", "mail")
        rows = self.paged_search(
            self.config.effective_user_search_base, ldap_filter, brief_attrs, limit=limit
        )
        results = []
        for row in rows:
            results.append(
                {
                    "dn": row["dn"],
                    "sAMAccountName": _first(row["sAMAccountName"]),
                    "displayName": _first(row["displayName"]),
                    "userPrincipalName": _first(row["userPrincipalName"]),
                    "mail": _first(row["mail"]),
                }
            )
        return {"count": len(results), "users": results, "page_size": self.config.page_size}

    def get_user(self, identifier: str) -> dict:
        """Fetch the agreed user attribute set plus computed password expiry."""
        attrs = tuple(USER_READ_ATTRIBUTES) + ("userAccountControl",)
        if "=" in identifier:
            entry = self._find_by_dn(identifier, "(objectClass=user)", attrs)
        else:
            term = escape_filter_chars(identifier)
            ldap_filter = (
                "(&(objectClass=user)(!(objectClass=computer))(|"
                f"(sAMAccountName={term})"
                f"(userPrincipalName={term})"
                f"(mail={term})"
                "))"
            )
            entry = self._find_one(self.config.effective_user_search_base, ldap_filter, attrs)

        record = _entry_attributes(entry, USER_READ_ATTRIBUTES)
        expiry = self._password_expiry(entry)
        record.update(expiry)
        # A user looked up directly is always returned (enabled or disabled); the
        # ACCOUNTDISABLE (0x2) bit of userAccountControl is surfaced as a bool.
        uac = _raw_int(_raw_values(entry, "userAccountControl"))
        record["account_disabled"] = bool(uac is not None and uac & _UAC_ACCOUNTDISABLE)
        return record

    def _password_expiry(self, user_entry) -> dict:
        """Compute password_expired / days_until_expiry for a user Entry."""
        pwd_last_set = _raw_int(_raw_values(user_entry, "pwdLastSet"))
        uac = _raw_int(_raw_values(user_entry, "userAccountControl"))
        max_pwd_age = self._domain_max_pwd_age()
        return compute_password_expiry(pwd_last_set, max_pwd_age, uac)

    def _domain_max_pwd_age(self) -> int | None:
        """Read the domain root's maxPwdAge as a raw integer (cached per client)."""
        if not hasattr(self, "_max_pwd_age_cache"):
            self.conn.search(
                self.config.base_dn,
                "(objectClass=*)",
                search_scope=BASE,
                attributes=["maxPwdAge"],
            )
            value: int | None = None
            if self.conn.entries:
                try:
                    value = _raw_int(_raw_values(self.conn.entries[0], "maxPwdAge"))
                except _ATTR_MISSING_ERRORS:
                    value = None
            self._max_pwd_age_cache = value
        return self._max_pwd_age_cache

    # ------------------------------------------------------------------ #
    # Computers
    # ------------------------------------------------------------------ #
    def find_computers(self, query: str, *, limit: int = 100) -> dict:
        """Search computer objects by name / dNSHostName substring."""
        term = escape_filter_chars(query)
        ldap_filter = (
            "(&(objectClass=computer)(|"
            f"(name=*{term}*)"
            f"(sAMAccountName=*{term}*)"
            f"(dNSHostName=*{term}*)"
            "))"
        )
        brief_attrs = ("name", "dNSHostName", "operatingSystem")
        rows = self.paged_search(
            self.config.effective_computer_search_base, ldap_filter, brief_attrs, limit=limit
        )
        results = []
        for row in rows:
            results.append(
                {
                    "dn": row["dn"],
                    "name": _first(row["name"]),
                    "dNSHostName": _first(row["dNSHostName"]),
                    "operatingSystem": _first(row["operatingSystem"]),
                }
            )
        return {"count": len(results), "computers": results, "page_size": self.config.page_size}

    def get_computer(self, identifier: str) -> dict:
        """Fetch the agreed computer attribute set including managedBy."""
        if "=" in identifier:
            entry = self._find_by_dn(identifier, "(objectClass=computer)", COMPUTER_READ_ATTRIBUTES)
        else:
            name = identifier[:-1] if identifier.endswith("$") else identifier
            term = escape_filter_chars(name)
            sam = escape_filter_chars(name + "$")
            ldap_filter = (
                "(&(objectClass=computer)(|"
                f"(name={term})"
                f"(cn={term})"
                f"(sAMAccountName={sam})"
                f"(dNSHostName={term})"
                "))"
            )
            entry = self._find_one(
                self.config.effective_computer_search_base, ldap_filter, COMPUTER_READ_ATTRIBUTES
            )
        return _entry_attributes(entry, COMPUTER_READ_ATTRIBUTES)

    def _resolve_computer_dn(self, identifier: str) -> str:
        """Resolve a computer identifier (name with/without ``$``, cn, dNSHostName,
        or DN) to its DN. Raises ``LookupError`` when no single computer matches.
        """
        attrs = ("distinguishedName",)
        if "=" in identifier:
            entry = self._find_by_dn(identifier, "(objectClass=computer)", attrs)
        else:
            name = identifier[:-1] if identifier.endswith("$") else identifier
            term = escape_filter_chars(name)
            sam = escape_filter_chars(name + "$")
            ldap_filter = (
                "(&(objectClass=computer)(|"
                f"(name={term})"
                f"(cn={term})"
                f"(sAMAccountName={sam})"
                f"(dNSHostName={term})"
                "))"
            )
            entry = self._find_one(self.config.effective_computer_search_base, ldap_filter, attrs)
        dn = _first(_entry_attributes(entry, attrs)["distinguishedName"])
        return dn or entry.entry_dn

    def _resolve_principal_dn(self, identifier: str) -> str:
        """Resolve an identifier to the DN of an existing **user OR group** object.

        Used to validate ``managedBy`` (a computer may be managed by either a user
        or a group) and reused by the bulk managedBy workflow. Accepts a DN,
        sAMAccountName, UPN, mail, or cn. Raises ``LookupError`` if no single user
        or group object matches.
        """
        attrs = ("distinguishedName",)
        principal_filter = "(|(objectClass=user)(objectClass=group))"
        if "=" in identifier:
            entry = self._find_by_dn(identifier, principal_filter, attrs)
        else:
            term = escape_filter_chars(identifier)
            ldap_filter = (
                "(&(|(objectClass=user)(objectClass=group))(|"
                f"(sAMAccountName={term})"
                f"(userPrincipalName={term})"
                f"(mail={term})"
                f"(cn={term})"
                "))"
            )
            entry = self._find_one(self.config.base_dn, ldap_filter, attrs)
        dn = _first(_entry_attributes(entry, attrs)["distinguishedName"])
        return dn or entry.entry_dn

    # ------------------------------------------------------------------ #
    # Groups
    # ------------------------------------------------------------------ #
    def list_group_members(self, identifier: str) -> dict:
        """List a group's members, resolving each member DN to a readable name."""
        if "=" in identifier:
            group = self._find_by_dn(identifier, "(objectClass=group)", ("distinguishedName", "cn", "member"))
        else:
            term = escape_filter_chars(identifier)
            ldap_filter = f"(&(objectClass=group)(|(sAMAccountName={term})(cn={term})))"
            group = self._find_one(
                self.config.base_dn, ldap_filter, ("distinguishedName", "cn", "member")
            )

        group_dn = _first(_entry_attributes(group, ("distinguishedName",))["distinguishedName"])
        member_dns = _entry_attributes(group, ("member",))["member"]

        members = []
        for dn in member_dns:
            members.append(self._resolve_member(dn))
        return {
            "group_dn": group_dn,
            "cn": _first(_entry_attributes(group, ("cn",))["cn"]),
            "count": len(members),
            "members": members,
        }

    def _resolve_member(self, dn: str) -> dict:
        """Resolve a member DN to its name / sAMAccountName / objectClass."""
        try:
            attrs = self.read_attributes(dn, ("cn", "sAMAccountName", "objectClass"))
        except LookupError:
            return {"dn": dn, "name": None, "sAMAccountName": None, "resolved": False}
        return {
            "dn": dn,
            "name": _first(attrs["cn"]),
            "sAMAccountName": _first(attrs["sAMAccountName"]),
            "objectClass": attrs["objectClass"],
            "resolved": True,
        }

    def _resolve_group_dn(self, identifier: str) -> str:
        """Resolve a group identifier (sAMAccountName/cn/DN) to its DN.

        Raises ``LookupError`` when no single group object matches.
        """
        attrs = ("distinguishedName",)
        if "=" in identifier:
            entry = self._find_by_dn(identifier, "(objectClass=group)", attrs)
        else:
            term = escape_filter_chars(identifier)
            ldap_filter = f"(&(objectClass=group)(|(sAMAccountName={term})(cn={term})))"
            entry = self._find_one(self.config.base_dn, ldap_filter, attrs)
        dn = _first(_entry_attributes(entry, attrs)["distinguishedName"])
        return dn or entry.entry_dn

    # ------------------------------------------------------------------ #
    # Dry-run/diff write framework
    # ------------------------------------------------------------------ #
    def diff_modify(
        self,
        dn: str,
        changes: Mapping[str, Sequence],
        *,
        dry_run: bool = True,
        before: Mapping[str, Sequence] | None = None,
    ) -> dict:
        """Apply a MODIFY_REPLACE-style change set behind the dry-run/diff guard.

        ``changes`` maps each attribute to its desired value list (``[]`` clears
        the attribute). The current values are read first and a before/after diff
        is computed. When ``dry_run`` is true (the default) nothing is written and
        the diff is returned; when false the change commits and the result records
        the outcome.

        A caller that has *already* read the current values via
        :meth:`read_raw_attributes` (the raw, wire-string form) may pass them as
        ``before`` to avoid a second round-trip. The mapping MUST be in the same
        raw-string form — passing decoded values (e.g. from
        :meth:`read_attributes`, where AD time/int attrs decode to
        datetime/objects) would corrupt the diff, so it is the caller's
        responsibility to supply a raw read or leave ``before`` unset.
        """
        # Normalise the desired values to wire-form strings, and read the current
        # values raw (string), so the diff compares like for like regardless of
        # attribute syntax (AD time attrs otherwise decode to datetime objects
        # that never compare equal to the strings a write sends).
        desired = {
            attr: [v if isinstance(v, (str, bytes)) else str(v) for v in _as_list(vals)]
            for attr, vals in changes.items()
        }
        if before is None:
            before = self.read_raw_attributes(dn, list(desired))
        diff = compute_diff(before, desired)

        result: dict[str, Any] = {
            "dn": dn,
            "dry_run": dry_run,
            "committed": False,
            "changes": diff,
        }

        if dry_run or not diff:
            # Nothing to do (dry-run, or a genuine no-op that needs no write).
            return result

        modification = {attr: [(MODIFY_REPLACE, diff[attr]["after"])] for attr in diff}
        committed = self.conn.modify(dn, modification)
        result["committed"] = bool(committed)
        result["result"] = {
            "code": self.conn.result.get("result"),
            "description": self.conn.result.get("description"),
            "message": self.conn.result.get("message"),
        }
        return result

    def _resolve_user_dn(self, identifier: str) -> str:
        """Resolve a user identifier (sAMAccountName/UPN/mail/DN) to its DN.

        Raises ``LookupError`` if no single user object matches — used to bind a
        write to a concrete object and to validate manager DNs before setting.
        """
        attrs = ("distinguishedName",)
        if "=" in identifier:
            entry = self._find_by_dn(identifier, "(objectClass=user)", attrs)
        else:
            term = escape_filter_chars(identifier)
            ldap_filter = (
                "(&(objectClass=user)(!(objectClass=computer))(|"
                f"(sAMAccountName={term})"
                f"(userPrincipalName={term})"
                f"(mail={term})"
                "))"
            )
            entry = self._find_one(self.config.effective_user_search_base, ldap_filter, attrs)
        dn = _first(_entry_attributes(entry, attrs)["distinguishedName"])
        return dn or entry.entry_dn

    # ------------------------------------------------------------------ #
    # User write tools
    # ------------------------------------------------------------------ #
    def set_user_attributes(
        self, identifier: str, attributes: Mapping[str, str], *, dry_run: bool = True
    ) -> dict:
        """MODIFY_REPLACE a whitelisted set of scalar user attributes.

        Only the attributes in :data:`USER_WRITABLE_ATTRIBUTES` may be set;
        anything else raises ``ValueError``. An empty-string value clears the
        attribute (MODIFY_REPLACE []). ``manager`` is intentionally rejected here
        — use :meth:`set_user_manager`.
        """
        if not attributes:
            raise ValueError("No attributes supplied to set.")
        allowed = set(USER_WRITABLE_ATTRIBUTES)
        rejected = [a for a in attributes if a not in allowed]
        if rejected:
            raise ValueError(
                "Attribute(s) not permitted by ad_set_user_attributes: "
                f"{', '.join(sorted(rejected))}. "
                f"Allowed: {', '.join(USER_WRITABLE_ATTRIBUTES)}."
            )
        # Empty string clears the attribute ([] → MODIFY_REPLACE with no values).
        changes = {attr: ([] if value == "" else [value]) for attr, value in attributes.items()}
        dn = self._resolve_user_dn(identifier)
        return self.diff_modify(dn, changes, dry_run=dry_run)

    def set_user_manager(
        self, identifier: str, manager: str | None, *, dry_run: bool = True
    ) -> dict:
        """Set or clear (None/empty) a user's ``manager`` (DN-valued).

        When setting, the supplied manager value is resolved and validated to be a
        real user object first; an unresolvable manager raises ``LookupError``.
        """
        dn = self._resolve_user_dn(identifier)
        if manager is None or manager == "":
            changes: dict[str, list] = {"manager": []}
        else:
            manager_dn = self._resolve_user_dn(manager)
            changes = {"manager": [manager_dn]}
        return self.diff_modify(dn, changes, dry_run=dry_run)

    def reset_password(
        self,
        identifier: str,
        new_password: str,
        *,
        force_change_at_logon: bool = False,
        dry_run: bool = True,
    ) -> dict:
        """Set a caller-supplied password via ``unicodePwd`` over LDAPS.

        The password is encoded by ldap3's ``ad_modify_password`` as a
        quoted UTF-16-LE ``unicodePwd`` MODIFY_REPLACE. NOT idempotent. When
        ``force_change_at_logon`` is true, ``pwdLastSet`` is set to 0 after a
        successful reset so the user must change the password at next logon.

        ``dry_run`` (default) reports the planned action without contacting the
        DC — the cleartext password is never echoed back.
        """
        dn = self._resolve_user_dn(identifier)
        planned = ["reset unicodePwd"]
        if force_change_at_logon:
            planned.append("set pwdLastSet=0 (force change at next logon)")

        result: dict[str, Any] = {
            "dn": dn,
            "dry_run": dry_run,
            "committed": False,
            "force_change_at_logon": force_change_at_logon,
            "planned": planned,
        }
        if dry_run:
            return result

        committed = ad_modify_password(self.conn, dn, new_password, None)
        result["committed"] = bool(committed)
        result["result"] = {
            "code": self.conn.result.get("result"),
            "description": self.conn.result.get("description"),
            "message": self.conn.result.get("message"),
        }
        if committed and force_change_at_logon:
            forced = self.conn.modify(dn, {"pwdLastSet": [(MODIFY_REPLACE, ["0"])]})
            result["pwdLastSet_committed"] = bool(forced)
        return result

    def set_account_status(
        self, identifier: str, enabled: bool, *, dry_run: bool = True
    ) -> dict:
        """Enable/disable an account by toggling ONLY the ACCOUNTDISABLE bit.

        Reads the current ``userAccountControl``, flips just the 0x2 bit, and
        writes it back via the dry-run/diff framework — every other UAC flag is
        preserved. Idempotent: a no-op (already in the desired state) returns an
        empty diff and commits nothing.
        """
        dn = self._resolve_user_dn(identifier)
        # Read the raw value once and reuse it as diff_modify's ``before`` so the
        # toggle and the before/after diff share a single round-trip. _raw_int
        # parses the same raw wire string the diff is computed against.
        current = self.read_raw_attributes(dn, ["userAccountControl"])
        uac = _raw_int(current.get("userAccountControl")) or _UAC_NORMAL_ACCOUNT
        if enabled:
            new_uac = uac & ~_UAC_ACCOUNTDISABLE
        else:
            new_uac = uac | _UAC_ACCOUNTDISABLE
        return self.diff_modify(
            dn, {"userAccountControl": [str(new_uac)]}, dry_run=dry_run, before=current
        )

    def unlock_account(self, identifier: str, *, dry_run: bool = True) -> dict:
        """Clear an account lockout by setting ``lockoutTime=0`` (idempotent)."""
        dn = self._resolve_user_dn(identifier)
        return self.diff_modify(dn, {"lockoutTime": ["0"]}, dry_run=dry_run)

    # ------------------------------------------------------------------ #
    # Computer write tools
    # ------------------------------------------------------------------ #
    def set_computer_attributes(
        self, identifier: str, attributes: Mapping[str, str], *, dry_run: bool = True
    ) -> dict:
        """MODIFY_REPLACE a whitelisted set of computer attributes.

        Only the attributes in :data:`COMPUTER_WRITABLE_ATTRIBUTES`
        (``description`` and ``managedBy``) may be set; anything else raises
        ``ValueError``. ``managedBy`` is validated to resolve to an existing user
        OR group object before it is set (an unresolvable principal raises
        ``LookupError``); an empty-string value clears the attribute
        (MODIFY_REPLACE []). Idempotent — a no-op returns an empty diff and
        commits nothing.
        """
        if not attributes:
            raise ValueError("No attributes supplied to set.")
        allowed = set(COMPUTER_WRITABLE_ATTRIBUTES)
        rejected = [a for a in attributes if a not in allowed]
        if rejected:
            raise ValueError(
                "Attribute(s) not permitted by ad_set_computer_attributes: "
                f"{', '.join(sorted(rejected))}. "
                f"Allowed: {', '.join(COMPUTER_WRITABLE_ATTRIBUTES)}."
            )
        changes: dict[str, list] = {}
        for attr, value in attributes.items():
            if value == "" or value is None:
                # Empty string clears the attribute (MODIFY_REPLACE []).
                changes[attr] = []
            elif attr == "managedBy":
                # Validate the manager resolves to a real user OR group object.
                changes[attr] = [self._resolve_principal_dn(value)]
            else:
                changes[attr] = [value]
        dn = self._resolve_computer_dn(identifier)
        return self.diff_modify(dn, changes, dry_run=dry_run)

    # ------------------------------------------------------------------ #
    # Bulk managedBy assignment (the headline workflow — story-005)
    # ------------------------------------------------------------------ #
    def _sweep_computers(self) -> list[dict]:
        """Page through every computer object, returning name/dn/description/managedBy.

        Reuses :meth:`paged_search` (honouring ``AD_PAGE_SIZE``). ``description``
        is read so the owner display name can be derived; it is NEVER written by
        the bulk workflow. ``managedBy`` is read to detect already-assigned
        computers.
        """
        attrs = ("name", "cn", "description", "managedBy")
        rows = self.paged_search(
            self.config.effective_computer_search_base, "(objectClass=computer)", attrs
        )
        computers: list[dict] = []
        for row in rows:
            computers.append(
                {
                    "dn": row["dn"],
                    "name": _first(row["name"]) or _first(row["cn"]),
                    "description": _first(row["description"]),
                    "managedBy": _first(row["managedBy"]),
                }
            )
        return computers

    def _all_users_for_matching(self) -> list[dict]:
        """Page through every ENABLED user object, returning dn/displayName/sAMAccountName.

        Used to build the case-insensitive display-name index that description
        owner strings are matched against. ONLY enabled users are owner-match
        candidates — a disabled user must never become a new ``managedBy``
        assignment — so the disabled-exclusion clause is applied unconditionally
        here (no caller override). Searches user_search_base when configured.
        """
        attrs = ("displayName", "sAMAccountName", "distinguishedName")
        ldap_filter = (
            "(&(objectClass=user)(!(objectClass=computer))" + _FILTER_EXCLUDE_DISABLED + ")"
        )
        rows = self.paged_search(self.config.effective_user_search_base, ldap_filter, attrs)
        users: list[dict] = []
        for row in rows:
            users.append(
                {
                    "dn": row["dn"] or _first(row["distinguishedName"]),
                    "displayName": _first(row["displayName"]),
                    "sAMAccountName": _first(row["sAMAccountName"]),
                }
            )
        return users

    def _derive_owner(self, computer: Mapping, hints: Mapping[str, str]) -> OwnerSource:
        """Resolve the owner *source* for one computer.

        Returns an :class:`OwnerSource` where:
        - ``source`` is ``"hint"`` when a hint applies (it overrides description
          and fills gaps), else ``"description"``;
        - for a hint source ``value`` is the raw hint identifier and ``hint_dn``
          is the resolved principal DN (or ``None`` if unresolvable);
        - for a description source ``value`` is the normalized owner string and
          ``hint_dn`` is ``None``.

        Hint lookup is keyed by the computer name first, then its DN, so the
        caller may key hints by whichever computer identifier they have.
        """
        name = computer.get("name")
        dn = computer.get("dn")
        hint = None
        for key in (name, dn):
            if key is not None and key in hints:
                hint = hints[key]
                break
        if hint:
            try:
                hint_dn = self._resolve_principal_dn(hint)
            except LookupError:
                hint_dn = None
            return OwnerSource(SOURCE_HINT, hint, hint_dn)
        return OwnerSource(SOURCE_DESCRIPTION, normalize_owner(computer.get("description")), None)

    def bulk_assign_managers(
        self,
        *,
        hints: Mapping[str, str] | None = None,
        apply: bool = False,
        overwrite: bool = False,
        chunk_size: int = _BULK_APPLY_CHUNK_SIZE,
    ) -> dict:
        """Plan (and optionally apply) fleet-wide ``managedBy`` assignment.

        **Plan mode** (``apply=False``, the default) sweeps every computer,
        derives each one's owner (from a caller hint when present, otherwise from
        the normalized ``description``), matches owner display names against users
        case-insensitively, and returns the classification buckets WITHOUT writing
        anything. **Apply mode** (``apply=True``) additionally commits only the
        high-confidence ``matched`` bucket (via :meth:`set_computer_attributes`'s
        validated ``managedBy`` path), in chunks, with per-item error capture.

        The ``description`` field is NEVER modified by this method.

        Buckets in the report:
        - ``matched`` — exactly one user matched (committed in apply mode);
        - ``ambiguous`` — 2+ users matched (skipped, candidates listed);
        - ``unmatched`` — no owner / no user / unresolvable hint (skipped, reason);
        - ``already_assigned`` — computer already has ``managedBy`` (skipped unless
          ``overwrite=True``, in which case a fresh match moves it back to matched).
        """
        hints = dict(hints or {})
        users = self._all_users_for_matching()
        display_index = build_display_index(users)
        computers = self._sweep_computers()

        matched: list[dict] = []
        ambiguous: list[dict] = []
        unmatched: list[dict] = []
        already_assigned: list[dict] = []

        for computer in computers:
            base = {"computer": computer.get("name"), "dn": computer.get("dn")}
            source, value, hint_dn = self._derive_owner(computer, hints)

            if source == SOURCE_HINT:
                if hint_dn is None:
                    unmatched.append(
                        {**base, "source": SOURCE_HINT, "hint": value,
                         "reason": REASON_HINT_UNRESOLVED}
                    )
                    continue
                entry = {
                    **base,
                    "source": SOURCE_HINT,
                    "owner": value,
                    "owner_dn": hint_dn,
                }
            else:
                result = classify_owner(value, display_index)
                if result["bucket"] == "ambiguous":
                    ambiguous.append(
                        {**base, "source": SOURCE_DESCRIPTION, "owner": value,
                         "candidates": result["candidates"]}
                    )
                    continue
                if result["bucket"] == "unmatched":
                    unmatched.append(
                        {**base, "source": SOURCE_DESCRIPTION, "owner": value,
                         "reason": result["reason"]}
                    )
                    continue
                user = result["user"]
                entry = {
                    **base,
                    "source": SOURCE_DESCRIPTION,
                    "owner": value,
                    "owner_dn": user["dn"],
                    "matched_user": user.get("sAMAccountName"),
                }

            # A high-confidence match (hint or description). Honour already-assigned.
            if computer.get("managedBy") and not overwrite:
                already_assigned.append({**entry, "current_managedBy": computer["managedBy"]})
            else:
                if computer.get("managedBy"):
                    entry["current_managedBy"] = computer["managedBy"]
                matched.append(entry)

        report: dict[str, Any] = {
            "apply": apply,
            "overwrite": overwrite,
            "scanned": len(computers),
            "counts": {
                "matched": len(matched),
                "ambiguous": len(ambiguous),
                "unmatched": len(unmatched),
                "already_assigned": len(already_assigned),
            },
            "matched": matched,
            "ambiguous": ambiguous,
            "unmatched": unmatched,
            "already_assigned": already_assigned,
        }

        if not apply:
            return report

        report["committed"] = []
        report["failed"] = []
        for start in range(0, len(matched), max(1, chunk_size)):
            chunk = matched[start : start + max(1, chunk_size)]
            for entry in chunk:
                try:
                    out = self.set_computer_attributes(
                        entry["dn"], {"managedBy": entry["owner_dn"]}, dry_run=False
                    )
                    report["committed"].append(
                        {
                            "computer": entry["computer"],
                            "dn": entry["dn"],
                            "owner_dn": entry["owner_dn"],
                            "source": entry["source"],
                            "committed": out.get("committed", False),
                            "changes": out.get("changes", {}),
                        }
                    )
                except Exception as exc:  # noqa: BLE001 — isolate per-item failures
                    report["failed"].append(
                        {
                            "computer": entry["computer"],
                            "dn": entry["dn"],
                            "owner_dn": entry["owner_dn"],
                            "error": str(exc),
                        }
                    )
        report["counts"]["committed"] = len(report["committed"])
        report["counts"]["failed"] = len(report["failed"])
        return report

    # ------------------------------------------------------------------ #
    # Group membership write tools
    # ------------------------------------------------------------------ #
    def _resolve_member_dn(self, identifier: str) -> str:
        """Resolve a prospective group member (user, computer, or group) to its DN.

        A group's ``member`` attribute may reference any of these object classes,
        so this is broader than :meth:`_resolve_principal_dn`. Raises
        ``LookupError`` if no single object matches.
        """
        attrs = ("distinguishedName",)
        member_filter = "(|(objectClass=user)(objectClass=computer)(objectClass=group))"
        if "=" in identifier:
            entry = self._find_by_dn(identifier, member_filter, attrs)
        else:
            term = escape_filter_chars(identifier)
            sam = escape_filter_chars(identifier + "$")
            ldap_filter = (
                "(&" + member_filter + "(|"
                f"(sAMAccountName={term})"
                f"(sAMAccountName={sam})"
                f"(userPrincipalName={term})"
                f"(mail={term})"
                f"(cn={term})"
                "))"
            )
            entry = self._find_one(self.config.base_dn, ldap_filter, attrs)
        dn = _first(_entry_attributes(entry, attrs)["distinguishedName"])
        return dn or entry.entry_dn

    def _modify_group_member(
        self, group_identifier: str, member: str, *, add: bool, dry_run: bool
    ) -> dict:
        """Add or remove a single member DN on a group's ``member`` attribute.

        Both operations are idempotent: adding an existing member or removing a
        non-member is a reported no-op (empty diff, nothing committed) rather than
        an error. The member is resolved to a concrete object DN first.
        """
        group_dn = self._resolve_group_dn(group_identifier)
        member_dn = self._resolve_member_dn(member)

        current = self.read_raw_attributes(group_dn, ["member"])["member"]
        present = any(_dn_equal(m, member_dn) for m in current)

        result: dict[str, Any] = {
            "group_dn": group_dn,
            "member_dn": member_dn,
            "dry_run": dry_run,
            "committed": False,
            "no_op": False,
            "action": "add" if add else "remove",
        }

        # Idempotency: adding an existing member / removing a non-member is a no-op.
        if (add and present) or (not add and not present):
            result["no_op"] = True
            result["changes"] = {}
            return result

        if add:
            after = current + [member_dn]
        else:
            after = [m for m in current if not _dn_equal(m, member_dn)]
        result["changes"] = compute_diff({"member": current}, {"member": after})

        if dry_run:
            return result

        op = MODIFY_ADD if add else MODIFY_DELETE
        committed = self.conn.modify(group_dn, {"member": [(op, [member_dn])]})
        result["committed"] = bool(committed)
        result["result"] = {
            "code": self.conn.result.get("result"),
            "description": self.conn.result.get("description"),
            "message": self.conn.result.get("message"),
        }
        return result

    def add_group_member(self, group: str, member: str, *, dry_run: bool = True) -> dict:
        """Add a user/computer/group to a group's ``member`` (idempotent no-op
        when already a member).
        """
        return self._modify_group_member(group, member, add=True, dry_run=dry_run)

    def remove_group_member(self, group: str, member: str, *, dry_run: bool = True) -> dict:
        """Remove a member from a group's ``member`` (idempotent no-op when not a
        member).
        """
        return self._modify_group_member(group, member, add=False, dry_run=dry_run)
