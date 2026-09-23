"""Read-only MCP tools: connection diagnostic, user/computer lookups, groups.

All tools here carry ``readOnlyHint: True`` and surface failures as
:class:`fastmcp.exceptions.ToolError` (which FastMCP converts to an ``isError``
response) rather than leaking raw tracebacks. Searches are paged via
``AD_PAGE_SIZE`` (default 500). ``ad_get_user`` additionally computes password
expiry from the user's ``pwdLastSet`` and the domain's ``maxPwdAge``.
"""

from __future__ import annotations

from typing import Annotated

from fastmcp.exceptions import ToolError
from pydantic import Field

from app import get_client, mcp
from config import ADConfigError


def _handle(fn):
    """Run a client call, mapping config/transport errors to clean ToolErrors."""
    try:
        return fn()
    except ADConfigError as exc:
        raise ToolError(f"Configuration error: {exc}") from exc
    except LookupError as exc:
        raise ToolError(str(exc)) from exc
    except ToolError:
        raise
    except Exception as exc:  # noqa: BLE001 — surface a clean transport error
        raise ToolError(f"Active Directory query failed: {exc}") from exc


# --------------------------------------------------------------------------- #
# Diagnostic
# --------------------------------------------------------------------------- #
@mcp.tool(
    name="ad_check_connection",
    description=(
        "Bind to the configured Active Directory domain controller over LDAPS and "
        "report the authenticated identity (whoami) and basic server information. "
        "Read-only diagnostic for verifying connectivity and credentials."
    ),
    annotations={"readOnlyHint": True, "openWorldHint": True},
)
def ad_check_connection() -> dict:
    """Return connection status, whoami, and server info for the configured DC."""
    return _handle(lambda: get_client().check_connection())


# --------------------------------------------------------------------------- #
# Users
# --------------------------------------------------------------------------- #
@mcp.tool(
    name="ad_find_users",
    description=(
        "Search Active Directory for user objects whose sAMAccountName, "
        "userPrincipalName, mail, or displayName contains the given substring. "
        "Disabled accounts are EXCLUDED by default; set include_disabled=true to "
        "include them. Results are paged with AD_PAGE_SIZE (default 500) and "
        "capped by 'limit'. Read-only. Returns a list of brief matches; use "
        "ad_get_user for full detail."
    ),
    annotations={"readOnlyHint": True, "openWorldHint": True},
)
def ad_find_users(
    query: Annotated[
        str,
        Field(
            description=(
                "Case-insensitive substring matched against sAMAccountName, "
                "userPrincipalName, mail, and displayName. Special LDAP filter "
                "characters are escaped automatically."
            ),
            min_length=1,
        ),
    ],
    limit: Annotated[
        int,
        Field(
            description="Maximum number of matches to return (1-1000).",
            ge=1,
            le=1000,
        ),
    ] = 100,
    include_disabled: Annotated[
        bool,
        Field(
            description=(
                "When false (the default), disabled accounts (the userAccountControl "
                "ACCOUNTDISABLE bit) are excluded from results. Set true to include "
                "disabled accounts."
            ),
        ),
    ] = False,
) -> dict:
    """Find users by identifier/name substring; returns brief match records."""
    return _handle(
        lambda: get_client().find_users(query, limit=limit, include_disabled=include_disabled)
    )


@mcp.tool(
    name="ad_get_user",
    description=(
        "Fetch a single user's agreed attribute set (22 attributes) plus computed "
        "password_expired (bool), days_until_expiry (int or null), and "
        "account_disabled (bool, the userAccountControl ACCOUNTDISABLE bit). The "
        "expiry fields derive from the user's pwdLastSet and the domain's "
        "maxPwdAge. Returns any user looked up directly, enabled or disabled. Look "
        "up by sAMAccountName, userPrincipalName, mail, or distinguished name. "
        "Read-only."
    ),
    annotations={"readOnlyHint": True, "openWorldHint": True},
)
def ad_get_user(
    identifier: Annotated[
        str,
        Field(
            description=(
                "The user's sAMAccountName, userPrincipalName, mail address, or "
                "full distinguished name (DN). A value containing '=' is treated "
                "as a DN."
            ),
            min_length=1,
        ),
    ],
) -> dict:
    """Return one user's full attribute set plus computed password expiry."""
    return _handle(lambda: get_client().get_user(identifier))


# --------------------------------------------------------------------------- #
# Computers
# --------------------------------------------------------------------------- #
@mcp.tool(
    name="ad_find_computers",
    description=(
        "Search Active Directory for computer objects whose name (cn/sAMAccountName) "
        "or dNSHostName contains the given substring. Results are paged with "
        "AD_PAGE_SIZE (default 500) and capped by 'limit'. Read-only. Returns brief "
        "match records; use ad_get_computer for full detail."
    ),
    annotations={"readOnlyHint": True, "openWorldHint": True},
)
def ad_find_computers(
    query: Annotated[
        str,
        Field(
            description=(
                "Case-insensitive substring matched against the computer name and "
                "dNSHostName. Special LDAP filter characters are escaped automatically."
            ),
            min_length=1,
        ),
    ],
    limit: Annotated[
        int,
        Field(
            description="Maximum number of matches to return (1-1000).",
            ge=1,
            le=1000,
        ),
    ] = 100,
) -> dict:
    """Find computers by name/dNSHostName substring; returns brief match records."""
    return _handle(lambda: get_client().find_computers(query, limit=limit))


@mcp.tool(
    name="ad_get_computer",
    description=(
        "Fetch a single computer's agreed attribute set: cn, description, "
        "distinguishedName, lastLogon, name, operatingSystem, whenCreated, and "
        "managedBy. Look up by name (with or without a trailing '$'), dNSHostName, "
        "or distinguished name. Read-only."
    ),
    annotations={"readOnlyHint": True, "openWorldHint": True},
)
def ad_get_computer(
    identifier: Annotated[
        str,
        Field(
            description=(
                "The computer name (sAMAccountName with or without a trailing '$', "
                "or cn), its dNSHostName, or full distinguished name (DN). A value "
                "containing '=' is treated as a DN."
            ),
            min_length=1,
        ),
    ],
) -> dict:
    """Return one computer's agreed attribute set including managedBy."""
    return _handle(lambda: get_client().get_computer(identifier))


# --------------------------------------------------------------------------- #
# Groups
# --------------------------------------------------------------------------- #
@mcp.tool(
    name="ad_list_group_members",
    description=(
        "List the members of an Active Directory group, resolving each member DN to "
        "its name/sAMAccountName/objectClass. Look up the group by sAMAccountName, "
        "cn, or distinguished name. Read-only."
    ),
    annotations={"readOnlyHint": True, "openWorldHint": True},
)
def ad_list_group_members(
    identifier: Annotated[
        str,
        Field(
            description=(
                "The group's sAMAccountName, cn, or full distinguished name (DN). "
                "A value containing '=' is treated as a DN."
            ),
            min_length=1,
        ),
    ],
) -> dict:
    """List a group's members, resolving member DNs to readable names."""
    return _handle(lambda: get_client().list_group_members(identifier))
