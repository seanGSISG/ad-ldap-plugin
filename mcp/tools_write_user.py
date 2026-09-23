"""Write MCP tools for user/account operations (story-003).

Every tool here defaults to ``dry_run=True`` and returns a before→after diff
without committing; only ``dry_run=False`` issues the write. Annotations match
the DESIGN.md tool-surface table:

| Tool                    | destructiveHint | idempotentHint |
|-------------------------|-----------------|----------------|
| ad_set_user_attributes  | True            | True           |
| ad_set_user_manager     | True            | True           |
| ad_reset_password       | True            | False          |
| ad_set_account_status   | True            | True           |
| ad_unlock_account       | False           | True           |

``ad_set_user_attributes`` enforces a strict whitelist (department, title,
physicalDeliveryOfficeName, telephoneNumber, extensionAttribute1,
extensionAttribute10); anything else is rejected. ``ad_reset_password`` sets a
caller-supplied password via ``unicodePwd`` over LDAPS (mandatory at config
level) with an optional force-change-at-logon flag. Failures surface as
:class:`fastmcp.exceptions.ToolError` (FastMCP ``isError``) via the shared
``_handle`` mapper from :mod:`tools_read`.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import Field

from ad_client import USER_WRITABLE_ATTRIBUTES
from app import get_client, mcp
from tools_read import _handle

_DRY_RUN_DESC = (
    "When true (the default) nothing is written: the tool returns the computed "
    "before/after diff so the change can be reviewed first. Set false to commit."
)

_IDENTIFIER_DESC = (
    "The target user's sAMAccountName, userPrincipalName, mail address, or full "
    "distinguished name (DN). A value containing '=' is treated as a DN."
)


# --------------------------------------------------------------------------- #
# ad_set_user_attributes
# --------------------------------------------------------------------------- #
@mcp.tool(
    name="ad_set_user_attributes",
    description=(
        "MODIFY_REPLACE a whitelisted set of user attributes. The ONLY permitted "
        "attributes are: " + ", ".join(USER_WRITABLE_ATTRIBUTES) + ". Any other "
        "attribute is rejected with an error. An empty-string value clears the "
        "attribute. 'manager' is NOT settable here — use ad_set_user_manager. "
        "Defaults to dry_run=true (returns a before/after diff without committing)."
    ),
    annotations={"destructiveHint": True, "idempotentHint": True, "openWorldHint": True},
)
def ad_set_user_attributes(
    identifier: Annotated[str, Field(description=_IDENTIFIER_DESC, min_length=1)],
    attributes: Annotated[
        dict[str, str],
        Field(
            description=(
                "Map of attribute name to its new string value. Permitted keys: "
                + ", ".join(USER_WRITABLE_ATTRIBUTES)
                + ". An empty string ('') clears the attribute."
            ),
        ),
    ],
    dry_run: Annotated[bool, Field(description=_DRY_RUN_DESC)] = True,
) -> dict:
    """Set whitelisted scalar user attributes; returns a before/after diff."""
    return _handle(
        lambda: get_client().set_user_attributes(identifier, attributes, dry_run=dry_run)
    )


# --------------------------------------------------------------------------- #
# ad_set_user_manager
# --------------------------------------------------------------------------- #
@mcp.tool(
    name="ad_set_user_manager",
    description=(
        "Set or clear a user's 'manager' attribute (DN-valued). To set, provide the "
        "manager's identifier (sAMAccountName/UPN/mail/DN); it is resolved and "
        "validated to be a real user before writing. To clear, pass null or an empty "
        "string. Defaults to dry_run=true (returns a before/after diff)."
    ),
    annotations={"destructiveHint": True, "idempotentHint": True, "openWorldHint": True},
)
def ad_set_user_manager(
    identifier: Annotated[str, Field(description=_IDENTIFIER_DESC, min_length=1)],
    manager: Annotated[
        str | None,
        Field(
            description=(
                "The manager's sAMAccountName, userPrincipalName, mail, or DN. The "
                "value is validated to resolve to a real user before being set. Pass "
                "null or an empty string to clear the manager attribute."
            ),
        ),
    ] = None,
    dry_run: Annotated[bool, Field(description=_DRY_RUN_DESC)] = True,
) -> dict:
    """Set/clear a user's manager (validated DN); returns a before/after diff."""
    return _handle(lambda: get_client().set_user_manager(identifier, manager, dry_run=dry_run))


# --------------------------------------------------------------------------- #
# ad_reset_password
# --------------------------------------------------------------------------- #
@mcp.tool(
    name="ad_reset_password",
    description=(
        "Set a caller-supplied password for a user via unicodePwd over LDAPS "
        "(an administrative reset — the old password is not required). Optionally "
        "force the user to change it at next logon (sets pwdLastSet=0). This is NOT "
        "idempotent. Defaults to dry_run=true, which reports the planned action "
        "WITHOUT contacting the directory and never echoes the password."
    ),
    annotations={"destructiveHint": True, "idempotentHint": False, "openWorldHint": True},
)
def ad_reset_password(
    identifier: Annotated[str, Field(description=_IDENTIFIER_DESC, min_length=1)],
    new_password: Annotated[
        str,
        Field(
            description=(
                "The new password to set. Supplied by the caller (not generated). "
                "Must satisfy the domain's password policy. Sent over LDAPS only."
            ),
            min_length=1,
        ),
    ],
    force_change_at_logon: Annotated[
        bool,
        Field(
            description=(
                "When true, set pwdLastSet=0 after the reset so the user must change "
                "the password at next logon."
            ),
        ),
    ] = False,
    dry_run: Annotated[bool, Field(description=_DRY_RUN_DESC)] = True,
) -> dict:
    """Reset a user's password via unicodePwd; optional force-change-at-logon."""
    return _handle(
        lambda: get_client().reset_password(
            identifier,
            new_password,
            force_change_at_logon=force_change_at_logon,
            dry_run=dry_run,
        )
    )


# --------------------------------------------------------------------------- #
# ad_set_account_status
# --------------------------------------------------------------------------- #
@mcp.tool(
    name="ad_set_account_status",
    description=(
        "Enable or disable a user account by toggling ONLY the ACCOUNTDISABLE bit "
        "(0x2) of userAccountControl via a read-modify-write; every other UAC flag "
        "is preserved. Idempotent — re-applying the same state is a no-op. Defaults "
        "to dry_run=true (returns a before/after diff)."
    ),
    annotations={"destructiveHint": True, "idempotentHint": True, "openWorldHint": True},
)
def ad_set_account_status(
    identifier: Annotated[str, Field(description=_IDENTIFIER_DESC, min_length=1)],
    enabled: Annotated[
        bool,
        Field(
            description=(
                "True to enable the account (clear ACCOUNTDISABLE); false to disable "
                "it (set ACCOUNTDISABLE)."
            ),
        ),
    ],
    dry_run: Annotated[bool, Field(description=_DRY_RUN_DESC)] = True,
) -> dict:
    """Enable/disable an account via the ACCOUNTDISABLE bit; before/after diff."""
    return _handle(
        lambda: get_client().set_account_status(identifier, enabled, dry_run=dry_run)
    )


# --------------------------------------------------------------------------- #
# ad_unlock_account
# --------------------------------------------------------------------------- #
@mcp.tool(
    name="ad_unlock_account",
    description=(
        "Clear an account lockout by setting lockoutTime=0. Non-destructive and "
        "idempotent. Defaults to dry_run=true (returns a before/after diff)."
    ),
    annotations={"destructiveHint": False, "idempotentHint": True, "openWorldHint": True},
)
def ad_unlock_account(
    identifier: Annotated[str, Field(description=_IDENTIFIER_DESC, min_length=1)],
    dry_run: Annotated[bool, Field(description=_DRY_RUN_DESC)] = True,
) -> dict:
    """Clear a lockout (lockoutTime=0); returns a before/after diff."""
    return _handle(lambda: get_client().unlock_account(identifier, dry_run=dry_run))
