"""Write MCP tools for computer and group operations (story-004).

Every tool here defaults to ``dry_run=True`` and returns a before→after diff
without committing; only ``dry_run=False`` issues the write. Annotations match
the DESIGN.md tool-surface table:

| Tool                       | destructiveHint | idempotentHint |
|----------------------------|-----------------|----------------|
| ad_set_computer_attributes | True            | True           |
| ad_add_group_member        | False           | True           |
| ad_remove_group_member     | True            | True           |

``ad_set_computer_attributes`` enforces a strict whitelist of exactly
``description`` and ``managedBy``; anything else is rejected. ``managedBy`` is
validated to resolve to an existing user OR group object before it is set
(reusing :meth:`ADClient._resolve_principal_dn`, which the bulk managedBy
workflow in story-005 builds on); an empty string clears it.

``ad_add_group_member`` / ``ad_remove_group_member`` are idempotent: adding an
existing member or removing a non-member is a reported no-op, not an error.
Failures surface as :class:`fastmcp.exceptions.ToolError` via the shared
``_handle`` mapper from :mod:`tools_read`.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import Field

from ad_client import COMPUTER_WRITABLE_ATTRIBUTES
from app import get_client, mcp
from tools_read import _handle

_DRY_RUN_DESC = (
    "When true (the default) nothing is written: the tool returns the computed "
    "before/after diff so the change can be reviewed first. Set false to commit."
)

_COMPUTER_IDENTIFIER_DESC = (
    "The target computer's name (sAMAccountName with or without a trailing '$', "
    "or cn), its dNSHostName, or full distinguished name (DN). A value containing "
    "'=' is treated as a DN."
)

_GROUP_IDENTIFIER_DESC = (
    "The group's sAMAccountName, cn, or full distinguished name (DN). A value "
    "containing '=' is treated as a DN."
)

_MEMBER_IDENTIFIER_DESC = (
    "The member to add/remove: a user, computer, or group identifier "
    "(sAMAccountName, userPrincipalName, mail, cn) or full distinguished name "
    "(DN). A value containing '=' is treated as a DN. Resolved to a concrete "
    "object before the membership change."
)


# --------------------------------------------------------------------------- #
# ad_set_computer_attributes
# --------------------------------------------------------------------------- #
@mcp.tool(
    name="ad_set_computer_attributes",
    description=(
        "MODIFY_REPLACE a whitelisted set of computer attributes. The ONLY "
        "permitted attributes are: " + ", ".join(COMPUTER_WRITABLE_ATTRIBUTES) + ". "
        "Any other attribute is rejected with an error. 'managedBy' must resolve "
        "to an existing user OR group object (validated before writing). An "
        "empty-string value clears the attribute. Defaults to dry_run=true "
        "(returns a before/after diff without committing)."
    ),
    annotations={"destructiveHint": True, "idempotentHint": True, "openWorldHint": True},
)
def ad_set_computer_attributes(
    identifier: Annotated[str, Field(description=_COMPUTER_IDENTIFIER_DESC, min_length=1)],
    attributes: Annotated[
        dict[str, str],
        Field(
            description=(
                "Map of attribute name to its new string value. Permitted keys: "
                + ", ".join(COMPUTER_WRITABLE_ATTRIBUTES)
                + ". 'managedBy' must be a user or group identifier/DN. An empty "
                "string ('') clears the attribute."
            ),
        ),
    ],
    dry_run: Annotated[bool, Field(description=_DRY_RUN_DESC)] = True,
) -> dict:
    """Set a computer's description and/or managedBy; returns a before/after diff."""
    return _handle(
        lambda: get_client().set_computer_attributes(identifier, attributes, dry_run=dry_run)
    )


# --------------------------------------------------------------------------- #
# ad_add_group_member
# --------------------------------------------------------------------------- #
@mcp.tool(
    name="ad_add_group_member",
    description=(
        "Add a user, computer, or group to a group's 'member' attribute. "
        "Idempotent: adding an object that is already a member is a clean no-op "
        "(reported as no_op=true), not an error. Defaults to dry_run=true "
        "(returns a before/after diff without committing)."
    ),
    annotations={"destructiveHint": False, "idempotentHint": True, "openWorldHint": True},
)
def ad_add_group_member(
    group: Annotated[str, Field(description=_GROUP_IDENTIFIER_DESC, min_length=1)],
    member: Annotated[str, Field(description=_MEMBER_IDENTIFIER_DESC, min_length=1)],
    dry_run: Annotated[bool, Field(description=_DRY_RUN_DESC)] = True,
) -> dict:
    """Add a member to a group (idempotent); returns a before/after diff."""
    return _handle(lambda: get_client().add_group_member(group, member, dry_run=dry_run))


# --------------------------------------------------------------------------- #
# ad_remove_group_member
# --------------------------------------------------------------------------- #
@mcp.tool(
    name="ad_remove_group_member",
    description=(
        "Remove a member from a group's 'member' attribute. Idempotent: removing "
        "an object that is not a member is a clean no-op (reported as "
        "no_op=true), not an error. Defaults to dry_run=true (returns a "
        "before/after diff without committing)."
    ),
    annotations={"destructiveHint": True, "idempotentHint": True, "openWorldHint": True},
)
def ad_remove_group_member(
    group: Annotated[str, Field(description=_GROUP_IDENTIFIER_DESC, min_length=1)],
    member: Annotated[str, Field(description=_MEMBER_IDENTIFIER_DESC, min_length=1)],
    dry_run: Annotated[bool, Field(description=_DRY_RUN_DESC)] = True,
) -> dict:
    """Remove a member from a group (idempotent); returns a before/after diff."""
    return _handle(lambda: get_client().remove_group_member(group, member, dry_run=dry_run))
