"""The headline write tool: bulk ``managedBy`` assignment (story-005).

``ad_bulk_assign_managers`` is the whole reason this server exists. Today no
computer object carries ``managedBy``; each computer's ``description`` instead
holds the owner's display name. This tool sweeps the fleet, matches those
display names to user objects, and (in apply mode) writes ``managedBy`` for the
high-confidence matches — WITHOUT ever touching ``description``.

Safety model (matches the rest of the tool surface):
- ``apply=False`` is the safe default → **plan mode**: classify everything into
  matched / ambiguous / unmatched / already_assigned buckets and return the
  report without performing a single write.
- ``apply=True`` → **apply mode**: commit only the ``matched`` bucket, in chunks,
  with per-item error isolation; everything else is skipped and reported.
- Annotations: ``destructiveHint=True`` (it can write managedBy on many objects),
  ``idempotentHint=True`` (re-running converges — already-correct objects produce
  empty diffs and already-assigned ones are skipped unless ``overwrite=True``).

Hints stay external: this server never calls TRMM or parses CSV. The caller (the
bundled agent) gathers owner hints and passes them as the structured ``hints``
mapping (computer name or DN → candidate owner identifier). A hint fills gaps
where ``description`` is empty and overrides ``description`` on conflict; an
unresolvable hint sends that computer to the unmatched bucket.

Only **enabled** users are owner-match candidates: the user index built for
matching excludes disabled accounts (ACCOUNTDISABLE bit), so a disabled user can
never become a new ``managedBy`` assignment.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import Field

from app import get_client, mcp
from tools_read import _handle

_HINTS_DESC = (
    "Optional caller-supplied owner hints: a mapping of computer identifier "
    "(name or distinguished name) to a candidate owner identifier "
    "(sAMAccountName, userPrincipalName, mail, cn, or DN). The agent gathers "
    "these externally (e.g. from TRMM last-logon data or a CSV) — this server "
    "never parses TRMM/CSV itself. A hint fills a gap where the computer's "
    "description is empty and overrides the description-derived match on "
    "conflict. A hint that does not resolve to a user/group sends that computer "
    "to the unmatched bucket (reason: hint_unresolved)."
)

_APPLY_DESC = (
    "When false (the default) the tool runs in PLAN mode: it sweeps every "
    "computer, classifies each into matched/ambiguous/unmatched/already_assigned "
    "buckets, and returns the report WITHOUT writing anything. Set true to APPLY: "
    "commit managedBy for the high-confidence matched bucket only, in chunks, "
    "skipping and reporting everything else. The description field is never "
    "modified in either mode."
)

_OVERWRITE_DESC = (
    "When false (the default), computers that already have managedBy set are "
    "reported in the already_assigned bucket and left untouched. Set true to "
    "let a fresh high-confidence match overwrite an existing managedBy."
)


@mcp.tool(
    name="ad_bulk_assign_managers",
    description=(
        "Plan or apply fleet-wide computer managedBy assignment by matching each "
        "computer's description (the owner's display name) to a user object. "
        "PLAN mode (apply=false, the default) returns matched/ambiguous/unmatched/"
        "already_assigned buckets WITHOUT writing. APPLY mode (apply=true) commits "
        "only the high-confidence matched bucket, in chunks, and skips plus reports "
        "the rest. An optional 'hints' mapping (computer -> candidate owner) "
        "supplements description matching (fills gaps) and overrides it on "
        "conflict. Only ENABLED users are owner-match candidates: a disabled user "
        "is never assigned as a new managedBy owner. The computer description "
        "field is NEVER modified."
    ),
    annotations={
        "destructiveHint": True,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
def ad_bulk_assign_managers(
    hints: Annotated[
        dict[str, str] | None,
        Field(description=_HINTS_DESC),
    ] = None,
    apply: Annotated[bool, Field(description=_APPLY_DESC)] = False,
    overwrite: Annotated[bool, Field(description=_OVERWRITE_DESC)] = False,
) -> dict:
    """Plan/apply mass managedBy assignment from description + optional hints."""
    return _handle(
        lambda: get_client().bulk_assign_managers(
            hints=hints, apply=apply, overwrite=overwrite
        )
    )
