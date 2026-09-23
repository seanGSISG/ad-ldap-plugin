"""Pure matching helpers for the bulk ``managedBy`` assignment workflow (story-005).

The orchestration (paged sweep, principal resolution, chunked commit) lives on
:meth:`ad_client.ADClient.bulk_assign_managers`; this module holds the
*deterministic, side-effect-free* pieces so they can be unit-tested without any
LDAP connection:

- :func:`normalize_owner` — trim + collapse whitespace, returning ``""`` for an
  empty/missing description.
- :func:`build_display_index` — fold a list of users into a case-insensitive
  ``normalized displayName -> [users]`` index (multiple users may share a name).
- :func:`classify_owner` — given a computer's normalized owner string and the
  display index, decide matched (exactly 1) / ambiguous (2+) / unmatched (0).

Bucket reasons (stable strings, asserted by tests and surfaced in the report):
``no_description`` (empty/missing description, no hint), ``no_user_match`` (a
non-empty owner that matches no user), ``hint_unresolved`` (a supplied hint that
does not resolve to a principal). The ``source`` of every derived owner is
either ``"description"`` or ``"hint"`` (a hint overrides description on conflict
and fills gaps where description is empty).
"""

from __future__ import annotations

from typing import Mapping, Sequence

# Stable reason codes for the unmatched bucket.
REASON_NO_DESCRIPTION = "no_description"
REASON_NO_USER_MATCH = "no_user_match"
REASON_HINT_UNRESOLVED = "hint_unresolved"

# Stable source codes for a derived owner.
SOURCE_DESCRIPTION = "description"
SOURCE_HINT = "hint"


def normalize_owner(description: str | None) -> str:
    """Normalise a computer ``description`` into a comparable owner string.

    Strips leading/trailing whitespace and collapses internal runs of
    whitespace to a single space. An empty or missing description normalises to
    the empty string (the caller treats that as "no owner").
    """
    if not description:
        return ""
    return " ".join(str(description).split())


def _casefold(value: str) -> str:
    """Case-fold for case-insensitive comparison (stronger than ``.lower()``)."""
    return value.casefold()


def build_display_index(users: Sequence[Mapping]) -> dict[str, list[dict]]:
    """Build a ``casefolded normalized displayName -> [user, ...]`` index.

    Each ``user`` mapping is expected to carry ``displayName`` and ``dn`` (and
    typically ``sAMAccountName``). Users with an empty/missing displayName are
    skipped (they can never be matched by description). Multiple users sharing a
    display name land in the same bucket, which is exactly what drives the
    ambiguous classification downstream.
    """
    index: dict[str, list[dict]] = {}
    for user in users:
        display = normalize_owner(user.get("displayName"))
        if not display:
            continue
        key = _casefold(display)
        index.setdefault(key, []).append(dict(user))
    return index


def classify_owner(owner: str, display_index: Mapping[str, Sequence[Mapping]]) -> dict:
    """Classify a normalized owner string against the display-name index.

    Returns ``{"bucket": ...}`` where bucket is one of:
    - ``"matched"`` — exactly one user matches; carries ``"user"``.
    - ``"ambiguous"`` — 2+ users match; carries ``"candidates"``.
    - ``"unmatched"`` — 0 users match; carries ``"reason"``
      (:data:`REASON_NO_DESCRIPTION` for an empty owner, otherwise
      :data:`REASON_NO_USER_MATCH`).

    Matching is exact after trim + case-fold — there is no fuzzy matching in v1.
    """
    if not owner:
        return {"bucket": "unmatched", "reason": REASON_NO_DESCRIPTION}
    candidates = list(display_index.get(_casefold(owner), []))
    if len(candidates) == 1:
        return {"bucket": "matched", "user": dict(candidates[0])}
    if len(candidates) >= 2:
        return {"bucket": "ambiguous", "candidates": [dict(c) for c in candidates]}
    return {"bucket": "unmatched", "reason": REASON_NO_USER_MATCH}
