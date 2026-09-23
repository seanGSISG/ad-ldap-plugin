---
description: Guided single-computer managedBy assignment — find the computer, show current description/managedBy, resolve the owner, dry-run the diff, confirm, then commit.
argument-hint: <computer name | dNSHostName> [owner name | sAMAccountName]
---

Assign `managedBy` on a single Active Directory computer. Arguments: **$ARGUMENTS**
(`$0` = computer identifier, `$1` = intended owner, if provided).

Drive the `ad-ldap` MCP tools through the dry-run-first loop — never commit without confirmation:

1. **Find the computer.** If `$0` is an exact name/dNSHostName/DN, use it; otherwise
   `ad_find_computers(query="$0")` and disambiguate (ask if more than one matches).
2. **Show current state.** Call `ad_get_computer` and report the computer's current `description`
   and `managedBy`. (The `description` field is informational here — owner display names often live
   there — and must NOT be modified by this command.)
3. **Resolve the owner.**
   - If `$1` (owner) was supplied, resolve it with `ad_find_users` (or treat it as a group).
   - If no owner was given, infer a candidate from the computer's `description` (it usually holds the
     owner's display name) and confirm it with `ad_find_users`.
   - If the owner is ambiguous or not found, ask the user; do not guess.
4. **Dry-run.** Call `ad_set_computer_attributes(identifier=<computer>, attributes={"managedBy": <owner identifier>}, dry_run=true)`
   and show the before→after diff verbatim. `managedBy` is validated to resolve to a real user/group.
5. **Confirm.** Ask for an explicit yes.
6. **Commit.** Re-run the identical call with `dry_run=false` and report the committed diff.

Notes:
- Only `description` and `managedBy` are writable on a computer; `description` is left untouched here.
- For fleet-wide assignment use `ad_bulk_assign_managers` (the ad-computer-admin agent / active-directory skill cover the plan→review→apply workflow) instead of this per-machine command.
- LDAPS only; on bind failure run `ad_check_connection` and surface the error.
