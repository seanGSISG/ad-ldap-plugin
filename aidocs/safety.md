# Write-operation safety

This project's core design constraint (locked in `DESIGN.md`): mutations must be
previewable, whitelisted, and bounded. Read this before touching any write path.

## Dry-run / diff framework

- **Every mutation tool defaults to `dry_run=True`.** A dry-run call returns a
  before→after diff without committing anything; only an explicit `dry_run=False`
  issues the LDAP modify.
- Enforced at the client layer: `ADClient.diff_modify()` reads current values, computes
  the diff, and commits only when `dry_run` is false. New write tools must route through
  it — don't call `connection.modify()` directly from a tool.

## Attribute whitelists (`mcp/ad_client.py`)

Writes outside these lists are hard-rejected:

- `USER_WRITABLE_ATTRIBUTES`: `department`, `title`, `physicalDeliveryOfficeName`,
  `telephoneNumber`, `extensionAttribute1`, `extensionAttribute10`.
  (`manager` is deliberately excluded — it has its own tool, `ad_set_user_manager`.)
- `COMPUTER_WRITABLE_ATTRIBUTES`: `description`, `managedBy`.
  `managedBy` is validated to resolve to an existing user/group before being set; an
  empty string clears it.

## Tool annotation hints (from `DESIGN.md`)

| Tool | destructiveHint | idempotentHint |
| --- | --- | --- |
| `ad_set_user_attributes` | true | true |
| `ad_set_user_manager` | true | true |
| `ad_reset_password` | true | **false** — every call changes the password |
| `ad_set_account_status` | true | true |
| `ad_unlock_account` | false | true |

## Password resets

- Use `ldap3.extend.microsoft.modifyPassword.ad_modify_password` over LDAPS (mandatory —
  AD refuses `unicodePwd` writes on plaintext connections).
- Optional `forceChangeAtLogon` flips the relevant UAC/pwdLastSet handling to force a
  change at next logon.
- **Passwords are never logged, echoed, or included in responses.**

## Bulk assignment (`ad_bulk_assign_managers`)

Plan→review→apply workflow for mass `managedBy` assignment from owner names stored in
computer description fields:

- **Review is CSV-based:** export each non-empty plan bucket to `bulk-review/*.csv`
  (`matched.csv`, `unmatched.csv`, `ambiguous.csv`, `already_assigned.csv`) and share the
  files with the operator before any apply. `bulk-review/` is gitignored — it contains
  real directory data.
- Matching is deterministic and offline-testable (`mcp/bulk_assign.py`): displayName
  matching is case-insensitive and whitespace-collapsed (`normalize_owner`).
- Unresolved hints and **ambiguous matches** (2+ users sharing a displayName) are
  bucketed separately and must be human-reviewed — they are never auto-applied.
- Apply phase chunks at `_BULK_APPLY_CHUNK_SIZE = 50` to bound blast radius; per-item
  errors are captured and one failure never aborts the chunk or the run.
- `scripts/smoke_bulk_plan.py` previews the plan against a live DC, read-only.

## Operator-facing safety layer

`skills/active-directory/` is the safety playbook skill, and `agents/` +
`commands/` wrap the tools in guided workflows. If you change tool behavior or defaults,
update those docs to match.

`hooks/guard.ts` enforces the dry-run discipline mechanically: a commit is refused unless the
identical call dry-ran this session, then the user confirms it (see `DESIGN.md`, "Write guard").
Adding a write tool means adding it to the guard's `AD_WRITES` pattern and to `tests/guard.test.ts`.
