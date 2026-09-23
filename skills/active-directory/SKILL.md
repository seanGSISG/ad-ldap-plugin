---
name: active-directory
description: Safety playbook for driving the ad-ldap MCP server (Active Directory over LDAPS). Use whenever performing AD reads or writes — user/computer/group lookups, attribute/manager/password/account changes, and the flagship bulk managedBy assignment. Enforces dry-run-first discipline (every write defaults dry_run=true; show the diff; explicit confirm before committing), the bulk plan→review→apply workflow with hint gathering from trmm-mcp or CSV, and the env/config + LDAPS rules.
---

# Active Directory administration — safety playbook

This skill governs how to use the `ad-ldap` MCP server: a local stdio FastMCP server wrapping
`ldap3`, talking to a domain controller over **LDAPS**. There are 15 tools (6 read, 9 write/bulk).
The cardinal rule: **dry-run first, show the diff, confirm explicitly, then commit.**

## Dry-run-first discipline (applies to EVERY write)

Every write tool takes `dry_run: bool = true`. When `dry_run=true` nothing is written — the tool
computes and returns the **before→after diff** so it can be reviewed. The loop is non-negotiable:

1. **Find** the target (`ad_find_users` / `ad_find_computers`); disambiguate if more than one matches.
2. **Get** current state (`ad_get_user` / `ad_get_computer` / `ad_list_group_members`).
3. **Dry-run** the write (default `dry_run=true`); show the diff to the user verbatim.
4. **Confirm** — get an explicit yes. Never infer consent for a destructive change.
5. **Commit** — re-run the identical call with `dry_run=false`; report the committed diff.

Annotations to respect (surfaced to the host as hints):

| Tool | readOnly | destructive | idempotent |
|------|:--------:|:-----------:|:----------:|
| ad_check_connection, ad_find_users, ad_get_user, ad_find_computers, ad_get_computer, ad_list_group_members | yes | — | — |
| ad_set_user_attributes | — | yes | yes |
| ad_set_user_manager | — | yes | yes |
| ad_reset_password | — | yes | **no** |
| ad_set_account_status | — | yes | yes |
| ad_unlock_account | — | no | yes |
| ad_set_computer_attributes | — | yes | yes |
| ad_add_group_member | — | no | yes |
| ad_remove_group_member | — | yes | yes |
| ad_bulk_assign_managers | — | yes | yes |

## Never echo passwords

`ad_reset_password` takes a **caller-supplied** `new_password` and sends it via `unicodePwd` over
LDAPS only. The dry-run path never contacts the DC and never echoes the password. Never print the
password into chat, summaries, or logs. After a real reset, report only success and whether
`force_change_at_logon` was applied.

## Whitelists (writes outside these are rejected by design)

- `ad_set_user_attributes`: only `department`, `title`, `physicalDeliveryOfficeName`,
  `telephoneNumber`, `extensionAttribute1`, `extensionAttribute10`. `manager` is NOT here — use
  `ad_set_user_manager`. Empty string clears an attribute.
- `ad_set_computer_attributes`: only `description` and `managedBy`. `managedBy` must resolve to an
  existing user or group (validated before writing).

## The bulk managedBy workflow: plan → review → apply

Headline use case: most computers have no `managedBy`; the owner's **display name lives in the
`description` field**. `ad_bulk_assign_managers` matches descriptions to users and assigns
`managedBy`. **It never modifies `description`.**

### Plan (always first, read-only)
Call `ad_bulk_assign_managers()` (defaults `apply=false`, `overwrite=false`). It returns `counts`
and buckets:
- `matched` — exactly one user → safe to apply.
- `ambiguous` — multiple candidates → human resolution required, never auto-applied.
- `unmatched` — no description or no user match → needs a hint or manual fix.
- `already_assigned` — managedBy already set → skipped unless `overwrite=true`.

### Review
**Export the plan to CSV first** so both the agent and the user can review the same artifact:
write one file per non-empty bucket to `bulk-review/` in the project root —
`matched.csv` (computer, owner, matched_user, owner_dn, source, dn), `unmatched.csv`
(computer, reason, owner, description, dn), `ambiguous.csv` (computer + all candidates),
`already_assigned.csv` (computer, current_managedBy, owner, matched_user, owner_dn, source, dn) —
and send them to the user. `bulk-review/` is gitignored (it contains real directory data).

Use the bundled driver, which does plan/apply + the CSV export in one step (and accepts a
hints CSV — see "Gather hints"):

```
uv run python skills/active-directory/scripts/bulk_plan.py [--hints <csv>] [--apply]
```

Then present the counts and walk the `ambiguous` + `unmatched` buckets with the user. Nothing is
dropped silently. Confirm the `matched` bucket (by CSV review or explicit sign-off) before applying.

### Skip pool/spare and shared-resource machines
Computers whose **AD or TRMM** `description` marks them as unassigned pool stock or a shared
resource are **never** assigned an owner — exclude them from hint gathering and apply.

- **Shared-resource words:** a description containing `Conf Rm`, `Plotter`, `Scan`, `Breakfix`,
  `Unassigned`, `Loaner` or `Spare` (substring, case-insensitive) is pool stock or a shared
  resource. Skip it.
- **Site words:** many orgs also name pool machines after an office (`<Office> Unassigned`). Ask
  the user which office or site words mark pool stock in their domain before the first apply.

Report the skipped list in the review CSVs so nothing is dropped silently.

### Gather hints (to shrink ambiguous/unmatched)
**The server never calls TRMM and never parses CSV** — hints stay external and are passed in as the
`hints` parameter: a `{ "COMPUTERNAME": "owner identifier" }` map (sAMAccountName / UPN / display
name). Hints **supplement** description matching (fill gaps) and **override** it on conflict.

- **trmm-mcp:** for unmatched/ambiguous machines, query the last-logged-on user via
  `mcp__trmm__find_agent` / `mcp__trmm__list_agents` / `mcp__trmm__get_agent`, map TRMM hostname →
  AD computer name, and build the hints map.
- **CSV:** read the user's file and build the same map from its hostname → owner columns. Show the
  assembled hints map back to the user before using it.

Re-run plan with hints to verify they move computers into `matched`.

### Apply (only after explicit confirmation)
`ad_bulk_assign_managers(hints=<map>, apply=true)` commits **only** the `matched` bucket (chunked)
and skips + reports the rest. Use `overwrite=true` only on explicit request. Report committed count
and the remaining ambiguous/unmatched for manual follow-up.

## Environment / config reference

Config is via environment variables (injected by the plugin's `.mcp.json` `env` block):

| Variable | Required | Default | Notes |
|----------|:--------:|---------|-------|
| `AD_SERVER` | yes | — | DC host or `ldaps://` URI |
| `AD_BASE_DN` | yes | — | e.g. `DC=corp,DC=example,DC=com` |
| `AD_BIND_USER` | yes | — | UPN or DN |
| `AD_BIND_PASSWORD` | yes | — | bind password (never logged; excluded from repr) |
| `AD_PORT` | no | `636` | LDAPS port |
| `AD_USE_SSL` | no | `true` | **`false` is REJECTED** (see below) |
| `AD_CA_CERTS` | no | — | path to a CA bundle for validation |
| `AD_TLS_VALIDATE` | no | `true` | **lab opt-out:** set `false` for a self-signed lab DC |
| `AD_PAGE_SIZE` | no | `500` | paged-search size for find_* |
| `AD_USER_SEARCH_BASE` | no | `AD_BASE_DN` | scope user searches / bulk user-index to an OU |
| `AD_COMPUTER_SEARCH_BASE` | no | `AD_BASE_DN` | scope computer searches / bulk sweep to an OU |

`ad_find_users` excludes disabled accounts by default; pass `include_disabled=true` to include them.
`ad_get_user` returns any user looked up directly and adds an `account_disabled` boolean. The bulk
`managedBy` workflow only matches **enabled** users as owners — a disabled user is never assigned.

### LDAPS is mandatory — `AD_USE_SSL=false` is rejected by design
A SIMPLE bind without SSL would transmit `AD_BIND_PASSWORD` (and any `unicodePwd` reset) in
cleartext, so the config layer **refuses to start** if `AD_USE_SSL=false`. The only sanctioned
relaxation for a self-signed lab DC is to keep SSL on and set **`AD_TLS_VALIDATE=false`** (skips
cert validation, still encrypted). Do not advise turning SSL off.

## Error handling
Tool failures surface as clean errors (`isError`), not raw tracebacks. Treat an error as a stop:
report it plainly. If a bind fails, run `ad_check_connection` to confirm connectivity/credentials
before retrying.
