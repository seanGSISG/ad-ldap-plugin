# ad-ldap — Design Brief

A Python MCP server (FastMCP 3.x) wrapping **ldap3** for Active Directory administration, shipped
as a **Claude Code plugin** that bundles the server, specialized agents, a skill, slash commands
and a write guard. The same server also runs as a shared HTTP container.

## Headline use case
In many domains computer objects have no `managedBy` set, and the owner's **display name lives
in the computer's `description` field** instead. The flagship workflow is **mass-assigning `managedBy`**:
a bulk tool sweeps computer objects, matches description-held names against users (optionally
supplemented by caller-supplied owner hints from TRMM last-logon data or CSV), returns a
matched/ambiguous/unmatched plan for review, then applies only exact matches. Ambiguous and
unmatched computers are skipped and reported for manual resolution. The `description` field is
**never modified**.

## Locked decisions
- **Deployment:** two transports from one entry point (`mcp/server.py --transport stdio|http`).
  - **Plugin (stdio):** distributed through this repo's marketplace (`ad-ldap@ad-ldap-plugin`).
    The manifest launches `uv run --project ${CLAUDE_PLUGIN_ROOT} python mcp/server.py --transport stdio`.
  - **Container (HTTP):** `docker compose up -d` serves streamable HTTP at `/mcp` behind a bearer
    token (`MCP_BEARER_TOKEN`, refuses to start without it) plus an open `/healthz`.
- **Tool pattern:** Pattern A — one tool per action (15 tools), consolidating where natural.
- **Framework:** FastMCP 3.x (PyPI `fastmcp`), Python — wraps the Python `ldap3` library.
- **Auth:** LDAPS (636) + SIMPLE bind. UPN or DN + password. LDAPS mandatory (password ops require it).
- **Config:** environment variables. The plugin fills them from its `userConfig` settings
  (prompted on install, the password kept in the OS keychain) through `${user_config.*}` in the
  manifest's `mcpServers` `env` block; the container reads them from `.env`.
  - `AD_SERVER` (host or ldaps:// URI), `AD_PORT` (default 636), `AD_BASE_DN`,
    `AD_BIND_USER` (UPN or DN), `AD_BIND_PASSWORD`, `AD_USE_SSL` (default true),
    `AD_CA_CERTS` (path to CA bundle, optional), `AD_TLS_VALIDATE` (default true; lab opt-out),
    `AD_PAGE_SIZE` (default 500), `AD_USER_SEARCH_BASE` / `AD_COMPUTER_SEARCH_BASE`
    (optional scoped search bases, default to `AD_BASE_DN`).
- **Safety:** annotated + dry-run. Every write tool accepts `dry_run: bool = true` and returns a
  before→after diff without committing when true. Destructive tools carry `destructiveHint: true`.
  TLS validation defaults on; documented insecure opt-out for the self-signed lab DC.
- **Write guard (function hooks):** `hooks/guard.ts` hooks `tool.call` on the 9 write tools. A
  commit (`dry_run=false`, or `apply=true` for the bulk tool) is refused unless the identical call
  (same target arguments, SHA-256 matched) dry-ran successfully this session, and then waits for
  the user's yes through `$.ui.ask`, so it holds in every permission mode and inside subagents.
  Its `.catch` refuses the call if the hook fails. It loads only where
  `CLAUDE_CODE_ENABLE_FUNCTION_HOOKS=1`; without it the server's dry-run defaults remain the
  safety net. `userConfig` fields are deliberately not `required`, because unmet required options
  stop the engine loading the hooks module at all.
- **Hints stay external:** the server never calls TRMM or parses CSV. The bundled agent gathers
  owner hints (e.g., via trmm-mcp) and passes them to the bulk tool as a structured parameter.

## Tool surface (read/write split, all annotated)

### Read tools — `readOnlyHint: true`
| Tool | Purpose |
|---|---|
| `ad_check_connection` | Bind to the DC and report server info / whoami. Diagnostic. |
| `ad_find_users` | Search users by sAMAccountName / UPN / email / display name (substring). Paged. Excludes disabled accounts by default (`include_disabled=true` to include). |
| `ad_get_user` | Fetch the agreed user attribute set, **plus computed `password_expired` and `days_until_expiry`** (from `pwdLastSet` + domain `maxPwdAge`). |
| `ad_find_computers` | Search computer objects by name / dNSHostName. Paged. |
| `ad_get_computer` | Fetch the agreed computer attribute set incl. `managedBy`. |
| `ad_list_group_members` | List members of a group (resolves member DNs to names). |

### Read attribute sets
- **Users:** cn, company, department, displayName, distinguishedName, employeeID,
  extensionAttribute1, extensionAttribute10, facsimileTelephoneNumber, givenName, initials,
  lastLogon, mail, manager, name, physicalDeliveryOfficeName, pwdLastSet, sAMAccountName, sn,
  telephoneNumber, title, userPrincipalName
- **Computers:** cn, description, distinguishedName, lastLogon, name, operatingSystem,
  whenCreated (+ managedBy)

### Write tools — each takes `dry_run` (default true)
| Tool | `destructiveHint` | `idempotentHint` | Purpose |
|---|---|---|---|
| `ad_set_user_attributes` | true | true | MODIFY_REPLACE a whitelisted set of user attributes (see below). |
| `ad_set_user_manager` | true | true | Set/clear a user's `manager` (DN-valued). |
| `ad_reset_password` | true | false | Set a **caller-supplied** password via LDAPS (`unicodePwd`). Optional force-change-at-logon. |
| `ad_set_account_status` | true | true | Enable/disable account by toggling ACCOUNTDISABLE bit (read-modify-write of userAccountControl). |
| `ad_unlock_account` | false | true | Clear lockout (`lockoutTime=0`). |
| `ad_set_computer_attributes` | true | true | Edit a computer's `description` and/or `managedBy` (validated user/group DN). Replaces the old `ad_assign_computer_manager`. |
| `ad_add_group_member` | false | true | Add a user/computer to a group's `member`. |
| `ad_remove_group_member` | true | true | Remove a member from a group. |

### Bulk tool — the headline
| Tool | Purpose |
|---|---|
| `ad_bulk_assign_managers` | Plan/apply mass `managedBy` assignment. **Plan mode** (default): sweep computers, match `description` display names → users, merge optional `hints` mapping (computer → candidate owner), return matched / ambiguous / unmatched buckets without writing. **Apply mode** (`apply=true`): commit exact matches only, in safe chunks; skip + report the rest. Never touches `description`. |

### Attribute whitelist for `ad_set_user_attributes`
department, title, physicalDeliveryOfficeName, telephoneNumber, extensionAttribute1,
extensionAttribute10. (`manager` handled by its own tool; empty string ⇒ MODIFY_REPLACE [] to clear.)

## Testing
- Offline pytest suite against ldap3 `MOCK_SYNC` (`uv run pytest tests/ -q`), no DC needed.
- Guard tests against the engine itself (`claude plugin test .`, `tests/guard.test.ts`).
- Live read-only smoke scripts in `scripts/` for a lab DC (self-signed cert → `AD_TLS_VALIDATE=false`).

## Repository layout

```
ad-ldap-plugin/
  .claude-plugin/
    marketplace.json             # the marketplace: one plugin, source "./"
    plugin.json                  # manifest: userConfig + mcpServers (stdio)
  hooks/
    hooks.json                   # names the hooks module
    guard.ts                     # the AD write guard
  mcp/
    server.py                    # entry point: --transport stdio|http
    app.py                       # FastMCP instance + lazy AD client
    http_app.py                  # bearer-token middleware + /healthz
    ad_client.py                 # ldap3 connection mgmt + safe read/modify helpers
    config.py                    # env config
    tools_*.py, bulk_assign.py   # tool definitions, bulk matching
  agents/                        # ad-user-admin, ad-computer-admin
  skills/active-directory/       # SKILL.md safety playbook + scripts/bulk_plan.py
  commands/                      # /ad-whois, /ad-assign-computer
  tests/                         # pytest suite + guard.test.ts
  scripts/                       # live-DC smoke scripts
  Dockerfile, docker-compose.yml, .env.example
```

## Non-goals (v1)
- User/group object lifecycle (create/delete), OU restructuring, object moves
- Entra ID / Graph integration; TRMM API calls inside the server
- Kerberos/NTLM auth (SIMPLE bind over LDAPS only); multi-domain/forest support
- Fuzzy auto-apply of ambiguous bulk matches (skip + report instead)

## Compliance checklist (Anthropic Directory criteria)
- [x] read/write in separate tools
- [x] every tool has title + readOnlyHint + destructiveHint
- [x] tool names ≤ 64 chars
- [x] descriptions describe, never instruct Claude
- [x] tight schemas with per-param descriptions
- [x] MCP errors (isError), not raised exceptions across transport
