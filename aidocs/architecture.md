# Architecture

FastMCP server wrapping `ldap3` for Active Directory administration. Distributed two
ways: as a Claude Code **plugin** (stdio transport, via `.claude-plugin/plugin.json`) and
as a **Docker container** (HTTP transport, bearer-token auth, for multi-client LAN use).

## Directory map

| Path | Purpose |
| --- | --- |
| `mcp/` | Core server — 10 flat Python modules (no `__init__.py`, intentional; see below) |
| `tests/` | Offline pytest suite (ldap3 `MOCK_SYNC`, no DC required) |
| `scripts/` | Live-DC smoke scripts (connection, reads, bulk plan preview) |
| `agents/` | Two Claude agents: `ad-user-admin`, `ad-computer-admin` (consume the tools) |
| `commands/` | Slash commands: `ad-whois`, `ad-assign-computer` |
| `skills/active-directory/` | Safety playbook skill — how to drive the tools safely |
| `research/` | Background docs (AD schema, ldap3, MCP patterns) — not runtime code |
| `cert/` | CA bundle (`ldap-ca.pem`) for LDAPS, mounted by docker-compose |
| `DESIGN.md` | Authoritative spec: locked decisions, tool surface, whitelists, test strategy |

## Module boundaries (`mcp/`)

| Module | Role |
| --- | --- |
| `server.py` | CLI entry point — parses `--transport stdio\|http`, imports all `tools_*.py` to register them |
| `app.py` | Shared FastMCP instance + lazy `get_client()` singleton accessor |
| `http_app.py` | Starlette app: bearer-protected MCP at `/mcp`, unauthenticated `/healthz` |
| `config.py` | `ADConfig` frozen dataclass from `AD_*` env vars; `ADConfigError` on bad config |
| `ad_client.py` | `ADClient` — all LDAP primitives: paged search, `diff_modify`, password reset, attribute whitelists (~1270 lines, the heart of the project) |
| `tools_read.py` | 6 read tools (`ad_find_users`, `ad_get_user`, `ad_find_computers`, `ad_get_computer`, `ad_list_group_members`, `ad_check_connection`) |
| `tools_write_user.py` | 5 user-write tools (`ad_set_user_attributes`, `ad_set_user_manager`, `ad_reset_password`, `ad_set_account_status`, `ad_unlock_account`) |
| `tools_write_computer_group.py` | 3 computer/group-write tools (`ad_set_computer_attributes`, `ad_add_group_member`, `ad_remove_group_member`) |
| `tools_bulk.py` | 1 bulk tool (`ad_bulk_assign_managers`) — mass `managedBy` assignment |
| `bulk_assign.py` | Pure matching helpers for bulk assignment (`normalize_owner`, `build_display_index`, `classify_owner`) |

## Key patterns

- **Tool registration:** each `tools_*.py` does `from app import mcp` and decorates with
  `@mcp.tool`. `server.py` imports the modules for the side effect of registration.
- **Lazy client singleton:** `app.get_client()` constructs `ADClient(ADConfig.from_env())`
  on first use; tools never build connections themselves.
- **Flat `mcp/` namespace, no `__init__.py`:** intentional, per pyproject comment — the
  real `mcp` package in site-packages must win imports. Tests/scripts add `mcp/` to
  `sys.path` and import modules as top-level names (`import config`, `import ad_client`).
- **Dry-run diff layer:** all mutations route through `ADClient.diff_modify()` which reads
  current values, computes a before→after diff, and commits only when `dry_run=False`.
  See [safety.md](safety.md).

## Data flow (tool call → LDAP → response)

```
MCP client (Claude)
  → transport (stdio via server.py | HTTP via http_app.py, bearer-checked)
  → tool handler in tools_*.py (params validated via Annotated[…, Field(...)])
  → _handle(lambda: …) error wrapper → ADClient method
  → ldap3 paged_search / modify over LDAPS
  → response dict (FastMCP serializes; errors surface as ToolError → isError)
```

## State & config

No database or persistent state — the server is a stateless proxy to the directory.
Config is env-only (see [integrations.md](integrations.md)). The Docker image is a
multi-stage build (uv-locked deps in builder, slim non-root production stage); compose
publishes container port 8000 as host 8001 and mounts `cert/ldap-ca.pem` read-only.
