# Conventions

Inferred from config and actual code — there is no explicit lint/format config, so match
the existing style.

## Modules & naming

- `mcp/` is a **flat namespace with no `__init__.py`** — intentional (pyproject comment:
  the site-packages `mcp` package must win imports). Never add an `__init__.py` there.
- Tool modules follow `tools_<category>.py`: `tools_read.py`, `tools_write_user.py`,
  `tools_write_computer_group.py`, `tools_bulk.py`.
- MCP tool names: `ad_` prefix, snake_case, function name == tool name
  (e.g. `ad_find_users`, `ad_reset_password`). All 15 tools follow this.
- Every module starts with `from __future__ import annotations`.
- Import order: stdlib → third-party (`fastmcp`, `ldap3`, `pydantic`) → local
  (`app`, `ad_client`, `config`). No `__all__` anywhere.

## Tool definitions

- Parameters use `Annotated[type, Field(description=…, constraints…)]` from Pydantic;
  required params have no default, optional params do. Constraints like `min_length=1`,
  `ge=1, le=1000` live in the `Field`.
- All tool functions return `dict`.
- `@mcp.tool(description=…)` descriptions are comprehensive and user-facing; tools also
  carry annotation hints (`destructiveHint`, `idempotentHint`, `readOnlyHint`).
- One-line function docstrings (summary only — params/returns live in annotations);
  module docstrings carry the design notes.
- A tool is named `mcp__ad-ldap__<tool>` on a hand-registered server and
  `mcp__plugin_ad-ldap_ad-ldap__<tool>` when the plugin starts it. Agent `tools:` lists and
  the guard's `AD_WRITES` pattern name both; a new tool goes in each.

## Error handling

- Custom config exception: `ADConfigError(ValueError)` in `mcp/config.py`.
- Every tool wraps its client call in the module-local `_handle(lambda: …)` helper, which
  maps `ADConfigError` → `ToolError("Configuration error: …")`, `LookupError` →
  `ToolError(str(exc))`, and any other exception → `ToolError("Active Directory query
  failed: …")`. FastMCP turns `ToolError` into an `isError` MCP response.
- No `logging` module is used; errors surface as ToolError messages. Never log or echo
  passwords.

## Testing

- pytest ≥ 8; tests in `tests/test_<subject>.py`, functions `test_<scenario>()`.
- `tests/conftest.py` only adds `mcp/` to `sys.path` — no shared fixtures; each test file
  defines its own helpers (`_env()`, `_build_conn()`, …).
- Offline mocking via `ldap3.MOCK_SYNC` with the `OFFLINE_AD_2012_R2` schema — never a
  real DC in `tests/`. Live-DC checks belong in `scripts/` smoke scripts instead.
- MOCK_SYNC caveat: it doesn't implement `LDAP_MATCHING_RULE_BIT_AND`; tests assert the
  generated filter string instead of evaluating the rule (see
  [domain.md](domain.md) for the UAC bit context).

## Style

- Python ≥ 3.12 type hints throughout.
- No enforced line length; existing code mostly stays under ~100 chars (max observed ~114).
- Lint with `uvx ruff check mcp/ tests/` (default rules; deliberate broad excepts carry a
  `# BLE001`-style comment).
- TODO: no commit/PR conventions are discernible (not a git repo at survey time).
