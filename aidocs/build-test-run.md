# Build, test, run

Canonical tool: **uv** (`uv.lock` is committed; Dockerfile and docs use `uv run`/`uv sync`).
Python ≥ 3.12.

## Install / bootstrap

```bash
uv sync                                   # dev setup (resolves fastmcp, ldap3, pytest)
uv sync --frozen --no-dev --no-install-project   # what the Dockerfile builder stage runs
```

`pyproject.toml` sets `[tool.uv] package = false` — the project is never installed as a
package; `mcp/` modules are imported flat.

## Run

### Local stdio (no container, no auth)
```bash
python mcp/server.py --transport stdio
```

### Docker compose (HTTP transport, permanent container)
```bash
docker compose build
docker compose up -d
docker compose logs -f
curl -s http://127.0.0.1:8001/healthz     # → {"ok":true}
```
Endpoint: `http://<host>:8001/mcp` with header `Authorization: Bearer <MCP_BEARER_TOKEN>`.
Container listens on 8000; compose publishes it as host 8001.

### As a Claude Code plugin (stdio)
```bash
claude plugin marketplace add seanGSISG/ad-ldap-plugin
claude plugin install ad-ldap@ad-ldap-plugin
```
The manifest launches `uv run --project ${CLAUDE_PLUGIN_ROOT} python mcp/server.py --transport stdio`
(the server defaults to `http`, so the flag is required). Settings come from `userConfig`.
To load a working copy instead: `claude --plugin-dir .`.

## Test

### Offline suite (no DC needed — ldap3 MOCK_SYNC)
```bash
uv run pytest tests/ -q                   # full suite
uv run pytest tests/test_client.py -q     # one file
uv run pytest tests/test_client.py -k <pattern> -q   # one test
```
pytest config in `pyproject.toml`: `testpaths = ["tests"]`, `addopts = "-ra"`.

### Live-DC smoke scripts (require reachable DC + `AD_*` env vars)
```bash
uv run python scripts/smoke_connection.py   # bind + whoami + server info
uv run python scripts/smoke_read.py         # safe read-tool discovery
uv run python scripts/smoke_read.py --user jdoe --computer PC1 --group "Domain Admins" --find smith
uv run python scripts/smoke_bulk_plan.py    # bulk managedBy PLAN mode (read-only preview)
uv run python scripts/smoke_bulk_plan.py --verbose
```
All smoke scripts are read-only / plan-only — none of them mutate the directory.

## Lint

```bash
uvx ruff check mcp/ tests/
```
No `[tool.ruff]` config exists — defaults apply. No formatter or type-checker is
configured. TODO: no CI workflows exist (`.github/workflows/` absent).
