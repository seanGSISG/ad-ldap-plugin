# Integrations & configuration

## External service: Active Directory over LDAPS

- Client library: **ldap3** (≥ 2.9.1). SIMPLE bind with a service account
  (UPN or full DN). Password resets use
  `ldap3.extend.microsoft.modifyPassword.ad_modify_password`.
- **LDAPS is mandatory** — `AD_USE_SSL=false` is rejected at config-parse time
  (`mcp/config.py`). No plaintext LDAP mode exists. Default port 636 (3269 = Global
  Catalog over SSL).
- TLS validation is on by default; the DC's CA bundle lives at `cert/ldap-ca.pem`, baked
  into the Docker image and mounted read-only at `/certs/ldap-ca.pem` by
  `docker-compose.yml`.

## Environment variables (names only — values live in `.env`, which is gitignored)

Parsed by `ADConfig.from_env()` in `mcp/config.py` (frozen dataclass; `bind_password`
excluded from repr; missing required vars fail loudly).

### Required
| Var | Purpose |
| --- | --- |
| `AD_SERVER` | DC hostname or `ldaps://` URI |
| `AD_BASE_DN` | Search base, e.g. `dc=example,dc=com` |
| `AD_BIND_USER` | Service account (UPN or DN) |
| `AD_BIND_PASSWORD` | Service account password |

### Optional (defaults)
| Var | Default | Purpose |
| --- | --- | --- |
| `AD_PORT` | `636` | LDAPS port |
| `AD_USE_SSL` | `true` | Must stay true — `false` rejected |
| `AD_TLS_VALIDATE` | `true` | Set false only for self-signed lab DCs |
| `AD_CA_CERTS` | — | Path to CA bundle (optional if in system store) |
| `AD_PAGE_SIZE` | `500` | Paged-search page size |
| `AD_USER_SEARCH_BASE` | — | Scoped OU for user searches |
| `AD_COMPUTER_SEARCH_BASE` | — | Scoped OU for computer searches |

### HTTP transport only
| Var | Default | Purpose |
| --- | --- | --- |
| `MCP_BEARER_TOKEN` | — | Required; startup raises `RuntimeError` if unset. Checked with constant-time comparison in `mcp/http_app.py` |
| `HTTP_HOST` | `0.0.0.0` | Bind address |
| `HTTP_PORT` | `8000` | Container port (published as 8001 by compose) |

Where set: `.env` (compose reads it), `.env.example` documents names, or, for plugin
installs, the manifest's `userConfig` (prompted at install) mapped into the `env` block via
`${user_config.*}`.

## Required infra

- Offline tests (`uv run pytest tests/ -q`) need **nothing** — ldap3 MOCK_SYNC.
- Smoke scripts and real use need a reachable domain controller over LDAPS plus the
  `AD_*` vars above.

## Footguns

1. **`AD_USE_SSL=false` is rejected** — don't try to "temporarily" disable TLS.
2. **A blank scoped search base means unset**: `AD_USER_SEARCH_BASE=""` falls back to
   `AD_BASE_DN`, because the plugin passes an empty setting as `""`. A typo'd OU is not
   caught here; `ad_check_connection` and the first search will fail on it.
3. **MOCK_SYNC can't evaluate `LDAP_MATCHING_RULE_BIT_AND`** (OID
   `1.2.840.113556.1.4.803`, used to filter disabled accounts) — it raises
   `LDAPAttributeError`. Tests assert filter strings instead; real AD evaluates it fine.
4. **Healthcheck**: compose polls `http://127.0.0.1:8000/healthz` in-container every 30s;
   `/healthz` is deliberately unauthenticated — don't put data behind it.
5. **Never copy `.env` values** into code, docs, or logs.

For write-operation guards (dry-run, whitelists, chunking) see [safety.md](safety.md).
