# ad-ldap

Active Directory administration from Claude Code, over LDAPS. One plugin installs:

- an **MCP server** (FastMCP + `ldap3`) with 15 tools: 6 reads, 8 writes, 1 bulk
- two **agents** (`ad-user-admin`, `ad-computer-admin`), two **commands** (`/ad-whois`,
  `/ad-assign-computer`) and a **safety skill**
- a **write guard** that refuses any AD change until the identical call has been dry-run first

Headline workflow: most computer objects have no `managedBy`, but the owner's name sits in
`description`. `ad_bulk_assign_managers` matches those names to users and assigns `managedBy`
through a plan → review → apply loop. It never modifies `description`.

## Install

You need Claude Code, [`uv`](https://docs.astral.sh/uv/) on your `PATH`, a domain controller
reachable on LDAPS (port 636), and a service account that can read the directory (and write, for
the write tools).

**1. Add the marketplace and install the plugin** (inside Claude Code):

```
/plugin marketplace add seanGSISG/ad-ldap-plugin
/plugin install ad-ldap@ad-ldap-plugin
```

**2. Enter your settings.** Claude Code prompts for them when the plugin is enabled. To change
them later, run `/plugin configure ad-ldap@ad-ldap-plugin`. The password goes to your OS keychain,
never to `settings.json`.

| Setting | Example | Notes |
|---|---|---|
| Domain controller | `dc01.example.com` | or an `ldaps://` URI |
| Base DN | `DC=example,DC=com` | |
| Service account | `svc-ldap@example.com` | UPN or full DN |
| Service account password | | stored in the keychain |
| LDAPS port | `636` | `3269` for the Global Catalog |
| CA bundle path | `/etc/ssl/certs/corp-ca.pem` | blank = system trust store |
| Validate the DC's certificate | `true` | `false` only for a self-signed lab DC |

**3. Turn on the write guard.** It is built on function hooks, which are early access. Add this to
the `env` block of `~/.claude/settings.json`:

```json
"CLAUDE_CODE_ENABLE_FUNCTION_HOOKS": "1"
```

Without it everything else works and writes still default to `dry_run=true`, but nothing forces
the dry run. The guard never prompts, so agents running batches and `claude -p` jobs work
unattended as long as they dry-run each change first (in the same session).

**4. Restart Claude Code and check the connection:**

```
> check the AD connection
```

Claude calls `ad_check_connection` and reports the bind identity and server.

<details>
<summary>Install from a terminal instead</summary>

```bash
claude plugin marketplace add seanGSISG/ad-ldap-plugin
claude plugin install ad-ldap@ad-ldap-plugin \
  --config server=dc01.example.com \
  --config base_dn=DC=example,DC=com \
  --config bind_user=svc-ldap@example.com
# then set the password inside Claude Code, so it stays out of your shell history:
#   /plugin configure ad-ldap@ad-ldap-plugin
```
</details>

## What the tools do

| Tools | Kind |
|---|---|
| `ad_check_connection`, `ad_find_users`, `ad_get_user`, `ad_find_computers`, `ad_get_computer`, `ad_list_group_members` | read |
| `ad_set_user_attributes`, `ad_set_user_manager`, `ad_reset_password`, `ad_set_account_status`, `ad_unlock_account`, `ad_set_computer_attributes`, `ad_add_group_member`, `ad_remove_group_member` | write, `dry_run=true` by default |
| `ad_bulk_assign_managers` | bulk, `apply=false` by default |

Attribute writes are limited to fixed whitelists (see `mcp/ad_client.py`):

- users: `department`, `title`, `physicalDeliveryOfficeName`, `telephoneNumber`,
  `extensionAttribute1`, `extensionAttribute10`
- computers: `description`, `managedBy`

## Safety

- **LDAPS only.** `AD_USE_SSL=false` is rejected, because a simple bind would send the password in
  cleartext.
- **Dry run first.** Every write returns a before → after diff unless you pass `dry_run=false`.
  With the guard on, a commit is refused until the identical call dry-ran in this session. This
  holds in every permission mode, subagents included, and the guard refuses the call if it fails
  itself.
- **Passwords are never echoed.** `ad_reset_password` sends `unicodePwd` over LDAPS only.

## Run as a shared HTTP container (optional)

To serve several clients from one host instead of each running the plugin:

```bash
cp .env.example .env        # fill in AD_* and MCP_BEARER_TOKEN (a long random secret)
mkdir -p cert && cp /path/to/ca.pem cert/ldap-ca.pem
docker compose up -d        # http://<host>:8001/mcp, health at /healthz
```

Register it in Claude Code:

```bash
claude mcp add --transport http ad-ldap http://<host>:8001/mcp \
  --header "Authorization: Bearer <MCP_BEARER_TOKEN>"
```

The write guard ships inside the plugin, so a container-only setup keeps the `dry_run=true`
defaults but has no guard.

## Development

```bash
uv sync
uv run pytest tests/ -q                          # offline suite, no DC needed
claude plugin test .                             # the write guard, against the engine
uv run python scripts/smoke_connection.py        # live DC, read-only (reads AD_* from env)
```

`DESIGN.md` holds the locked design decisions; `aidocs/` the architecture notes.

## License

MIT
