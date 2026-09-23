# Project documentation (aidocs)

On-demand knowledge base for this project. `CLAUDE.md` stays short by pointing here.
Open a doc when its "read when" cue matches your task.

| Doc | Read when… |
| --- | --- |
| [architecture.md](architecture.md) | changing module boundaries, data flow, adding tools/transports, or touching `mcp/` internals |
| [build-test-run.md](build-test-run.md) | a command in CLAUDE.md is insufficient, you need Docker/plugin install details, or a smoke script against a live DC |
| [conventions.md](conventions.md) | writing new code — tool definitions, error handling, tests, naming |
| [integrations.md](integrations.md) | touching LDAP/AD connectivity, env config, TLS/certs, or the HTTP transport |
| [safety.md](safety.md) | implementing or modifying any **write** operation (dry-run framework, whitelists, bulk chunking) |
| [domain.md](domain.md) | confused by AD/LDAP terms (UAC bits, FILETIME, managedBy, DN forms) |

<!-- Keep this table in sync with the "Detailed documentation" section of CLAUDE.md. -->
