"""Entrypoint for the AD LDAP MCP server.

Supports two transports:

* ``--transport http`` (default): a bearer-protected streamable-HTTP server bound
  on ``HTTP_HOST``/``HTTP_PORT`` (default ``0.0.0.0:8000``), MCP mounted at
  ``/mcp``, with an unauthenticated ``/healthz`` probe. Intended for a permanent
  Docker container serving multiple clients over the LAN.
* ``--transport stdio``: runs the FastMCP server over stdio for a local desktop
  MCP client. No bearer token required.

Run as a script (``python mcp/server.py``): this file's directory goes on
``sys.path`` so the flat sibling modules import as top-level names, and the
site-packages ``mcp`` package keeps winning the import over this directory.
Importing the tool modules is what registers their tools on the shared app.
"""

from __future__ import annotations

import argparse
import os
import sys

# Ensure sibling modules (app, ad_client, config, http_app, tools_*) import as
# top-level names regardless of how the interpreter was launched.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import mcp  # noqa: E402
import tools_read  # noqa: E402,F401  (registers read tools on import)
import tools_write_user  # noqa: E402,F401  (registers user write tools on import)
import tools_write_computer_group  # noqa: E402,F401  (registers computer/group write tools)
import tools_bulk  # noqa: E402,F401  (registers the bulk managedBy tool on import)


def _run_http(host: str | None, port: int | None) -> None:
    import uvicorn

    from http_app import create_app, http_host, http_port

    bind_host = host if host is not None else http_host()
    bind_port = port if port is not None else http_port()

    # create_app raises RuntimeError if MCP_BEARER_TOKEN is unset.
    app = create_app()
    print(
        f"Starting AD LDAP MCP HTTP server on http://{bind_host}:{bind_port} "
        f"(MCP mounted at /mcp; bearer auth required, /healthz open).",
        file=sys.stderr,
    )
    uvicorn.run(app, host=bind_host, port=bind_port)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="ad-ldap-mcp",
        description=(
            "AD LDAP MCP server. 'http' (default) runs a bearer-protected "
            "streamable-HTTP transport for a shared LAN container; 'stdio' runs "
            "the transport over stdin/stdout for a local desktop client."
        ),
    )
    parser.add_argument(
        "--transport",
        choices=("http", "stdio"),
        default="http",
        help="Transport to run (default: http).",
    )
    parser.add_argument(
        "--host", default=None, help="Bind host for HTTP (overrides HTTP_HOST)."
    )
    parser.add_argument(
        "--port", type=int, default=None, help="Bind port for HTTP (overrides HTTP_PORT)."
    )
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)

    if args.transport == "stdio":
        mcp.run(transport="stdio")
    else:
        _run_http(args.host, args.port)


if __name__ == "__main__":
    main()
