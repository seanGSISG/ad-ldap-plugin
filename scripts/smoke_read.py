#!/usr/bin/env python3
"""Live smoke test for the AD LDAP read tools (story-002).

Binds to the DC named by the ``AD_*`` environment variables and exercises each
read primitive against the live directory:

    uv run python scripts/smoke_read.py [--user IDENT] [--computer IDENT]
                                        [--group IDENT] [--find TERM]

With no arguments it runs the safe discovery path: find a few users and
computers, then fetch the first match of each (so password expiry and the full
attribute sets are exercised). Pass explicit identifiers to target known
objects. Use the documented ``AD_TLS_VALIDATE=false`` opt-out for a self-signed
lab DC. Exit code 0 on success, 1 on failure. Requires a reachable DC, so it is
intentionally separate from the offline unit tests.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

# Import the flat server modules from ../mcp.
_MCP_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "mcp")
sys.path.insert(0, _MCP_DIR)

from config import ADConfig, ADConfigError  # noqa: E402
from ad_client import ADClient  # noqa: E402


def _dump(label: str, payload) -> None:
    print(f"\n=== {label} ===")
    print(json.dumps(payload, indent=2, default=str))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Live smoke test for AD read tools.")
    parser.add_argument("--find", default="a", help="substring for find_users/find_computers")
    parser.add_argument("--user", help="explicit user identifier (sAMAccountName/UPN/mail/DN)")
    parser.add_argument("--computer", help="explicit computer identifier (name/dNSHostName/DN)")
    parser.add_argument("--group", help="explicit group identifier (sAMAccountName/cn/DN)")
    parser.add_argument("--limit", type=int, default=5, help="max matches for find_* (default 5)")
    args = parser.parse_args(argv)

    try:
        config = ADConfig.from_env()
    except ADConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        print(
            "Set AD_SERVER, AD_BASE_DN, AD_BIND_USER, AD_BIND_PASSWORD "
            "(and AD_TLS_VALIDATE=false for a self-signed lab DC).",
            file=sys.stderr,
        )
        return 1

    client = ADClient(config)

    try:
        _dump("check_connection", client.check_connection())

        users = client.find_users(args.find, limit=args.limit)
        _dump("find_users", users)
        user_ident = args.user or (
            users["users"][0]["sAMAccountName"] if users["users"] else None
        )
        if user_ident:
            _dump(f"get_user({user_ident})", client.get_user(user_ident))
        else:
            print("\n(no user matched; skipping get_user)")

        computers = client.find_computers(args.find, limit=args.limit)
        _dump("find_computers", computers)
        comp_ident = args.computer or (
            computers["computers"][0]["name"] if computers["computers"] else None
        )
        if comp_ident:
            _dump(f"get_computer({comp_ident})", client.get_computer(comp_ident))
        else:
            print("\n(no computer matched; skipping get_computer)")

        if args.group:
            _dump(f"list_group_members({args.group})", client.list_group_members(args.group))
        else:
            print("\n(no --group supplied; skipping list_group_members)")

    except Exception as exc:  # noqa: BLE001
        print(f"\nRead smoke failed: {exc}", file=sys.stderr)
        return 1

    print("\nAll read smoke checks completed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
