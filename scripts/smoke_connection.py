#!/usr/bin/env python3
"""Live smoke test for the AD LDAPS connection (story-001).

Binds to the DC named by the ``AD_*`` environment variables and prints the
diagnostic returned by ``ADClient.check_connection`` (whoami + server info). Use
the documented ``AD_TLS_VALIDATE=false`` opt-out against a self-signed lab DC.

    uv run python scripts/smoke_connection.py

Exit code 0 on a successful bind, 1 otherwise. Requires a reachable DC, so it is
intentionally separate from the offline unit tests.
"""

from __future__ import annotations

import json
import os
import sys

# Import the flat server modules from ../mcp.
_MCP_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "mcp")
sys.path.insert(0, _MCP_DIR)

from config import ADConfig, ADConfigError  # noqa: E402
from ad_client import ADClient  # noqa: E402


def main() -> int:
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
        info = client.check_connection()
    except Exception as exc:  # noqa: BLE001
        print(f"Connection failed: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(info, indent=2, default=str))
    if not info.get("connected"):
        print("Bind did not succeed.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
