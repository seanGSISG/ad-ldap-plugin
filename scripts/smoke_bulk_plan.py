#!/usr/bin/env python3
"""Live smoke test for the bulk managedBy PLAN workflow (story-005).

Binds to the DC named by the ``AD_*`` environment variables and runs
``ad_bulk_assign_managers`` in PLAN mode (apply=false) against the live
directory, then prints a bucket summary. This is strictly READ-ONLY: plan mode
never issues a write. Use it to preview how the fleet's descriptions map to
users before anyone runs an apply.

    uv run python scripts/smoke_bulk_plan.py [--verbose]

Use the documented ``AD_TLS_VALIDATE=false`` opt-out for a self-signed lab DC.
Exit code 0 on success, 1 on failure. Requires a reachable DC, so it is
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


def _print_samples(label: str, rows: list, verbose: bool, key: str = "owner") -> None:
    if not rows:
        return
    shown = rows if verbose else rows[:5]
    print(f"\n  {label} (showing {len(shown)}/{len(rows)}):")
    for row in shown:
        detail = row.get(key) or row.get("reason") or ""
        print(f"    - {row.get('computer')}: {detail}  [{row.get('source', '')}]")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Live PLAN-mode smoke for bulk managedBy.")
    parser.add_argument("--verbose", action="store_true", help="print every per-computer entry")
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
        print("=== ad_bulk_assign_managers (PLAN mode — read-only) ===")
        report = client.bulk_assign_managers(apply=False)

        print(f"\nScanned {report['scanned']} computer object(s).")
        print("Bucket counts:")
        print(json.dumps(report["counts"], indent=2, default=str))

        _print_samples("matched", report["matched"], args.verbose)
        _print_samples("ambiguous", report["ambiguous"], args.verbose)
        _print_samples("unmatched", report["unmatched"], args.verbose)
        _print_samples("already_assigned", report["already_assigned"], args.verbose)

        if report["apply"] is not False:
            print("\nUNEXPECTED: plan-mode report had apply != False", file=sys.stderr)
            return 1

    except Exception as exc:  # noqa: BLE001
        print(f"\nBulk plan smoke failed: {exc}", file=sys.stderr)
        return 1

    print("\nPlan smoke completed (no writes performed).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
