#!/usr/bin/env python3
"""Bulk managedBy plan/apply driver with the mandatory CSV review export.

Implements the SKILL.md "plan -> review -> apply" workflow when driving the
server code directly (e.g. the MCP transport is unavailable, or you want the
review CSVs without hand-parsing the tool's JSON):

- loads ``AD_*`` config from the project ``.env`` (values are never printed),
- optionally loads a hints CSV (``computer`` + owner column; rows whose
  ``flag`` column exists and isn't ``ok`` are ignored),
- runs ``ADClient.bulk_assign_managers`` — PLAN mode unless ``--apply``,
- writes one CSV per non-empty bucket into ``bulk-review/`` (gitignored).

    uv run python skills/active-directory/scripts/bulk_plan.py
    uv run python skills/active-directory/scripts/bulk_plan.py --hints bulk-review/hints.csv
    uv run python skills/active-directory/scripts/bulk_plan.py --hints ... --apply

Apply commits ONLY the matched bucket, chunked, through the validated
``managedBy`` path — same code the MCP tool uses. Never run ``--apply``
without an explicit operator sign-off on the exported CSVs.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))
sys.path.insert(0, os.path.join(_ROOT, "mcp"))

from config import ADConfig  # noqa: E402
from ad_client import ADClient  # noqa: E402

_BUCKET_COLUMNS = {
    "matched": ["computer", "owner", "matched_user", "owner_dn", "source", "dn"],
    "unmatched": ["computer", "reason", "owner", "hint", "source", "dn"],
    "ambiguous": ["computer", "owner", "candidates", "source", "dn"],
    "already_assigned": [
        "computer", "current_managedBy", "owner", "matched_user", "owner_dn", "source", "dn",
    ],
}


def load_env(root: str) -> None:
    """Set vars from .env without echoing any value."""
    with open(os.path.join(root, ".env"), encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def load_hints(path: str, owner_column: str) -> dict[str, str]:
    """Build {COMPUTER: owner} from a CSV; rows with a non-'ok' flag are dropped."""
    hints: dict[str, str] = {}
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            computer = (row.get("computer") or "").strip().upper()
            owner = (row.get(owner_column) or "").strip()
            flag = (row.get("flag") or "ok").strip()
            if computer and owner and flag == "ok":
                hints[computer] = owner
    return hints


def export_buckets(report: dict, outdir: str, suffix: str) -> None:
    os.makedirs(outdir, exist_ok=True)
    for bucket, columns in _BUCKET_COLUMNS.items():
        rows = report.get(bucket) or []
        if not rows:
            continue
        path = os.path.join(outdir, f"{bucket}{suffix}.csv")
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=columns, extrasaction="ignore")
            writer.writeheader()
            for row in rows:
                flat = dict(row)
                if isinstance(flat.get("candidates"), list):
                    flat["candidates"] = "; ".join(
                        c.get("sAMAccountName") or c.get("dn", "") if isinstance(c, dict) else str(c)
                        for c in flat["candidates"]
                    )
                writer.writerow(flat)
        print(f"  wrote {path} ({len(rows)} rows)")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Bulk managedBy plan/apply with CSV review export.")
    parser.add_argument("--hints", help="path to a hints CSV (computer + owner columns)")
    parser.add_argument(
        "--owner-column", default="proposed_owner",
        help="hints CSV column holding the owner identifier (default: proposed_owner)",
    )
    parser.add_argument("--apply", action="store_true", help="commit the matched bucket")
    parser.add_argument("--overwrite", action="store_true", help="re-match already_assigned computers")
    parser.add_argument(
        "--outdir", default=os.path.join(_ROOT, "bulk-review"),
        help="directory for the review CSVs (default: bulk-review/)",
    )
    args = parser.parse_args(argv)

    load_env(_ROOT)
    hints: dict[str, str] = {}
    if args.hints:
        hints = load_hints(args.hints, args.owner_column)
        print(f"Loaded {len(hints)} hints from {args.hints}")

    client = ADClient(ADConfig.from_env())
    mode = "APPLY" if args.apply else "PLAN (read-only)"
    print(f"=== bulk_assign_managers — {mode} ===")
    report = client.bulk_assign_managers(hints=hints, apply=args.apply, overwrite=args.overwrite)

    print(f"Scanned {report['scanned']} computers; counts:")
    print(json.dumps(report["counts"], indent=2, default=str))

    if args.apply:
        committed = report.get("committed") or []
        failed = report.get("failed") or []
        print(f"Apply results: {len(committed)} committed, {len(failed)} failed")
        for err in failed:
            print(f"  FAILED {err.get('computer')}: {err.get('error')}")
        export_buckets(report, args.outdir, "_applied")
        return 1 if failed else 0

    if hints:
        matched_names = {(r.get("computer") or "").upper() for r in report.get("matched", [])}
        missing = sorted(h for h in hints if h not in matched_names)
        print(f"Hint coverage: {len(hints) - len(missing)}/{len(hints)} hint computers in matched")
        for name in missing:
            print(f"  NOT MATCHED via hint: {name}")
    export_buckets(report, args.outdir, "_with_hints" if hints else "")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
