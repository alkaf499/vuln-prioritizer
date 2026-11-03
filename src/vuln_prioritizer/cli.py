"""``vuln-prioritizer run`` — the single entrypoint for the whole pipeline (CLAUDE.md §5).

    vuln-prioritizer run --db <navi.db> --overlay <yaml> --out <dir> [--offline] [--threat-first]

Writes ``worklist.md``, ``worklist.csv`` and ``excluded.csv`` into ``--out`` (gitignored) and
prints the ranked worklist to stdout. Reads navi.db + the overlay only; never writes to the
Tenable tenant.
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
from datetime import datetime
from pathlib import Path
from typing import Sequence

from . import pipeline, worklist

OUTPUT_FILES = ("worklist.md", "worklist.csv", "excluded.csv")


def _parse_as_of(raw: str) -> datetime:
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as e:
        raise argparse.ArgumentTypeError(f"not an ISO-8601 timestamp: {raw!r}") from e


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vuln-prioritizer",
        description="Context-aware vulnerability prioritization (read-only).",
    )
    sub = p.add_subparsers(dest="command", required=True)
    r = sub.add_parser("run", help="run the full pipeline and emit the ranked worklist")
    r.add_argument("--db", required=True, type=Path, help="path to navi.db (opened read-only)")
    r.add_argument("--overlay", type=Path, help="CMDB classification overlay (YAML); "
                   "omitted => every asset is unknown/internal and flagged for re-evaluation")
    r.add_argument("--out", required=True, type=Path, help="output directory (created if absent)")
    r.add_argument("--offline", action="store_true",
                   help="no network: enrichment answers from --intel-cache or 'unknown' (deterministic)")
    r.add_argument("--intel-cache", type=Path,
                   help="offline threat-intel cache (JSON: CVE -> exploit-availability-check result); needs --offline")
    r.add_argument("--threat-first", action="store_true",
                   help="publish only threat-linked findings (KEV / weaponized or public exploit)")
    r.add_argument("--as-of", type=_parse_as_of, metavar="ISO8601",
                   help="fix the as-of time (due dates derive from it); default: now, UTC")
    r.add_argument("--top", type=int, default=15, help="rows to print to stdout (default 15)")
    return p


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.intel_cache and not args.offline:
        parser.error("--intel-cache requires --offline")

    try:
        result = pipeline.run_pipeline(
            args.db,
            args.overlay,
            offline=args.offline,
            threat_first=args.threat_first,
            as_of=args.as_of,
            intel_cache=args.intel_cache,
        )
    except (OSError, ValueError, RuntimeError, sqlite3.Error) as e:
        # missing db/overlay, bad overlay/cache, missing tables, not a sqlite file
        print(f"error: {e}", file=sys.stderr)
        return 2

    rows = worklist.build_rows(result)
    excluded = worklist.build_excluded_rows(result)

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "worklist.md").write_text(worklist.to_markdown(result, rows, excluded), encoding="utf-8")
    (args.out / "worklist.csv").write_text(worklist.to_csv(rows, worklist.COLUMNS), encoding="utf-8")
    (args.out / "excluded.csv").write_text(
        worklist.to_csv(excluded, worklist.EXCLUDED_COLUMNS), encoding="utf-8"
    )

    sys.stdout.write(worklist.to_chat(result, rows, top=args.top))
    print(f"\nwrote {', '.join(str(args.out / f) for f in OUTPUT_FILES)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
