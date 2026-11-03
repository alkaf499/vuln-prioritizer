"""``vuln-prioritizer run`` — the single entrypoint for the whole pipeline (CLAUDE.md §5).

    vuln-prioritizer run --db <navi.db> --overlay <yaml> --out <dir> [--offline] [--threat-first]

Writes ``worklist.md``, ``worklist.csv``, ``excluded.csv`` (out-of-scope assets) and
``informational.csv`` (Info-severity scanner output, not ranked) and ``executive_report.md``
(toil saved, SLA compliance, per-role view, top risks) into ``--out`` (gitignored) and
prints the ranked worklist to stdout. Reads navi.db + the overlay only; never writes to the
Tenable tenant.
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Sequence

from . import pipeline, report, worklist

OUTPUT_FILES = ("worklist.md", "worklist.csv", "excluded.csv", "informational.csv", "executive_report.md")


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
                   help="no network: enrichment answers from --intel-cache (read-only) or 'unknown' (deterministic)")
    r.add_argument("--intel-cache", type=Path, metavar="FILE",
                   help="dated JSON threat-intel cache (CVE -> exploit-availability-check result). "
                        "Live: written through (created if absent; an interrupted run resumes, cached CVEs "
                        "are never re-fetched). With --offline: replayed read-only, so a live-enriched "
                        "worklist is byte-reproducible")
    r.add_argument("--enrich", choices=pipeline.ENRICH_MODES, default=None,
                   help="live only. local (default): use ONLY the four cached feeds (CISA KEV, Metasploit, "
                        "Exploit-DB, Nuclei) - no per-CVE network, evidence says PoC aggregators were not "
                        "consulted. full: also per-CVE EPSS API + nomi-sec/trickest PoC repos "
                        "(~3 HTTP calls per CVE; pair with --intel-cache and --max-lookups)")
    r.add_argument("--max-lookups", type=int, metavar="N",
                   help="live only: fetch at most N new CVEs this run, top-ranked first (cache hits are free); "
                        "the rest are reported as deferred - re-run with the same cache to continue")
    r.add_argument("--progress-every", type=int, default=100, metavar="N",
                   help="live only: print a progress line to stderr every N fetches (0 = silent; default 100)")
    r.add_argument("--threat-first", action="store_true",
                   help="publish only threat-linked findings (KEV / weaponized or public exploit)")
    r.add_argument("--as-of", type=_parse_as_of, metavar="ISO8601",
                   help="fix the as-of time (due dates derive from it); default: now, UTC")
    r.add_argument("--top", type=int, default=15, help="rows to print to stdout (default 15)")
    r.add_argument("--triage-minutes", type=float, metavar="M",
                   help="executive report: assumed manual-triage minutes per finding, to illustrate analyst "
                        "time saved (an operator assumption, labelled as such; omitted by default)")
    r.add_argument("--no-timing", action="store_true",
                   help="omit the measured time-to-worklist line so executive_report.md is byte-reproducible")
    return p


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.max_lookups is not None and (args.offline or args.max_lookups < 0):
        parser.error("--max-lookups applies to live runs only (not --offline) and must be >= 0")
    if args.progress_every < 0:
        parser.error("--progress-every must be >= 0")
    if args.enrich is not None and args.offline:
        parser.error("--enrich applies to live runs only (an --offline run looks nothing up)")
    enrich = args.enrich or pipeline.DEFAULT_ENRICH

    def progress(msg: str) -> None:
        print(msg, file=sys.stderr, flush=True)

    if args.triage_minutes is not None and args.triage_minutes <= 0:
        parser.error("--triage-minutes must be > 0")

    started = time.perf_counter()
    try:
        result = pipeline.run_pipeline(
            args.db,
            args.overlay,
            offline=args.offline,
            threat_first=args.threat_first,
            as_of=args.as_of,
            intel_cache=args.intel_cache,
            max_lookups=args.max_lookups,
            enrich=enrich,
            progress=progress if args.progress_every else None,
            progress_every=args.progress_every,
        )
    except KeyboardInterrupt:
        note = f" Cache saved to {args.intel_cache}; re-run to resume." if args.intel_cache else ""
        print(f"interrupted.{note}", file=sys.stderr)
        return 130
    except (OSError, ValueError, RuntimeError, sqlite3.Error) as e:
        # missing db/overlay/cache, bad overlay/cache, missing tables, not a sqlite file
        print(f"error: {e}", file=sys.stderr)
        return 2

    rows = worklist.build_rows(result)
    excluded = worklist.build_excluded_rows(result)
    elapsed = None if args.no_timing else time.perf_counter() - started  # load -> ... -> rows

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "executive_report.md").write_text(
        report.to_exec_markdown(
            result, rows, excluded, elapsed_seconds=elapsed, triage_minutes=args.triage_minutes
        ),
        encoding="utf-8",
    )
    (args.out / "worklist.md").write_text(worklist.to_markdown(result, rows, excluded), encoding="utf-8")
    (args.out / "worklist.csv").write_text(worklist.to_csv(rows, worklist.COLUMNS), encoding="utf-8")
    (args.out / "excluded.csv").write_text(
        worklist.to_csv(excluded, worklist.EXCLUDED_COLUMNS), encoding="utf-8"
    )
    (args.out / "informational.csv").write_text(
        worklist.to_csv(worklist.build_informational_rows(result), worklist.INFORMATIONAL_COLUMNS),
        encoding="utf-8",
    )

    sys.stdout.write(worklist.to_chat(result, rows, top=args.top))
    print(f"\nwrote {', '.join(str(args.out / f) for f in OUTPUT_FILES)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
