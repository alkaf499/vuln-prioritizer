"""``vuln-prioritizer classify`` - draft an overlay for assets no hand rule covers.

    vuln-prioritizer classify --db <navi.db> [--overlay hand.yaml ...] --out out/classification.ai.yaml
        [--only-unclassified | --no-only-unclassified] [--model ID] [--batch N] [--min-confidence X]

Reads navi.db read-only, calls the Anthropic Messages API (stdlib urllib, key from
ANTHROPIC_API_KEY), writes a DRAFT overlay for human review. ``run`` never consumes it
automatically: pass it explicitly as a LATER ``--overlay``. Without a key it logs and exits 0,
leaving the deterministic overlays in charge.
"""

from __future__ import annotations

import argparse
import re
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from ..adapters.navi import load_assets
from ..context import OverlayError, load_overlays
from .cache import ClassifierCache
from .engine import DEFAULT_BATCH, classify_keys, targets
from .llm import DEFAULT_MODEL, LLM, AnthropicHTTP, LLMError, MissingApiKey, api_key_from_env
from .render import render_overlay
from .signals import gather_signals
from .validate import DEFAULT_MIN_CONFIDENCE, SAFE_TOKEN

DEFAULT_OUT = Path("out/classification.ai.yaml")


def default_llm() -> LLM | None:
    """The real client if ``ANTHROPIC_API_KEY`` is set, else ``None`` (graceful degradation)."""
    key = api_key_from_env()
    return AnthropicHTTP(key) if key else None


def default_cache_path(out: Path) -> Path:
    return out.with_name(out.stem + ".cache.json")


def run_classify(
    args: argparse.Namespace, *, llm_factory: Callable[[], LLM | None] = default_llm
) -> int:
    def err(msg: str) -> None:
        print(msg, file=sys.stderr, flush=True)

    model = args.model or DEFAULT_MODEL
    batch = args.batch if args.batch is not None else DEFAULT_BATCH
    min_conf = DEFAULT_MIN_CONFIDENCE if args.min_confidence is None else args.min_confidence
    out_path: Path = args.out or DEFAULT_OUT
    if not SAFE_TOKEN.fullmatch(model):
        err(f"error: --model {model!r} is not a plausible model id")
        return 2
    if batch < 1:
        err("error: --batch must be >= 1")
        return 2
    if not 0.0 <= min_conf <= 1.0:
        err("error: --min-confidence must be between 0 and 1")
        return 2
    if args.limit is not None and args.limit < 1:
        err("error: --limit must be >= 1")
        return 2
    if args.as_of:
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", args.as_of):
            err("error: --as-of must be YYYY-MM-DD")
            return 2
        today = args.as_of
    else:
        today = datetime.now(timezone.utc).date().isoformat()

    try:
        assets = load_assets(args.db)
        overlay = load_overlays(args.overlay)
        keys = targets(assets, overlay, only_unclassified=args.only_unclassified)
        if args.limit is not None:
            keys = keys[: args.limit]
        cache = ClassifierCache.load(args.cache or default_cache_path(out_path))
    except (OSError, ValueError, OverlayError, sqlite3.Error, RuntimeError) as e:
        err(f"error: {e}")
        return 2

    uncached = sum(1 for k in keys if cache.get(k) is None)
    scope = "unclassified" if args.only_unclassified else "all"
    print(f"{len(assets)} assets in db; {len(keys)} distinct (hostname, OS) {scope} target(s); "
          f"{len(keys) - uncached} cached, {uncached} to classify with {model}")
    if cache.dropped:
        err(f"note: ignored {cache.dropped} invalid cache entr{'y' if cache.dropped == 1 else 'ies'} (will re-classify)")
    if cache.stale:
        err(f"note: discarded {cache.stale} cache entr{'y' if cache.stale == 1 else 'ies'} from an older "
            "input format (fewer signals); those assets are re-classified")
    if args.dry_run:
        print("dry run: nothing sent, nothing written")
        return 0

    try:
        pending = [k for k in keys if cache.get(k) is None]
        signals = gather_signals(args.db, pending) if pending else {}
    except (OSError, sqlite3.Error) as e:
        err(f"note: could not read scanner signals ({e}); classifying on hostname + OS only")
        signals = {}
    if pending:
        print(f"signals found for {len(signals)}/{len(pending)} asset(s) to classify")

    try:
        outcome = classify_keys(
            keys,
            llm=llm_factory(),
            model=model,
            today=today,
            cache=cache,
            batch_size=batch,
            signals=signals,
            progress=err,
        )
    except MissingApiKey:
        err("ANTHROPIC_API_KEY is not set: skipping AI classification. Nothing written; "
            "`run` works as usual with the deterministic overlays.")
        return 0
    except LLMError as e:
        err(f"error: {e}\nprogress is saved in {cache.path}; re-run to resume")
        return 2
    except KeyboardInterrupt:
        err(f"interrupted. progress is saved in {cache.path}; re-run to resume")
        return 130

    text, abstained = render_overlay(
        outcome.classified, min_confidence=min_conf, rejected=outcome.rejected, unsafe=outcome.unsafe
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(text, encoding="utf-8")
    written = text.count("\n  - match:")
    print(f"sent {outcome.sent} asset(s) in {outcome.batches} batch(es); {outcome.from_cache} from cache")
    print(f"wrote {out_path}: {written} rule(s), {len(abstained)} abstained (unknown + flagged for review)")
    print("DRAFT: review it, then pass it explicitly as a later --overlay (hand overlays first). "
          "It is tenant-derived: do not commit it.")
    return 0
