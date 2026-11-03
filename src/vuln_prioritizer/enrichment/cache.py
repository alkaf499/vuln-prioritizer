"""Frozen, dated threat-intel cache (``--intel-cache``) and the caching/budgeted lookup wrapper.

One JSON file serves two jobs:

* a **live** run writes through it (resumable: CVEs already in the file are never fetched again),
* an **offline** run replays it read-only, so a live-enriched worklist is byte-reproducible.

File format (a superset of the original offline cache; old files without ``_meta`` still load)::

    {"_meta": {"format": 1, "as_of": "2026-11-03T00:00:00+00:00", "updated": "...", "entries": 123},
     "CVE-2024-0001": { ...upstream exploit_check.assess()-shaped dict... }, ...}

``as_of`` is the run time that first created the file (the demo-facing date of the frozen intel);
``updated`` is the last run that wrote to it. Both come from the pipeline's ``as_of`` (injectable).

Every fresh lookup is passed through a JSON round-trip *before* it is used, so the first (live)
run and every later replay see byte-identical data (tuples -> lists, ``None`` keys, etc.).

Not persisted, so a later run retries them: lookups that raised, and records where a core local
feed (KEV / Metasploit / Exploit-DB / Nuclei) was unavailable. Caveat inherited from upstream:
its EPSS / nomi-sec / trickest helpers swallow their own errors, so a transient failure there is
indistinguishable from "none" and *is* frozen.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Mapping

META_KEY = "_meta"
FORMAT = 1
_CORE_FEED_FLAGS = ("kev_available", "msf_available", "edb_available", "nuclei_available")


class IntelCacheError(ValueError):
    """The intel cache is not a JSON object of CVE -> object."""


def parse_cache(data: Any, where: str) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    """Validate a decoded cache; returns ``(entries keyed by upper-case CVE, meta)``."""
    if not isinstance(data, dict):
        raise IntelCacheError(f"{where}: expected a JSON object mapping CVE -> object")
    meta = data.get(META_KEY, {})
    if not isinstance(meta, dict):
        raise IntelCacheError(f"{where}: {META_KEY} must be an object")
    entries: dict[str, dict[str, Any]] = {}
    for k, v in data.items():
        if k == META_KEY:
            continue
        if not isinstance(v, dict):
            raise IntelCacheError(f"{where}: expected a JSON object mapping CVE -> object")
        entries[str(k).upper()] = v
    return entries, dict(meta)


def normalize(raw: Mapping[str, Any]) -> dict[str, Any]:
    """The exact form a reload would produce (JSON round-trip)."""
    return json.loads(json.dumps(raw, default=str, ensure_ascii=False))


def is_degraded(raw: Mapping[str, Any]) -> bool:
    """A core local feed was unavailable for this lookup (so 'none' would be 'unknown')."""
    if not raw.get("kev_available", False) and not raw.get("kev"):
        return True
    return not all(raw.get(flag, False) for flag in _CORE_FEED_FLAGS[1:])


class IntelCache:
    """In-memory view of the cache file; ``save()`` writes it atomically and deterministically."""

    def __init__(
        self,
        path: str | os.PathLike[str] | None = None,
        entries: dict[str, dict[str, Any]] | None = None,
        meta: dict[str, Any] | None = None,
    ) -> None:
        self.path = Path(path) if path else None
        self.entries: dict[str, dict[str, Any]] = entries if entries is not None else {}
        self.meta: dict[str, Any] = meta if meta is not None else {}
        self.dirty = False

    @classmethod
    def load(cls, path: str | os.PathLike[str]) -> "IntelCache":
        """Read ``path``; a missing file is an empty cache that will be created on save."""
        p = Path(path)
        if not p.exists():
            return cls(p)
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            raise IntelCacheError(f"{p}: invalid JSON ({e})") from e
        entries, meta = parse_cache(data, str(p))
        return cls(p, entries, meta)

    @property
    def as_of(self) -> str | None:
        v = self.meta.get("as_of")
        return str(v) if v else None

    def put(self, cve: str, raw: Mapping[str, Any]) -> None:
        self.entries[cve.upper()] = dict(raw)
        self.dirty = True

    def stamp(self, as_of: datetime) -> None:
        stamp = as_of.isoformat()
        self.meta.setdefault("as_of", stamp)
        self.meta["updated"] = stamp

    def save(self) -> None:
        """Atomic write (temp file + rename); no-op for an in-memory cache or when unchanged."""
        if self.path is None or not self.dirty:
            return
        meta = {**self.meta, "format": FORMAT, "entries": len(self.entries)}
        data = {META_KEY: meta, **self.entries}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(self.path.name + ".tmp")
        tmp.write_text(
            json.dumps(data, indent=1, sort_keys=True, default=str, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        os.replace(tmp, self.path)
        self.dirty = False


class CachingAssess:
    """``assess(cve)`` that reads/writes an :class:`IntelCache`, with a live-lookup budget.

    * cache hit -> returned, no lookup (``mode="full"`` does not accept ``local``-mode entries; they
  are re-fetched and overwritten, while ``mode="local"`` accepts either);
    * miss within budget -> ``inner(cve)`` is called, normalized, kept (and persisted unless
      degraded), counted as ``fetched``;
    * miss with the budget spent -> the minimal ``{"cve": ...}`` record ("unknown") and the CVE
      is recorded in ``skipped`` so reports can say it was deferred, not unreachable;
    * ``inner`` raising -> remembered (not retried within the run, not cached) and re-raised.
    """

    def __init__(
        self,
        inner: Callable[[str], Mapping[str, Any]],
        cache: IntelCache,
        *,
        max_lookups: int | None = None,
        progress: Callable[[str], None] | None = None,
        progress_every: int = 100,
        save_every: int = 200,
        total: int = 0,
        mode: str = "full",
    ) -> None:
        self.inner, self.cache = inner, cache
        self.mode = mode
        self.max_lookups = max_lookups
        self.progress, self.progress_every, self.save_every = progress, progress_every, save_every
        self.total = total
        self.fetched = 0
        self.cache_hits = 0
        self.uncached_degraded = 0
        self.skipped: set[str] = set()
        self.failed: dict[str, Exception] = {}
        self._session: dict[str, dict[str, Any]] = {}  # degraded results: reused, never persisted

    @property
    def exhausted(self) -> bool:
        return self.max_lookups is not None and self.fetched >= self.max_lookups

    def _satisfies(self, entry: Mapping[str, Any]) -> bool:
        """A ``local`` request accepts any entry; a ``full`` request does not accept a
        ``local`` one (it lacks EPSS / PoC aggregators), so it is re-fetched and upgraded."""
        return self.mode == "local" or entry.get("enrich_mode") != "local"

    def __call__(self, cve: str) -> dict[str, Any]:
        key = cve.upper()
        hit = self.cache.entries.get(key) or self._session.get(key)
        if hit is not None and self._satisfies(hit):
            self.cache_hits += 1
            return hit
        if key in self.failed:
            raise self.failed[key]
        if self.exhausted:
            if hit is not None:  # budget spent before this local entry could be upgraded: keep it
                return hit
            self.skipped.add(key)
            return {"cve": key}
        try:
            raw = normalize(self.inner(key))
        except Exception as e:  # noqa: BLE001 - recorded; the caller decides what a failure means
            self.failed[key] = e
            raise
        self.fetched += 1
        if is_degraded(raw):
            self.uncached_degraded += 1
            self._session[key] = raw
        else:
            self.cache.put(key, raw)
            if self.save_every and self.fetched % self.save_every == 0:
                self.cache.save()
        self._tick()
        return raw

    def _tick(self) -> None:
        if self.progress and self.progress_every and self.fetched % self.progress_every == 0:
            self.report()

    def report(self) -> None:
        if self.progress:
            done = self.fetched + self.cache_hits + len(self.failed)
            self.progress(
                f"enrich: {done}/{self.total} CVEs "
                f"({self.fetched} fetched, {self.cache_hits} from cache, {len(self.failed)} failed)"
            )
