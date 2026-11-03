"""Offline enrichment source (``--offline``): deterministic, no network, ever.

``enrich_findings`` takes an ``assess(cve) -> dict`` callable shaped like upstream
threat-intel-toolkit's ``exploit_check.assess``. Offline, that callable is a lookup into a
local JSON *cache* (CVE -> upstream-shaped dict; see :mod:`.cache` for the file format, which
may be a frozen artifact written by an earlier live run). A CVE with no cache entry yields the
minimal ``{"cve": ...}`` record, which :func:`~.toolkit.to_intel` maps to "unknown" on every
feed — never to "not on KEV". The scorer therefore only sees what navi.db itself carried
plus whatever the cache asserts.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Mapping

from .cache import IntelCache, IntelCacheError

__all__ = ["IntelCacheError", "load_intel_cache", "offline_assess"]


def load_intel_cache(path: str | Path) -> dict[str, dict[str, Any]]:
    """Read a cache file's entries (keys upper-cased; the ``_meta`` stamp is ignored). Read-only.

    Unlike :meth:`IntelCache.load`, a missing file is an error here: an offline replay of a
    cache that is not there is a mistake, not an empty cache."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"intel cache not found: {p}")
    return IntelCache.load(p).entries


def offline_assess(
    cache: Mapping[str, Mapping[str, Any]] | None = None,
) -> Callable[[str], dict[str, Any]]:
    """An ``assess`` replacement that answers only from ``cache`` (no I/O)."""
    table = {k.upper(): v for k, v in (cache or {}).items()}

    def assess(cve: str) -> dict[str, Any]:
        hit = table.get(cve.upper())
        return {**hit, "cve": cve.upper()} if hit is not None else {"cve": cve.upper()}

    return assess
