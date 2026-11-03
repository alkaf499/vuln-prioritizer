"""Offline enrichment source (``--offline``): deterministic, no network, ever.

``enrich_findings`` takes an ``assess(cve) -> dict`` callable shaped like upstream
threat-intel-toolkit's ``exploit_check.assess``. Offline, that callable is a lookup into a
local JSON *cache* (CVE -> upstream-shaped dict). A CVE with no cache entry yields the
minimal ``{"cve": ...}`` record, which :func:`~.toolkit.to_intel` maps to "unknown" on every
feed — never to "not on KEV". The scorer therefore only sees what navi.db itself carried
plus whatever the cache asserts.

Cache file format (JSON object)::

    {"CVE-2099-0002": {"cve": "CVE-2099-0002", "kev_available": true, "kev": {"dateAdded": "2026-09-01"},
                       "msf_available": true, "edb_available": true, "nuclei_available": true,
                       "epss": 0.95, "tier": "RED - weaponized", "msf": [], "edb": [], "nomi": []}}
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Mapping


class IntelCacheError(ValueError):
    """The offline intel cache is not a JSON object of CVE -> object."""


def load_intel_cache(path: str | Path) -> dict[str, dict[str, Any]]:
    """Read an offline cache file (keys upper-cased). Read-only."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise IntelCacheError(f"{path}: invalid JSON ({e})") from e
    if not isinstance(data, dict) or not all(isinstance(v, dict) for v in data.values()):
        raise IntelCacheError(f"{path}: expected a JSON object mapping CVE -> object")
    return {str(k).upper(): v for k, v in data.items()}


def offline_assess(
    cache: Mapping[str, Mapping[str, Any]] | None = None,
) -> Callable[[str], dict[str, Any]]:
    """An ``assess`` replacement that answers only from ``cache`` (no I/O)."""
    table = {k.upper(): v for k, v in (cache or {}).items()}

    def assess(cve: str) -> dict[str, Any]:
        hit = table.get(cve.upper())
        return {**hit, "cve": cve.upper()} if hit is not None else {"cve": cve.upper()}

    return assess
