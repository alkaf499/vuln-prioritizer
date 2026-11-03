"""Bridge to threat-intel-toolkit's ``exploit_check.py`` (kevinmhorvath/threat-intel-toolkit, MIT).

We **import the upstream script unmodified** from ``reference/`` (its MIT license
header and attribution stay in that file) rather than copying it. This module adds:

* ``load_exploit_check`` — locate and import the upstream script by path.
* ``make_resilient_fetch`` / ``install_resilient_fetch`` — retry with exponential
  backoff and an optional ``GITHUB_TOKEN`` (from the environment only; never
  stored, logged or committed). Upstream's per-CVE helpers (``epss``, ``nomisec``,
  ``trickest``) swallow their own errors, so retrying has to happen *inside*
  ``_fetch_bytes``; we replace that one module attribute.
* ``CveIntel`` / ``to_intel`` — normalize upstream's ``assess()`` dict into an
  immutable, hashable per-CVE record. Feed outages are carried as "unknown",
  never as "not listed".

No network happens at import time.
"""

from __future__ import annotations

import enum
import importlib.util
import os
import re
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import urlparse

EXPLOIT_CHECK_ENV = "EXPLOIT_CHECK_PATH"
_DEFAULT_RELPATH = (
    "reference/threat-intel-toolkit/skills/exploit-availability-check/scripts/exploit_check.py"
)
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")

GITHUB_HOSTS = frozenset({"raw.githubusercontent.com", "api.github.com"})
RETRY_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504})


# --------------------------------------------------------------------------
# loading the upstream script
# --------------------------------------------------------------------------
_module: Any = None


def default_exploit_check_path() -> Path:
    env = os.environ.get(EXPLOIT_CHECK_ENV)
    if env:
        return Path(env)
    return Path(__file__).resolve().parents[3] / _DEFAULT_RELPATH


def load_exploit_check(path: str | os.PathLike[str] | None = None) -> Any:
    """Import (once) and return the upstream ``exploit_check`` module."""
    global _module
    if _module is not None and path is None:
        return _module
    p = Path(path) if path else default_exploit_check_path()
    if not p.is_file():
        raise FileNotFoundError(
            f"exploit_check.py not found at {p} (set {EXPLOIT_CHECK_ENV} to override)"
        )
    spec = importlib.util.spec_from_file_location("exploit_check", p)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["exploit_check"] = mod  # same name healthcheck.py imports
    spec.loader.exec_module(mod)
    if path is None:
        _module = mod
    return mod


# --------------------------------------------------------------------------
# resilient fetch
# --------------------------------------------------------------------------
def _retry_after(err: urllib.error.HTTPError, max_delay: float) -> float | None:
    raw = err.headers.get("Retry-After") if err.headers else None
    if raw is None:
        return None
    try:
        return min(max(float(raw), 0.0), max_delay)
    except ValueError:
        return None


def _retryable(err: urllib.error.HTTPError) -> bool:
    if err.code in RETRY_STATUS:
        return True
    # GitHub signals primary rate-limit exhaustion with 403 + remaining=0
    if err.code == 403 and err.headers and err.headers.get("X-RateLimit-Remaining") == "0":
        return True
    return False


def make_resilient_fetch(
    *,
    headers: Mapping[str, str] | None = None,
    token: str | None = None,
    attempts: int = 4,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
    urlopen: Callable[..., Any] | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> Callable[..., bytes]:
    """Return a drop-in for upstream ``_fetch_bytes(url, timeout=60)``.

    Retries network errors, timeouts, 408/425/429/5xx and GitHub rate-limit 403s
    with exponential backoff (``base_delay * 2**n``, capped; ``Retry-After`` is
    honoured). 404 and other client errors are *not* retried (a missing PoC file
    is a normal answer). ``token`` is attached only to GitHub hosts.
    """
    base_headers = dict(headers or {})

    def fetch(url: str, timeout: float = 60) -> bytes:
        opener = urlopen or urllib.request.urlopen  # resolved late so tests can patch
        hdrs = dict(base_headers)
        if token and urlparse(url).hostname in GITHUB_HOSTS:
            hdrs["Authorization"] = f"token {token}"
        last: BaseException | None = None
        for n in range(attempts):
            delay: float | None = None
            try:
                req = urllib.request.Request(url, headers=hdrs)
                with opener(req, timeout=timeout) as r:
                    return r.read()
            except urllib.error.HTTPError as e:
                if not _retryable(e):
                    raise
                last, delay = e, _retry_after(e, max_delay)
            except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as e:
                last = e
            if n < attempts - 1:
                sleep(delay if delay is not None else min(max_delay, base_delay * 2**n))
        assert last is not None
        raise last

    return fetch


def install_resilient_fetch(module: Any, **kwargs: Any) -> str | None:
    """Replace ``module._fetch_bytes`` with a retrying one; returns the token source note.

    ``GITHUB_TOKEN`` is read from the environment unless ``token=`` is given.
    """
    token = kwargs.pop("token", None) or os.environ.get("GITHUB_TOKEN") or None
    kwargs.setdefault("headers", getattr(module, "UA", None))
    module._fetch_bytes = make_resilient_fetch(token=token, **kwargs)
    return "GITHUB_TOKEN" if token else None


def make_default_assess() -> Callable[[str], dict[str, Any]]:
    """Upstream ``assess`` with retry/backoff (+ optional GITHUB_TOKEN) installed."""
    mod = load_exploit_check()
    install_resilient_fetch(mod)
    return mod.assess


# --------------------------------------------------------------------------
# normalized per-CVE intel
# --------------------------------------------------------------------------
class Maturity(str, enum.Enum):
    """Normalized exploit maturity (from upstream's RED/ORANGE/YELLOW/WHITE tiers)."""

    WEAPONIZED = "weaponized"
    PUBLIC_EXPLOIT = "public_exploit"
    POC = "poc"
    NONE = "none"
    UNKNOWN = "unknown"  # cannot say: feeds were unreachable


MATURITY_RANK = {Maturity.NONE: 0, Maturity.POC: 1, Maturity.PUBLIC_EXPLOIT: 2, Maturity.WEAPONIZED: 3}
_TIER_MATURITY = {
    "RED": Maturity.WEAPONIZED,
    "ORANGE": Maturity.PUBLIC_EXPLOIT,
    "YELLOW": Maturity.POC,
    "WHITE": Maturity.NONE,
}


@dataclass(frozen=True, slots=True)
class CveIntel:
    cve: str
    kev: bool = False
    kev_known: bool = False
    """True if the KEV feed was consulted (so ``kev=False`` means "not listed")."""
    kev_added: datetime | None = None
    ransomware: bool = False
    epss: float | None = None
    epss_percentile: float | None = None
    maturity: Maturity = Maturity.UNKNOWN
    msf_modules: tuple[str, ...] = ()
    msf_has_exploit: bool = False
    edb_count: int = 0
    nuclei: bool = False
    poc_repos: int = 0
    top_stars: int = 0
    feeds_missing: tuple[str, ...] = ()
    """Names of feeds that were unreachable / returned nothing usable."""
    error: str | None = None
    """Set when the whole lookup failed (exception)."""

    @property
    def degraded(self) -> bool:
        return bool(self.feeds_missing) or self.error is not None


def unknown_intel(cve: str, error: str | None = None) -> CveIntel:
    return CveIntel(cve=cve, feeds_missing=("all",) if error else (), error=error)


def _parse_date(s: Any) -> datetime | None:
    try:
        return datetime.strptime(str(s), "%Y-%m-%d")
    except (TypeError, ValueError):
        return None


def to_intel(raw: Mapping[str, Any]) -> CveIntel:
    """Map one upstream ``assess()`` result to a :class:`CveIntel`."""
    kev = raw.get("kev") or None
    kev_known = bool(raw.get("kev_available")) or bool(kev)
    missing = [
        name
        for name, key in (
            ("CISA KEV", "kev_available"),
            ("Metasploit", "msf_available"),
            ("Exploit-DB", "edb_available"),
            ("Nuclei", "nuclei_available"),
        )
        if not raw.get(key, False) and not (key == "kev_available" and kev)
    ]
    epss = raw.get("epss")
    if epss is None:
        missing.append("EPSS")

    tier_key = str(raw.get("tier", "")).split(" ")[0]
    maturity = _TIER_MATURITY.get(tier_key, Maturity.UNKNOWN)
    # WHITE ("none found") is only trustworthy if the exploit feeds were reachable.
    if maturity is Maturity.NONE and {"Metasploit", "Exploit-DB", "Nuclei"} & set(missing):
        maturity = Maturity.UNKNOWN

    msf = raw.get("msf") or []
    return CveIntel(
        cve=str(raw["cve"]).upper(),
        kev=bool(kev),
        kev_known=kev_known,
        kev_added=_parse_date(kev.get("dateAdded")) if kev else None,
        ransomware=bool(kev and kev.get("knownRansomwareCampaignUse") == "Known"),
        epss=float(epss) if epss is not None else None,
        epss_percentile=raw.get("epss_pctl"),
        maturity=maturity,
        msf_modules=tuple(m.get("fullname") for m in msf if m.get("fullname")),
        msf_has_exploit=bool(raw.get("msf_exploit")),
        edb_count=len(raw.get("edb") or []),
        nuclei=bool(raw.get("nuclei")),
        poc_repos=len(raw.get("nomi") or []),
        top_stars=int(raw.get("top_star") or 0),
        feeds_missing=tuple(missing),
    )
