"""Normalized finding schema — the contract between adapters and the scorer.

Design rules (later sessions depend on these):

* **Raw inputs, not decisions.** Adapters report what the source says. The
  fallback hierarchy (NVD -> CNA -> scan severity), the EPSS->band map, the KEV
  floor and asset classification are decided by the scorer (S1/S2), never here.
* **Missing means ``None``/empty.** An absent value is never coerced to 0.
* **Immutable and hashable.** Collections are tuples, so the same input always
  yields an equal, comparable object (deterministic by construction).
* **Source-agnostic.** ``source`` names the origin ("navi" today). Nothing
  navi-specific (table or column names) leaks into these types.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from datetime import datetime


class Severity(enum.IntEnum):
    """Scan-source severity (Tenable/Defender native), ordered for comparison."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class CvssSource(str, enum.Enum):
    """Provenance of the CVSS v3 base score, when the source reports it."""

    NVD = "nvd"
    CNA = "cna"
    OTHER = "other"  # reported, but neither NVD nor a CNA
    UNKNOWN = "unknown"  # a score exists but the source did not say who produced it


@dataclass(frozen=True, slots=True)
class Tag:
    """An asset tag (key/value). Used to derive environment and criticality."""

    key: str
    value: str


@dataclass(frozen=True, slots=True)
class Asset:
    """Asset context (Layer-2 inputs). Raw attributes only; no class assigned yet."""

    asset_id: str
    """Stable join key. For navi this is ``assets.uuid``."""
    source: str = "navi"
    hostname: str | None = None
    fqdn: str | None = None
    ip_address: str | None = None
    operating_system: str | None = None
    acr: float | None = None
    """Tenable Asset Criticality Rating, 1-10."""
    aes: int | None = None
    """Tenable Asset Exposure Score, 0-1000."""
    exposure_classes: tuple[str, ...] = ()
    """Raw exposure classes as reported (e.g. Tenable One ``exposure_classes``)."""
    tags: tuple[Tag, ...] = ()
    """Raw tags. The prod/non-prod and crown-jewel conventions are mapped in S2 config."""

    def tag_values(self, key: str) -> tuple[str, ...]:
        """Values for ``key`` (case-insensitive key match), in stored order."""
        k = key.casefold()
        return tuple(t.value for t in self.tags if t.key.casefold() == k)

    @property
    def display_name(self) -> str:
        return self.hostname or self.fqdn or self.ip_address or self.asset_id


@dataclass(frozen=True, slots=True)
class CveSignal:
    """Per-CVE intel for multi-CVE findings (e.g. from threat-intel enrichment).

    The scorer takes the worst case across these and the finding-level fields.
    All values optional; ``None`` = this source has no value for this CVE.
    """

    cve: str
    cvss_base_score: float | None = None
    cvss_source: CvssSource = CvssSource.UNKNOWN
    epss_score: float | None = None
    kev: bool = False
    source: str = "unknown"


@dataclass(frozen=True, slots=True)
class Finding:
    """One vulnerability on one asset (the unit of scoring and SLA)."""

    # --- identity -----------------------------------------------------------
    finding_id: str
    asset: Asset
    plugin_id: str
    name: str | None = None
    cves: tuple[str, ...] = ()
    """Upper-case ``CVE-YYYY-NNNN`` ids, de-duplicated, source order. May be empty."""
    port: int | None = None
    protocol: str | None = None
    state: str | None = None
    """Source state, upper-cased (e.g. ACTIVE, NEW, RESURFACED, FIXED)."""
    first_found: datetime | None = None
    last_found: datetime | None = None
    source: str = "navi"

    # --- Layer 1 impact inputs (resolver in S1 picks per the fallback hierarchy)
    cvss3_base_score: float | None = None
    cvss3_source: CvssSource = CvssSource.UNKNOWN
    """Only meaningful when ``cvss3_base_score`` is set."""
    cvss2_base_score: float | None = None
    severity: Severity | None = None
    """Scan-source severity; last-resort impact signal."""

    # --- Layer 1 probability inputs ----------------------------------------
    vpr_score: float | None = None
    """Tenable VPR, 0-10. ``None`` triggers the EPSS/RF fallback."""
    vpr_updated: datetime | None = None
    epss_score: float | None = None
    """EPSS probability, 0-1. With several CVEs, the maximum (worst case)."""
    epss_percentile: float | None = None
    epss_cve: str | None = None
    """The CVE that ``epss_score`` came from."""

    # --- Exploit maturity / in-the-wild evidence ---------------------------
    exploit_available: bool | None = None
    exploit_frameworks: tuple[str, ...] = ()
    """Sorted names, e.g. ``("canvas", "metasploit")``."""
    exploit_maturity: str | None = None
    """Raw source maturity label if provided (e.g. Tenable One)."""
    kev: bool = False
    """On CISA KEV *according to this source*. False = not known from the source;
    the threat-intel enrichment (S3) may still set the floor independently."""
    kev_added: datetime | None = None
    kev_due: datetime | None = None

    # --- optional per-CVE intel (multi-CVE worst case; populated by S3/adapters)
    cve_signals: tuple[CveSignal, ...] = ()

    @property
    def has_cvss(self) -> bool:
        return self.cvss3_base_score is not None or self.cvss2_base_score is not None
