"""Bands, the tier ladder, SLAs and the Layer-1 matrix (CLAUDE.md §3, LOCKED v0.4).

Pure data + pure functions. No I/O.
"""

from __future__ import annotations

import enum
import math
from datetime import timedelta

from ..schema import Severity


class Band(enum.IntEnum):
    """Impact / probability band. Higher value = more urgent."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class Tier(enum.IntEnum):
    """Remediation tier. LOWER value = MORE urgent (T0 Emergency ... T4 next cycle).

    Layer 1 only produces T1-T4; T0 exists for the Layer-2 uplift (S2).
    """

    T0 = 0
    T1 = 1
    T2 = 2
    T3 = 3
    T4 = 4

    @property
    def sla(self) -> timedelta | None:
        """Time to remediate; ``None`` = next patch cycle (no fixed window)."""
        return _SLA[self]

    @property
    def sla_label(self) -> str:
        return _SLA_LABEL[self]

    @property
    def label(self) -> str:
        return f"Tier {self.value}"


# T0 figure is flagged "confirm" in the spec (§3); kept in one place.
_SLA: dict[Tier, timedelta | None] = {
    Tier.T0: timedelta(hours=12),
    Tier.T1: timedelta(hours=24),
    Tier.T2: timedelta(days=10),
    Tier.T3: timedelta(days=30),
    Tier.T4: None,
}
_SLA_LABEL: dict[Tier, str] = {
    Tier.T0: "Emergency ~12h / out-of-band",
    Tier.T1: "24h",
    Tier.T2: "10d",
    Tier.T3: "30d",
    Tier.T4: "next patch cycle",
}

# rows = impact band, cols = probability band
TIER_MATRIX: dict[Band, dict[Band, Tier]] = {
    Band.CRITICAL: {Band.CRITICAL: Tier.T1, Band.HIGH: Tier.T2, Band.MEDIUM: Tier.T3, Band.LOW: Tier.T4},
    Band.HIGH:     {Band.CRITICAL: Tier.T2, Band.HIGH: Tier.T2, Band.MEDIUM: Tier.T3, Band.LOW: Tier.T4},
    Band.MEDIUM:   {Band.CRITICAL: Tier.T2, Band.HIGH: Tier.T3, Band.MEDIUM: Tier.T4, Band.LOW: Tier.T4},
    Band.LOW:      {Band.CRITICAL: Tier.T4, Band.HIGH: Tier.T4, Band.MEDIUM: Tier.T4, Band.LOW: Tier.T4},
}  # fmt: skip


def matrix_tier(impact: Band, probability: Band) -> Tier:
    return TIER_MATRIX[impact][probability]


def _check(value: float, lo: float, hi: float, what: str) -> float:
    v = float(value)
    if math.isnan(v) or not lo <= v <= hi:
        raise ValueError(f"{what} out of range [{lo}, {hi}]: {value!r}")
    return v


def score_band(score: float, *, what: str = "score") -> Band:
    """Bin a 0-10 CVSS or VPR score: >=9 Critical, >=7 High, >=4 Medium, else Low."""
    v = _check(score, 0.0, 10.0, what)
    if v >= 9.0:
        return Band.CRITICAL
    if v >= 7.0:
        return Band.HIGH
    if v >= 4.0:
        return Band.MEDIUM
    return Band.LOW


def epss_band(epss: float) -> Band:
    """EPSS (0-1) -> band: >=0.90 Critical, >=0.50 High, >=0.10 Medium, else Low."""
    v = _check(epss, 0.0, 1.0, "EPSS")
    if v >= 0.90:
        return Band.CRITICAL
    if v >= 0.50:
        return Band.HIGH
    if v >= 0.10:
        return Band.MEDIUM
    return Band.LOW


SEVERITY_BAND: dict[Severity, Band] = {
    Severity.CRITICAL: Band.CRITICAL,
    Severity.HIGH: Band.HIGH,
    Severity.MEDIUM: Band.MEDIUM,
    Severity.LOW: Band.LOW,
    Severity.INFO: Band.LOW,
}
