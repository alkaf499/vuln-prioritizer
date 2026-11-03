"""Layer 1 — intrinsic vulnerability score (CLAUDE.md §3, LOCKED v0.4).

``score_layer1(finding) -> Layer1Result`` is a pure function: no I/O, no clock,
no randomness, no dependence on input ordering. Same Finding -> equal result.

Resolution rules
----------------
Impact (CVSS fallback hierarchy, per CVE, then worst case across CVEs):
  1. CVSS with source NVD
  2. CVSS with source CNA
  3. CVSS v3 whose producer the source didn't attribute (OTHER/UNKNOWN), then
     CVSS v2. *Not named in §3*: a real base score beats a scan-severity guess,
     so it sits above (4); the result records it as "unattributed".
  4. Scan severity, mapped straight to a band (no numeric CVSS is invented).
  Each "group" (the finding-level scores, and each CVE in ``cve_signals``)
  resolves to its highest-precedence score; the worst-case band across groups
  wins. Severity is used only when no group has any CVSS.

Probability:
  1. VPR, if present.
  2. Else EPSS, worst case across the finding and every ``cve_signals`` entry,
     binned >=0.90 Crit / >=0.50 High / >=0.10 Med / else Low.
     (Recorded Future is not modelled: the schema has no RF field and §3 sets
     no RF->band map.)
  3. KEV floor, applied LAST and ALWAYS: if ``kev`` (finding-level OR any CVE
     signal) and the band is below High (or absent), it becomes High.
  4. Still no band -> scored on impact alone + REEVALUATE flag. "Impact alone"
     uses the impact band as the probability column (the matrix diagonal),
     see ``IMPACT_ONLY_POLICY``. Consequence: Critical impact -> T1, High -> T2,
     Low -> T4, and **Medium impact -> T4** (the worst-case-column reading would
     give T2; Medium is the only band where the two policies differ). The
     less-alarmist diagonal is the default because the finding is flagged for
     re-evaluation anyway. KEV alone counts as a signal (observed in the wild),
     so a KEV finding never reaches this step.

  Extension point — Recorded Future: §3 allows RF alongside EPSS in step 2
  ("most conservative = highest-urgency band"). Not modelled in v1 (no RF field,
  no RF->band map). To add it: give ``Finding``/``CveSignal`` an RF score, add
  an ``rf_band`` binning in ``tiers.py``, and include its band among the step-2
  candidates in ``resolve_probability``.

``finding.kev`` is the caller's resolved view (S3/S4 OR together navi and
threat intel before calling); the scorer does not care where it came from.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Any

from ..schema import CvssSource, Finding, Severity
from .tiers import SEVERITY_BAND, Band, Tier, epss_band, matrix_tier, score_band

class ImpactOnlyPolicy(str, enum.Enum):
    """Which probability column to use when there is no probability signal."""

    DIAGONAL = "diagonal"
    """Use the impact band itself (Crit->T1, High->T2, Med->T4, Low->T4)."""
    WORST_CASE = "worst_case"
    """Assume Critical probability (Crit->T1, High->T2, Med->T2, Low->T4)."""


IMPACT_ONLY_POLICY = ImpactOnlyPolicy.DIAGONAL
"""Default impact-only policy (approved). Only Medium impact is sensitive to it:
DIAGONAL -> T4, WORST_CASE -> T2. Override per call via ``score_layer1(...,
impact_only_policy=...)``."""


class ImpactSource(str, enum.Enum):
    CVSS_NVD = "cvss_nvd"
    CVSS_CNA = "cvss_cna"
    CVSS_UNATTRIBUTED = "cvss_unattributed"
    CVSS2_UNATTRIBUTED = "cvss2_unattributed"
    SCAN_SEVERITY = "scan_severity"
    NONE = "none"


class ProbabilitySource(str, enum.Enum):
    VPR = "vpr"
    EPSS = "epss"
    NONE = "none"


class Flag(str, enum.Enum):
    REEVALUATE_PROBABILITY = "reevaluate_probability"
    """No VPR/EPSS/KEV: scored on impact alone; re-score when probability publishes."""
    IMPACT_MISSING = "impact_missing"
    """No CVSS and no scan severity: impact defaulted to Low. Needs a human look."""


_CVSS_RANK: dict[CvssSource, tuple[int, ImpactSource]] = {
    CvssSource.NVD: (0, ImpactSource.CVSS_NVD),
    CvssSource.CNA: (1, ImpactSource.CVSS_CNA),
    CvssSource.OTHER: (2, ImpactSource.CVSS_UNATTRIBUTED),
    CvssSource.UNKNOWN: (2, ImpactSource.CVSS_UNATTRIBUTED),
}
_CVSS2_RANK = (3, ImpactSource.CVSS2_UNATTRIBUTED)


@dataclass(frozen=True, slots=True)
class ImpactResolution:
    band: Band
    source: ImpactSource
    score: float | None = None
    """CVSS value used (None when banded from severity or missing)."""
    severity: Severity | None = None
    """Scan severity used (only when source is SCAN_SEVERITY)."""
    cve: str | None = None
    """CVE the winning score belongs to (None = finding-level score)."""


@dataclass(frozen=True, slots=True)
class ProbabilityResolution:
    band: Band
    """Band used as the matrix column (after KEV floor / impact-only policy)."""
    source: ProbabilitySource
    """Signal that produced ``base_band``; NONE if there was none."""
    base_band: Band | None
    """Band from VPR/EPSS before the KEV floor; None if no signal."""
    value: float | None = None
    """VPR (0-10) or EPSS (0-1) value used."""
    cve: str | None = None
    """CVE the EPSS value belongs to, if known."""
    kev: bool = False
    kev_floor_applied: bool = False
    impact_only: bool = False


@dataclass(frozen=True, slots=True)
class Layer1Result:
    finding_id: str
    impact: ImpactResolution
    probability: ProbabilityResolution
    tier: Tier
    flags: tuple[Flag, ...] = ()

    @property
    def matrix_cell(self) -> tuple[Band, Band]:
        """(impact band, probability band) — the exact matrix lookup used."""
        return (self.impact.band, self.probability.band)

    def explain(self) -> str:
        """One deterministic, human-readable evidence line."""
        return (
            f"{self.tier.label} · {self.tier.sla_label} — "
            f"impact {self.impact.band.name.title()} ({_impact_text(self.impact)}) × "
            f"probability {self.probability.band.name.title()} ({_prob_text(self.probability)})"
        )

    def as_record(self) -> dict[str, Any]:
        """Flat, JSON/CSV-friendly audit record of every input used."""
        i, p = self.impact, self.probability
        return {
            "finding_id": self.finding_id,
            "tier": self.tier.name,
            "sla": self.tier.sla_label,
            "impact_band": i.band.name,
            "impact_source": i.source.value,
            "impact_score": i.score,
            "impact_severity": i.severity.name if i.severity is not None else None,
            "impact_cve": i.cve,
            "probability_band": p.band.name,
            "probability_base_band": p.base_band.name if p.base_band is not None else None,
            "probability_source": p.source.value,
            "probability_value": p.value,
            "probability_cve": p.cve,
            "kev": p.kev,
            "kev_floor_applied": p.kev_floor_applied,
            "impact_only": p.impact_only,
            "flags": ";".join(f.value for f in self.flags),
            "explanation": self.explain(),
        }


# --------------------------------------------------------------------------
# resolvers
# --------------------------------------------------------------------------
def resolve_impact(finding: Finding) -> ImpactResolution:
    # group key: "" = finding-level scores; otherwise the CVE id
    groups: dict[str, list[tuple[int, float, Band, ImpactSource]]] = {}

    if finding.cvss3_base_score is not None:
        rank, src = _CVSS_RANK[finding.cvss3_source]
        s = finding.cvss3_base_score
        groups.setdefault("", []).append((rank, s, score_band(s, what="CVSS"), src))
    if finding.cvss2_base_score is not None:
        rank, src = _CVSS2_RANK
        s = finding.cvss2_base_score
        groups.setdefault("", []).append((rank, s, score_band(s, what="CVSS"), src))
    for sig in finding.cve_signals:
        if sig.cvss_base_score is not None:
            rank, src = _CVSS_RANK[sig.cvss_source]
            s = sig.cvss_base_score
            groups.setdefault(sig.cve.upper(), []).append(
                (rank, s, score_band(s, what="CVSS"), src)
            )

    if groups:
        # per group: best precedence, then highest score
        best = []
        for key, cands in groups.items():
            rank, s, band, src = min(cands, key=lambda c: (c[0], -c[1]))
            best.append((band, s, rank, key, src))
        # across groups: worst-case band, then highest score, better precedence, key
        band, s, _rank, key, src = min(best, key=lambda b: (-b[0], -b[1], b[2], b[3]))
        return ImpactResolution(band=band, source=src, score=s, cve=key or None)

    if finding.severity is not None:
        return ImpactResolution(
            band=SEVERITY_BAND[finding.severity],
            source=ImpactSource.SCAN_SEVERITY,
            severity=finding.severity,
        )
    return ImpactResolution(band=Band.LOW, source=ImpactSource.NONE)


def resolve_probability(
    finding: Finding,
    impact_band: Band,
    *,
    impact_only_policy: ImpactOnlyPolicy = IMPACT_ONLY_POLICY,
) -> ProbabilityResolution:
    kev = finding.kev or any(s.kev for s in finding.cve_signals)

    source = ProbabilitySource.NONE
    base: Band | None = None
    value: float | None = None
    cve: str | None = None

    if finding.vpr_score is not None:
        source, value = ProbabilitySource.VPR, finding.vpr_score
        base = score_band(value, what="VPR")
    else:
        cands: list[tuple[float, str]] = []
        if finding.epss_score is not None:
            cands.append((finding.epss_score, (finding.epss_cve or "").upper()))
        for sig in finding.cve_signals:
            if sig.epss_score is not None:
                cands.append((sig.epss_score, sig.cve.upper()))
        for v, _ in cands:
            epss_band(v)  # validate every candidate, not just the winner
        if cands:
            value, c = min(cands, key=lambda x: (-x[0], x[1]))
            source, cve = ProbabilitySource.EPSS, c or None
            base = epss_band(value)

    band = base
    floor = False
    if kev and (band is None or band < Band.HIGH):
        band, floor = Band.HIGH, True

    impact_only = band is None
    if band is None:
        if impact_only_policy is ImpactOnlyPolicy.DIAGONAL:
            band = impact_band
        elif impact_only_policy is ImpactOnlyPolicy.WORST_CASE:
            band = Band.CRITICAL
        else:
            raise ValueError(f"unknown impact-only policy: {impact_only_policy!r}")

    return ProbabilityResolution(
        band=band,
        source=source,
        base_band=base,
        value=value,
        cve=cve,
        kev=kev,
        kev_floor_applied=floor,
        impact_only=impact_only,
    )


def score_layer1(
    finding: Finding,
    *,
    impact_only_policy: ImpactOnlyPolicy = IMPACT_ONLY_POLICY,
) -> Layer1Result:
    """Layer-1 tier for one finding. Raises ``ValueError`` on out-of-range scores."""
    impact = resolve_impact(finding)
    prob = resolve_probability(finding, impact.band, impact_only_policy=impact_only_policy)
    flags = []
    if prob.impact_only:
        flags.append(Flag.REEVALUATE_PROBABILITY)
    if impact.source is ImpactSource.NONE:
        flags.append(Flag.IMPACT_MISSING)
    return Layer1Result(
        finding_id=finding.finding_id,
        impact=impact,
        probability=prob,
        tier=matrix_tier(impact.band, prob.band),
        flags=tuple(sorted(flags, key=lambda f: f.value)),
    )


# --------------------------------------------------------------------------
# explanation text
# --------------------------------------------------------------------------
_IMPACT_LABEL = {
    ImpactSource.CVSS_NVD: "NVD",
    ImpactSource.CVSS_CNA: "CNA",
    ImpactSource.CVSS_UNATTRIBUTED: "source unattributed",
    ImpactSource.CVSS2_UNATTRIBUTED: "CVSSv2, source unattributed",
}


def _impact_text(i: ImpactResolution) -> str:
    if i.source is ImpactSource.SCAN_SEVERITY:
        return f"scan severity {i.severity.name.lower()}"  # type: ignore[union-attr]
    if i.source is ImpactSource.NONE:
        return "no impact data"
    cve = f", {i.cve}" if i.cve else ""
    return f"CVSS {i.score:g}, {_IMPACT_LABEL[i.source]}{cve}"


def _prob_text(p: ProbabilityResolution) -> str:
    if p.source is ProbabilitySource.VPR:
        base = f"VPR {p.value:g}"
    elif p.source is ProbabilitySource.EPSS:
        cve = f" {p.cve}" if p.cve else ""
        base = f"EPSS {p.value * 100:.4g}%{cve}"  # type: ignore[operator]
    else:
        base = "no VPR/EPSS"
    if p.kev_floor_applied:
        return f"{base}; raised to High: on CISA KEV"
    if p.impact_only:
        return f"{base}; scored on impact alone, re-evaluate when probability publishes"
    if p.kev:
        return f"{base}; on CISA KEV"
    return base
