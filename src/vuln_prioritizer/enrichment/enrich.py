"""S3 — evidence/enrichment layer (CLAUDE.md §5 steps 2-3).

``enrich_findings`` takes normalized findings and:

1. **Cheap local gate** — only findings with severity >= High, or CVSS base >= 7,
   or KEV, or EPSS >= threshold are deep-enriched. Everything else passes through untouched.
2. **Memoize per distinct CVE** — the CVEs of all gated survivors are collected,
   de-duplicated, sorted (deterministic), and each is looked up exactly ONCE; the
   result is fanned back to every finding that shares it. A CVE on 500 assets is
   one fetch.
3. **Merge, never lower** — KEV is OR-ed, EPSS is max-ed (worst case), exploit
   maturity comes from threat intel when known. Source data is never downgraded.
   ``cve_signals`` is populated per CVE (merged with any existing signals).
4. **Evidence + divergence** — a human-readable evidence string per finding and a
   flag when VPR and KEV/maturity strongly disagree.

A dead feed yields ``unknown`` (see :mod:`.toolkit`), never an exception and never
a false "not listed". The scorer is untouched: it simply sees richer inputs
(``kev``, ``epss_score``, ``cve_signals``) — this is how the KEV floor and the
VPR-absent EPSS fallback get their data.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, replace
from typing import Any, Callable, Iterable, Mapping

from ..schema import CveSignal, Finding, Severity
from .toolkit import (
    CVE_RE,
    MATURITY_RANK,
    CveIntel,
    Maturity,
    make_default_assess,
    to_intel,
    unknown_intel,
)

DEFAULT_EPSS_GATE = 0.10
"""EPSS at/above this passes the gate (the Medium band floor from §3)."""

CVSS_GATE = 7.0
"""CVSS base at/above this passes the gate (the High band floor from §3)."""

SIGNAL_SOURCE ="exploit-availability-check"

VPR_LOW_BELOW = 4.0
"""VPR under this is the Low band."""
VPR_HIGH_AT = 9.0
"""VPR at/above this is the Critical band."""
EPSS_LOW_BELOW = 0.10


class Divergence(str, enum.Enum):
    VPR_LOW_BUT_EXPLOITED = "vpr_low_but_exploited"
    """VPR is Low yet the CVE is on KEV or has a weaponized public exploit."""
    VPR_HIGH_NO_EXPLOIT_SIGNAL = "vpr_high_no_exploit_signal"
    """VPR is Critical yet KEV says not listed, no public exploit exists and EPSS is Low
    (all feeds reachable) — worth a human look; not used to lower the tier."""


@dataclass(frozen=True, slots=True)
class EnrichedFinding:
    finding: Finding
    evidence: str
    divergence: tuple[Divergence, ...] = ()
    enriched: bool = False
    """True if threat intel was looked up for this finding."""
    degraded: bool = False
    """True if any consulted feed was unreachable (some facts are 'unknown')."""


@dataclass(frozen=True, slots=True)
class EnrichmentStats:
    findings: int
    gated: int
    distinct_cves: int
    """== number of upstream lookups performed."""
    failures: int
    """Lookups that raised (result recorded as unknown)."""
    skipped_invalid_cves: int


@dataclass(frozen=True, slots=True)
class EnrichmentReport:
    results: tuple[EnrichedFinding, ...]
    stats: EnrichmentStats

    @property
    def findings(self) -> tuple[Finding, ...]:
        return tuple(r.finding for r in self.results)


# --------------------------------------------------------------------------
# gate
# --------------------------------------------------------------------------
def passes_gate(finding: Finding, epss_threshold: float = DEFAULT_EPSS_GATE) -> bool:
    """severity >= High OR CVSS base >= 7 OR KEV OR EPSS >= threshold.

    CVSS (v3, v2, or any CVE signal) is checked so findings from sources without a
    scan severity (non-Tenable adapters) still get enriched. KEV/EPSS are checked at
    finding level and on every CVE signal.
    """
    if finding.severity is not None and finding.severity >= Severity.HIGH:
        return True
    cvss = [finding.cvss3_base_score, finding.cvss2_base_score,
            *(s.cvss_base_score for s in finding.cve_signals)]
    if any(c is not None and c >= CVSS_GATE for c in cvss):
        return True
    if finding.kev or any(s.kev for s in finding.cve_signals):
        return True
    epss = [finding.epss_score, *(s.epss_score for s in finding.cve_signals)]
    return any(e is not None and e >= epss_threshold for e in epss)


# --------------------------------------------------------------------------
# aggregation across a finding's CVEs
# --------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class _Agg:
    kev: bool
    kev_all_known: bool
    maturity: Maturity
    epss: float | None
    epss_cve: str | None
    epss_all_known: bool


def _aggregate(finding: Finding, intels: list[CveIntel]) -> _Agg:
    kev = finding.kev or any(i.kev for i in intels)
    kev_all_known = all(i.kev_known for i in intels)

    known = [i.maturity for i in intels if i.maturity is not Maturity.UNKNOWN]
    if not known:
        maturity = Maturity.UNKNOWN
    else:
        best = max(known, key=MATURITY_RANK.__getitem__)
        # "none" is only a real answer if nothing was unknown
        maturity = (
            Maturity.UNKNOWN
            if best is Maturity.NONE and len(known) < len(intels)
            else best
        )

    cands = [(i.epss, i.cve) for i in intels if i.epss is not None]
    if finding.epss_score is not None:
        cands.append((finding.epss_score, (finding.epss_cve or "").upper()))
    epss, epss_cve = (None, None)
    if cands:
        epss, c = min(cands, key=lambda x: (-x[0], x[1]))
        epss_cve = c or None
    return _Agg(kev, kev_all_known, maturity, epss, epss_cve, all(i.epss is not None for i in intels))


def divergence_flags(finding: Finding, agg: _Agg) -> tuple[Divergence, ...]:
    """VPR vs KEV/maturity disagreement. Needs a VPR; otherwise nothing to compare."""
    vpr = finding.vpr_score
    if vpr is None:
        return ()
    flags = []
    if vpr < VPR_LOW_BELOW and (agg.kev or agg.maturity is Maturity.WEAPONIZED):
        flags.append(Divergence.VPR_LOW_BUT_EXPLOITED)
    if (
        vpr >= VPR_HIGH_AT
        and not agg.kev
        and agg.kev_all_known
        and agg.maturity is Maturity.NONE
        and agg.epss_all_known
        and agg.epss is not None
        and agg.epss < EPSS_LOW_BELOW
    ):
        flags.append(Divergence.VPR_HIGH_NO_EXPLOIT_SIGNAL)
    return tuple(flags)


# --------------------------------------------------------------------------
# evidence strings
# --------------------------------------------------------------------------
def _pct(x: float) -> str:
    return f"{x * 100:.4g}%"


def describe(i: CveIntel) -> str:
    """One-CVE evidence clause, e.g. 'on CISA KEV since 2021-12-10; Metasploit exploit module; EPSS 97%'."""
    if i.error:
        return f"threat-intel lookup failed ({i.error}); status unknown"
    parts: list[str] = []
    if i.kev:
        since = f" since {i.kev_added:%Y-%m-%d}" if i.kev_added else ""
        rw = " (known ransomware use)" if i.ransomware else ""
        parts.append(f"on CISA KEV{since}{rw}")
    elif not i.kev_known:
        parts.append("CISA KEV status unknown (feed unreachable)")
    if i.msf_modules:
        kind = "exploit module" if i.msf_has_exploit else "module (aux/scanner)"
        parts.append(f"Metasploit {kind}")
    if i.edb_count:
        parts.append(f"Exploit-DB {i.edb_count} entr{'y' if i.edb_count == 1 else 'ies'}")
    if i.nuclei:
        parts.append("Nuclei template")
    if i.poc_repos:
        stars = f", top {i.top_stars}★" if i.top_stars else ""
        parts.append(f"{i.poc_repos} GitHub PoC repo{'s' if i.poc_repos != 1 else ''}{stars}")
    if i.maturity is Maturity.NONE:
        parts.append("no public exploit found")
    elif i.maturity is Maturity.UNKNOWN:
        feeds = [f for f in i.feeds_missing if f in ("Metasploit", "Exploit-DB", "Nuclei")]
        why = f" ({', '.join(feeds)} unreachable)" if feeds else ""
        parts.append(f"exploit maturity unknown{why}")
    if i.epss is not None:
        parts.append(f"EPSS {_pct(i.epss)}")
    return "; ".join(parts)


def build_evidence(
    finding: Finding, intels: list[CveIntel], divergence: tuple[Divergence, ...]
) -> str:
    if len(intels) == 1:
        text = describe(intels[0])
    else:
        text = " | ".join(f"{i.cve}: {describe(i)}" for i in intels)
    for d in divergence:
        if d is Divergence.VPR_LOW_BUT_EXPLOITED:
            text += f" — DIVERGENCE: VPR {finding.vpr_score:g} is Low but exploitation evidence is strong"
        else:
            text += f" — DIVERGENCE: VPR {finding.vpr_score:g} is Critical but no KEV/exploit/EPSS signal"
    return text


# --------------------------------------------------------------------------
# merge into the Finding
# --------------------------------------------------------------------------
def _merge_signals(
    existing: tuple[CveSignal, ...], intels: list[CveIntel]
) -> tuple[CveSignal, ...]:
    by_cve = {s.cve.upper(): s for s in existing}
    for i in intels:
        if i.epss is None and not i.kev:
            continue  # nothing to add; keep signals meaningful
        old = by_cve.get(i.cve)
        if old is None:
            by_cve[i.cve] = CveSignal(
                cve=i.cve, epss_score=i.epss, kev=i.kev, source=SIGNAL_SOURCE
            )
        else:
            epss = max((e for e in (old.epss_score, i.epss) if e is not None), default=None)
            by_cve[i.cve] = replace(old, epss_score=epss, kev=old.kev or i.kev)
    return tuple(by_cve[k] for k in sorted(by_cve))


def _merge(finding: Finding, intels: list[CveIntel], agg: _Agg) -> Finding:
    kev_dates = [i.kev_added for i in intels if i.kev and i.kev_added]
    updates: dict[str, Any] = {
        "kev": agg.kev,
        "cve_signals": _merge_signals(finding.cve_signals, intels),
    }
    if finding.kev_added is None and kev_dates:
        updates["kev_added"] = min(kev_dates)
    if agg.epss is not None and (finding.epss_score is None or agg.epss > finding.epss_score):
        updates["epss_score"] = agg.epss
        updates["epss_cve"] = agg.epss_cve
        pct = next((i.epss_percentile for i in intels if i.cve == agg.epss_cve), None)
        if pct is not None:
            updates["epss_percentile"] = pct
    if agg.maturity is not Maturity.UNKNOWN:
        updates["exploit_maturity"] = agg.maturity.value
    return replace(finding, **updates)


# --------------------------------------------------------------------------
# main entry point
# --------------------------------------------------------------------------
def enrich_findings(
    findings: Iterable[Finding],
    assess: Callable[[str], Mapping[str, Any]] | None = None,
    *,
    epss_threshold: float = DEFAULT_EPSS_GATE,
) -> EnrichmentReport:
    """Gate -> memoized per-CVE lookup -> fan-out. Input order is preserved.

    ``assess`` is upstream ``exploit_check.assess``-shaped (CVE -> dict); default
    is the real toolkit with retry/backoff (+ optional ``GITHUB_TOKEN``).
    """
    flist = list(findings)
    gated_idx = [n for n, f in enumerate(flist) if passes_gate(f, epss_threshold)]

    skipped_invalid = 0
    wanted: set[str] = set()
    for n in gated_idx:
        for c in flist[n].cves:
            if CVE_RE.match(c.upper()):
                wanted.add(c.upper())
            else:
                skipped_invalid += 1

    intel: dict[str, CveIntel] = {}
    failures = 0
    if wanted:
        fetch = assess or make_default_assess()
        for cve in sorted(wanted):  # ONE lookup per distinct CVE
            try:
                intel[cve] = to_intel(fetch(cve))
            except Exception as e:  # noqa: BLE001 - a dead feed must never crash a run
                failures += 1
                intel[cve] = unknown_intel(cve, error=f"{type(e).__name__}: {e}"[:120])

    gated = set(gated_idx)
    results: list[EnrichedFinding] = []
    for n, f in enumerate(flist):
        if n not in gated:
            results.append(EnrichedFinding(f, "below enrichment gate; not deep-checked"))
            continue
        intels = [intel[c.upper()] for c in f.cves if c.upper() in intel]
        if not intels:
            results.append(EnrichedFinding(f, "no valid CVE id; nothing to look up"))
            continue
        agg = _aggregate(f, intels)
        div = divergence_flags(f, agg)
        results.append(
            EnrichedFinding(
                finding=_merge(f, intels, agg),
                evidence=build_evidence(f, intels, div),
                divergence=div,
                enriched=True,
                degraded=any(i.degraded for i in intels),
            )
        )

    return EnrichmentReport(
        results=tuple(results),
        stats=EnrichmentStats(
            findings=len(flist),
            gated=len(gated_idx),
            distinct_cves=len(wanted),
            failures=failures,
            skipped_invalid_cves=skipped_invalid,
        ),
    )
