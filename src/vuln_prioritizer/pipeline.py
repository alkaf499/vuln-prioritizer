"""S4 orchestration — CLAUDE.md §5, asset-first by default.

This module only *composes* existing stages; it contains no scoring, gating or enrichment
logic of its own:

    adapter (navi.db, read-only) -> enrich (S3: gate + memoized lookups)
        -> score (S1 ∘ S2: Layer 1 matrix, Layer 2 asset conditioning, with the CMDB overlay)
        -> rank (the scorer's stable order, see ``scoring.layer2._rank_key``)

The overlay is applied inside the scorer's context resolver; the order above is
data-dependency order (enrichment must precede scoring so the KEV floor and EPSS fallback
see the merged inputs).

Informational filter
--------------------
Info-severity findings are split off right after loading (``split_informational``): they are
neither enriched, scored nor ranked, and are reported separately (counted, listed in
``informational.csv``), the same pattern as ``in_scope: false`` exclusions.

Threat-intel sources
--------------------
* ``offline=True``: no network. Enrichment answers from ``intel_cache`` (read-only; a frozen
  artifact from an earlier live run, or hand-made) or "unknown".
* live (default): upstream ``assess`` per distinct CVE, written THROUGH ``intel_cache`` if one
  is given. ``enrich="local"`` (default) consults only the four cached feeds (KEV, Metasploit,
  Exploit-DB, Nuclei); ``enrich="full"`` adds per-CVE EPSS and the PoC aggregators. CVEs already in the file are not fetched again (an interrupted run resumes), and
  replaying the file with ``offline=True`` reproduces the worklist byte for byte.
  ``max_lookups`` caps live fetches; lookups happen in RANK order (a preliminary un-enriched
  scoring pass decides which CVEs matter most), so a small cap covers the top of the worklist.

Read-only: the only things read are navi.db, the overlay and the intel cache; the only thing
written is the intel cache itself. Nothing is ever written to the Tenable tenant.

Threat-first toggle (``threat_first=True``): same scoring, but the *worklist view* is
restricted to findings with a threat signal (KEV, weaponized/public exploit maturity, or a
public exploit framework). Non-hits are counted, not hidden. Exclusions are reported in both views.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from .adapters.navi import load_findings
from .context import Overlay, load_overlay
from .enrichment.cache import CachingAssess, IntelCache
from .enrichment.enrich import EnrichedFinding, EnrichmentReport, enrich_findings, passes_gate
from .enrichment.offline import offline_assess
from .enrichment.toolkit import CVE_RE, make_default_assess, make_local_assess
from .schema import Finding, Severity
from .scoring.layer2 import ScoredFinding, ScoringRun, score_findings

THREAT_MATURITIES = frozenset({"weaponized", "public_exploit"})

ENRICH_MODES = ("local", "full")
DEFAULT_ENRICH = "local"


def threat_signals(finding: Finding) -> tuple[str, ...]:
    """Why a finding counts as threat-linked (empty = no threat signal). Pure."""
    out: list[str] = []
    if finding.kev:
        out.append("kev")
    if finding.exploit_maturity and finding.exploit_maturity.casefold() in THREAT_MATURITIES:
        out.append(f"maturity={finding.exploit_maturity.casefold()}")
    if finding.exploit_frameworks:
        out.append("framework=" + "+".join(finding.exploit_frameworks))
    return tuple(out)


@dataclass(frozen=True, slots=True)
class LookupStats:
    """What the live enrichment actually did (absent for offline runs)."""

    total: int
    """Distinct CVEs the gate wants looked up."""
    fetched: int
    cache_hits: int
    failed: int
    deferred: int
    """CVEs left un-looked-up because ``max_lookups`` was reached."""
    uncached_degraded: int
    """Lookups kept in memory only because a core feed was down (retried on the next run)."""


@dataclass(frozen=True, slots=True)
class PipelineResult:
    as_of: datetime
    offline: bool
    threat_first: bool
    source_name: str
    """Base name of the navi.db (never the full path: keeps outputs location-independent)."""
    overlay_name: str | None
    scoring: ScoringRun
    enrichment: EnrichmentReport
    enriched: Mapping[str, EnrichedFinding]
    """finding_id -> enrichment result (carries the evidence string and divergence flags)."""
    worklist: tuple[ScoredFinding, ...]
    """The ranked view to publish (== ``scoring.scored``, or its threat-linked subset)."""
    omitted_non_threat: int = 0
    """Scored findings left out of a threat-first view (0 in asset-first)."""
    intel_cache_name: str | None = None
    intel_as_of: str | None = None
    """The cache's own as-of stamp: the date of the frozen intel (not the run's ``as_of``)."""
    skipped_cves: frozenset[str] = frozenset()
    """CVEs not looked up because the lookup budget ran out."""
    lookups: LookupStats | None = None
    enrich_mode: str | None = None
    """``local`` / ``full`` for live runs; ``None`` offline (nothing was looked up)."""
    informational: tuple[Finding, ...] = ()
    """Info-severity findings (scanner output, not vulnerabilities): never enriched, scored or
    ranked; reported in their own section / ``informational.csv``."""


def split_informational(findings: list[Finding]) -> tuple[list[Finding], list[Finding]]:
    """``(remediation candidates, informational)`` keyed off the scan-source severity field.

    Nessus Info-severity plugins (Service Detection, Traceroute, OS Identification, CPE, MAC
    addresses, ...) describe what the scanner learned; they are not remediation work. A pipeline
    filter, not a scoring rule: Layer 1 / Layer 2 are untouched. Order is preserved."""
    rest: list[Finding] = []
    info: list[Finding] = []
    for f in findings:
        (info if f.severity is Severity.INFO else rest).append(f)
    return rest, info


def normalize_as_of(as_of: datetime | None) -> datetime:
    """Timezone-aware UTC, whole seconds. ``None`` -> now."""
    if as_of is None:
        as_of = datetime.now(timezone.utc)
    if as_of.tzinfo is None:
        as_of = as_of.replace(tzinfo=timezone.utc)
    return as_of.astimezone(timezone.utc).replace(microsecond=0)


def priority_cves(
    findings: list[Finding], overlay: Overlay | None, as_of: datetime
) -> list[str]:
    """Distinct CVEs the gate wants enriched, most important first.

    A preliminary scoring pass on the *un-enriched* findings ranks them (same scorer, same
    order as the final worklist would use with navi's own signals); CVEs are listed in the
    order of the first ranked finding that carries them. CVEs of excluded / unranked findings
    follow, in finding order. Deterministic."""
    gated = {f.finding_id: f for f in findings if passes_gate(f)}
    order: dict[str, None] = {}

    def add(f: Finding) -> None:
        for c in f.cves:
            u = c.upper()
            if CVE_RE.match(u):
                order.setdefault(u)

    for sf in score_findings(findings, overlay=overlay, as_of=as_of).scored:
        f = gated.get(sf.finding_id)
        if f is not None:
            add(f)
    for f in gated.values():
        add(f)
    return list(order)


def run_pipeline(
    db_path: str | Path,
    overlay_path: str | Path | None = None,
    *,
    offline: bool = False,
    threat_first: bool = False,
    as_of: datetime | None = None,
    intel_cache: str | Path | None = None,
    assess: Callable[[str], Mapping[str, Any]] | None = None,
    include_fixed: bool = False,
    max_lookups: int | None = None,
    progress: Callable[[str], None] | None = None,
    progress_every: int = 100,
    save_every: int = 200,
    enrich: str = DEFAULT_ENRICH,
) -> PipelineResult:
    """Run the whole pipeline and return the ranked result (no report files are written).

    ``offline``: never touches the network; ``intel_cache`` is read-only. Live: ``intel_cache``
    is read AND written (created if absent); ``max_lookups`` caps live fetches (cache hits are
    free, so a resumed run with N fetches N more). ``assess`` injects the lookup function
    (tests; or any upstream-shaped source) in place of the offline cache / live toolkit.
    ``as_of`` anchors due dates and the cache stamp — inject it for byte-identical output.

    ``enrich`` (live runs): ``local`` (default) uses only the four cached feeds — CISA KEV,
    Metasploit, Exploit-DB, Nuclei — with no per-CVE network; ``full`` adds the per-CVE EPSS API
    and the nomi-sec / trickest PoC aggregators (about 3 HTTP calls per CVE).
    """
    as_of = normalize_as_of(as_of)
    if enrich not in ENRICH_MODES:
        raise ValueError(f"enrich must be one of {ENRICH_MODES}, got {enrich!r}")
    if max_lookups is not None and (offline or max_lookups < 0):
        raise ValueError("max_lookups applies to live runs and must be >= 0")

    findings, informational = split_informational(load_findings(db_path, include_fixed=include_fixed))
    overlay: Overlay | None = load_overlay(overlay_path) if overlay_path else None

    cache: IntelCache | None = None
    caching: CachingAssess | None = None
    if offline:
        if intel_cache is not None:
            cache = IntelCache.load(intel_cache)
            if cache.path is not None and not cache.path.is_file():
                raise FileNotFoundError(f"intel cache not found: {cache.path}")
        fetch = assess or offline_assess(cache.entries if cache else None)
    else:
        cache = IntelCache.load(intel_cache) if intel_cache is not None else IntelCache()
        # loads the upstream script; no network happens until the first lookup
        inner = assess or (make_local_assess() if enrich == "local" else make_default_assess())
        order = priority_cves(findings, overlay, as_of)
        caching = CachingAssess(
            inner, cache, max_lookups=max_lookups, progress=progress,
            progress_every=progress_every, save_every=save_every, total=len(order), mode=enrich,
        )
        try:
            for cve in order:  # rank order: a small budget covers the top of the worklist
                if caching.exhausted:
                    break
                try:
                    caching(cve)
                except Exception:  # noqa: BLE001 - recorded in caching.failed; re-raised below
                    pass
        finally:  # an interrupted / failed run still leaves a resumable cache
            cache.stamp(as_of)
            cache.save()
        fetch = caching
        prewarm_hits = caching.cache_hits  # CVEs that were already in the file before this run

    report = enrich_findings(findings, fetch)  # CVEs are cache hits by now (or deferred)
    if caching is not None:
        caching.cache_hits = prewarm_hits  # the enrich pass re-reads everything; don't count that
        if progress:
            caching.report()

    run = score_findings(report.findings, overlay=overlay, as_of=as_of)
    enriched = {r.finding.finding_id: r for r in report.results}

    if threat_first:
        view = tuple(sf for sf in run.scored if threat_signals(enriched[sf.finding_id].finding))
    else:
        view = run.scored

    return PipelineResult(
        as_of=as_of,
        offline=offline,
        threat_first=threat_first,
        source_name=Path(db_path).name,
        overlay_name=Path(overlay_path).name if overlay_path else None,
        scoring=run,
        enrichment=report,
        enriched=enriched,
        worklist=view,
        omitted_non_threat=len(run.scored) - len(view),
        intel_cache_name=cache.path.name if cache is not None and cache.path else None,
        intel_as_of=cache.as_of if cache is not None else None,
        skipped_cves=frozenset(caching.skipped) if caching else frozenset(),
        lookups=LookupStats(
            total=caching.total,
            fetched=caching.fetched,
            cache_hits=caching.cache_hits,
            failed=len(caching.failed),
            deferred=len(caching.skipped),
            uncached_degraded=caching.uncached_degraded,
        )
        if caching
        else None,
        enrich_mode=enrich if caching else None,
        informational=tuple(informational),
    )
