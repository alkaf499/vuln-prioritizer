"""S4 orchestration — CLAUDE.md §5, asset-first by default.

This module only *composes* existing stages; it contains no scoring, gating or enrichment
logic of its own:

    adapter (navi.db, read-only) -> enrich (S3: gate + memoized lookups)
        -> score (S1 ∘ S2: Layer 1 matrix, Layer 2 asset conditioning, with the CMDB overlay)
        -> rank (the scorer's stable order: tier, impact band, probability band, finding_id)

The overlay is applied inside the scorer's context resolver; the order above is
data-dependency order (enrichment must precede scoring so the KEV floor and EPSS fallback
see the merged inputs).

Read-only: the only things read are navi.db and the overlay (and an optional local intel
cache); nothing is ever written to the Tenable tenant.

Threat-first toggle (``threat_first=True``): same scoring, but the *worklist view* is
restricted to findings with a threat signal (KEV, weaponized/public exploit maturity, or a
public exploit framework) — "a threat just landed, are we exposed?". Non-hits are counted,
not hidden: run the default view for the full list. Exclusions are reported in both views.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from .adapters.navi import load_findings
from .context import Overlay, load_overlay
from .enrichment.enrich import EnrichedFinding, EnrichmentReport, enrich_findings
from .enrichment.offline import load_intel_cache, offline_assess
from .schema import Finding
from .scoring.layer2 import ScoredFinding, ScoringRun, score_findings

THREAT_MATURITIES = frozenset({"weaponized", "public_exploit"})


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


def normalize_as_of(as_of: datetime | None) -> datetime:
    """Timezone-aware UTC, whole seconds. ``None`` -> now."""
    if as_of is None:
        as_of = datetime.now(timezone.utc)
    if as_of.tzinfo is None:
        as_of = as_of.replace(tzinfo=timezone.utc)
    return as_of.astimezone(timezone.utc).replace(microsecond=0)


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
) -> PipelineResult:
    """Run the whole pipeline and return the ranked result (no files are written).

    ``offline`` never touches the network: enrichment answers from ``intel_cache`` (or
    "unknown"). ``assess`` injects a custom lookup (tests); it wins over the default source.
    ``as_of`` anchors due dates — inject it for byte-identical output.
    """
    as_of = normalize_as_of(as_of)
    if intel_cache is not None and not offline and assess is None:
        raise ValueError("an intel cache only applies to offline runs")

    findings = load_findings(db_path, include_fixed=include_fixed)
    overlay: Overlay | None = load_overlay(overlay_path) if overlay_path else None

    if assess is None and offline:
        assess = offline_assess(load_intel_cache(intel_cache) if intel_cache else None)
    report = enrich_findings(findings, assess)  # assess=None => live toolkit (S3 default)

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
    )
