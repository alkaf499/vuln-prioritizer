"""Layer 2 — asset conditioning, composed onto Layer 1 (CLAUDE.md §3 v0.6).

``final_tier = Layer2(Layer1(finding), asset_context)``. Pure and deterministic: no I/O, no
clock (pass ``as_of`` to get due dates), no dependence on input order.

Rule ordering (pinned by tests)
-------------------------------
1. **Scope gate.** ``in_scope: false`` excludes the finding. It is *counted and reported*
   (``ScoringRun.excluded``), never silently dropped. Environment never excludes. The gate runs
   first, so an out-of-scope asset stays excluded even if it is externally exposed.
2. **Classification** (precedence): external exposure > non-production > non-critical prod >
   business-critical prod. Exposure uplift applies in ANY environment.
3. **Shift** (+1 uplift / -1 downgrade, a one-step move on T4<T3<T2<T1<T0), clamped at the
   T0 ceiling / T4 floor.
There is NO no-downgrade floor (removed in v0.7): a Layer-1 Tier 1 on a non-production or
non-critical-prod asset downgrades to Tier 2 like any other tier. Exactly one ±1 shift is
applied per asset, chosen by classification precedence, so non-production + externally exposed
+ Layer-1 Tier 1 is classified external, +1 => Tier 0 (via exposure precedence, not a floor).

Impact-only findings (v0.8, decision #12): a finding with NO probability signal (no VPR, EPSS or
KEV; ``Flag.REEVALUATE_PROBABILITY`` stays set) gets NO exposure uplift and its final tier is capped
at ``IMPACT_ONLY_TIER_CAP`` (Tier 3). The downgrade still applies; the cap is applied after the shift.
Once a probability signal appears (incl. live threat-intel) the finding is no longer impact-only and
the normal matrix + uplift apply on the next run.

Unknown environment (not exposed, not business critical) is treated as baseline (shift 0): we
do not downgrade on information we don't have. It is flagged for re-evaluation by the resolver.
"""

from __future__ import annotations

import enum
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Iterable

from ..context import (
    AssetContext,
    Environment,
    Exposure,
    Overlay,
    resolve_context,
)
from ..context.resolver import (
    DEFAULT_ACR_CROWN_JEWEL_MIN,
    DEFAULT_TAG_CONVENTION,
    TagConvention,
)
from ..schema import Finding
from ..context.model import CRITICALITY_ORDER
from .layer1 import (
    IMPACT_ONLY_POLICY,
    ImpactOnlyPolicy,
    Layer1Result,
    ProbabilitySource,
    score_layer1,
)
from .tiers import Tier


class AssetClass(str, enum.Enum):
    EXTERNALLY_EXPOSED = "externally_exposed"
    BUSINESS_CRITICAL_PROD = "business_critical_prod"
    NON_CRITICAL_PROD = "non_critical_prod"
    NON_PRODUCTION = "non_production"
    UNKNOWN = "unknown"  # environment unknown, internal, not business critical
    EXCLUDED = "excluded"  # in_scope: false


CLASS_SHIFT: dict[AssetClass, int] = {
    AssetClass.EXTERNALLY_EXPOSED: +1,
    AssetClass.BUSINESS_CRITICAL_PROD: 0,
    AssetClass.NON_CRITICAL_PROD: -1,
    AssetClass.NON_PRODUCTION: -1,
    AssetClass.UNKNOWN: 0,
    AssetClass.EXCLUDED: 0,
}
"""Urgency shift per class: +1 = one tier MORE urgent, -1 = one tier LESS urgent."""

_CLASS_TEXT = {
    AssetClass.EXTERNALLY_EXPOSED: "externally exposed",
    AssetClass.BUSINESS_CRITICAL_PROD: "business-critical prod",
    AssetClass.NON_CRITICAL_PROD: "non-critical prod",
    AssetClass.NON_PRODUCTION: "non-production",
    AssetClass.UNKNOWN: "environment unknown",
    AssetClass.EXCLUDED: "out of scope",
}


def classify_asset(ctx: AssetContext) -> AssetClass:
    if ctx.in_scope.value is False:
        return AssetClass.EXCLUDED
    if ctx.exposure.value is Exposure.EXTERNAL:
        return AssetClass.EXTERNALLY_EXPOSED
    env = ctx.environment.value
    if env is Environment.NON_PRODUCTION:
        return AssetClass.NON_PRODUCTION
    if env is Environment.PRODUCTION:
        if ctx.criticality.value.business_critical:
            return AssetClass.BUSINESS_CRITICAL_PROD
        return AssetClass.NON_CRITICAL_PROD
    return AssetClass.UNKNOWN


# --------------------------------------------------------------------------
# tier ladder shifts
# --------------------------------------------------------------------------
def shift_tier(tier: Tier, shift: int) -> tuple[Tier, bool]:
    """Move ``shift`` steps toward urgency (+) or away (-), clamped to [T0, T4].

    Returns ``(new_tier, clamped)``; ``clamped`` is True if the move was cut short.
    Pure ladder arithmetic — the no-downgrade floor lives in ``apply_shift``.
    """
    target = int(tier) - shift
    clamped = target < int(Tier.T0) or target > int(Tier.T4)
    return Tier(min(max(target, int(Tier.T0)), int(Tier.T4))), clamped


IMPACT_ONLY_TIER_CAP = Tier.T3
"""Most-urgent tier an impact-only finding (no probability signal) can reach: 30d, planned
remediation. No exploitation evidence must never produce a false emergency."""


@dataclass(frozen=True, slots=True)
class ShiftOutcome:
    tier: Tier
    """The final tier (after the shift and, for impact-only findings, the cap)."""
    requested: int
    """Shift the asset class asked for (+1 / 0 / -1)."""
    applied: int
    """Tiers the shift actually moved toward urgency (+) / away (-); differs from requested
    only on clamp or when the uplift was withheld. The impact-only cap is NOT a shift."""
    clamped: bool = False
    uplift_suppressed: bool = False
    """Impact-only finding on an uplift-eligible class: the +1 was withheld."""
    capped_from: Tier | None = None
    """Set when the impact-only cap lowered the urgency: the tier before the cap."""


def apply_shift(layer1_tier: Tier, shift: int) -> ShiftOutcome:
    new, clamped = shift_tier(layer1_tier, shift)
    return ShiftOutcome(new, shift, int(layer1_tier) - int(new), clamped=clamped)


# --------------------------------------------------------------------------
# composed result
# --------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class ScoredFinding:
    finding_id: str
    asset_id: str
    asset_name: str
    layer1: Layer1Result
    context: AssetContext
    asset_class: AssetClass
    shift: ShiftOutcome
    final_tier: Tier | None
    """``None`` for excluded findings (they are reported, not scheduled)."""
    due: datetime | None = None
    exclusion_reason: str | None = None

    @property
    def excluded(self) -> bool:
        return self.asset_class is AssetClass.EXCLUDED

    def _shift_text(self) -> str:
        s, l1 = self.shift, self.layer1.tier
        cls = _CLASS_TEXT[self.asset_class]
        after = s.capped_from or s.tier  # tier after the shift, before any impact-only cap
        if s.uplift_suppressed:
            text = f"{cls}: uplift withheld (no probability signal), {l1.label} unchanged"
        elif s.requested == 0:
            text = f"{cls}: baseline, {l1.label} unchanged"
        else:
            verb = "uplift" if s.requested > 0 else "downgrade"
            clamp = " (clamped)" if s.clamped else ""
            text = f"{cls}: {verb} {l1.label} -> {after.label}{clamp}"
        if s.capped_from is not None:
            text += (
                f"; capped {s.capped_from.label} -> {s.tier.label} (impact-only: no exploitation "
                "evidence, planned remediation until a probability signal appears)"
            )
        return text

    def explain(self) -> str:
        if self.excluded:
            return (
                f"EXCLUDED (not scheduled) — {self.exclusion_reason}; "
                f"Layer 1 would have been: {self.layer1.explain()}"
            )
        assert self.final_tier is not None
        due = f" · due {self.due.isoformat()}" if self.due else ""
        return (
            f"{self.final_tier.label} · {self.final_tier.sla_label}{due} — {self._shift_text()}. "
            f"Layer 1: {self.layer1.explain()}. Asset: {self.context.summary()}"
        )

    def as_record(self) -> dict[str, Any]:
        l1 = {k: v for k, v in self.layer1.as_record().items() if k != "finding_id"}
        for k in ("tier", "sla", "flags", "explanation"):
            l1[f"layer1_{k}"] = l1.pop(k)
        ctx = {k: v for k, v in self.context.as_record().items() if k != "asset_id"}
        return {
            "finding_id": self.finding_id,
            "asset_id": self.asset_id,
            **l1,
            **ctx,
            "asset_class": self.asset_class.value,
            "shift_requested": self.shift.requested,
            "shift_applied": self.shift.applied,
            "shift_clamped": self.shift.clamped,
            "uplift_suppressed": self.shift.uplift_suppressed,
            "impact_only_capped": self.shift.capped_from is not None,
            "excluded": self.excluded,
            "exclusion_reason": self.exclusion_reason,
            "final_tier": self.final_tier.name if self.final_tier is not None else None,
            "final_sla": self.final_tier.sla_label if self.final_tier is not None else None,
            "due": self.due.isoformat() if self.due else None,
            "explanation": self.explain(),
        }


def score_finding(
    finding: Finding,
    context: AssetContext,
    *,
    as_of: datetime | None = None,
    impact_only_policy: ImpactOnlyPolicy = IMPACT_ONLY_POLICY,
) -> ScoredFinding:
    """Layer 1 then Layer 2 for one finding. ``due`` = ``as_of`` + SLA (``None`` without
    ``as_of`` or for Tier 4, which has no fixed window)."""
    l1 = score_layer1(finding, impact_only_policy=impact_only_policy)
    cls = classify_asset(context)

    if cls is AssetClass.EXCLUDED:
        reason = context.in_scope.detail or f"in_scope=false ({context.in_scope.source.value})"
        return ScoredFinding(
            finding_id=finding.finding_id,
            asset_id=context.asset_id,
            asset_name=context.asset_name,
            layer1=l1,
            context=context,
            asset_class=cls,
            shift=ShiftOutcome(l1.tier, 0, 0),
            final_tier=None,
            due=None,
            exclusion_reason=reason,
        )

    requested = CLASS_SHIFT[cls]
    impact_only = l1.probability.impact_only  # no VPR / EPSS / KEV: Flag.REEVALUATE_PROBABILITY
    suppressed = impact_only and requested > 0  # no exploitation evidence => no uplift
    step = apply_shift(l1.tier, 0 if suppressed else requested)
    tier, capped_from = step.tier, None
    if impact_only and tier < IMPACT_ONLY_TIER_CAP:  # lower value = more urgent
        capped_from, tier = tier, IMPACT_ONLY_TIER_CAP
    outcome = ShiftOutcome(
        tier,
        requested,
        step.applied,
        clamped=step.clamped,
        uplift_suppressed=suppressed,
        capped_from=capped_from,
    )
    sla = outcome.tier.sla
    return ScoredFinding(
        finding_id=finding.finding_id,
        asset_id=context.asset_id,
        asset_name=context.asset_name,
        layer1=l1,
        context=context,
        asset_class=cls,
        shift=outcome,
        final_tier=outcome.tier,
        due=(as_of + sla) if (as_of is not None and sla is not None) else None,
    )


def _probability_signal(sf: ScoredFinding) -> float:
    """Probability value on VPR's 0-10 scale (EPSS 0-1 is scaled x10); -1 = no value.

    Raw value, not the band: within a tier this puts VPR 9.9 ahead of VPR 9.0. A KEV-floored
    finding is ranked by the value it actually has (a floored VPR 3.0 sorts as 3.0)."""
    p = sf.layer1.probability
    if p.value is None:
        return -1.0
    return p.value * 10.0 if p.source is ProbabilitySource.EPSS else p.value


def _rank_key(sf: ScoredFinding) -> tuple:
    """Highest-signal first. Ascending sort on:

    1. final tier (T0 first)
    2. KEV — confirmed exploitation first; outranks a higher VPR with no exploit evidence
    3. probability value (VPR, or EPSS x10 when VPR is absent) — descending
    4. CVSS impact score — descending (-1 when impact came from scan severity)
    5. asset criticality: crown_jewel > cj_support > rto_defined > standard
    6. exposure: external before internal
    7. finding_id — total, stable final tiebreak
    """
    ctx = sf.context
    score = sf.layer1.impact.score
    return (
        int(sf.final_tier) if sf.final_tier is not None else 99,
        0 if sf.layer1.probability.kev else 1,
        -_probability_signal(sf),
        -(score if score is not None else -1.0),
        -CRITICALITY_ORDER[ctx.criticality.value],
        0 if ctx.exposure.value is Exposure.EXTERNAL else 1,
        sf.finding_id,
    )


@dataclass(frozen=True, slots=True)
class ScoringRun:
    scored: tuple[ScoredFinding, ...]
    """In-scope findings, ranked by ``_rank_key``: tier, then KEV first, VPR desc, CVSS desc,
    criticality, exposure, finding_id."""
    excluded: tuple[ScoredFinding, ...]
    """Out-of-scope findings, reported separately (sorted by finding_id)."""

    @property
    def total(self) -> int:
        return len(self.scored) + len(self.excluded)

    @property
    def excluded_count(self) -> int:
        return len(self.excluded)

    @property
    def excluded_asset_count(self) -> int:
        return len({sf.asset_id for sf in self.excluded})

    def by_class(self) -> dict[str, int]:
        c = Counter(sf.asset_class.value for sf in (*self.scored, *self.excluded))
        return dict(sorted(c.items()))

    def by_tier(self) -> dict[str, int]:
        c = Counter(sf.final_tier.name for sf in self.scored if sf.final_tier is not None)
        return dict(sorted(c.items()))

    def summary(self) -> dict[str, Any]:
        return {
            "total_findings": self.total,
            "scored": len(self.scored),
            "excluded": self.excluded_count,
            "excluded_assets": self.excluded_asset_count,
            "by_tier": self.by_tier(),
            "by_asset_class": self.by_class(),
            "reevaluate_context": sum(1 for sf in self.scored if sf.context.reevaluate),
        }


def score_findings(
    findings: Iterable[Finding],
    *,
    overlay: Overlay | None = None,
    as_of: datetime | None = None,
    impact_only_policy: ImpactOnlyPolicy = IMPACT_ONLY_POLICY,
    tag_convention: TagConvention = DEFAULT_TAG_CONVENTION,
    use_ip_heuristic: bool = False,
    acr_crown_jewel_min: float = DEFAULT_ACR_CROWN_JEWEL_MIN,
) -> ScoringRun:
    """Resolve asset context (once per distinct asset), score every finding, split off
    exclusions. ``len(scored) + len(excluded) == len(findings)`` always."""
    ctx_cache: dict = {}
    scored: list[ScoredFinding] = []
    excluded: list[ScoredFinding] = []
    for f in findings:
        ctx = ctx_cache.get(f.asset)
        if ctx is None:
            ctx = ctx_cache[f.asset] = resolve_context(
                f.asset,
                overlay=overlay,
                tag_convention=tag_convention,
                use_ip_heuristic=use_ip_heuristic,
                acr_crown_jewel_min=acr_crown_jewel_min,
            )
        sf = score_finding(f, ctx, as_of=as_of, impact_only_policy=impact_only_policy)
        (excluded if sf.excluded else scored).append(sf)
    return ScoringRun(
        scored=tuple(sorted(scored, key=_rank_key)),
        excluded=tuple(sorted(excluded, key=lambda s: s.finding_id)),
    )
