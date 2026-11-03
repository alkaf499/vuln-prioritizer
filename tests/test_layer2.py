"""S2: Layer-2 asset conditioning composed onto Layer 1. All data is synthetic."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from vuln_prioritizer.context import (
    AssetContext,
    ContextSource,
    Criticality,
    Environment,
    Exposure,
    Resolved,
    parse_overlay,
)
from vuln_prioritizer.schema import Asset, CvssSource, Finding, Severity
from vuln_prioritizer.scoring.layer1 import Flag
from vuln_prioritizer.scoring import (
    AssetClass,
    Tier,
    apply_shift,
    classify_asset,
    score_finding,
    score_findings,
    score_layer1,
    shift_tier,
)

AS_OF = datetime(2026, 11, 2, 12, 0, 0)

PROD, NONPROD, UNK = Environment.PRODUCTION, Environment.NON_PRODUCTION, Environment.UNKNOWN
INTERNAL, EXTERNAL = Exposure.INTERNAL, Exposure.EXTERNAL
STANDARD, CJ = Criticality.STANDARD, Criticality.CROWN_JEWEL


def ctx(env=PROD, exposure=INTERNAL, crit=STANDARD, in_scope=True, detail=None) -> AssetContext:
    r = lambda v, d=None: Resolved(v, ContextSource.OVERLAY, d)  # noqa: E731
    return AssetContext(
        asset_id="a-1",
        asset_name="host-1",
        environment=r(env),
        exposure=r(exposure),
        criticality=r(crit),
        in_scope=r(in_scope, detail),
        role=r(None),
    )


def finding(fid="f-1", asset=None, *, cvss=9.8, vpr=None, epss=None, kev=False) -> Finding:
    return Finding(
        finding_id=fid,
        asset=asset or Asset(asset_id="a-1", hostname="host-1"),
        plugin_id="1",
        cvss3_base_score=cvss,
        cvss3_source=CvssSource.NVD,
        vpr_score=vpr,
        epss_score=epss,
        kev=kev,
    )


# Layer-1 findings that land on each tier (impact Critical x probability <col>)
def l1(tier: Tier, fid="f-1", asset=None) -> Finding:
    vpr = {Tier.T1: 9.5, Tier.T2: 7.5, Tier.T3: 5.0, Tier.T4: 1.0}[tier]
    f = finding(fid, asset, vpr=vpr)
    assert score_layer1(f).tier is tier  # guard the fixture itself
    return f


# --------------------------------------------------------------------------
# asset classes
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    "c,expected",
    [
        (ctx(PROD, EXTERNAL), AssetClass.EXTERNALLY_EXPOSED),
        (ctx(NONPROD, EXTERNAL), AssetClass.EXTERNALLY_EXPOSED),  # any environment
        (ctx(UNK, EXTERNAL), AssetClass.EXTERNALLY_EXPOSED),
        (ctx(PROD, EXTERNAL, CJ), AssetClass.EXTERNALLY_EXPOSED),  # exposure beats criticality
        (ctx(PROD, INTERNAL, CJ), AssetClass.BUSINESS_CRITICAL_PROD),
        (ctx(PROD, INTERNAL, Criticality.CJ_SUPPORT), AssetClass.BUSINESS_CRITICAL_PROD),
        (ctx(PROD, INTERNAL, Criticality.RTO_DEFINED), AssetClass.BUSINESS_CRITICAL_PROD),
        (ctx(PROD, INTERNAL, STANDARD), AssetClass.NON_CRITICAL_PROD),
        (ctx(NONPROD, INTERNAL), AssetClass.NON_PRODUCTION),
        (ctx(NONPROD, INTERNAL, CJ), AssetClass.NON_PRODUCTION),
        (ctx(UNK, INTERNAL), AssetClass.UNKNOWN),
        (ctx(PROD, INTERNAL, in_scope=False), AssetClass.EXCLUDED),
        (ctx(NONPROD, EXTERNAL, in_scope=False), AssetClass.EXCLUDED),  # scope gate runs first
    ],
)
def test_classification(c, expected):
    assert classify_asset(c) is expected


# expected final tier for a Layer-1 T2 finding, per class (uplift / baseline / downgrade)
@pytest.mark.parametrize(
    "c,expected",
    [
        (ctx(PROD, EXTERNAL), Tier.T1),
        (ctx(PROD, INTERNAL, CJ), Tier.T2),
        (ctx(PROD, INTERNAL, STANDARD), Tier.T3),
        (ctx(NONPROD, INTERNAL), Tier.T3),
        (ctx(UNK, INTERNAL), Tier.T2),
    ],
)
def test_every_asset_class_tier_effect_on_layer1_t2(c, expected):
    sf = score_finding(l1(Tier.T2), c)
    assert sf.layer1.tier is Tier.T2
    assert sf.final_tier is expected


def test_exposure_uplift_on_non_production_asset():
    # Non-prod would be -1, but exposure takes precedence and applies regardless of environment.
    sf = score_finding(l1(Tier.T2), ctx(NONPROD, EXTERNAL))
    assert sf.asset_class is AssetClass.EXTERNALLY_EXPOSED
    assert sf.final_tier is Tier.T1
    assert sf.shift.applied == +1


def test_uniform_uplift_and_downgrade_steps():
    assert shift_tier(Tier.T4, +1) == (Tier.T3, False)
    assert shift_tier(Tier.T3, +1) == (Tier.T2, False)
    assert shift_tier(Tier.T2, +1) == (Tier.T1, False)
    assert shift_tier(Tier.T1, +1) == (Tier.T0, False)
    assert shift_tier(Tier.T1, -1) == (Tier.T2, False)  # raw ladder: floor lives in apply_shift
    assert shift_tier(Tier.T2, -1) == (Tier.T3, False)
    assert shift_tier(Tier.T3, -1) == (Tier.T4, False)


# --------------------------------------------------------------------------
# clamp boundaries
# --------------------------------------------------------------------------
def test_clamp_at_t0_ceiling():
    assert shift_tier(Tier.T0, +1) == (Tier.T0, True)
    o = apply_shift(Tier.T0, +1)
    assert (o.tier, o.clamped, o.applied) == (Tier.T0, True, 0)


def test_clamp_at_t4_floor():
    assert shift_tier(Tier.T4, -1) == (Tier.T4, True)
    sf = score_finding(l1(Tier.T4), ctx(NONPROD))
    assert sf.final_tier is Tier.T4
    assert sf.shift.clamped is True and sf.shift.applied == 0


def test_t4_on_external_asset_uplifts_to_t3_without_clamp():
    sf = score_finding(l1(Tier.T4), ctx(PROD, EXTERNAL))
    assert sf.final_tier is Tier.T3 and not sf.shift.clamped


# --------------------------------------------------------------------------
# v0.7: no floor — the -1 downgrade applies to Layer-1 Tier 1 like any other tier
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    "c",
    [ctx(NONPROD, INTERNAL), ctx(PROD, INTERNAL, STANDARD)],
    ids=["non_production", "non_critical_prod"],
)
def test_layer1_t1_downgrades_to_t2(c):
    sf = score_finding(l1(Tier.T1), c)
    assert sf.layer1.tier is Tier.T1
    assert sf.final_tier is Tier.T2
    assert sf.shift.requested == -1 and sf.shift.applied == -1
    assert not sf.shift.clamped


def test_apply_shift_has_no_tier1_special_case():
    assert apply_shift(Tier.T1, -1).tier is Tier.T2
    assert apply_shift(Tier.T1, -1).applied == -1
    assert not hasattr(apply_shift(Tier.T1, -1), "floor_applied")


def test_business_critical_prod_t1_stays_t1_because_baseline_not_because_of_a_floor():
    sf = score_finding(l1(Tier.T1), ctx(PROD, INTERNAL, CJ))
    assert sf.final_tier is Tier.T1 and sf.shift.requested == 0


def test_exactly_one_shift_per_asset():
    # non-prod (-1) AND non-critical (-1 if it were prod): still a single -1; and an
    # external non-prod asset gets a single +1 (the downgrade is not also applied).
    assert score_finding(l1(Tier.T3), ctx(NONPROD, INTERNAL, STANDARD)).final_tier is Tier.T4
    assert score_finding(l1(Tier.T3), ctx(NONPROD, EXTERNAL, STANDARD)).final_tier is Tier.T2


# --------------------------------------------------------------------------
# worked SLA cases (CLAUDE.md §3)
# --------------------------------------------------------------------------
def test_worked_internal_laptop_kev_critical_low_vpr_is_t3():
    # CVSS 9.8, VPR 3.0, on KEV: KEV floors probability to High (not Critical) => Layer-1 T2;
    # internal non-production laptop => -1 => T3.
    f = finding(cvss=9.8, vpr=3.0, kev=True)
    assert score_layer1(f).tier is Tier.T2
    sf = score_finding(f, ctx(NONPROD, INTERNAL))
    assert sf.final_tier is Tier.T3


def test_worked_internal_laptop_epss_90_plus_is_t2():
    # CVSS 9.8, EPSS 0.97 (no VPR) => Layer-1 T1; internal non-production laptop => -1 => T2.
    f = finding(cvss=9.8, epss=0.97)
    assert score_layer1(f).tier is Tier.T1
    assert score_finding(f, ctx(NONPROD, INTERNAL)).final_tier is Tier.T2


def test_worked_exposed_laptop_is_t1_or_t0():
    # Same two findings on an externally exposed laptop (non-production, exposure wins).
    kev_low_vpr = finding(cvss=9.8, vpr=3.0, kev=True)  # Layer-1 T2 -> +1 -> T1
    epss_high = finding(cvss=9.8, epss=0.97)  # Layer-1 T1 -> +1 -> T0
    assert score_finding(kev_low_vpr, ctx(NONPROD, EXTERNAL)).final_tier is Tier.T1
    assert score_finding(epss_high, ctx(NONPROD, EXTERNAL)).final_tier is Tier.T0


# --------------------------------------------------------------------------
# three-way interaction: non-production AND externally exposed AND Layer-1 Tier 1
# --------------------------------------------------------------------------
def test_three_way_nonprod_external_layer1_t1_is_tier0():
    sf = score_finding(l1(Tier.T1), ctx(NONPROD, EXTERNAL), as_of=AS_OF)
    assert sf.layer1.tier is Tier.T1
    assert sf.asset_class is AssetClass.EXTERNALLY_EXPOSED  # precedence: exposure first
    assert sf.shift.requested == +1 and sf.shift.applied == +1  # a single +1; non-prod's -1 is not applied
    assert sf.final_tier is Tier.T0
    assert sf.due == AS_OF + timedelta(hours=12)


def test_three_way_rule_order_exposure_precedence_not_net_zero():
    # Same Layer-1 T1, same non-production environment: only exposure differs.
    # Internal => -1 => T2; external => +1 => T0 (T0, not "net zero" T1: exactly one shift).
    assert score_finding(l1(Tier.T1), ctx(NONPROD, INTERNAL)).final_tier is Tier.T2
    assert score_finding(l1(Tier.T1), ctx(NONPROD, EXTERNAL)).final_tier is Tier.T0


def test_three_way_via_overlay_end_to_end():
    ov = parse_overlay(
        'assets:\n  - match: { hostname: "lab-gw*" }\n    role: lab_gateway\n'
        "    environment: non_production\n    exposure: external\n"
    )
    a = Asset(asset_id="a-9", hostname="lab-gw01")
    run = score_findings([l1(Tier.T1, "f-9", a)], overlay=ov, as_of=AS_OF)
    (sf,) = run.scored
    assert sf.final_tier is Tier.T0
    assert sf.context.environment.value is NONPROD
    assert sf.context.exposure.value is EXTERNAL
    assert "externally exposed" in sf.explain()


# --------------------------------------------------------------------------
# exclusion: counted and reported, never dropped
# --------------------------------------------------------------------------
EX_OV = parse_overlay(
    """
assets:
  - match: { hostname: "dev-*" }
    environment: non_production
    in_scope: false
    reason: "covered by pre-prod patch testing"
  - match: { operating_system: "Palo Alto Networks PAN-OS*" }
    environment: production
    exposure: external
  - match: { hostname: "endpoint #*" }
    environment: non_production
"""
)
DEV = Asset(asset_id="dev-1", hostname="dev-build")
FW = Asset(asset_id="fw-1", hostname="fw", operating_system="Palo Alto Networks PAN-OS 11")
EP = Asset(asset_id="ep-1", hostname="Endpoint #1")


def test_excluded_assets_are_counted_and_reported_not_dropped():
    findings = [
        l1(Tier.T1, "f-a", DEV),
        l1(Tier.T2, "f-b", DEV),
        l1(Tier.T2, "f-c", FW),
        l1(Tier.T2, "f-d", EP),
    ]
    run = score_findings(findings, overlay=EX_OV, as_of=AS_OF)

    assert run.total == len(findings) == len(run.scored) + len(run.excluded)
    assert run.excluded_count == 2
    assert run.excluded_asset_count == 1
    assert [s.finding_id for s in run.excluded] == ["f-a", "f-b"]
    assert {s.finding_id for s in run.scored} == {"f-c", "f-d"}

    ex = run.excluded[0]
    assert ex.excluded and ex.final_tier is None and ex.due is None
    assert "pre-prod patch testing" in ex.exclusion_reason
    assert ex.layer1.tier is Tier.T1  # Layer 1 still computed and visible
    assert ex.explain().startswith("EXCLUDED")

    s = run.summary()
    assert s["excluded"] == 2 and s["excluded_assets"] == 1 and s["scored"] == 2
    assert s["by_asset_class"]["excluded"] == 2


def test_non_production_is_scored_not_excluded():
    run = score_findings([l1(Tier.T2, "f-d", EP)], overlay=EX_OV)
    assert run.excluded_count == 0
    (sf,) = run.scored
    assert sf.asset_class is AssetClass.NON_PRODUCTION and sf.final_tier is Tier.T3


def test_out_of_scope_stays_excluded_even_if_externally_exposed():
    sf = score_finding(l1(Tier.T1), ctx(NONPROD, EXTERNAL, in_scope=False, detail="policy"))
    assert sf.excluded and sf.final_tier is None
    assert sf.exclusion_reason == "policy"


def test_no_floor_vocabulary_remains():
    sf = score_finding(l1(Tier.T1), ctx(NONPROD, INTERNAL))
    assert "floor" not in sf.explain()


def test_exclusion_reason_has_a_default():
    sf = score_finding(l1(Tier.T2), ctx(in_scope=False))
    assert sf.exclusion_reason and "in_scope=false" in sf.exclusion_reason


# --------------------------------------------------------------------------
# composition: inputs from both layers, due dates, ranking, determinism
# --------------------------------------------------------------------------
def test_record_carries_layer1_inputs_and_layer2_shift():
    sf = score_finding(l1(Tier.T2), ctx(NONPROD, INTERNAL), as_of=AS_OF)
    rec = sf.as_record()
    assert rec["layer1_tier"] == "T2" and rec["final_tier"] == "T3"
    assert rec["impact_source"] == "cvss_nvd" and rec["probability_source"] == "vpr"
    assert rec["asset_class"] == "non_production"
    assert rec["shift_requested"] == -1 and rec["shift_applied"] == -1
    assert rec["shift_clamped"] is False and "no_downgrade_floor_applied" not in rec
    assert rec["environment"] == "non_production" and rec["environment_source"] == "overlay"
    assert rec["exposure"] == "internal" and rec["in_scope"] is True
    assert rec["final_sla"] == "30d"
    assert rec["due"] == (AS_OF + timedelta(days=30)).isoformat()
    assert rec["excluded"] is False


def test_explanation_names_layer1_asset_class_and_sources():
    text = score_finding(l1(Tier.T1), ctx(PROD, EXTERNAL), as_of=AS_OF).explain()
    assert text.startswith("Tier 0 · Emergency ~12h / out-of-band")
    assert "externally exposed" in text and "CVSS 9.8" in text and "VPR 9.5" in text
    assert "overlay" in text


def test_due_dates_follow_final_tier_sla():
    due = lambda t, c: score_finding(l1(t), c, as_of=AS_OF).due  # noqa: E731
    assert due(Tier.T1, ctx(PROD, INTERNAL, CJ)) == AS_OF + timedelta(hours=24)
    assert due(Tier.T2, ctx(PROD, INTERNAL, CJ)) == AS_OF + timedelta(days=10)
    assert due(Tier.T3, ctx(PROD, INTERNAL, CJ)) == AS_OF + timedelta(days=30)
    assert due(Tier.T4, ctx(PROD, INTERNAL, CJ)) is None  # next patch cycle: no fixed window
    assert score_finding(l1(Tier.T1), ctx()).due is None  # no as_of => no due date


def test_ranking_is_by_final_tier_then_vpr_and_input_order_independent():
    fs = [
        l1(Tier.T2, "f-1", EP),  # non-prod -> T3
        l1(Tier.T2, "f-2", FW),  # external -> T1
        l1(Tier.T1, "f-3", EP),  # non-prod -> T2
        l1(Tier.T3, "f-4", FW),  # external -> T2
    ]
    run = score_findings(fs, overlay=EX_OV)
    assert [(s.finding_id, s.final_tier) for s in run.scored] == [
        ("f-2", Tier.T1),
        ("f-3", Tier.T2),  # tie on final tier: higher VPR (9.5 vs 5.0) first
        ("f-4", Tier.T2),
        ("f-1", Tier.T3),
    ]
    assert score_findings(list(reversed(fs)), overlay=EX_OV) == run


# --- within-tier order: VPR desc > CVSS desc > criticality > exposure > finding_id --------
# In every case below the alphabetical (finding_id) order is the OPPOSITE of the expected
# order, so a pass proves the earlier key, not the final tiebreak, decided it.
RANK_OV = parse_overlay(
    """
assets:
  - match: { hostname: "cj-*" }
    environment: production
    criticality: crown_jewel
  - match: { hostname: "sup-*" }
    environment: production
    criticality: cj_support
"""
)


def _ranked(*items) -> list[str]:
    """items: (finding_id, hostname, finding kwargs). All are business-critical prod => baseline."""
    fs = [
        finding(fid, Asset(asset_id=f"as-{fid}", hostname=host), **kw) for fid, host, kw in items
    ]
    run = score_findings(fs, overlay=RANK_OV)
    assert len({s.final_tier for s in run.scored}) == 1, "fixture must tie on final tier"
    return [s.finding_id for s in run.scored]


def test_rank_vpr_desc_beats_finding_id():
    assert _ranked(
        ("a", "cj-1", dict(cvss=9.8, vpr=9.0)),
        ("b", "cj-2", dict(cvss=9.8, vpr=9.9)),
        ("c", "cj-3", dict(cvss=9.8, vpr=9.5)),
    ) == ["b", "c", "a"]


def test_rank_cvss_desc_breaks_a_vpr_tie():
    assert _ranked(
        ("a", "cj-1", dict(cvss=9.0, vpr=9.5)),
        ("b", "cj-2", dict(cvss=10.0, vpr=9.5)),
    ) == ["b", "a"]


def test_rank_vpr_outranks_cvss():
    assert _ranked(
        ("a", "cj-1", dict(cvss=10.0, vpr=9.0)),
        ("b", "cj-2", dict(cvss=9.0, vpr=9.9)),
    ) == ["b", "a"]


def test_rank_kev_first_beats_a_higher_vpr_within_a_tier():
    # Both land on T2 (Critical x High). The KEV'd one has the LOWER VPR and the LATER id, so only
    # the KEV term can put it first: confirmed exploitation outranks higher VPR without exploit evidence.
    assert _ranked(
        ("a", "cj-1", dict(cvss=9.8, vpr=7.5)),
        ("z", "cj-2", dict(cvss=9.8, vpr=3.0, kev=True)),
    ) == ["z", "a"]


def test_rank_kev_beats_higher_cvss_too_and_vpr_orders_within_the_kev_group():
    assert _ranked(
        ("a", "cj-1", dict(cvss=10.0, vpr=7.8)),
        ("b", "cj-2", dict(cvss=9.0, vpr=3.0, kev=True)),
        ("c", "cj-3", dict(cvss=9.0, vpr=3.3, kev=True)),
    ) == ["c", "b", "a"]


def test_rank_kev_never_outranks_a_more_urgent_tier():
    # KEV is a tiebreak WITHIN a tier: a non-KEV T1 still sits above a KEV'd T2.
    fs = [
        finding("kev-t2", Asset(asset_id="as-1", hostname="cj-1"), cvss=9.8, vpr=3.0, kev=True),
        finding("plain-t1", Asset(asset_id="as-2", hostname="cj-2"), cvss=9.8, vpr=9.5),
    ]
    run = score_findings(fs, overlay=RANK_OV)
    assert [(s.finding_id, s.final_tier) for s in run.scored] == [
        ("plain-t1", Tier.T1),
        ("kev-t2", Tier.T2),
    ]


def test_rank_criticality_breaks_a_vpr_and_cvss_tie():
    assert _ranked(
        ("a", "sup-1", dict(cvss=9.8, vpr=9.5)),  # cj_support
        ("b", "cj-1", dict(cvss=9.8, vpr=9.5)),  # crown_jewel
    ) == ["b", "a"]


def test_rank_exposure_breaks_a_criticality_tie_external_first():
    from dataclasses import replace

    from vuln_prioritizer.scoring.layer2 import _rank_key

    ext = score_finding(finding("z-ext", vpr=9.5), ctx(PROD, EXTERNAL, CJ))
    internal = score_finding(finding("a-int", vpr=9.5), ctx(PROD, INTERNAL, CJ))
    # force a common final tier so only the later keys can differ
    ext, internal = replace(ext, final_tier=Tier.T1), replace(internal, final_tier=Tier.T1)
    assert [s.finding_id for s in sorted([internal, ext], key=_rank_key)] == ["z-ext", "a-int"]


def test_rank_finding_id_is_the_final_stable_tiebreak():
    assert _ranked(
        ("b", "cj-2", dict(cvss=9.8, vpr=9.5)),
        ("a", "cj-1", dict(cvss=9.8, vpr=9.5)),
    ) == ["a", "b"]


def test_rank_epss_fallback_is_scaled_to_the_vpr_scale():
    # EPSS 0.97 (no VPR) == 9.7 on the VPR scale: it outranks VPR 9.5.
    assert _ranked(
        ("a", "cj-1", dict(cvss=9.8, vpr=9.5)),
        ("b", "cj-2", dict(cvss=9.8, epss=0.97)),
    ) == ["b", "a"]


def test_rank_missing_probability_value_sorts_last_within_tier():
    # impact-only (no VPR/EPSS/KEV) Critical => diagonal T1, capped to T3 (v0.8); VPR 5.0 x
    # Critical impact is also T3. No value sorts after any VPR within that tier.
    assert _ranked(
        ("a", "cj-1", dict(cvss=9.8)),
        ("b", "cj-2", dict(cvss=9.8, vpr=5.0)),
    ) == ["b", "a"]


# --------------------------------------------------------------------------
# v0.8: impact-only findings — no exposure uplift, final tier capped at T3, flag kept
# --------------------------------------------------------------------------
FIREWALL_OV = parse_overlay(
    """
assets:
  - match: { operating_system: "*FortiGate*" }
    role: perimeter_firewall
    environment: production
    exposure: external
"""
)


def eol_no_cve_critical(fid="eol", asset=None) -> Finding:
    """'Unsupported OS' style finding: no CVE, no CVSS, scan severity Critical, no VPR/EPSS/KEV."""
    return Finding(
        finding_id=fid,
        asset=asset or Asset(asset_id="a-1", hostname="host-1"),
        plugin_id="999",
        name="Unsupported Fortinet Hardware and Operating System",
        severity=Severity.CRITICAL,
    )


def test_eol_no_cve_critical_on_external_firewall_is_t3_flagged_not_t0():
    f = eol_no_cve_critical()
    l1_res = score_layer1(f)
    assert l1_res.tier is Tier.T1 and l1_res.probability.impact_only  # diagonal: Crit x Crit
    assert Flag.REEVALUATE_PROBABILITY in l1_res.flags

    sf = score_finding(f, ctx(PROD, EXTERNAL), as_of=AS_OF)
    assert sf.asset_class is AssetClass.EXTERNALLY_EXPOSED  # still described as exposed...
    assert sf.final_tier is Tier.T3  # ...but not T0, and not even T1/T2
    assert sf.due == AS_OF + timedelta(days=30)
    assert Flag.REEVALUATE_PROBABILITY in sf.layer1.flags  # flag kept
    assert sf.shift.uplift_suppressed and sf.shift.capped_from is Tier.T1
    assert sf.shift.requested == +1 and sf.shift.applied == 0
    rec = sf.as_record()
    assert rec["layer1_flags"] == "reevaluate_probability"
    assert rec["uplift_suppressed"] is True and rec["impact_only_capped"] is True
    text = sf.explain()
    assert text.startswith("Tier 3 · 30d") and "uplift withheld" in text and "capped" in text
    assert "Tier 0" not in text.split("—")[0]


def test_eol_no_cve_critical_on_firewall_via_overlay_end_to_end():
    fw = Asset(asset_id="fw-9", hostname="lab-fortigate-001", operating_system="FortiGate FortiOS 6.0")
    run = score_findings([eol_no_cve_critical("eol-fw", fw)], overlay=FIREWALL_OV, as_of=AS_OF)
    (sf,) = run.scored
    assert sf.context.exposure.value is EXTERNAL
    assert sf.final_tier is Tier.T3
    assert run.summary()["by_tier"] == {"T3": 1}


@pytest.mark.parametrize("cvss", [10.0, 9.0, 7.5])
def test_numeric_cvss_without_any_probability_signal_is_also_capped(cvss):
    sf = score_finding(finding(cvss=cvss), ctx(PROD, EXTERNAL))  # no vpr / epss / kev
    assert sf.layer1.probability.impact_only
    assert sf.final_tier is Tier.T3  # Critical diag T1 / High diag T2 -> uplift withheld -> cap T3


@pytest.mark.parametrize(
    "c,why",
    [
        (ctx(PROD, INTERNAL, CJ), "baseline"),
        (ctx(PROD, INTERNAL, STANDARD), "downgrade, then cap"),
        (ctx(NONPROD, INTERNAL), "downgrade, then cap"),
        (ctx(NONPROD, EXTERNAL), "uplift withheld, then cap"),
    ],
    ids=["crown_jewel", "non_critical_prod", "non_production", "external_non_prod"],
)
def test_impact_only_critical_is_t3_on_every_asset_class(c, why):
    sf = score_finding(finding(cvss=9.8), c)
    assert sf.final_tier is Tier.T3, why


def test_cap_only_lowers_urgency_it_never_raises_t4():
    # Medium impact-only => diagonal T4. An external asset's uplift is withheld, so it must NOT become T3.
    f = finding(cvss=5.0)
    assert score_layer1(f).tier is Tier.T4 and score_layer1(f).probability.impact_only
    ext = score_finding(f, ctx(PROD, EXTERNAL))
    assert ext.final_tier is Tier.T4 and ext.shift.uplift_suppressed and ext.shift.capped_from is None
    assert score_finding(f, ctx(NONPROD, INTERNAL)).final_tier is Tier.T4  # downgrade clamps at T4


def test_findings_with_a_probability_signal_are_untouched_by_the_cap():
    sf = score_finding(finding(cvss=9.8, vpr=5.0), ctx(NONPROD, INTERNAL))  # L1 T3 -> T4
    assert sf.final_tier is Tier.T4 and not sf.shift.uplift_suppressed and sf.shift.capped_from is None


def test_probability_signal_restores_normal_matrix_and_uplift():
    ext = ctx(PROD, EXTERNAL)
    base = dict(cvss=9.8)
    assert score_finding(finding(**base), ext).final_tier is Tier.T3  # impact-only
    # each probability signal ends impact-only handling
    assert score_finding(finding(**base, epss=0.97), ext).final_tier is Tier.T0  # Crit x Crit T1, +1
    assert score_finding(finding(**base, vpr=9.5), ext).final_tier is Tier.T0
    kev = score_finding(finding(**base, kev=True), ext)  # KEV floor High => L1 T2, +1
    assert kev.final_tier is Tier.T1 and not kev.shift.uplift_suppressed
    assert Flag.REEVALUATE_PROBABILITY not in kev.layer1.flags


def test_unknown_context_is_baseline_and_flagged():
    run = score_findings([l1(Tier.T2, "f-1", Asset(asset_id="zz", hostname="mystery"))], overlay=EX_OV)
    (sf,) = run.scored
    assert sf.asset_class is AssetClass.UNKNOWN and sf.final_tier is Tier.T2
    assert sf.context.reevaluate and run.summary()["reevaluate_context"] == 1
