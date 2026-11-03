import ast
import itertools
import math
from pathlib import Path

import pytest

import vuln_prioritizer.scoring.layer1 as layer1_mod
import vuln_prioritizer.scoring.tiers as tiers_mod
from vuln_prioritizer.schema import Asset, CveSignal, CvssSource, Finding, Severity
from vuln_prioritizer.scoring import (
    IMPACT_ONLY_POLICY,
    Band,
    Flag,
    ImpactOnlyPolicy,
    ImpactSource,
    ProbabilitySource,
    Tier,
    epss_band,
    score_band,
    score_layer1,
)

C, H, M, L = Band.CRITICAL, Band.HIGH, Band.MEDIUM, Band.LOW
NVD, CNA, UNK = CvssSource.NVD, CvssSource.CNA, CvssSource.UNKNOWN


def mk(**kw) -> Finding:
    kw.setdefault("finding_id", "f1")
    kw.setdefault("asset", Asset("a1"))
    kw.setdefault("plugin_id", "1")
    return Finding(**kw)


# ---- binning ---------------------------------------------------------------
@pytest.mark.parametrize(
    "score,band",
    [(10.0, C), (9.0, C), (8.99, H), (8.9, H), (7.0, H), (6.99, M), (6.9, M),
     (4.0, M), (3.99, L), (3.9, L), (0.0, L)],
)
def test_score_band_cutoffs(score, band):
    assert score_band(score) is band


@pytest.mark.parametrize(
    "epss,band",
    [(1.0, C), (0.90, C), (0.8999, H), (0.899, H), (0.50, H), (0.4999, M),
     (0.499, M), (0.10, M), (0.0999, L), (0.0, L)],
)
def test_epss_band_cutoffs(epss, band):
    assert epss_band(epss) is band


@pytest.mark.parametrize(
    "kw",
    [dict(vpr_score=10.5), dict(vpr_score=-0.1), dict(vpr_score=math.nan),
     dict(cvss3_base_score=11.0, cvss3_source=NVD), dict(cvss2_base_score=math.nan),
     dict(epss_score=1.2), dict(epss_score=-0.01),
     dict(cve_signals=(CveSignal("CVE-2099-0001", epss_score=2.0),))],
)
def test_out_of_range_inputs_raise(kw):
    kw.setdefault("severity", Severity.HIGH)
    with pytest.raises(ValueError):
        score_layer1(mk(**kw))


# ---- the matrix, written out independently of TIER_MATRIX -------------------
_SPEC_MATRIX = {  # impact -> [Crit, High, Med, Low] probability
    C: [Tier.T1, Tier.T2, Tier.T3, Tier.T4],
    H: [Tier.T2, Tier.T2, Tier.T3, Tier.T4],
    M: [Tier.T2, Tier.T3, Tier.T4, Tier.T4],
    L: [Tier.T4, Tier.T4, Tier.T4, Tier.T4],
}
_REP = {C: 9.0, H: 7.0, M: 4.0, L: 0.0}  # lowest score in each band


@pytest.mark.parametrize("impact,prob", list(itertools.product([C, H, M, L], repeat=2)))
def test_full_matrix(impact, prob):
    r = score_layer1(mk(cvss3_base_score=_REP[impact], cvss3_source=NVD, vpr_score=_REP[prob]))
    assert r.matrix_cell == (impact, prob)
    assert r.tier is _SPEC_MATRIX[impact][[C, H, M, L].index(prob)]
    assert r.flags == ()


def test_sla_ladder():
    assert [t.sla_label for t in Tier] == [
        "Emergency ~12h / out-of-band", "24h", "10d", "30d", "next patch cycle"]
    assert Tier.T1.sla.total_seconds() == 24 * 3600 and Tier.T4.sla is None
    assert Tier.T0 < Tier.T1 < Tier.T4  # lower = more urgent


# ---- impact hierarchy -------------------------------------------------------
@pytest.mark.parametrize(
    "src,expected",
    [(NVD, ImpactSource.CVSS_NVD), (CNA, ImpactSource.CVSS_CNA),
     (UNK, ImpactSource.CVSS_UNATTRIBUTED), (CvssSource.OTHER, ImpactSource.CVSS_UNATTRIBUTED)],
)
def test_finding_level_cvss_source_recorded(src, expected):
    i = score_layer1(mk(cvss3_base_score=8.1, cvss3_source=src, vpr_score=5)).impact
    assert (i.band, i.source, i.score, i.cve) == (H, expected, 8.1, None)


def test_cvss2_used_when_no_cvss3():
    i = score_layer1(mk(cvss2_base_score=9.3, severity=Severity.LOW, vpr_score=5)).impact
    assert (i.band, i.source, i.score) == (C, ImpactSource.CVSS2_UNATTRIBUTED, 9.3)


def test_cvss3_outranks_cvss2_even_if_lower():
    i = score_layer1(mk(cvss3_base_score=5.0, cvss2_base_score=9.3, vpr_score=5)).impact
    assert (i.band, i.source) == (M, ImpactSource.CVSS_UNATTRIBUTED)


def test_nvd_beats_cna_for_the_same_cve_even_if_cna_is_higher():
    sigs = (CveSignal("CVE-2099-0001", 9.8, CNA), CveSignal("CVE-2099-0001", 7.5, NVD))
    i = score_layer1(mk(cve_signals=sigs, vpr_score=5)).impact
    assert (i.band, i.source, i.score, i.cve) == (H, ImpactSource.CVSS_NVD, 7.5, "CVE-2099-0001")


def test_cna_used_when_no_nvd():
    sigs = (CveSignal("CVE-2099-0001", 9.8, CNA),)
    i = score_layer1(mk(cve_signals=sigs, vpr_score=5)).impact
    assert (i.band, i.source) == (C, ImpactSource.CVSS_CNA)


def test_severity_ignored_when_any_cvss_exists():
    i = score_layer1(mk(cvss3_base_score=3.0, cvss3_source=NVD, severity=Severity.CRITICAL,
                        vpr_score=5)).impact
    assert (i.band, i.source, i.severity) == (L, ImpactSource.CVSS_NVD, None)


@pytest.mark.parametrize(
    "sev,band",
    [(Severity.CRITICAL, C), (Severity.HIGH, H), (Severity.MEDIUM, M),
     (Severity.LOW, L), (Severity.INFO, L)],
)
def test_scan_severity_fallback_maps_to_band_without_inventing_cvss(sev, band):
    i = score_layer1(mk(severity=sev, vpr_score=9.5)).impact
    assert (i.band, i.source, i.severity, i.score) == (band, ImpactSource.SCAN_SEVERITY, sev, None)


def test_no_impact_data_defaults_low_and_flags():
    r = score_layer1(mk(vpr_score=9.5))
    assert (r.impact.band, r.impact.source) == (L, ImpactSource.NONE)
    assert Flag.IMPACT_MISSING in r.flags and r.tier is Tier.T4


# ---- multi-CVE worst case ---------------------------------------------------
def test_multi_cve_impact_worst_case():
    sigs = (CveSignal("CVE-2099-0001", 5.0, NVD), CveSignal("CVE-2099-0002", 9.8, NVD))
    i = score_layer1(mk(cve_signals=sigs, vpr_score=9.5)).impact
    assert (i.band, i.score, i.cve) == (C, 9.8, "CVE-2099-0002")


def test_multi_cve_worst_case_spans_finding_level_and_signals():
    sigs = (CveSignal("CVE-2099-0002", 9.8, CNA),)
    r = score_layer1(mk(cvss3_base_score=7.5, cvss3_source=NVD, cve_signals=sigs, vpr_score=9.5))
    assert (r.impact.band, r.impact.source, r.impact.cve) == (C, ImpactSource.CVSS_CNA, "CVE-2099-0002")
    assert r.tier is Tier.T1


def test_multi_cve_epss_worst_case():
    sigs = (CveSignal("CVE-2099-0002", epss_score=0.71), CveSignal("CVE-2099-0003", epss_score=0.3))
    p = score_layer1(mk(cvss3_base_score=9.8, cvss3_source=NVD, epss_score=0.12,
                        epss_cve="CVE-2099-0001", cve_signals=sigs)).probability
    assert (p.band, p.source, p.value, p.cve) == (H, ProbabilitySource.EPSS, 0.71, "CVE-2099-0002")


def test_multi_cve_kev_any():
    sigs = (CveSignal("CVE-2099-0001"), CveSignal("CVE-2099-0002", kev=True))
    p = score_layer1(mk(cvss3_base_score=9.8, cvss3_source=NVD, vpr_score=2.0, cve_signals=sigs)).probability
    assert p.kev and p.kev_floor_applied and p.band is H


# ---- probability resolution -------------------------------------------------
def test_vpr_beats_epss_even_when_epss_is_more_urgent():
    p = score_layer1(mk(cvss3_base_score=9.8, vpr_score=2.0, epss_score=0.95)).probability
    assert (p.band, p.source, p.value) == (L, ProbabilitySource.VPR, 2.0)


def test_epss_fallback_when_vpr_missing():
    r = score_layer1(mk(cvss3_base_score=9.8, cvss3_source=NVD, epss_score=0.93, epss_cve="CVE-2099-0008"))
    p = r.probability
    assert (p.band, p.source, p.value, p.cve) == (C, ProbabilitySource.EPSS, 0.93, "CVE-2099-0008")
    assert r.tier is Tier.T1 and r.flags == ()


@pytest.mark.parametrize("impact,tier", [(C, Tier.T1), (H, Tier.T2), (M, Tier.T4), (L, Tier.T4)])
def test_no_probability_signal_scores_on_impact_alone(impact, tier):
    r = score_layer1(mk(cvss3_base_score=_REP[impact], cvss3_source=NVD))
    p = r.probability
    assert p.impact_only and p.source is ProbabilitySource.NONE and p.base_band is None
    assert p.band is impact  # diagonal policy
    assert r.tier is tier and Flag.REEVALUATE_PROBABILITY in r.flags


def test_default_impact_only_policy_is_diagonal():
    assert IMPACT_ONLY_POLICY is ImpactOnlyPolicy.DIAGONAL


@pytest.mark.parametrize("impact,tier", [(C, Tier.T1), (H, Tier.T2), (M, Tier.T2), (L, Tier.T4)])
def test_worst_case_impact_only_policy(impact, tier):
    r = score_layer1(mk(cvss3_base_score=_REP[impact], cvss3_source=NVD),
                     impact_only_policy=ImpactOnlyPolicy.WORST_CASE)
    assert r.probability.band is C and r.probability.impact_only
    assert r.tier is tier and Flag.REEVALUATE_PROBABILITY in r.flags


def test_impact_only_policy_irrelevant_when_signal_present():
    f = mk(cvss3_base_score=5.0, cvss3_source=NVD, vpr_score=2.0)
    assert score_layer1(f) == score_layer1(f, impact_only_policy=ImpactOnlyPolicy.WORST_CASE)


# ---- KEV floor (last, always) -----------------------------------------------
@pytest.mark.parametrize(
    "kw,base,final,applied",
    [
        (dict(vpr_score=2.0), L, H, True),
        (dict(vpr_score=5.0), M, H, True),
        (dict(vpr_score=7.5), H, H, False),
        (dict(vpr_score=9.5), C, C, False),
        (dict(epss_score=0.01), L, H, True),
        (dict(epss_score=0.95), C, C, False),
        (dict(), None, H, True),
    ],
)
def test_kev_floor(kw, base, final, applied):
    r = score_layer1(mk(cvss3_base_score=9.8, cvss3_source=NVD, kev=True, **kw))
    p = r.probability
    assert (p.base_band, p.band, p.kev_floor_applied, p.kev) == (base, final, applied, True)
    assert not p.impact_only and Flag.REEVALUATE_PROBABILITY not in r.flags


def test_kev_false_never_raises_band():
    p = score_layer1(mk(cvss3_base_score=9.8, vpr_score=2.0, kev=False)).probability
    assert p.band is L and not p.kev_floor_applied


# ---- determinism / audit ----------------------------------------------------
def test_same_input_same_output():
    f = mk(cvss3_base_score=9.8, cvss3_source=NVD, vpr_score=3.0, kev=True)
    a, b = score_layer1(f), score_layer1(f)
    assert a == b and hash(a) == hash(b) and a.explain() == b.explain()
    assert a.as_record() == b.as_record()


def test_cve_signal_order_does_not_matter():
    sigs = [
        CveSignal("CVE-2099-0001", 9.8, CNA, epss_score=0.71),
        CveSignal("CVE-2099-0002", 9.8, NVD, epss_score=0.71),
        CveSignal("CVE-2099-0003", 7.0, NVD, kev=True),
    ]
    results = {score_layer1(mk(cve_signals=tuple(p))) for p in itertools.permutations(sigs)}
    assert len(results) == 1
    r = results.pop()
    assert (r.impact.cve, r.impact.source) == ("CVE-2099-0002", ImpactSource.CVSS_NVD)
    assert r.probability.cve == "CVE-2099-0001"  # EPSS tie -> lowest CVE id


def test_input_finding_untouched():
    f = mk(cvss3_base_score=9.8, vpr_score=3.0, kev=True)
    before = repr(f)
    score_layer1(f)
    assert repr(f) == before


def test_explain_and_record_carry_every_input():
    r = score_layer1(mk(finding_id="F08", cvss3_base_score=9.8, cvss3_source=NVD, vpr_score=3.0, kev=True))
    assert r.explain() == (
        "Tier 2 · 10d — impact Critical (CVSS 9.8, NVD) × "
        "probability High (VPR 3; raised to High: on CISA KEV)"
    )
    rec = r.as_record()
    assert rec["tier"] == "T2" and rec["sla"] == "10d"
    assert (rec["impact_band"], rec["impact_source"], rec["impact_score"]) == ("CRITICAL", "cvss_nvd", 9.8)
    assert (rec["probability_base_band"], rec["probability_band"]) == ("LOW", "HIGH")
    assert (rec["probability_source"], rec["probability_value"]) == ("vpr", 3.0)
    assert rec["kev"] and rec["kev_floor_applied"] and not rec["impact_only"]


def test_explain_epss_text():
    r = score_layer1(mk(cvss3_base_score=9.8, cvss3_source=NVD, epss_score=0.97,
                        epss_cve="CVE-2099-0001", kev=True))
    assert "EPSS 97% CVE-2099-0001; on CISA KEV" in r.explain()


@pytest.mark.parametrize("mod", [layer1_mod, tiers_mod])
def test_scoring_modules_are_pure(mod):
    """No I/O-capable imports in the scorer."""
    tree = ast.parse(Path(mod.__file__).read_text())
    absolute = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            absolute |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            absolute.add(node.module.split(".")[0])
    assert absolute <= {"__future__", "enum", "dataclasses", "typing", "math", "datetime"}


# ---- worked edge cases from the synthetic navi fixture ----------------------
_EXPECTED_FIXTURE_TIERS = {
    "F01": 1, "F02": 2, "F03": 1, "F04": 4, "F05": 1, "F06": 2, "F07": 2, "F08": 2,
    "F09": 3, "F10": 1, "F11": 3, "F12": 1, "F13": 1, "F14": 3, "F15": 4, "F16": 2,
    "F17": 4, "F18": 2, "F19": 1, "F20": 1, "F21": 4, "F22": 1, "F23": 4, "F24": 2,
    "F25": 1, "F26": 1, "F27": 1, "F28": 3, "F29": 1,
}


@pytest.fixture(scope="module")
def scored(findings):
    return {f.finding_id: score_layer1(f) for f in findings}


def test_fixture_tiers(scored):
    assert {k: r.tier.value for k, r in scored.items()} == _EXPECTED_FIXTURE_TIERS


def test_fixture_kev_floor_F08(scored):
    p = scored["F08"].probability  # KEV + VPR 3.0 (Low) on Critical impact
    assert (p.base_band, p.band, p.kev_floor_applied) == (L, H, True)
    assert scored["F08"].tier is Tier.T2  # would be T4 without the floor


def test_fixture_missing_vpr_epss_fallback(scored):
    hi, lo = scored["F03"].probability, scored["F17"].probability
    assert (hi.source, hi.band, hi.value) == (ProbabilitySource.EPSS, C, 0.93)
    assert (lo.source, lo.band, lo.value) == (ProbabilitySource.EPSS, L, 0.002)


def test_fixture_missing_cvss_uses_scan_severity(scored):
    i = scored["F09"].impact
    assert (i.source, i.band, i.severity) == (ImpactSource.SCAN_SEVERITY, H, Severity.HIGH)


def test_fixture_cna_and_unattributed_sources(scored):
    assert scored["F14"].impact.source is ImpactSource.CVSS_CNA
    assert scored["F24"].impact.source is ImpactSource.CVSS_UNATTRIBUTED  # no Tenable One row
    assert scored["F01"].impact.source is ImpactSource.CVSS_NVD


def test_fixture_reevaluation_flags(scored):
    flagged = {k for k, r in scored.items() if Flag.REEVALUATE_PROBABILITY in r.flags}
    assert flagged == {"F04", "F12", "F25"}
