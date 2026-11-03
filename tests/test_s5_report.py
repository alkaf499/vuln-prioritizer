"""S5: SLA-breach view, executive report, fetched_at dating, generic example overlay.

Offline only: the live path is exercised with an injected fake ``assess``; the network is blocked.
"""

from __future__ import annotations

import csv
import io
import json
import socket
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from vuln_prioritizer import cli, pipeline, report, sla, worklist
from vuln_prioritizer.context import (
    Criticality,
    Environment,
    Exposure,
    load_overlay,
    resolve_context,
)
from vuln_prioritizer.enrichment.cache import IntelCache
from vuln_prioritizer.schema import Asset
from vuln_prioritizer.scoring.tiers import Tier

AS_OF = datetime(2026, 11, 3, 12, 0, 0, tzinfo=timezone.utc)
FETCHED = datetime(2026, 10, 28, 8, 15, 0, tzinfo=timezone.utc)  # real time != the as-of label
OVERLAY = Path(__file__).resolve().parents[1] / "classification.example.yaml"
SLA = {"T0": timedelta(hours=12), "T1": timedelta(hours=24), "T2": timedelta(days=10), "T3": timedelta(days=30)}


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket.socket, "connect", boom)
    monkeypatch.setattr(pipeline, "make_default_assess", boom)
    monkeypatch.setattr(pipeline, "make_local_assess", boom)


def read_csv(path):
    return list(csv.DictReader(io.StringIO(Path(path).read_text(encoding="utf-8"))))


def run_cli(db, out, *extra):
    return cli.main(["run", "--db", str(db), "--overlay", str(OVERLAY), "--out", str(out),
                     "--offline", "--as-of", AS_OF.isoformat(), *extra])


# --------------------------------------------------------------------------
# sla_status
# --------------------------------------------------------------------------
def test_breached_by_days_uses_discovery_date_plus_tier_sla():
    ff = datetime(2026, 8, 15, 10, 0, tzinfo=timezone.utc)
    st = sla.sla_status(ff, Tier.T3, AS_OF)
    assert st.discovery_due == ff + timedelta(days=30)
    assert st.breached is True and st.overdue_days == 50  # 50d 2h past 2026-09-14T10:00
    assert st.label == "BREACHED +50d"


def test_sub_day_breach_is_labelled_in_hours():
    st = sla.sla_status(AS_OF - timedelta(hours=20), Tier.T0, AS_OF)  # 12h SLA, 20h old -> 8h over
    assert st.breached is True and st.overdue_days == 0 and st.label == "BREACHED +8h"


def test_on_track_and_exact_boundary():
    assert sla.sla_status(AS_OF - timedelta(days=1), Tier.T2, AS_OF).label == sla.ON_TRACK
    edge = sla.sla_status(AS_OF - timedelta(hours=24), Tier.T1, AS_OF)  # due == as_of exactly
    assert edge.breached is False and edge.label == sla.ON_TRACK


def test_tier4_and_missing_first_found_are_not_assessed():
    ff = datetime(2020, 1, 1, tzinfo=timezone.utc)
    t4 = sla.sla_status(ff, Tier.T4, AS_OF)
    assert t4.breached is None and t4.label == sla.NO_SLA and t4.discovery_due is None
    unk = sla.sla_status(None, Tier.T1, AS_OF)
    assert unk.breached is None and unk.label == sla.UNKNOWN  # never silently "on-track"
    assert sla.sla_status(ff, None, AS_OF).label == sla.NO_SLA


# --------------------------------------------------------------------------
# worklist rows carry both dates
# --------------------------------------------------------------------------
def test_worklist_rows_record_fix_by_and_discovery_due(navi_db, tmp_path):
    assert run_cli(navi_db, tmp_path / "o") == 0
    rows = read_csv(tmp_path / "o" / "worklist.csv")
    assert {"first_found", "discovery_due", "sla_status", "overdue_days"} <= set(rows[0])
    seen_tiers = set()
    for r in rows:
        seen_tiers.add(r["tier"])
        if r["tier"] == "T4":
            assert r["due"] == "" and r["discovery_due"] == ""
            assert r["sla_status"] == sla.NO_SLA and r["overdue_days"] == ""
            continue
        s = SLA[r["tier"]]
        assert datetime.fromisoformat(r["due"]) == AS_OF + s  # forward fix_by
        ff = datetime.fromisoformat(r["first_found"])
        dd = datetime.fromisoformat(r["discovery_due"])
        assert dd == ff + s  # audit discovery clock
        if dd < AS_OF:
            assert r["sla_status"].startswith("BREACHED +")
            assert int(r["overdue_days"]) == (AS_OF - dd).days
        else:
            assert r["sla_status"] == sla.ON_TRACK and r["overdue_days"] == ""
    assert seen_tiers - {"T4"}, "fixture should produce at least one tier with a hard SLA"


def test_markdown_worklist_shows_both_dates(navi_db, tmp_path):
    run_cli(navi_db, tmp_path / "o")
    md = (tmp_path / "o" / "worklist.md").read_text(encoding="utf-8")
    assert "| Fix by | SLA status |" in md and "BREACHED +" in md


# --------------------------------------------------------------------------
# pure aggregations
# --------------------------------------------------------------------------
def row(rank, tier, status, *, days="", role="server", asset="a1", kev=False, div="", cves="CVE-2099-0001"):
    return {
        "rank": rank, "tier": tier, "sla_status": status, "overdue_days": days, "role": role,
        "asset_id": asset, "kev": kev, "divergence": div, "cves": cves, "finding": f"finding {rank}",
        "asset": asset, "first_found": "2026-08-15T10:00:00+00:00", "evidence": "ev", "sla": "x",
        "impact_band": "critical", "probability_band": "high", "probability_source": "vpr",
        "probability_value": 3.0, "asset_class": "business_critical_prod",
    }  # fmt: skip


ROWS = [
    row(1, "T0", "BREACHED +3d", days=3, role="perimeter_firewall", asset="fw", kev=True, div="vpr_low_but_exploited"),
    row(2, "T0", sla.ON_TRACK, role="perimeter_firewall", asset="fw"),
    row(3, "T2", "BREACHED +120d", days=120, role="server", asset="s1"),
    row(4, "T2", "BREACHED +40d", days=40, role="server", asset="s2", kev=True),
    row(5, "T3", sla.UNKNOWN, role="", asset="x"),
    row(6, "T4", sla.NO_SLA, role="server", asset="s1"),
]


def test_sla_breakdown_is_per_tier_and_excludes_tier4():
    by = {b["tier"]: b for b in report.sla_breakdown(ROWS)}
    assert set(by) == {"T0", "T1", "T2", "T3"}
    assert (by["T0"]["findings"], by["T0"]["breached"], by["T0"]["on_track"]) == (2, 1, 1)
    assert by["T0"]["compliance"] == 0.5
    assert by["T1"]["compliance"] is None  # nothing in the tier
    assert (by["T2"]["breached"], by["T2"]["compliance"]) == (2, 0.0)
    assert by["T3"]["unknown"] == 1 and by["T3"]["compliance"] is None  # unknown is not compliant


def test_overdue_buckets_and_top_overdue_order():
    assert dict(report.overdue_buckets(ROWS)) == {"30 days or less": 1, "31-90 days": 1, "over 90 days": 1}
    assert [r["rank"] for r in report.top_overdue(ROWS)] == [3, 4, 1]  # most overdue first
    assert [r["rank"] for r in report.top_overdue(ROWS, limit=1)] == [3]


def test_role_groups_roll_up_and_order_most_urgent_first():
    groups = {g["role"]: g for g in report.role_groups(ROWS)}
    fw, srv = groups["perimeter_firewall"], groups["server"]
    assert (fw["assets"], fw["findings"], fw["T0"], fw["urgent"], fw["kev"], fw["breached"]) == (1, 2, 2, 2, 1, 1)
    assert (srv["assets"], srv["findings"], srv["T2"], srv["T4"], srv["breached"]) == (2, 3, 2, 1, 2)
    assert srv["urgent"] == 0  # urgent = T0-T1; T2 is not
    assert report.NO_ROLE in groups  # a missing role is shown, not dropped
    # tier-lexicographic: fw (2 x T0) first, then server (2 x T2) before the T3-only "(no role)"
    assert [g["role"] for g in report.role_groups(ROWS)] == ["perimeter_firewall", "server", report.NO_ROLE]
    # many T1s do not outrank a single T0
    many_t1 = [row(i, "T1", sla.ON_TRACK, role="bulk", asset=f"b{i}") for i in range(5)]
    one_t0 = [row(99, "T0", sla.ON_TRACK, role="edge", asset="e")]
    assert [g["role"] for g in report.role_groups(many_t1 + one_t0)] == ["edge", "bulk"]


def test_divergence_rows_filters_by_kind():
    assert [r["rank"] for r in report.divergence_rows(ROWS, "vpr_low_but_exploited")] == [1]
    assert report.divergence_rows(ROWS, "vpr_high_no_exploit_signal") == []


# --------------------------------------------------------------------------
# executive report end to end
# --------------------------------------------------------------------------
def test_exec_report_sections_and_toil_funnel(navi_db, tmp_path):
    out = tmp_path / "o"
    assert run_cli(navi_db, out, "--triage-minutes", "5") == 0
    md = (out / "executive_report.md").read_text(encoding="utf-8")
    rows = read_csv(out / "worklist.csv")
    result = pipeline.run_pipeline(navi_db, OVERLAY, offline=True, as_of=AS_OF)

    for heading in ("## Toil saved", "## Findings by tier", "## SLA compliance", "## By asset role",
                    "## Top risks", "## Divergence highlights", "## Needs a human look"):
        assert heading in md
    urgent = sum(1 for r in rows if r["tier"] in ("T0", "T1"))  # report.URGENT_MAX_TIER = T1
    loaded = len(rows) + result.scoring.excluded_count + len(result.informational)
    assert f"**{loaded} findings loaded → {len(rows)} ranked → {urgent} urgent**" in md
    assert "Time to worklist:" in md
    assert "Analyst time (illustrative)" in md and "assumed 5 min per finding" in md
    assert rows[0]["finding"] in md.split("## Top risks")[1]  # the #1 finding is in the top-risks table
    assert "(no role)" in md  # the fixture matches no role rule
    assert "single total hides" in md  # breakdown, not one number


def test_exec_report_is_byte_reproducible_without_timing(navi_db, tmp_path):
    for name in ("a", "b"):
        assert run_cli(navi_db, tmp_path / name, "--no-timing") == 0
    a = (tmp_path / "a" / "executive_report.md").read_bytes()
    assert a == (tmp_path / "b" / "executive_report.md").read_bytes()
    assert b"Time to worklist" not in a and b"Analyst time" not in a
    for f in ("worklist.md", "worklist.csv", "excluded.csv", "informational.csv"):
        assert (tmp_path / "a" / f).read_bytes() == (tmp_path / "b" / f).read_bytes()


def test_triage_minutes_must_be_positive(navi_db, tmp_path):
    with pytest.raises(SystemExit) as e:
        cli.main(["run", "--db", str(navi_db), "--out", str(tmp_path / "o"), "--offline", "--triage-minutes", "0"])
    assert e.value.code == 2


def test_toil_summary_counts_the_full_scored_set_even_in_threat_first(navi_db):
    full = pipeline.run_pipeline(navi_db, OVERLAY, offline=True, as_of=AS_OF)
    tf = pipeline.run_pipeline(navi_db, OVERLAY, offline=True, as_of=AS_OF, threat_first=True)
    assert report.toil_summary(full) == report.toil_summary(tf)
    t = report.toil_summary(full)
    assert t["loaded"] == t["ranked"] + t["excluded"] + t["informational"]


# --------------------------------------------------------------------------
# fetched_at: real fetch time vs the --as-of label
# --------------------------------------------------------------------------
def rec(cve):
    return {
        "cve": cve, "kev_available": True, "kev": None, "msf_available": True, "edb_available": True,
        "nuclei_available": True, "epss": 0.5, "epss_pctl": 0.9, "tier": "WHITE No public exploit found",
        "msf": [], "msf_exploit": [], "edb": [], "edb_verified": [], "nuclei": None,
        "nomi": [], "trickest": [], "top_star": 0,
    }  # fmt: skip


def test_stamp_records_real_fetch_time_separately_from_the_label(tmp_path):
    p = tmp_path / "intel.json"
    c = IntelCache(p)
    c.put("CVE-2099-0001", rec("CVE-2099-0001"))
    c.stamp(AS_OF, fetched_at=FETCHED)
    c.save()
    meta = json.loads(p.read_text(encoding="utf-8"))["_meta"]
    assert meta["as_of"] == AS_OF.isoformat()  # the label
    assert meta["fetched_at"] == meta["fetched_updated"] == FETCHED.isoformat()  # the real time

    later_label, later_real = AS_OF + timedelta(days=30), FETCHED + timedelta(days=5)
    again = IntelCache.load(p)
    again.put("CVE-2099-0002", rec("CVE-2099-0002"))
    again.stamp(later_label, fetched_at=later_real)
    again.save()
    meta = json.loads(p.read_text(encoding="utf-8"))["_meta"]
    assert meta["as_of"] == AS_OF.isoformat() and meta["updated"] == later_label.isoformat()
    assert meta["fetched_at"] == FETCHED.isoformat()  # first fetch is kept
    assert meta["fetched_updated"] == later_real.isoformat()  # refresh recorded
    assert (again.fetched_at, again.fetched_updated) == (FETCHED.isoformat(), later_real.isoformat())


def test_stamp_without_fetched_at_or_without_new_entries_records_nothing(tmp_path):
    p = tmp_path / "intel.json"
    c = IntelCache(p)
    c.put("CVE-2099-0001", rec("CVE-2099-0001"))
    c.stamp(AS_OF)  # legacy call: unchanged format
    c.save()
    assert "fetched_at" not in json.loads(p.read_text(encoding="utf-8"))["_meta"]

    idle = IntelCache.load(p)  # nothing fetched this run -> not back-dated
    idle.stamp(AS_OF + timedelta(days=1), fetched_at=FETCHED)
    assert idle.fetched_at is None and idle.fetched_updated is None


def test_live_run_reports_both_dates_and_replay_keeps_them(navi_db, tmp_path):
    cache = tmp_path / "intel.json"
    live = pipeline.run_pipeline(
        navi_db, OVERLAY, as_of=AS_OF, fetched_at=FETCHED, assess=rec, intel_cache=cache
    )
    assert live.intel_as_of == AS_OF.isoformat() and live.intel_fetched_at == FETCHED.isoformat()
    md = worklist.to_markdown(live, worklist.build_rows(live), worklist.build_excluded_rows(live))
    assert f"intel as of {AS_OF.isoformat()}" in md and f"feeds actually fetched {FETCHED.isoformat()}" in md

    replay = pipeline.run_pipeline(navi_db, OVERLAY, offline=True, as_of=AS_OF, intel_cache=cache)
    assert replay.intel_fetched_at == FETCHED.isoformat()
    rmd = worklist.to_markdown(replay, worklist.build_rows(replay), worklist.build_excluded_rows(replay))
    assert f"(intel as of {AS_OF.isoformat()}; deterministic, no network)" in rmd
    assert f"feeds actually fetched {FETCHED.isoformat()}" in rmd
    em = report.to_exec_markdown(replay, worklist.build_rows(replay), worklist.build_excluded_rows(replay))
    assert f"feeds actually fetched {FETCHED.isoformat()}" in em


def test_hand_made_cache_says_fetch_time_not_recorded(navi_db, tmp_path):
    p = tmp_path / "hand.json"
    p.write_text(json.dumps({"CVE-2099-0002": rec("CVE-2099-0002")}), encoding="utf-8")
    r = pipeline.run_pipeline(navi_db, OVERLAY, offline=True, as_of=AS_OF, intel_cache=p)
    assert r.intel_fetched_at is None
    md = worklist.to_markdown(r, worklist.build_rows(r), worklist.build_excluded_rows(r))
    assert "feeds actually fetched not recorded" in md


# --------------------------------------------------------------------------
# generic example overlay
# --------------------------------------------------------------------------
@pytest.fixture(scope="module")
def example():
    return load_overlay(OVERLAY)


@pytest.mark.parametrize(
    "host,os,role,env,exposure,crit",
    [
        ("dc01", None, "domain_controller", Environment.PRODUCTION, Exposure.INTERNAL, Criticality.CROWN_JEWEL),
        ("fw1", "Fortinet FortiOS 7.2", "perimeter_firewall", Environment.PRODUCTION, Exposure.EXTERNAL, Criticality.STANDARD),
        ("fw2", "SonicWALL SonicOS 7.0", "perimeter_firewall", Environment.PRODUCTION, Exposure.EXTERNAL, Criticality.STANDARD),
        ("esx1", "VMware ESXi 7.0.3", "hypervisor", Environment.PRODUCTION, Exposure.INTERNAL, Criticality.CJ_SUPPORT),
        ("sw1", "Cisco IOS 15.2(7)E", "network_device", Environment.PRODUCTION, Exposure.INTERNAL, Criticality.CJ_SUPPORT),
        ("n9k", "Linux Kernel 3.14 on Cisco Nexus Switch aci-n9000", "network_device", Environment.PRODUCTION, Exposure.INTERNAL, Criticality.CJ_SUPPORT),
        ("rtu1", "VxWorks 6.9", "network_device", Environment.PRODUCTION, Exposure.INTERNAL, Criticality.CJ_SUPPORT),
        ("srv-idrac-01", None, "bmc", Environment.PRODUCTION, Exposure.INTERNAL, Criticality.CROWN_JEWEL),
        ("ilo-db1", None, "bmc", Environment.PRODUCTION, Exposure.INTERNAL, Criticality.CROWN_JEWEL),
        ("bm1", "Dell iDRAC9 firmware", "bmc", Environment.PRODUCTION, Exposure.INTERNAL, Criticality.CROWN_JEWEL),
        ("pc9", "Microsoft Windows 11 Pro", "workstation", Environment.NON_PRODUCTION, Exposure.INTERNAL, Criticality.STANDARD),
        ("Work Station #4", None, "workstation", Environment.NON_PRODUCTION, Exposure.INTERNAL, Criticality.STANDARD),
    ],
)
def test_example_generic_rules(example, host, os, role, env, exposure, crit):
    ctx = resolve_context(Asset(asset_id="a", hostname=host, operating_system=os), overlay=example)
    assert ctx.role.value == role
    assert (ctx.environment.value, ctx.exposure.value, ctx.criticality.value) == (env, exposure, crit)
    assert ctx.in_scope.value is True


def test_example_every_rule_has_a_role_and_domain_controller_beats_server_rule(example):
    assert all(r.role for r in example.rules)
    dc = resolve_context(Asset(asset_id="a", hostname="dc02", operating_system="Microsoft Windows Server 2022"), overlay=example)
    assert dc.role.value == "domain_controller"  # not the generic server rule
    srv = resolve_context(Asset(asset_id="a", hostname="app01", operating_system="Microsoft Windows Server 2022"), overlay=example)
    assert srv.role.value == "server"


def test_example_overlay_is_still_inert_on_the_fixture(navi_db):
    """The enriched example must not change fixture tiers: only the dev-* exclusion rule matches."""
    result = pipeline.run_pipeline(navi_db, OVERLAY, offline=True, as_of=AS_OF)
    rules = {worklist.overlay_rule(sf.context) for sf in result.scoring.scored}
    assert rules == {""}
    assert {worklist.overlay_rule(sf.context) for sf in result.scoring.excluded} == {"rule 1 (dev_host)"}
