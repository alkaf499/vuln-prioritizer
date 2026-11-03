import hashlib
import re
import sqlite3
from datetime import datetime, timezone

import pytest

from vuln_prioritizer.adapters.navi import (
    NaviSchemaError,
    connect_readonly,
    load_findings,
)
from vuln_prioritizer.fixtures.navi_fixture import build_fixture
from vuln_prioritizer.schema import CvssSource, Severity


# ---- volume / determinism ---------------------------------------------------
def test_counts(navi_db, findings):
    assert len(findings) == 29  # F30 is FIXED and excluded by default
    assert len(load_findings(navi_db, include_fixed=True)) == 30
    assert len({f.asset.asset_id for f in findings}) == 12


def test_deterministic_and_sorted(navi_db, findings):
    assert load_findings(navi_db) == findings
    ids = [f.finding_id for f in findings]
    assert ids == sorted(ids)


def test_assets_are_shared_instances(by_id):
    assert by_id["F01"].asset is by_id["F02"].asset


# ---- field mapping ----------------------------------------------------------
def test_kev_exploit_internet_exposed_prod(by_id):
    f = by_id["F01"]
    assert f.cves == ("CVE-2099-0001",)
    assert (f.port, f.protocol, f.state) == (443, "TCP", "ACTIVE")
    assert (f.cvss3_base_score, f.cvss3_source) == (9.8, CvssSource.NVD)
    assert f.cvss2_base_score == 10.0
    assert f.severity is Severity.CRITICAL
    assert f.vpr_score == 9.8 and f.vpr_updated is not None
    assert f.epss_score == 0.97 and f.epss_percentile == 0.999
    assert f.exploit_available is True
    assert f.exploit_frameworks == ("canvas", "metasploit")
    assert f.exploit_maturity == "High"
    assert f.kev is True
    assert f.kev_added == datetime(2026, 9, 1, tzinfo=timezone.utc)
    assert f.kev_due == datetime(2026, 9, 22, tzinfo=timezone.utc)
    assert f.first_found == datetime(2026, 8, 15, 10, tzinfo=timezone.utc)
    assert f.asset.exposure_classes == ("INTERNET_EXPOSED",)
    assert f.asset.tag_values("Environment") == ("Production",)
    assert (f.asset.acr, f.asset.aes) == (7.0, 640)
    assert f.asset.hostname == "web-prod-01"


def test_missing_cvss_falls_to_scan_severity_only(by_id):
    f = by_id["F09"]  # plugin has no CVSS anywhere
    assert f.cvss3_base_score is None and f.cvss2_base_score is None
    assert f.cvss3_source is CvssSource.UNKNOWN
    assert f.severity is Severity.HIGH
    assert not f.has_cvss


def test_cna_sourced_cvss_comes_from_tone_findings(by_id):
    f = by_id["F14"]
    assert (f.cvss3_base_score, f.cvss3_source) == (8.8, CvssSource.CNA)


def test_missing_vpr_with_epss_high_and_low(by_id):
    hi, lo = by_id["F03"], by_id["F17"]
    assert hi.vpr_score is None and hi.epss_score == 0.93
    assert lo.vpr_score is None and lo.epss_score == 0.002


def test_no_probability_signal_at_all(by_id):
    f = by_id["F12"]
    assert f.vpr_score is None and f.epss_score is None and f.epss_cve is None
    assert f.kev is False and f.cvss3_base_score == 9.1


def test_multi_cve_takes_worst_case_epss(by_id):
    f = by_id["F06"]
    assert f.cves == ("CVE-2099-0012", "CVE-2099-0013")
    assert (f.epss_score, f.epss_cve) == (0.71, "CVE-2099-0013")


def test_kev_with_low_vpr(by_id):
    f = by_id["F08"]
    assert f.kev is True and f.vpr_score == 3.0


def test_informational_finding_without_cve_or_scores(by_id):
    f = by_id["F04"]
    assert f.cves == () and f.severity is Severity.INFO
    assert f.cvss3_base_score is None and f.vpr_score is None and f.port == 0


def test_asset_without_tenable_one_data(by_id):
    f = by_id["F24"]  # wiki-prod-06: no tone_assets / tone_findings rows
    assert f.asset.exposure_classes == ()
    assert f.kev is False and f.exploit_maturity is None
    assert (f.asset.acr, f.asset.aes) == (3.0, 200)  # falls back to assets table
    assert f.cvss3_base_score == 8.1 and f.cvss3_source is CvssSource.UNKNOWN
    assert f.asset.tag_values("Environment") == ("Production",)


def test_state_variants(navi_db):
    allf = {f.finding_id: f for f in load_findings(navi_db, include_fixed=True)}
    assert allf["F30"].state == "FIXED"
    assert allf["F07"].state == "RESURFACED"
    assert allf["F03"].state == "NEW"


# ---- asset-context coverage (Layer 2 inputs present for every case) ---------
def test_fixture_covers_every_asset_case(findings):
    assets = {f.asset.asset_id: f.asset for f in findings}.values()
    env = {a.tag_values("Environment")[0] for a in assets}
    crit = {a.tag_values("BusinessCriticality")[0] for a in assets}
    exposed = [a for a in assets if a.exposure_classes]
    assert {"Production", "Development", "Test", "Staging"} <= env
    assert {"CrownJewel", "CrownJewelSupport", "Standard", "Low"} <= crit
    assert any(a.tag_values("Environment") == ("Production",) for a in exposed)
    assert any(a.tag_values("Environment") == ("Staging",) for a in exposed)  # exposed non-prod
    assert any(
        a.exposure_classes and a.tag_values("BusinessCriticality") == ("CrownJewel",) for a in exposed
    )  # multi-class: exposed + crown jewel


# ---- read-only + safety -----------------------------------------------------
def test_adapter_does_not_modify_db(navi_db):
    before = hashlib.sha256(navi_db.read_bytes()).hexdigest()
    load_findings(navi_db)
    load_findings(navi_db, include_fixed=True)
    assert hashlib.sha256(navi_db.read_bytes()).hexdigest() == before


def test_connection_rejects_writes(navi_db):
    conn = connect_readonly(navi_db)
    try:
        with pytest.raises(sqlite3.OperationalError):
            conn.execute("DELETE FROM vulns")
    finally:
        conn.close()


def test_missing_file_is_not_created(tmp_path):
    p = tmp_path / "nope.db"
    with pytest.raises(FileNotFoundError):
        load_findings(p)
    assert not p.exists()


def test_missing_required_table(tmp_path):
    p = tmp_path / "bad.db"
    conn = sqlite3.connect(p)
    conn.execute("CREATE TABLE unrelated (x text)")
    conn.commit()
    conn.close()
    with pytest.raises(NaviSchemaError, match="vulns"):
        load_findings(p)


def test_optional_tables_may_be_absent(tmp_path):
    p = build_fixture(tmp_path / "slim.db")
    conn = sqlite3.connect(p)
    for t in ("tone_assets", "tone_findings", "epss", "tags"):
        conn.execute(f"DROP TABLE {t}")
    conn.commit()
    conn.close()
    got = {f.finding_id: f for f in load_findings(p)}
    assert len(got) == 29
    f = got["F01"]
    assert f.kev is False and f.epss_score is None and f.asset.exposure_classes == ()
    assert f.asset.tags == () and f.cvss3_base_score == 9.8


def test_fixture_is_synthetic_and_refuses_overwrite(navi_db):
    conn = sqlite3.connect(f"{navi_db.as_uri()}?mode=ro", uri=True)
    try:
        cves = {c for (s,) in conn.execute("SELECT cves FROM plugins WHERE cves IS NOT NULL")
                for c in re.findall(r"CVE-\d{4}-\d+", s)}
        hosts = [h for (h,) in conn.execute("SELECT fqdn FROM assets")]
    finally:
        conn.close()
    assert cves and all(c.startswith("CVE-2099-") for c in cves)
    assert all(h.endswith(".example.test") for h in hosts)
    with pytest.raises(FileExistsError):
        build_fixture(navi_db)
