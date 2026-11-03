"""S4 end-to-end: fixture navi.db -> overlay -> enrich (offline) -> score -> ranked worklist.

Every test here is --offline. Network access is blocked for the whole module, so a regression
that reached for a live feed fails loudly instead of silently going online.
"""

import csv
import hashlib
import io
import json
import socket
from datetime import datetime, timezone
from pathlib import Path

import pytest

from vuln_prioritizer import cli, pipeline, worklist
from vuln_prioritizer.enrichment import enrich, toolkit
from vuln_prioritizer.enrichment.offline import IntelCacheError, load_intel_cache, offline_assess

AS_OF = datetime(2026, 11, 3, 12, 0, 0, tzinfo=timezone.utc)
OVERLAY = Path(__file__).resolve().parents[1] / "classification.example.yaml"

# upstream exploit_check.assess()-shaped record: CVE-2099-0002 is NOT on KEV in the fixture's navi.db
INTEL = {
    "CVE-2099-0002": {
        "cve": "CVE-2099-0002",
        "kev_available": True,
        "kev": {"dateAdded": "2026-10-01", "knownRansomwareCampaignUse": "Known"},
        "msf_available": True,
        "edb_available": True,
        "nuclei_available": True,
        "msf": [{"fullname": "exploit/synthetic/auth_bypass_b"}],
        "msf_exploit": True,
        "edb": [],
        "nuclei": False,
        "nomi": [],
        "epss": 0.95,
        "tier": "RED - weaponized",
    }
}


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("network access attempted in an --offline test")

    monkeypatch.setattr(socket.socket, "connect", boom)
    monkeypatch.setattr(toolkit, "make_default_assess", boom)
    monkeypatch.setattr(enrich, "make_default_assess", boom)  # the name enrich_findings actually calls


@pytest.fixture()
def cache_file(tmp_path):
    p = tmp_path / "intel.json"
    p.write_text(json.dumps(INTEL), encoding="utf-8")
    return p


def run_cli(db, out, *extra):
    argv = ["run", "--db", str(db), "--overlay", str(OVERLAY), "--out", str(out),
            "--offline", "--as-of", AS_OF.isoformat(), *extra]
    return cli.main(argv)


def read_csv(path):
    return list(csv.DictReader(io.StringIO(Path(path).read_text(encoding="utf-8"))))


# --------------------------------------------------------------------------
def test_full_worklist_is_produced(navi_db, tmp_path, capsys):
    out = tmp_path / "out"
    assert run_cli(navi_db, out) == 0

    for name in ("worklist.md", "worklist.csv", "excluded.csv"):
        assert (out / name).is_file()

    rows = read_csv(out / "worklist.csv")
    assert rows, "empty worklist"
    # 30 fixture findings, F30 is FIXED and skipped by the adapter
    result = pipeline.run_pipeline(navi_db, OVERLAY, offline=True, as_of=AS_OF)
    assert result.scoring.total == 29
    assert len(rows) + result.scoring.excluded_count == 29

    # chat output is the same ranking
    stdout = capsys.readouterr().out
    assert "as of 2026-11-03T12:00:00+00:00" in stdout
    assert rows[0]["finding_id"] in stdout or "more in the report files" in stdout


def test_every_row_carries_evidence_and_resolved_sources(navi_db, tmp_path):
    run_cli(navi_db, tmp_path / "o")
    rows = read_csv(tmp_path / "o" / "worklist.csv")
    assert tuple(rows[0].keys()) == worklist.COLUMNS
    for r in rows:
        for col in ("tier", "sla", "asset", "evidence", "inputs", "explanation",
                    "impact_source", "probability_source", "asset_class",
                    "environment_source", "exposure_source", "criticality_source", "as_of"):
            assert r[col] != "", f"{r['finding_id']}: empty {col}"
        assert r["as_of"] == AS_OF.isoformat()
    md = (tmp_path / "o" / "worklist.md").read_text(encoding="utf-8")
    assert "As of:** 2026-11-03T12:00:00+00:00" in md
    assert "Excluded assets" in md


def test_ranking_is_ordered_and_ranks_are_contiguous(navi_db, tmp_path):
    run_cli(navi_db, tmp_path / "o")
    rows = read_csv(tmp_path / "o" / "worklist.csv")
    assert [int(r["rank"]) for r in rows] == list(range(1, len(rows) + 1))
    tiers = [int(r["tier"][1]) for r in rows]
    assert tiers == sorted(tiers)


def test_within_tier_vpr_desc_in_the_published_worklist(navi_db, tmp_path):
    run_cli(navi_db, tmp_path / "o")
    rows = read_csv(tmp_path / "o" / "worklist.csv")
    for a, b in zip(rows, rows[1:]):
        if a["tier"] == b["tier"] and a["probability_source"] == b["probability_source"] == "vpr":
            assert float(a["probability_value"]) >= float(b["probability_value"]), (a["finding_id"], b["finding_id"])


def test_offline_evidence_never_claims_a_feed_was_unreachable(navi_db, tmp_path, cache_file):
    for extra in ((), ("--intel-cache", str(cache_file))):
        out = tmp_path / ("c" if extra else "p")
        run_cli(navi_db, out, *extra)
        rows = read_csv(out / "worklist.csv")
        assert not any("unreachable" in r["evidence"] for r in rows)
        degraded = [r for r in rows if r["intel_degraded"] == "True"]
        assert degraded
        for r in degraded:
            assert r["evidence"].startswith("[offline: threat-intel not consulted] ")
            assert "not consulted)" in r["evidence"]


def test_offline_wording_rewrites_only_the_inner_clause():
    raw = "CISA KEV status unknown (feed unreachable); exploit maturity unknown (Metasploit, Exploit-DB, Nuclei unreachable)"
    assert worklist.offline_wording(raw) == (
        "CISA KEV status unknown (not consulted); exploit maturity unknown "
        "(Metasploit, Exploit-DB, Nuclei not consulted)"
    )


def test_kev_floor_and_exposure_uplift_visible_in_row(navi_db, tmp_path):
    # F08: internet-exposed, KEV'd critical with VPR 3.0 -> KEV floor High -> L1 T2 -> +1 -> T1
    run_cli(navi_db, tmp_path / "o")
    row = next(r for r in read_csv(tmp_path / "o" / "worklist.csv") if r["finding_id"] == "F08")
    assert row["kev_floor_applied"] == "True"
    assert row["asset_class"] == "externally_exposed"
    assert row["tier"] == "T1"


def test_excluded_assets_reported_separately_with_reason(navi_db, tmp_path):
    run_cli(navi_db, tmp_path / "o")
    ex = read_csv(tmp_path / "o" / "excluded.csv")
    dev = [e for e in ex if e["asset"] == "dev-web-01"]
    assert len(dev) == 1 and int(dev[0]["findings"]) == 2
    assert "pre-prod" in dev[0]["reason"]
    wl_assets = {r["asset"] for r in read_csv(tmp_path / "o" / "worklist.csv")}
    assert "dev-web-01" not in wl_assets
    md = (tmp_path / "o" / "worklist.md").read_text(encoding="utf-8")
    assert "dev-web-01" in md.split("## Excluded assets")[1]


def test_matched_overlay_rule_is_recorded_per_asset(navi_db, tmp_path):
    ov = tmp_path / "ov.yaml"
    ov.write_text(
        'assets:\n'
        '  - match: { hostname: "dev-*" }\n    role: dev_host\n    in_scope: false\n    reason: "pre-prod covers dev"\n'
        '  - match: { hostname: "web-*" }\n    role: edge_named\n    exposure: external\n',
        encoding="utf-8",
    )
    out = tmp_path / "o"
    assert cli.main(["run", "--db", str(navi_db), "--overlay", str(ov), "--out", str(out),
                     "--offline", "--as-of", AS_OF.isoformat()]) == 0
    rows = read_csv(out / "worklist.csv")
    by_asset = {}
    for r in rows:
        by_asset.setdefault(r["asset"], set()).add(r["overlay_rule"])
    assert by_asset["web-prod-01"] == {"rule 2 (edge_named)"}
    assert by_asset["db-prod-01"] == {""}  # no rule matched -> empty, not a guess
    web_row = next(r for r in rows if r["asset"] == "web-prod-01")
    assert "overlay rule 2 (edge_named)" in web_row["inputs"]
    ex = read_csv(out / "excluded.csv")
    assert [e["overlay_rule"] for e in ex if e["asset"] == "dev-web-01"] == ["rule 1 (dev_host)"]


def test_lab_style_overlay_parses_and_ranks(tmp_path):
    """The shape used by out/classification.lab.yaml (glob contains-matches, quoted '#', many roles)."""
    from vuln_prioritizer.context import parse_overlay
    from vuln_prioritizer.schema import Asset

    ov = parse_overlay(
        'assets:\n'
        '  - match: { operating_system: "*SonicOS*" }\n    role: perimeter_firewall\n'
        '    environment: production\n    exposure: external\n'
        '  - match: { hostname: "plc #*" }\n    role: ot_plc\n    environment: production\n'
        '    criticality: crown_jewel\n'
    )
    assert ov.match(Asset(asset_id="1", hostname="x", operating_system="SonicWALL SonicOS 7.0")).label == (
        "rule 1 (perimeter_firewall)"
    )
    assert ov.match(Asset(asset_id="2", hostname="PLC #14")).label == "rule 2 (ot_plc)"
    assert ov.match(Asset(asset_id="3", hostname="pc-7", operating_system="Ubuntu")) is None


def test_offline_output_is_byte_identical(navi_db, tmp_path, cache_file):
    for name in ("a", "b"):
        assert run_cli(navi_db, tmp_path / name, "--intel-cache", str(cache_file)) == 0
    for f in ("worklist.md", "worklist.csv", "excluded.csv"):
        assert (tmp_path / "a" / f).read_bytes() == (tmp_path / "b" / f).read_bytes()


def test_intel_cache_feeds_enrichment_and_the_scorer(navi_db, tmp_path, cache_file):
    run_cli(navi_db, tmp_path / "plain")
    run_cli(navi_db, tmp_path / "cached", "--intel-cache", str(cache_file))
    plain = {r["finding_id"]: r for r in read_csv(tmp_path / "plain" / "worklist.csv")}
    cached = {r["finding_id"]: r for r in read_csv(tmp_path / "cached" / "worklist.csv")}

    # F05 = CVE-2099-0002 on api-prod-02: KEV only via the cache
    assert plain["F05"]["kev"] == "False"
    assert cached["F05"]["kev"] == "True"
    assert "on CISA KEV since 2026-10-01" in cached["F05"]["evidence"]
    assert "[offline" not in cached["F05"]["evidence"]  # feeds answered, nothing degraded
    assert "kev" in cached["F05"]["threat_signals"].split(";")
    # CVEs missing from the cache are 'unknown', and say so
    assert plain["F05"]["evidence"].startswith("[offline: threat-intel not consulted]")


def test_threat_first_limits_view_but_keeps_exclusions(navi_db, tmp_path, cache_file):
    run_cli(navi_db, tmp_path / "full", "--intel-cache", str(cache_file))
    run_cli(navi_db, tmp_path / "tf", "--intel-cache", str(cache_file), "--threat-first")
    full = read_csv(tmp_path / "full" / "worklist.csv")
    tf = read_csv(tmp_path / "tf" / "worklist.csv")
    assert 0 < len(tf) < len(full)
    assert all(r["threat_signals"] for r in tf)
    # same relative order as the full ranking
    order = {r["finding_id"]: int(r["rank"]) for r in full}
    ids = [order[r["finding_id"]] for r in tf]
    assert ids == sorted(ids)
    assert (tmp_path / "tf" / "excluded.csv").read_bytes() == (tmp_path / "full" / "excluded.csv").read_bytes()
    md = (tmp_path / "tf" / "worklist.md").read_text(encoding="utf-8")
    assert f"{len(full) - len(tf)} in-scope finding(s) without a threat signal omitted" in md


def test_run_is_read_only_for_the_database(navi_db, tmp_path):
    before = hashlib.sha256(Path(navi_db).read_bytes()).hexdigest()
    run_cli(navi_db, tmp_path / "o")
    assert hashlib.sha256(Path(navi_db).read_bytes()).hexdigest() == before
    assert sorted(p.name for p in Path(navi_db).parent.iterdir()) == ["navi.db"]  # no -wal/-journal


def test_overlay_is_optional_and_flags_context(navi_db):
    result = pipeline.run_pipeline(navi_db, None, offline=True, as_of=AS_OF)
    assert result.overlay_name is None
    assert result.scoring.total == 29


# --------------------------------------------------------------------------
def test_missing_db_is_a_clean_error(tmp_path, capsys):
    assert cli.main(["run", "--db", str(tmp_path / "nope.db"), "--out", str(tmp_path / "o"), "--offline"]) == 2
    assert "not found" in capsys.readouterr().err
    assert not (tmp_path / "o").exists()


def test_intel_cache_requires_offline(navi_db, tmp_path, cache_file):
    with pytest.raises(SystemExit) as e:
        cli.main(["run", "--db", str(navi_db), "--out", str(tmp_path / "o"), "--intel-cache", str(cache_file)])
    assert e.value.code == 2


def test_bad_intel_cache(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("[1, 2]", encoding="utf-8")
    with pytest.raises(IntelCacheError):
        load_intel_cache(p)


def test_offline_assess_unknown_is_never_not_listed():
    intel = toolkit.to_intel(offline_assess({})("cve-2099-0001"))
    assert intel.cve == "CVE-2099-0001"
    assert not intel.kev and not intel.kev_known
    assert intel.maturity is toolkit.Maturity.UNKNOWN


def test_compact_evidence_collapses_only_identical_clauses():
    same = "CVE-2099-0001: KEV unknown | CVE-2099-0002: KEV unknown | CVE-2099-0003: KEV unknown"
    assert worklist.compact_evidence(same) == "3 CVEs, each: KEV unknown"
    diff = "CVE-2099-0001: on CISA KEV | CVE-2099-0002: KEV unknown"
    assert worklist.compact_evidence(diff) == diff
    assert worklist.compact_evidence("single clause") == "single clause"
    div = same + " — DIVERGENCE: VPR 3 is Low but exploitation evidence is strong"
    assert worklist.compact_evidence(div).endswith(" — DIVERGENCE: VPR 3 is Low but exploitation evidence is strong")


def test_csv_formula_injection_is_neutralized():
    assert worklist._csv_cell("=HYPERLINK(1)") == "'=HYPERLINK(1)"
    assert worklist._csv_cell("-cmd") == "'-cmd"
    assert worklist._csv_cell(None) == ""
    assert worklist._csv_cell("web-prod-01") == "web-prod-01"
