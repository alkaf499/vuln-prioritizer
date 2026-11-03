"""--enrich local|full. The upstream script is replaced by a tiny stand-in module whose per-CVE
network helpers EXPLODE if called, and whose feed indexes are in-memory dicts (the 'mocked local
indexes'). No network, no downloads."""

import socket
import types
from datetime import datetime, timezone
from pathlib import Path

import pytest

from vuln_prioritizer import cli, pipeline, worklist
from vuln_prioritizer.enrichment import enrich, toolkit
from vuln_prioritizer.enrichment.cache import CachingAssess, IntelCache
from vuln_prioritizer.schema import Asset, Finding, Severity

AS_OF = datetime(2026, 11, 3, 12, 0, 0, tzinfo=timezone.utc)
OVERLAY = Path(__file__).resolve().parents[1] / "classification.example.yaml"

# Mirrors upstream exploit_check.assess() composition (same helper names, same result keys).
FAKE_UPSTREAM = '''
KEV = {"CVE-2099-0001": {"dateAdded": "2026-09-01", "knownRansomwareCampaignUse": "Known"}}
MSF = {"CVE-2099-0002": [{"fullname": "exploit/synthetic/b", "type": "exploit", "rank": 600}]}
NUCLEI = {"CVE-2099-0004": {"name": "synthetic detection"}}
EDB = {}

def epss(cve):
    raise AssertionError("per-CVE EPSS API called in local mode")

def nomisec(cve):
    raise AssertionError("nomi-sec called in local mode")

def trickest(cve):
    raise AssertionError("trickest called in local mode")

def assess(cve, refresh=False):
    cve = cve.upper()
    e, pctl = epss(cve)
    nomi, trk = nomisec(cve), trickest(cve)
    kev, msf, nuc, edb = KEV.get(cve), MSF.get(cve, []), NUCLEI.get(cve), EDB.get(cve, [])
    msf_exploit = [m for m in msf if m.get("type") == "exploit"]
    if msf_exploit:
        tier = "RED Weaponized"
    elif edb or msf:
        tier = "ORANGE Public working exploit"
    elif nomi or trk or nuc:
        tier = "YELLOW Proof-of-concept only"
    else:
        tier = "WHITE No public exploit found"
    return dict(cve=cve, kev=kev, kev_available=True, epss=e, epss_pctl=pctl,
                msf=msf, msf_exploit=msf_exploit, msf_available=True,
                nuclei=nuc, nuclei_available=True, edb=edb, edb_verified=[], edb_available=True,
                nomi=nomi, trickest=trk, top_star=0, tier=tier)
'''


@pytest.fixture()
def upstream(monkeypatch):
    mod = types.ModuleType("exploit_check_fake")
    exec(FAKE_UPSTREAM, mod.__dict__)  # noqa: S102 - test-owned source
    monkeypatch.setattr(toolkit, "load_exploit_check", lambda *a, **k: mod)
    monkeypatch.setattr(toolkit, "install_resilient_fetch", lambda *a, **k: None)

    def boom(*a, **k):
        raise AssertionError("network used")

    monkeypatch.setattr(socket.socket, "connect", boom)
    return mod


def finding(cve, fid="f-1"):
    return Finding(finding_id=fid, asset=Asset(asset_id="a-1", hostname="h"), plugin_id="1",
                   cves=(cve,), severity=Severity.CRITICAL)


# --------------------------------------------------------------------------
# toolkit.make_local_assess
# --------------------------------------------------------------------------
def test_local_assess_uses_only_the_feed_indexes_and_restores_the_helpers(upstream):
    originals = (upstream.epss, upstream.nomisec, upstream.trickest)
    assess = toolkit.make_local_assess()

    kev = assess("cve-2099-0001")  # would raise if any per-CVE helper were reached
    assert kev["kev"]["dateAdded"] == "2026-09-01" and kev["kev_available"] is True
    assert kev["epss"] is None and kev["nomi"] == [] and kev["trickest"] == []
    assert kev["enrich_mode"] == "local"

    assert assess("CVE-2099-0002")["tier"] == "RED Weaponized"  # Metasploit index
    assert assess("CVE-2099-0004")["tier"].startswith("YELLOW")  # Nuclei index
    assert (upstream.epss, upstream.nomisec, upstream.trickest) == originals  # restored

    with pytest.raises(AssertionError):  # a 'full' assess in the same process still hits them
        upstream.assess("CVE-2099-0001")


def test_helpers_are_restored_even_if_assess_raises(upstream):
    originals = (upstream.epss, upstream.nomisec, upstream.trickest)
    upstream.assess = lambda cve: (_ for _ in ()).throw(RuntimeError("boom"))
    with pytest.raises(RuntimeError):
        toolkit.make_local_assess()("CVE-2099-0001")
    assert (upstream.epss, upstream.nomisec, upstream.trickest) == originals


# --------------------------------------------------------------------------
# evidence wording
# --------------------------------------------------------------------------
def test_local_record_never_claims_no_public_exploit_found(upstream):
    intel = toolkit.to_intel(toolkit.make_local_assess()("CVE-2099-0009"))  # in no feed
    assert intel.maturity is toolkit.Maturity.NONE and intel.poc_consulted is False
    assert intel.epss is None and "EPSS" not in intel.feeds_missing and not intel.degraded

    text = enrich.describe(intel)
    assert "no exploit in Metasploit/Exploit-DB/Nuclei; PoC aggregators not consulted" in text
    assert "no public exploit found" not in text


def test_full_mode_wording_is_unchanged():
    full = {"cve": "CVE-2099-0009", "kev_available": True, "msf_available": True,
            "edb_available": True, "nuclei_available": True, "epss": 0.01, "tier": "WHITE None"}
    intel = toolkit.to_intel(full)
    assert intel.poc_consulted is True
    assert "no public exploit found" in enrich.describe(intel)
    assert "EPSS" in toolkit.to_intel({**full, "epss": None}).feeds_missing  # full mode still reports it missing


def test_local_enrichment_end_to_end_evidence_and_signals(upstream):
    assess = toolkit.make_local_assess()
    report = enrich.enrich_findings(
        [finding("CVE-2099-0001", "kev"), finding("CVE-2099-0002", "msf"), finding("CVE-2099-0009", "none")],
        assess,
    )
    kev, msf, none = report.results
    assert kev.finding.kev and "on CISA KEV since 2026-09-01" in kev.evidence
    assert msf.finding.exploit_maturity == "weaponized" and "Metasploit exploit module" in msf.evidence
    assert "PoC aggregators not consulted" in none.evidence and "no public exploit found" not in none.evidence
    assert not any(r.degraded for r in report.results)  # not consulting EPSS/PoC is not an outage
    assert report.stats.failures == 0


# --------------------------------------------------------------------------
# cache: local entries are upgraded by full, accepted by local
# --------------------------------------------------------------------------
def _entry(cve, mode=None):
    r = {"cve": cve, "kev_available": True, "msf_available": True, "edb_available": True,
         "nuclei_available": True, "epss": 0.4}
    if mode:
        r["enrich_mode"] = mode
    return r


def test_full_run_upgrades_local_cache_entries_but_local_accepts_full_ones():
    cache = IntelCache()
    cache.entries["CVE-2099-0001"] = _entry("CVE-2099-0001", "local")
    cache.entries["CVE-2099-0002"] = _entry("CVE-2099-0002")  # a full-mode entry
    calls = []

    def inner(cve):
        calls.append(cve)
        return _entry(cve)

    full = CachingAssess(inner, cache, mode="full")
    full("CVE-2099-0002")
    assert calls == [] and full.cache_hits == 1  # full entry satisfies a full request
    full("CVE-2099-0001")
    assert calls == ["CVE-2099-0001"] and "enrich_mode" not in cache.entries["CVE-2099-0001"]  # upgraded

    cache.entries["CVE-2099-0003"] = _entry("CVE-2099-0003", "local")
    local = CachingAssess(inner, cache, mode="local")
    local("CVE-2099-0003")
    local("CVE-2099-0002")
    assert calls == ["CVE-2099-0001"]  # local accepts both


def test_full_run_with_spent_budget_keeps_the_existing_local_entry():
    cache = IntelCache()
    cache.entries["CVE-2099-0001"] = _entry("CVE-2099-0001", "local")
    w = CachingAssess(lambda c: _entry(c), cache, mode="full", max_lookups=0)
    got = w("CVE-2099-0001")
    assert got["enrich_mode"] == "local" and not w.skipped  # stale-but-real beats 'unknown'
    w("CVE-2099-0005")
    assert w.skipped == {"CVE-2099-0005"}


# --------------------------------------------------------------------------
# pipeline / CLI wiring
# --------------------------------------------------------------------------
class Marker:
    def __init__(self, name, log):
        self.name, self.log = name, log

    def __call__(self, cve):
        self.log.append((self.name, cve))
        return _entry(cve, "local" if self.name == "local" else None)


def _patch_factories(monkeypatch, log):
    monkeypatch.setattr(pipeline, "make_local_assess", lambda: Marker("local", log))
    monkeypatch.setattr(pipeline, "make_default_assess", lambda: Marker("full", log))


@pytest.mark.parametrize("kwargs,expected", [({}, "local"), ({"enrich": "local"}, "local"), ({"enrich": "full"}, "full")])
def test_pipeline_selects_the_enrichment_source(navi_db, upstream, monkeypatch, kwargs, expected):
    log = []
    _patch_factories(monkeypatch, log)
    r = pipeline.run_pipeline(navi_db, OVERLAY, as_of=AS_OF, max_lookups=2, **kwargs)
    assert {name for name, _ in log} == {expected} and len(log) == 2
    assert r.enrich_mode == expected


def test_pipeline_rejects_unknown_mode(navi_db):
    with pytest.raises(ValueError):
        pipeline.run_pipeline(navi_db, OVERLAY, enrich="turbo")


def test_offline_runs_have_no_enrich_mode_and_never_build_a_live_source(navi_db, monkeypatch):
    def boom():
        raise AssertionError("live source built for an offline run")

    monkeypatch.setattr(pipeline, "make_local_assess", boom)
    monkeypatch.setattr(pipeline, "make_default_assess", boom)
    assert pipeline.run_pipeline(navi_db, OVERLAY, offline=True, as_of=AS_OF).enrich_mode is None


def test_cli_defaults_to_local_and_passes_full_through(monkeypatch, tmp_path):
    seen = []

    def fake_run(*a, **k):
        seen.append(k["enrich"])
        raise ValueError("stop after capturing")

    monkeypatch.setattr(pipeline, "run_pipeline", fake_run)
    base = ["run", "--db", "x.db", "--out", str(tmp_path / "o")]
    assert cli.main(base) == 2 and cli.main([*base, "--enrich", "full"]) == 2
    assert seen == ["local", "full"]


def test_cli_rejects_enrich_with_offline_and_bad_values(tmp_path):
    base = ["run", "--db", "x.db", "--out", str(tmp_path / "o")]
    for extra in (["--offline", "--enrich", "local"], ["--enrich", "turbo"]):
        with pytest.raises(SystemExit) as e:
            cli.main([*base, *extra])
        assert e.value.code == 2


def test_local_mode_report_header_and_cache_replay(navi_db, tmp_path, monkeypatch):
    """A local-mode live run, frozen to a cache, replays offline with the same honest wording."""
    log = []

    def local_record(cve):
        log.append(cve)
        return {**_entry(cve, "local"), "epss": None, "kev": None, "tier": "WHITE No public exploit found",
                "msf": [], "msf_exploit": [], "edb": [], "edb_verified": [], "nuclei": None,
                "nomi": [], "trickest": [], "top_star": 0}

    cache = tmp_path / "intel.json"
    live = pipeline.run_pipeline(navi_db, OVERLAY, as_of=AS_OF, intel_cache=cache, assess=local_record)
    replay = pipeline.run_pipeline(navi_db, OVERLAY, offline=True, as_of=AS_OF, intel_cache=cache)

    def csv_of(res):
        return worklist.to_csv(worklist.build_rows(res), worklist.COLUMNS)

    assert csv_of(live) == csv_of(replay)
    rows = worklist.build_rows(replay)
    assert any("PoC aggregators not consulted" in r["evidence"] for r in rows)
    assert not any("no public exploit found" in r["evidence"] for r in rows)

    md = worklist.to_markdown(live, worklist.build_rows(live), worklist.build_excluded_rows(live))
    assert "local feeds only: CISA KEV, Metasploit, Exploit-DB, Nuclei" in md
