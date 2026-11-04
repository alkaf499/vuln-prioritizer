"""S3 enrichment — OFFLINE unit tests. No network: every upstream call is mocked."""

from __future__ import annotations

import email.message
import urllib.error
from datetime import datetime

import pytest

from vuln_prioritizer.enrichment import (
    Divergence,
    Maturity,
    enrich_findings,
    passes_gate,
    to_intel,
)
from vuln_prioritizer.enrichment import toolkit as tk
from vuln_prioritizer.schema import Asset, CveSignal, CvssSource, Finding, Severity
from vuln_prioritizer.scoring.layer1 import Band, score_layer1

LOG4J = "CVE-2021-44228"


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def raw(cve=LOG4J, **kw):
    """An exploit_check.assess()-shaped dict; defaults = all feeds up, nothing found."""
    d = dict(
        cve=cve, kev=None, kev_available=True, epss=None, epss_pctl=None,
        msf=[], msf_exploit=[], msf_available=True,
        nuclei=None, nuclei_available=True,
        edb=[], edb_verified=[], edb_available=True,
        nomi=[], trickest=[], top_star=0,
        tier="WHITE No public exploit found",
    )
    d.update(kw)
    return d


def log4shell_raw(cve=LOG4J):
    return raw(
        cve,
        kev={"dateAdded": "2021-12-10", "knownRansomwareCampaignUse": "Known",
             "vulnerabilityName": "Log4j RCE"},
        epss=0.97, epss_pctl=0.9999,
        msf=[{"fullname": "exploit/multi/http/log4shell_header_injection", "type": "exploit"}],
        msf_exploit=[{"fullname": "exploit/multi/http/log4shell_header_injection"}],
        edb=[{"id": "50592"}, {"id": "50590"}],
        nuclei={"Severity": "critical"},
        nomi=[{"stargazers_count": 1200}], top_star=1200, trickest=["x"],
        tier="RED Weaponized",
    )


def mk(fid="F1", cves=(LOG4J,), asset="a1", **kw):
    return Finding(finding_id=fid, asset=Asset(asset_id=asset), plugin_id="1", cves=tuple(cves), **kw)


class FakeAssess:
    """Records every call; serves canned raw dicts (default: nothing found)."""

    def __init__(self, table=None, boom=()):
        self.table = table or {}
        self.boom = set(boom)
        self.calls: list[str] = []

    def __call__(self, cve):
        self.calls.append(cve)
        if cve in self.boom:
            raise RuntimeError("feed exploded")
        return self.table.get(cve, raw(cve))


# --------------------------------------------------------------------------
# mapping
# --------------------------------------------------------------------------
def test_maps_kev_epss_maturity_and_signals():
    fake = FakeAssess({LOG4J: log4shell_raw()})
    rep = enrich_findings([mk(severity=Severity.CRITICAL)], fake)
    f = rep.results[0].finding
    assert f.kev is True
    assert f.kev_added == datetime(2021, 12, 10)
    assert f.epss_score == 0.97 and f.epss_cve == LOG4J and f.epss_percentile == 0.9999
    assert f.exploit_maturity == "weaponized"
    assert f.cve_signals == (
        CveSignal(cve=LOG4J, cvss_base_score=None, cvss_source=CvssSource.UNKNOWN,
                  epss_score=0.97, kev=True, source="exploit-availability-check"),
    )
    assert rep.results[0].enriched and not rep.results[0].degraded


@pytest.mark.parametrize(
    "tier,expected",
    [("RED Weaponized", Maturity.WEAPONIZED), ("ORANGE Public working exploit", Maturity.PUBLIC_EXPLOIT),
     ("YELLOW Proof-of-concept only", Maturity.POC), ("WHITE No public exploit found", Maturity.NONE)],
)
def test_tier_to_maturity(tier, expected):
    assert to_intel(raw(tier=tier)).maturity is expected


def test_white_with_dead_exploit_feed_is_unknown_not_none():
    i = to_intel(raw(msf_available=False))
    assert i.maturity is Maturity.UNKNOWN
    assert "Metasploit" in i.feeds_missing and i.degraded


def test_kev_feed_down_is_unknown_not_false():
    i = to_intel(raw(kev_available=False))
    assert i.kev is False and i.kev_known is False


def test_never_lowers_source_data():
    f = mk(severity=Severity.HIGH, kev=True, epss_score=0.95, epss_cve="CVE-2021-44228")
    out = enrich_findings([f], FakeAssess({LOG4J: raw(epss=0.2)})).results[0].finding
    assert out.kev is True and out.epss_score == 0.95


def test_multi_cve_worst_case():
    a, b = "CVE-2020-0001", "CVE-2020-0002"
    fake = FakeAssess({a: raw(a, epss=0.3, tier="YELLOW Proof-of-concept only"),
                       b: raw(b, epss=0.8, tier="RED Weaponized")})
    f = enrich_findings([mk(cves=(a, b), severity=Severity.HIGH)], fake).results[0].finding
    assert f.epss_score == 0.8 and f.epss_cve == b
    assert f.exploit_maturity == "weaponized"
    assert {s.cve for s in f.cve_signals} == {a, b}


def test_existing_signals_are_merged_not_clobbered():
    sig = CveSignal(cve=LOG4J, cvss_base_score=10.0, cvss_source=CvssSource.NVD, epss_score=0.1)
    f = mk(severity=Severity.HIGH, cve_signals=(sig,))
    out = enrich_findings([f], FakeAssess({LOG4J: log4shell_raw()})).results[0].finding
    (s,) = out.cve_signals
    assert s.cvss_base_score == 10.0 and s.cvss_source is CvssSource.NVD
    assert s.epss_score == 0.97 and s.kev is True


def test_invalid_cve_ids_are_never_looked_up():
    fake = FakeAssess()
    rep = enrich_findings([mk(cves=("not-a-cve", "CVE-2021-1/../x"), severity=Severity.HIGH)], fake)
    assert fake.calls == [] and rep.stats.skipped_invalid_cves == 2
    assert not rep.results[0].enriched


# --------------------------------------------------------------------------
# gate
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    "kw,expected",
    [
        (dict(severity=Severity.HIGH), True),
        (dict(severity=Severity.CRITICAL), True),
        (dict(severity=Severity.MEDIUM), False),
        (dict(severity=None), False),
        (dict(severity=Severity.LOW, kev=True), True),
        (dict(severity=Severity.LOW, cve_signals=(CveSignal(cve=LOG4J, kev=True),)), True),
        (dict(severity=Severity.LOW, epss_score=0.10), True),   # boundary inclusive
        (dict(severity=Severity.LOW, epss_score=0.0999), False),
        (dict(severity=Severity.LOW, cve_signals=(CveSignal(cve=LOG4J, epss_score=0.5),)), True),
        # CVSS >= 7 gate (non-Tenable sources with no scan severity)
        (dict(severity=None, cvss3_base_score=7.0), True),          # boundary inclusive
        (dict(severity=None, cvss3_base_score=6.9), False),
        (dict(severity=None, cvss3_base_score=9.8, cvss3_source=CvssSource.NVD), True),
        (dict(severity=Severity.LOW, cvss3_base_score=8.1), True),  # CVSS beats low severity
        (dict(severity=None, cvss2_base_score=7.5), True),
        (dict(severity=None, cvss2_base_score=6.9), False),
        (dict(severity=None, cve_signals=(CveSignal(cve=LOG4J, cvss_base_score=7.2),)), True),
        (dict(severity=None, cve_signals=(CveSignal(cve=LOG4J, cvss_base_score=3.0),)), False),
        (dict(severity=None), False),
    ],
)
def test_gate(kw, expected):
    assert passes_gate(mk(**kw)) is expected


def test_only_gated_findings_are_fetched():
    fake = FakeAssess()
    low = mk("L", cves=("CVE-2020-1111",), severity=Severity.MEDIUM)
    high = mk("H", cves=("CVE-2020-2222",), severity=Severity.HIGH)
    rep = enrich_findings([low, high], fake)
    assert fake.calls == ["CVE-2020-2222"]
    assert rep.stats.gated == 1 and rep.stats.findings == 2
    assert rep.results[0].finding is low and not rep.results[0].enriched
    assert "below enrichment gate" in rep.results[0].evidence


def test_high_cvss_without_severity_is_fetched():
    fake = FakeAssess()
    f = mk("N", cves=("CVE-2020-3333",), severity=None, cvss3_base_score=8.8)
    rep = enrich_findings([f], fake)
    assert fake.calls == ["CVE-2020-3333"] and rep.results[0].enriched


def test_nothing_gated_means_no_backend_is_even_created(monkeypatch):
    def explode():
        raise AssertionError("default backend must not be built when nothing is gated")

    monkeypatch.setattr("vuln_prioritizer.enrichment.enrich.make_default_assess", explode)
    rep = enrich_findings([mk(severity=Severity.LOW)])
    assert rep.stats.distinct_cves == 0


# --------------------------------------------------------------------------
# memoization
# --------------------------------------------------------------------------
def test_one_fetch_per_distinct_cve_fanned_out_to_500_assets():
    fake = FakeAssess({LOG4J: log4shell_raw()})
    fs = [mk(f"F{n}", asset=f"asset-{n}", severity=Severity.CRITICAL) for n in range(500)]
    rep = enrich_findings(fs, fake)
    assert fake.calls == [LOG4J]                      # exactly one lookup
    assert rep.stats.distinct_cves == 1 and rep.stats.gated == 500
    assert all(r.finding.kev and r.finding.epss_score == 0.97 for r in rep.results)
    assert [r.finding.finding_id for r in rep.results] == [f.finding_id for f in fs]


def test_overlapping_multi_cve_findings_fetch_each_cve_once_sorted():
    c1, c2, c3 = "CVE-2020-0001", "CVE-2020-0002", "CVE-2020-0003"
    fake = FakeAssess()
    enrich_findings(
        [mk("A", cves=(c3, c2), severity=Severity.HIGH),
         mk("B", cves=(c2, c1), severity=Severity.HIGH),
         mk("C", cves=(c1,), severity=Severity.HIGH)],
        fake,
    )
    assert fake.calls == [c1, c2, c3]


def test_cve_only_on_ungated_findings_is_not_fetched():
    shared = "CVE-2020-0009"
    fake = FakeAssess()
    enrich_findings([mk("L", cves=(shared,), severity=Severity.LOW),
                     mk("H", cves=("CVE-2020-0010",), severity=Severity.HIGH)], fake)
    assert shared not in fake.calls


def test_deterministic():
    fs = [mk("A", severity=Severity.HIGH), mk("B", cves=("CVE-2020-0001",), severity=Severity.HIGH)]
    table = {LOG4J: log4shell_raw()}
    assert enrich_findings(fs, FakeAssess(table)) == enrich_findings(fs, FakeAssess(table))


# --------------------------------------------------------------------------
# graceful degradation
# --------------------------------------------------------------------------
def test_dead_lookup_yields_unknown_not_crash():
    bad, good = "CVE-2020-0001", LOG4J
    fake = FakeAssess({good: log4shell_raw()}, boom={bad})
    rep = enrich_findings(
        [mk("bad", cves=(bad,), severity=Severity.HIGH), mk("good", severity=Severity.HIGH)], fake
    )
    b, g = rep.results
    assert rep.stats.failures == 1
    assert b.degraded and b.finding.kev is False and b.finding.exploit_maturity is None
    assert "failed" in b.evidence and "unknown" in b.evidence
    assert g.finding.kev is True and not g.degraded   # one bad CVE doesn't poison the rest


def test_partial_feed_outage_is_flagged_degraded_with_unknown_wording():
    fake = FakeAssess({LOG4J: raw(kev_available=False, msf_available=False, epss=0.4)})
    r = enrich_findings([mk(severity=Severity.HIGH)], fake).results[0]
    assert r.degraded
    assert "CISA KEV status unknown" in r.evidence
    assert "exploit maturity unknown (Metasploit unreachable)" in r.evidence
    assert r.finding.exploit_maturity is None


# --------------------------------------------------------------------------
# evidence strings
# --------------------------------------------------------------------------
def test_evidence_string_log4shell():
    r = enrich_findings([mk(severity=Severity.CRITICAL)], FakeAssess({LOG4J: log4shell_raw()})).results[0]
    assert r.evidence == (
        "on CISA KEV since 2021-12-10 (known ransomware use); Metasploit exploit module; "
        "Exploit-DB 2 entries; Nuclei template; 1 GitHub PoC repo, top 1200★; EPSS 97%"
    )


def test_evidence_none_found():
    r = enrich_findings([mk(severity=Severity.HIGH)], FakeAssess({LOG4J: raw(epss=0.02)})).results[0]
    assert r.evidence == "no public exploit found; EPSS 2%"


def test_evidence_multi_cve_is_prefixed():
    a, b = "CVE-2020-0001", "CVE-2020-0002"
    r = enrich_findings([mk(cves=(a, b), severity=Severity.HIGH)], FakeAssess()).results[0]
    assert r.evidence.startswith(f"{a}: ") and f" | {b}: " in r.evidence


# --------------------------------------------------------------------------
# divergence
# --------------------------------------------------------------------------
def test_divergence_low_vpr_but_kev():
    r = enrich_findings([mk(severity=Severity.HIGH, vpr_score=2.1)],
                        FakeAssess({LOG4J: log4shell_raw()})).results[0]
    assert r.divergence == (Divergence.VPR_LOW_BUT_EXPLOITED,)
    assert "DIVERGENCE" in r.evidence


def test_divergence_low_vpr_but_weaponized_without_kev():
    t = raw(tier="RED Weaponized")
    r = enrich_findings([mk(severity=Severity.HIGH, vpr_score=3.9)], FakeAssess({LOG4J: t})).results[0]
    assert r.divergence == (Divergence.VPR_LOW_BUT_EXPLOITED,)


def test_divergence_high_vpr_no_exploit_signal():
    r = enrich_findings([mk(severity=Severity.HIGH, vpr_score=9.4)],
                        FakeAssess({LOG4J: raw(epss=0.01)})).results[0]
    assert r.divergence == (Divergence.VPR_HIGH_NO_EXPLOIT_SIGNAL,)


def test_no_divergence_when_feeds_down_or_vpr_absent_or_consistent():
    hi = mk(severity=Severity.HIGH, vpr_score=9.4)
    assert enrich_findings([hi], FakeAssess({LOG4J: raw(epss=0.01, msf_available=False)})).results[0].divergence == ()
    assert enrich_findings([mk(severity=Severity.HIGH)], FakeAssess({LOG4J: log4shell_raw()})).results[0].divergence == ()
    assert enrich_findings([mk(severity=Severity.HIGH, vpr_score=9.4)],
                           FakeAssess({LOG4J: log4shell_raw()})).results[0].divergence == ()


# --------------------------------------------------------------------------
# end-to-end with the real scorer: KEV floor + VPR-absent EPSS fallback
# --------------------------------------------------------------------------
def test_enrichment_feeds_the_kev_floor():
    f = mk(severity=Severity.HIGH, cvss3_base_score=5.0, cvss3_source=CvssSource.NVD)
    before = score_layer1(f)
    out = enrich_findings([f], FakeAssess({LOG4J: raw(kev={"dateAdded": "2022-01-01"})})).results[0].finding
    after = score_layer1(out)
    assert before.probability.impact_only
    assert after.probability.band is Band.HIGH and after.probability.kev_floor_applied


def test_enrichment_feeds_the_epss_fallback_when_vpr_absent():
    f = mk(severity=Severity.HIGH, cvss3_base_score=9.8, cvss3_source=CvssSource.NVD)
    out = enrich_findings([f], FakeAssess({LOG4J: raw(epss=0.95)})).results[0].finding
    p = score_layer1(out).probability
    assert p.source.value == "epss" and p.band is Band.CRITICAL and p.cve == LOG4J


# --------------------------------------------------------------------------
# resilient fetch: retry / backoff / token
# --------------------------------------------------------------------------
class _Resp:
    def __init__(self, body=b"ok"):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return self.body


def http_error(code, headers=None):
    m = email.message.Message()
    for k, v in (headers or {}).items():
        m[k] = v
    return urllib.error.HTTPError("http://x", code, "err", m, None)


def scripted_opener(*script):
    """Each call pops the next item: exception -> raised, bytes -> returned. Records requests."""
    seen = []
    items = list(script)

    def opener(req, timeout=None):
        seen.append(req)
        item = items.pop(0)
        if isinstance(item, BaseException):
            raise item
        return _Resp(item)

    opener.seen = seen
    return opener


def test_retries_then_succeeds_with_exponential_backoff():
    sleeps = []
    op = scripted_opener(urllib.error.URLError("down"), TimeoutError(), b"data")
    fetch = tk.make_resilient_fetch(urlopen=op, sleep=sleeps.append, base_delay=1.0)
    assert fetch("https://api.first.org/x") == b"data"
    assert sleeps == [1.0, 2.0] and len(op.seen) == 3


def test_gives_up_after_attempts_and_raises_last_error():
    sleeps = []
    op = scripted_opener(*[urllib.error.URLError("down")] * 3)
    fetch = tk.make_resilient_fetch(urlopen=op, sleep=sleeps.append, attempts=3)
    with pytest.raises(urllib.error.URLError):
        fetch("https://api.first.org/x")
    assert len(op.seen) == 3 and len(sleeps) == 2   # no sleep after the final attempt


def test_404_is_not_retried():
    op = scripted_opener(http_error(404))
    fetch = tk.make_resilient_fetch(urlopen=op, sleep=lambda s: None)
    with pytest.raises(urllib.error.HTTPError):
        fetch("https://raw.githubusercontent.com/x")
    assert len(op.seen) == 1


def test_429_honours_retry_after_and_github_403_ratelimit_is_retried():
    sleeps = []
    op = scripted_opener(http_error(429, {"Retry-After": "7"}),
                         http_error(403, {"X-RateLimit-Remaining": "0"}), b"ok")
    fetch = tk.make_resilient_fetch(urlopen=op, sleep=sleeps.append, base_delay=1.0)
    assert fetch("https://raw.githubusercontent.com/x") == b"ok"
    assert sleeps == [7.0, 2.0]


def test_plain_403_is_not_retried():
    op = scripted_opener(http_error(403))
    fetch = tk.make_resilient_fetch(urlopen=op, sleep=lambda s: None)
    with pytest.raises(urllib.error.HTTPError):
        fetch("https://raw.githubusercontent.com/x")
    assert len(op.seen) == 1


def test_token_sent_only_to_github_hosts():
    op = scripted_opener(b"a", b"b", b"c")
    fetch = tk.make_resilient_fetch(urlopen=op, token="SECRET", headers={"User-Agent": "t"})
    fetch("https://raw.githubusercontent.com/x")
    fetch("https://api.first.org/x")
    fetch("https://www.cisa.gov/x")
    gh, first, cisa = op.seen
    assert gh.get_header("Authorization") == "token SECRET"
    assert first.get_header("Authorization") is None and cisa.get_header("Authorization") is None
    assert gh.get_header("User-agent") == "t"


def test_install_reads_token_from_env_only(monkeypatch):
    class Mod:
        UA = {"User-Agent": "u"}

    monkeypatch.setenv("GITHUB_TOKEN", "FROM_ENV")
    m = Mod()
    assert tk.install_resilient_fetch(m) == "GITHUB_TOKEN"
    monkeypatch.delenv("GITHUB_TOKEN")
    assert tk.install_resilient_fetch(Mod()) is None


# --------------------------------------------------------------------------
# the REAL upstream script, with the network forced dead (still offline)
# --------------------------------------------------------------------------
def test_real_exploit_check_degrades_to_unknown_when_all_feeds_dead(monkeypatch, tmp_path):
    try:
        ec = tk.load_exploit_check()
    except FileNotFoundError as exc:
        pytest.skip(f"upstream exploit_check.py not vendored into reference/: {exc}")
    monkeypatch.setattr(ec, "CACHE", str(tmp_path))      # never touch ~/.cache
    monkeypatch.setattr(ec, "_IDX", {})
    monkeypatch.setattr(ec, "_fetch_bytes", ec._fetch_bytes)  # restored on teardown

    def boom(*a, **k):
        raise urllib.error.URLError("network disabled in unit tests")

    tk.install_resilient_fetch(ec, urlopen=boom, sleep=lambda s: None, attempts=2, token=None)
    rep = enrich_findings([mk(severity=Severity.CRITICAL)], ec.assess)
    r = rep.results[0]
    assert r.enriched and r.degraded
    assert r.finding.kev is False and r.finding.exploit_maturity is None
    assert "status unknown" in r.evidence and rep.stats.failures == 0
