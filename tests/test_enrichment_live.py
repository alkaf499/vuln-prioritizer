"""S3 LIVE smoke test — hits the real feeds. SKIPPED by default.

Run explicitly:   pytest -m live tests/test_enrichment_live.py
Optional:         GITHUB_TOKEN=<token> to raise GitHub rate limits (env only, never committed).

Mirrors threat-intel-toolkit's healthcheck.py: canary = Log4Shell, which should
be present in every source.
"""

from __future__ import annotations

import pytest

from vuln_prioritizer.enrichment import Maturity, enrich_findings
from vuln_prioritizer.enrichment import toolkit as tk
from vuln_prioritizer.schema import Asset, Finding, Severity

pytestmark = pytest.mark.live

CANARY = "CVE-2021-44228"


def test_toolkit_healthcheck_all_sources_reachable(monkeypatch):
    ec = tk.load_exploit_check()
    scripts = tk.default_exploit_check_path().parent
    monkeypatch.syspath_prepend(str(scripts))
    import healthcheck  # upstream, same dir

    tk.install_resilient_fetch(ec)
    results = healthcheck.checks()
    failed = [r for r in results if r["status"] != "OK"]
    assert not failed, f"dead/changed feeds: {failed}"


def test_log4shell_enriches_correctly_end_to_end():
    f = Finding(finding_id="L1", asset=Asset(asset_id="a"), plugin_id="1",
                cves=(CANARY,), severity=Severity.CRITICAL)
    rep = enrich_findings([f])            # default backend: real toolkit + retry
    r = rep.results[0]
    assert r.enriched and not r.degraded, r.evidence
    assert r.finding.kev is True
    assert r.finding.exploit_maturity == Maturity.WEAPONIZED.value
    assert r.finding.epss_score is not None and r.finding.epss_score > 0.5
    assert "on CISA KEV" in r.evidence and "Metasploit" in r.evidence
    assert rep.stats.distinct_cves == 1
