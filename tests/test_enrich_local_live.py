"""Real-feed check of --enrich local. Network + a one-time ~35 MB feed download: skipped by default.

    pytest -m live tests/test_enrich_local_live.py
"""

import pytest

from vuln_prioritizer.enrichment import enrich, toolkit

pytestmark = pytest.mark.live


def test_local_assess_against_the_real_cached_feeds():
    assess = toolkit.make_local_assess()
    raw = assess("CVE-2021-44228")  # Log4Shell: on KEV, Metasploit module, Nuclei template
    intel = toolkit.to_intel(raw)
    assert raw["enrich_mode"] == "local" and raw["epss"] is None  # per-CVE EPSS was NOT called
    assert raw["nomi"] == [] and raw["trickest"] == []  # nor were the PoC aggregators
    assert intel.kev and intel.msf_modules
    assert "PoC aggregators" not in enrich.describe(intel)  # a positive finding needs no caveat
