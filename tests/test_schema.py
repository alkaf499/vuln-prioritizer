import dataclasses

import pytest

from vuln_prioritizer.schema import Asset, CvssSource, Finding, Severity, Tag


def test_severity_is_ordered():
    assert Severity.INFO < Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL


def test_asset_tag_values_case_insensitive():
    a = Asset("a1", tags=(Tag("Environment", "Production"), Tag("env", "x")))
    assert a.tag_values("environment") == ("Production",)
    assert a.tag_values("missing") == ()


def test_models_are_frozen_and_hashable():
    a = Asset("a1", exposure_classes=("INTERNET_EXPOSED",))
    f = Finding(finding_id="f1", asset=a, plugin_id="1")
    with pytest.raises(dataclasses.FrozenInstanceError):
        f.vpr_score = 9.0  # type: ignore[misc]
    assert hash(f) == hash(Finding(finding_id="f1", asset=a, plugin_id="1"))


def test_missing_values_default_to_none_not_zero():
    f = Finding(finding_id="f1", asset=Asset("a1"), plugin_id="1")
    assert f.cvss3_base_score is None and f.vpr_score is None and f.epss_score is None
    assert f.cvss3_source is CvssSource.UNKNOWN
    assert f.kev is False and f.cves == () and not f.has_cvss
