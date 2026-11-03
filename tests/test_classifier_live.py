"""One real classification call on three synthetic assets. Skipped by default
(`addopts = -m 'not live'`); run with:  ANTHROPIC_API_KEY=... pytest -m live tests/test_classifier_live.py
Costs a fraction of a cent on the default (Haiku-class) model."""

from __future__ import annotations

import pytest

from vuln_prioritizer.classifier.cache import AssetKey, ClassifierCache
from vuln_prioritizer.classifier.engine import classify_keys
from vuln_prioritizer.classifier.llm import DEFAULT_MODEL, AnthropicHTTP, api_key_from_env
from vuln_prioritizer.classifier.render import render_overlay
from vuln_prioritizer.classifier.validate import Classification, abstain_reason
from vuln_prioritizer.context import parse_overlay


@pytest.mark.live
def test_live_classifies_three_synthetic_assets():
    key = api_key_from_env()
    if not key:
        pytest.skip("ANTHROPIC_API_KEY not set")
    ks = [
        AssetKey("endpoint #17", "Microsoft Windows 10 Pro"),
        AssetKey("plc #3", "Siemens SIMATIC S7-1500"),
        AssetKey("fw-edge-01", "Palo Alto Networks PAN-OS 10.2"),
    ]
    out = classify_keys(ks, llm=AnthropicHTTP(key), model=DEFAULT_MODEL, today="2026-11-03",
                        cache=ClassifierCache(None), batch_size=3)  # fmt: skip
    assert out.sent == 3 and out.batches == 1
    assert len(out.classified) + len(out.rejected) == 3  # every asset was answered or explicitly rejected
    assert out.classified, f"nothing usable came back: {out.rejected}"
    for c in out.classified.values():
        assert isinstance(c, Classification) and c.model == DEFAULT_MODEL

    text, abstained = render_overlay(out.classified, min_confidence=0.7, rejected=out.rejected)
    rules = parse_overlay(text).rules
    assert len(rules) + len(abstained) == 3
    for r in rules:
        assert r.source.startswith(f"ai-classifier ({DEFAULT_MODEL}, 2026-11-03, conf=")
    assert all(abstain_reason(c, 0.7) is None for k, c in out.classified.items() if k.hostname in {dict(r.match)["hostname"] for r in rules})
