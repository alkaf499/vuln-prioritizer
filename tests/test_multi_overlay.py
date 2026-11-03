"""Repeatable --overlay: consulted in the order given, first overlay with a matching rule wins,
provenance names the winning file, and a single --overlay behaves exactly as before."""

from __future__ import annotations

import csv

import pytest

from vuln_prioritizer.cli import main
from vuln_prioritizer.context import (
    ContextSource,
    Criticality,
    Environment,
    Overlay,
    OverlaySet,
    load_overlays,
    resolve_context,
)
from vuln_prioritizer.schema import Asset

HAND = """\
defaults: { environment: unknown, exposure: internal, criticality: standard, in_scope: true }
assets:
  - match: { hostname: "web-prod-01" }
    role: hand_web
    environment: production
    criticality: standard
"""

AI = """\
defaults: { environment: production, exposure: external, criticality: crown_jewel, in_scope: true }
assets:
  - match: { hostname: "web-prod-01" }
    role: ai_workstation
    environment: non_production
    source: "ai-classifier (claude-test, 2026-11-03, conf=0.95)"
    rationale: "looks like a laptop"
  - match: { hostname: "api-prod-02" }
    role: ai_server
    environment: non_production
    source: "ai-classifier (claude-test, 2026-11-03, conf=0.95)"
"""

WEB = Asset(asset_id="a1", hostname="web-prod-01")
API = Asset(asset_id="a2", hostname="api-prod-02")
NOBODY = Asset(asset_id="a3", hostname="nobody-01")


@pytest.fixture()
def overlays(tmp_path):
    hand, ai = tmp_path / "hand.yaml", tmp_path / "ai.yaml"
    hand.write_text(HAND, encoding="utf-8")
    ai.write_text(AI, encoding="utf-8")
    return hand, ai


def test_single_overlay_is_the_plain_overlay_with_todays_label(overlays):
    hand, _ = overlays
    o = load_overlays(hand)
    assert isinstance(o, Overlay) and not isinstance(o, OverlaySet)
    ctx = resolve_context(WEB, overlay=o)
    assert ctx.role.detail == "rule 1 (hand_web)"  # no file prefix: unchanged from before
    assert load_overlays(str(hand)).rules == load_overlays([hand]).rules  # str / list forms agree


def test_no_overlay_is_none():
    assert load_overlays(None) is None
    assert load_overlays([]) is None


def test_first_listed_overlay_wins_and_provenance_names_the_file(overlays):
    hand, ai = overlays
    o = load_overlays([hand, ai])
    assert isinstance(o, OverlaySet)

    web = resolve_context(WEB, overlay=o)  # both overlays have a rule: the hand one is first
    assert web.environment.value is Environment.PRODUCTION
    assert web.role.value == "hand_web"
    assert web.role.detail == "hand.yaml rule 1 (hand_web)"
    assert web.role.source is ContextSource.OVERLAY

    api = resolve_context(API, overlay=o)  # only the AI overlay knows it
    assert api.environment.value is Environment.NON_PRODUCTION
    assert api.role.detail == "ai.yaml rule 2 (ai_server)"


def test_order_decides_not_file_authority(overlays):
    hand, ai = overlays
    flipped = resolve_context(WEB, overlay=load_overlays([ai, hand]))
    assert flipped.role.value == "ai_workstation"
    assert flipped.role.detail == "ai.yaml rule 1 (ai_workstation)"


def test_defaults_come_from_the_first_overlay(overlays):
    hand, ai = overlays
    ctx = resolve_context(NOBODY, overlay=load_overlays([hand, ai]))
    assert ctx.environment.value is Environment.UNKNOWN  # hand defaults, not the AI file's
    assert ctx.criticality.value is Criticality.STANDARD
    assert ctx.reevaluate


def test_rule_metadata_source_and_rationale_are_parsed_not_matched_on(overlays):
    _, ai = overlays
    rule = load_overlays(ai).rules[0]
    assert rule.source == "ai-classifier (claude-test, 2026-11-03, conf=0.95)"
    assert rule.rationale == "looks like a laptop"


def test_same_basename_in_different_dirs_is_disambiguated(tmp_path):
    a, b = tmp_path / "x" / "o.yaml", tmp_path / "y" / "o.yaml"
    for p in (a, b):
        p.parent.mkdir()
        p.write_text(HAND, encoding="utf-8")
    labels = [r.label for r in load_overlays([a, b]).rules]
    assert labels[0].startswith("#1:o.yaml ") and labels[1].startswith("#2:o.yaml ")


def _run(navi_db, out, *overlays):
    args = ["run", "--db", str(navi_db), "--out", str(out), "--offline", "--no-timing",
            "--as-of", "2026-01-01T00:00:00Z"]  # fmt: skip
    for o in overlays:
        args += ["--overlay", str(o)]
    assert main(args) == 0
    with open(out / "worklist.csv", newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def test_worklist_provenance_names_the_winning_overlay_file(navi_db, overlays, tmp_path):
    hand, ai = overlays
    rows = _run(navi_db, tmp_path / "out", hand, ai)
    web = [r for r in rows if r["asset"] == "web-prod-01"]
    assert web, "fixture asset web-prod-01 should carry findings"
    assert {r["overlay_rule"] for r in web} == {"hand.yaml rule 1 (hand_web)"}
    for r in rows:
        if r["asset"] == "api-prod-02":
            assert r["overlay_rule"] == "ai.yaml rule 2 (ai_server)"


def test_single_overlay_run_has_unprefixed_provenance(navi_db, overlays, tmp_path):
    hand, _ = overlays
    rows = _run(navi_db, tmp_path / "out", hand)
    assert {r["overlay_rule"] for r in rows if r["asset"] == "web-prod-01"} == {"rule 1 (hand_web)"}


def test_same_frozen_overlays_give_byte_identical_outputs(navi_db, overlays, tmp_path):
    """The determinism pitch: the pipeline never learns who wrote an overlay, so the same
    frozen files give the same bytes."""
    hand, ai = overlays
    _run(navi_db, tmp_path / "one", hand, ai)
    _run(navi_db, tmp_path / "two", hand, ai)
    for name in ("worklist.csv", "worklist.md", "excluded.csv", "informational.csv", "executive_report.md"):
        assert (tmp_path / "one" / name).read_bytes() == (tmp_path / "two" / name).read_bytes(), name


def test_ai_overlay_changes_only_what_it_covers(navi_db, overlays, tmp_path):
    """Adding the AI overlay AFTER the hand overlay must not change assets the hand overlay
    already classifies."""
    hand, ai = overlays
    solo = {r["finding_id"]: r for r in _run(navi_db, tmp_path / "solo", hand)}
    both = {r["finding_id"]: r for r in _run(navi_db, tmp_path / "both", hand, ai)}
    for fid, r in solo.items():
        if r["asset"] == "web-prod-01":
            assert both[fid]["tier"] == r["tier"] and both[fid]["environment"] == r["environment"]
