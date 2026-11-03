"""Frozen dated intel cache: write-through live runs, resume, --max-lookups ordering, replay.

The live code path is exercised with an INJECTED fake ``assess`` — no network, ever.
"""

import json
import socket
from datetime import datetime, timezone
from pathlib import Path

import pytest

from vuln_prioritizer import cli, pipeline, worklist
from vuln_prioritizer.adapters.navi import load_findings
from vuln_prioritizer.context import load_overlay
from vuln_prioritizer.enrichment import enrich
from vuln_prioritizer.enrichment.cache import IntelCache, IntelCacheError, is_degraded
from vuln_prioritizer.enrichment.offline import load_intel_cache
from vuln_prioritizer.scoring.layer2 import score_findings

AS_OF = datetime(2026, 11, 3, 12, 0, 0, tzinfo=timezone.utc)
OVERLAY = Path(__file__).resolve().parents[1] / "classification.example.yaml"


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("network / live toolkit used in the default suite")

    monkeypatch.setattr(socket.socket, "connect", boom)
    monkeypatch.setattr(enrich, "make_default_assess", boom)
    monkeypatch.setattr(pipeline, "make_default_assess", boom)
    monkeypatch.setattr(pipeline, "make_local_assess", boom)


def record(cve, *, kev=False):
    """A complete, non-degraded upstream assess()-shaped record."""
    return {
        "cve": cve, "kev_available": True,
        "kev": {"dateAdded": "2026-09-01"} if kev else None,
        "msf_available": True, "edb_available": True, "nuclei_available": True,
        "epss": 0.5, "epss_pctl": 0.9, "tier": "WHITE No public exploit found",
        "msf": [], "msf_exploit": [], "edb": [], "edb_verified": [], "nuclei": None,
        "nomi": [], "trickest": [], "top_star": 0,
    }  # fmt: skip


class Fake:
    def __init__(self, fail=(), degraded=False):
        self.calls, self.fail, self.degraded = [], set(fail), degraded

    def __call__(self, cve):
        self.calls.append(cve)
        if cve in self.fail:
            raise RuntimeError("feed down")
        r = record(cve)
        if self.degraded:
            r["kev_available"] = False
        return r


def run(navi_db, **kw):
    kw.setdefault("as_of", AS_OF)
    return pipeline.run_pipeline(navi_db, OVERLAY, **kw)


def csv_of(result):
    return worklist.to_csv(worklist.build_rows(result), worklist.COLUMNS)


def priority(navi_db):
    return pipeline.priority_cves(load_findings(navi_db), load_overlay(OVERLAY), AS_OF)


# --------------------------------------------------------------------------
# file format
# --------------------------------------------------------------------------
def test_cache_file_is_dated_sorted_atomic_and_backward_compatible(tmp_path):
    p = tmp_path / "intel.json"
    c = IntelCache(p)
    c.put("cve-2099-0002", record("CVE-2099-0002"))
    c.put("cve-2099-0001", record("CVE-2099-0001"))
    c.stamp(AS_OF)
    c.save()

    data = json.loads(p.read_text(encoding="utf-8"))
    assert data["_meta"] == {
        "as_of": AS_OF.isoformat(), "updated": AS_OF.isoformat(), "entries": 2, "format": 1,
    }
    assert [k for k in data if k != "_meta"] == ["CVE-2099-0001", "CVE-2099-0002"]
    assert not list(tmp_path.glob("*.tmp"))

    again = IntelCache.load(p)
    assert again.as_of == AS_OF.isoformat() and set(again.entries) == {"CVE-2099-0001", "CVE-2099-0002"}
    assert set(load_intel_cache(p)) == {"CVE-2099-0001", "CVE-2099-0002"}  # _meta is not a CVE

    # a later run keeps the ORIGINAL as_of and moves `updated`
    later = datetime(2026, 11, 9, tzinfo=timezone.utc)
    again.put("CVE-2099-0003", record("CVE-2099-0003"))
    again.stamp(later)
    again.save()
    meta = json.loads(p.read_text(encoding="utf-8"))["_meta"]
    assert meta["as_of"] == AS_OF.isoformat() and meta["updated"] == later.isoformat() and meta["entries"] == 3


def test_old_format_cache_without_meta_still_loads(tmp_path):
    p = tmp_path / "old.json"
    p.write_text(json.dumps({"CVE-2099-0001": record("CVE-2099-0001")}), encoding="utf-8")
    c = IntelCache.load(p)
    assert set(c.entries) == {"CVE-2099-0001"} and c.as_of is None


def test_missing_cache_is_empty_for_live_but_an_error_for_offline_replay(navi_db, tmp_path):
    assert IntelCache.load(tmp_path / "nope.json").entries == {}
    with pytest.raises(FileNotFoundError):
        pipeline.run_pipeline(navi_db, OVERLAY, offline=True, intel_cache=tmp_path / "nope.json", as_of=AS_OF)


def test_malformed_meta_is_rejected(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text('{"_meta": 5}', encoding="utf-8")
    with pytest.raises(IntelCacheError):
        IntelCache.load(p)


def test_degraded_means_a_core_feed_was_down():
    assert not is_degraded(record("CVE-2099-0001"))
    assert is_degraded({**record("CVE-2099-0001"), "kev_available": False})
    assert is_degraded({**record("CVE-2099-0001"), "msf_available": False})
    assert not is_degraded({**record("CVE-2099-0001", kev=True), "kev_available": False})  # KEV hit is positive


# --------------------------------------------------------------------------
# live write-through, replay, determinism
# --------------------------------------------------------------------------
def test_live_run_writes_a_dated_cache_and_offline_replay_is_byte_identical(navi_db, tmp_path):
    cache = tmp_path / "intel.json"
    fake = Fake()
    live = run(navi_db, assess=fake, intel_cache=cache)

    assert len(fake.calls) == len(set(fake.calls)) == live.lookups.fetched > 0  # one lookup per CVE
    assert json.loads(cache.read_text(encoding="utf-8"))["_meta"]["as_of"] == AS_OF.isoformat()
    assert live.intel_as_of == AS_OF.isoformat()

    replay = run(navi_db, offline=True, intel_cache=cache)
    assert csv_of(replay) == csv_of(live)  # the live-enriched worklist is reproducible offline
    assert worklist.to_csv(worklist.build_excluded_rows(replay), worklist.EXCLUDED_COLUMNS) == worklist.to_csv(
        worklist.build_excluded_rows(live), worklist.EXCLUDED_COLUMNS
    )

    # a second live run is served entirely from the cache
    again = Fake()
    third = run(navi_db, assess=again, intel_cache=cache)
    assert again.calls == [] and third.lookups.fetched == 0 and third.lookups.cache_hits == live.lookups.fetched
    assert csv_of(third) == csv_of(live)

    # the replay report is dated by the frozen intel
    md = worklist.to_markdown(replay, worklist.build_rows(replay), worklist.build_excluded_rows(replay))
    assert "frozen threat-intel cache `intel.json`" in md and f"intel as of {AS_OF.isoformat()}" in md


def test_cli_replay_of_a_live_cache(navi_db, tmp_path):
    cache = tmp_path / "intel.json"
    run(navi_db, assess=Fake(), intel_cache=cache)
    args = ["run", "--db", str(navi_db), "--overlay", str(OVERLAY), "--offline",
            "--intel-cache", str(cache), "--as-of", AS_OF.isoformat()]
    assert cli.main([*args, "--out", str(tmp_path / "a")]) == 0
    assert cli.main([*args, "--out", str(tmp_path / "b")]) == 0
    for f in ("worklist.md", "worklist.csv", "excluded.csv"):
        assert (tmp_path / "a" / f).read_bytes() == (tmp_path / "b" / f).read_bytes()
    assert "frozen threat-intel cache `intel.json`" in (tmp_path / "a" / "worklist.md").read_text(encoding="utf-8")


def test_cli_offline_with_a_missing_cache_is_a_clean_error(navi_db, tmp_path, capsys):
    rc = cli.main(["run", "--db", str(navi_db), "--out", str(tmp_path / "o"), "--offline",
                   "--intel-cache", str(tmp_path / "nope.json")])
    assert rc == 2 and "not found" in capsys.readouterr().err


# --------------------------------------------------------------------------
# --max-lookups: rank order, deferral, resume
# --------------------------------------------------------------------------
def test_priority_order_starts_with_the_top_ranked_finding(navi_db):
    findings = load_findings(navi_db)
    by_id = {f.finding_id: f for f in findings}
    order = priority(navi_db)
    assert len(order) == len(set(order)) > 5
    top = next(
        sf for sf in score_findings(findings, overlay=load_overlay(OVERLAY), as_of=AS_OF).scored
        if enrich.passes_gate(by_id[sf.finding_id])
    )
    assert order[0] in by_id[top.finding_id].cves
    assert priority(navi_db) == order  # deterministic


def test_max_lookups_fetches_top_ranked_first_defers_the_rest_and_resumes(navi_db, tmp_path):
    order = priority(navi_db)
    cache = tmp_path / "intel.json"

    first = Fake()
    r1 = run(navi_db, assess=first, intel_cache=cache, max_lookups=3)
    assert first.calls == order[:3]  # rank order, exactly N
    assert (r1.lookups.fetched, r1.lookups.deferred) == (3, len(order) - 3)
    assert r1.skipped_cves == frozenset(order[3:])
    assert set(IntelCache.load(cache).entries) == set(order[:3])

    rows = worklist.build_rows(r1)
    assert any(r["evidence"].startswith("[lookup budget reached") for r in rows)
    assert not any("unreachable" in r["evidence"] for r in rows)  # deferred != down

    second = Fake()
    r2 = run(navi_db, assess=second, intel_cache=cache)  # resume, no cap
    assert second.calls == order[3:]  # only what is missing, nothing repeated
    assert (r2.lookups.cache_hits, r2.lookups.deferred) == (3, 0)

    full = run(navi_db, assess=Fake(), intel_cache=tmp_path / "full.json")
    assert csv_of(r2) == csv_of(full)  # resumed result == one uninterrupted run


def test_max_lookups_zero_looks_up_nothing_but_still_runs(navi_db, tmp_path):
    fake = Fake()
    r = run(navi_db, assess=fake, intel_cache=tmp_path / "i.json", max_lookups=0)
    assert fake.calls == [] and r.lookups.fetched == 0 and r.lookups.deferred > 0


def test_max_lookups_rules():
    with pytest.raises(ValueError):
        pipeline.run_pipeline("x", offline=True, max_lookups=5)
    with pytest.raises(SystemExit) as e:
        cli.main(["run", "--db", "x", "--out", "o", "--offline", "--max-lookups", "5"])
    assert e.value.code == 2
    with pytest.raises(SystemExit) as e:
        cli.main(["run", "--db", "x", "--out", "o", "--max-lookups", "-1"])
    assert e.value.code == 2


# --------------------------------------------------------------------------
# failures, degraded feeds, progress
# --------------------------------------------------------------------------
def test_failed_lookup_is_not_cached_and_is_retried_next_run(navi_db, tmp_path):
    order = priority(navi_db)
    bad = order[0]
    cache = tmp_path / "intel.json"

    first = Fake(fail={bad})
    r1 = run(navi_db, assess=first, intel_cache=cache)
    assert first.calls == order  # the failure did not stop the run, and was not retried in-run
    assert r1.lookups.failed == 1 and bad not in IntelCache.load(cache).entries
    assert any("lookup failed" in r["evidence"] for r in worklist.build_rows(r1))

    second = Fake()
    r2 = run(navi_db, assess=second, intel_cache=cache)
    assert second.calls == [bad] and r2.lookups.failed == 0


def test_degraded_records_are_used_in_memory_but_never_frozen(navi_db, tmp_path):
    cache = tmp_path / "intel.json"
    fake = Fake(degraded=True)
    r = run(navi_db, assess=fake, intel_cache=cache)
    assert len(fake.calls) == len(set(fake.calls))  # not re-fetched within the run
    assert r.lookups.uncached_degraded == r.lookups.fetched > 0
    assert not cache.exists()  # nothing worth freezing: a later run retries them


def test_progress_lines_are_emitted(navi_db, tmp_path):
    msgs = []
    r = run(navi_db, assess=Fake(), intel_cache=tmp_path / "i.json", progress=msgs.append, progress_every=5)
    assert len(msgs) >= 3
    assert all(m.startswith("enrich: ") for m in msgs)
    assert f"/{r.lookups.total} CVEs" in msgs[-1] and f"{r.lookups.fetched} fetched" in msgs[-1]
