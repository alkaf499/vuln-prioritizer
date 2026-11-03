"""Executive report (S5): a one-page management/audit view built from the worklist rows.

Pure formatting and counting over ``worklist.build_rows`` output and the ``PipelineResult`` — no
scoring, no I/O. Everything in it is derived from the same rows as ``worklist.csv``, so a number
in this report can always be traced to rows. The ONLY non-reproducible field is the measured
wall-clock ``elapsed_seconds`` (the CLI measures it; pass ``None`` to omit it and the report is
byte-identical for the same inputs and ``--as-of``).

Sections: toil saved · tiers · SLA compliance (a breakdown, not one total) · per-role view ·
top risks with evidence · divergence highlights · items needing a human look.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from .pipeline import PipelineResult
from .scoring.tiers import Tier
from .sla import BREACHED, ON_TRACK
from .worklist import _clip, _table

URGENT_MAX_TIER = Tier.T1
"""'Urgent' = due within 24h (T0, T1). Printed in the report next to the number."""
URGENT_LABEL = "Tier 0-1, due within 24h"

TOP_RISKS = 10
TOP_OVERDUE = 10
TOP_DIVERGENT = 10
ANALYST_DAY_HOURS = 8.0
NO_ROLE = "(no role)"

_BUCKETS = (("30 days or less", 0, 30), ("31-90 days", 31, 90), ("over 90 days", 91, None))


def _n(v: int) -> str:
    return f"{v:,}"


def _pct(part: int, whole: int) -> str:
    return "n/a" if whole == 0 else f"{100.0 * part / whole:.1f}%"


def _tier(row: dict[str, Any]) -> Tier:
    return Tier[row["tier"]]


def _is_breached(row: dict[str, Any]) -> bool:
    return str(row["sla_status"]).startswith(BREACHED)


def _is_unknown(row: dict[str, Any]) -> bool:
    return str(row["sla_status"]).startswith("unknown")


# --------------------------------------------------------------------------
# pure aggregations (unit-tested directly)
# --------------------------------------------------------------------------
def sla_breakdown(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One entry per tier with a hard SLA (T0-T3): findings, breached, on-track, unknown,
    compliance (on-track / assessable). Tier 4 (next patch cycle) has no hard SLA and is not
    included; ``compliance`` is ``None`` when nothing in the tier is assessable."""
    out = []
    for tier in Tier:
        if tier.sla is None:
            continue
        group = [r for r in rows if _tier(r) is tier]
        breached = sum(1 for r in group if _is_breached(r))
        on_track = sum(1 for r in group if r["sla_status"] == ON_TRACK)
        unknown = sum(1 for r in group if _is_unknown(r))
        assessable = breached + on_track
        out.append(
            {
                "tier": tier.name, "sla": tier.sla_label, "findings": len(group),
                "breached": breached, "on_track": on_track, "unknown": unknown,
                "compliance": None if assessable == 0 else on_track / assessable,
            }
        )  # fmt: skip
    return out


def overdue_buckets(rows: list[dict[str, Any]]) -> list[tuple[str, int]]:
    """Breached findings by how far past ``discovery_due`` they are (whole days, floor);
    breaches under a day land in the first bucket."""
    counts = {name: 0 for name, _, _ in _BUCKETS}
    for r in rows:
        if not _is_breached(r):
            continue
        days = int(r["overdue_days"] or 0)
        for name, lo, hi in _BUCKETS:
            if days >= lo and (hi is None or days <= hi):
                counts[name] += 1
                break
    return list(counts.items())


def top_overdue(rows: list[dict[str, Any]], limit: int = TOP_OVERDUE) -> list[dict[str, Any]]:
    """Most overdue first; ties by tier (more urgent first), then worklist rank. Deterministic."""
    breached = [r for r in rows if _is_breached(r)]
    breached.sort(key=lambda r: (-int(r["overdue_days"] or 0), int(_tier(r)), int(r["rank"])))
    return breached[:limit]


def role_groups(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Per-role roll-up (the role comes from the CMDB overlay): assets, findings, findings per
    tier, KEV count, SLA breaches. Most urgent roles first (T0 count, then T1, then T2)."""
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        groups[r["role"] or NO_ROLE].append(r)
    out = []
    for role, g in groups.items():
        per_tier = {t.name: sum(1 for r in g if _tier(r) is t) for t in Tier}
        out.append(
            {
                "role": role,
                "assets": len({r["asset_id"] for r in g}),
                "findings": len(g),
                **per_tier,
                "urgent": sum(1 for r in g if _tier(r) <= URGENT_MAX_TIER),
                "kev": sum(1 for r in g if str(r["kev"]) == "True"),
                "breached": sum(1 for r in g if _is_breached(r)),
            }
        )  # fmt: skip
    # tier-lexicographic: a role holding a Tier 0 outranks one with many Tier 1s
    out.sort(key=lambda d: (-d["T0"], -d["T1"], -d["T2"], -d["findings"], d["role"]))
    return out


def divergence_rows(rows: list[dict[str, Any]], kind: str) -> list[dict[str, Any]]:
    return [r for r in rows if kind in str(r["divergence"]).split(";")]


def toil_summary(result: PipelineResult) -> dict[str, int]:
    """The toil-saved counts, from the scorer's full result (not the published view, so a
    threat-first run reports the same funnel)."""
    run = result.scoring
    info = len(result.informational)
    return {
        "loaded": run.total + info,
        "informational": info,
        "excluded": run.excluded_count,
        "ranked": len(run.scored),
        "urgent": sum(1 for sf in run.scored if sf.final_tier is not None and sf.final_tier <= URGENT_MAX_TIER),
    }


# --------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------
def _intel_line(result: PipelineResult) -> str:
    fetched = result.intel_fetched_at or "not recorded"
    if result.offline and result.intel_cache_name:
        return (
            f"offline replay of frozen cache `{result.intel_cache_name}` "
            f"(intel label {result.intel_as_of or 'unstamped'}; feeds actually fetched {fetched})"
        )
    if result.offline:
        return "offline — live threat-intel NOT consulted (no KEV/exploit evidence beyond navi.db)"
    cached = f", cache `{result.intel_cache_name}`" if result.intel_cache_name else ""
    return (
        f"live, `{result.enrich_mode}` feeds{cached} "
        f"(intel label {result.intel_as_of or 'unstamped'}; feeds actually fetched {fetched})"
    )


def _why(r: dict[str, Any]) -> str:
    kev = ", KEV" if str(r["kev"]) == "True" else ""
    return (
        f"{r['impact_band']} impact x {r['probability_band']} probability "
        f"[{r['probability_source']}{kev}]; {r['asset_class']}"
    )


def to_exec_markdown(
    result: PipelineResult,
    rows: list[dict[str, Any]],
    excluded: list[dict[str, Any]],
    *,
    elapsed_seconds: float | None = None,
    triage_minutes: float | None = None,
) -> str:
    toil = toil_summary(result)
    run = result.scoring
    view = "threat-first (threat-linked findings only)" if result.threat_first else "asset-first (all in-scope findings)"
    L: list[str] = [
        "# Executive Report — Vulnerability Remediation",
        "",
        f"**As of:** {result.as_of.isoformat()} · **View:** {view}  ",
        f"**Source:** {result.source_name} · **Asset-context overlay:** {result.overlay_name or 'none (all assets unknown/internal, flagged)'}  ",
        f"**Threat intel:** {_intel_line(result)}  ",
        "**Posture:** read-only — nothing was written to the Tenable tenant.",
        "",
        "## Toil saved",
        "",
        f"**{_n(toil['loaded'])} findings loaded → {_n(toil['ranked'])} ranked → "
        f"{_n(toil['urgent'])} urgent** ({URGENT_LABEL}). "
        f"{_n(toil['informational'])} informational scanner findings were removed from remediation work.",
        "",
    ]
    funnel = [
        ["Findings loaded from the scanner", _n(toil["loaded"])],
        ["Informational (service detection, OS/CPE/MAC ID, traceroute …) — removed, listed in `informational.csv`", _n(toil["informational"])],
        [f"Out of scope — {run.excluded_asset_count} asset(s), reported in `excluded.csv`, not scheduled", _n(toil["excluded"])],
        ["Ranked remediation worklist", _n(toil["ranked"])],
        [f"**Urgent — start here** ({URGENT_LABEL})", f"**{_n(toil['urgent'])}**"],
    ]
    L += _table(["Stage", "Findings"], funnel)
    L.append("")
    if toil["loaded"]:
        L.append(
            f"The analyst's starting list is {_pct(toil['urgent'], toil['loaded'])} of what the scanner reported "
            f"(a {100.0 - 100.0 * toil['urgent'] / toil['loaded']:.1f}% reduction), each item with evidence and a due date."
        )
    if elapsed_seconds is not None:
        basis = (
            "offline: enrichment answered from a frozen cache, so feed download time is NOT included"
            if result.offline
            else "live: includes feed download and lookups"
        )
        L.append(
            f"- **Time to worklist:** {elapsed_seconds:.1f} s wall-clock "
            f"(navi.db load → enrichment → two-layer scoring → ranking → reports; measured this run; {basis})."
        )
    if triage_minutes:
        manual = toil["loaded"] * triage_minutes / 60.0 / ANALYST_DAY_HOURS
        focused = toil["urgent"] * triage_minutes / 60.0 / ANALYST_DAY_HOURS
        L.append(
            f"- **Analyst time (illustrative):** at an assumed {triage_minutes:g} min per finding, reviewing everything "
            f"is ≈ {manual:,.1f} analyst-days; starting from the urgent list is ≈ {focused:,.1f}. "
            f"The per-finding time is an operator-supplied assumption (`--triage-minutes`), not a measurement."
        )
    L.append("")

    # ---- tiers
    ranked_rows = len(rows)
    tier_counts = {t: sum(1 for r in rows if _tier(r) is t) for t in Tier}
    L += ["## Findings by tier", ""]
    L += _table(
        ["Tier", "SLA", "Findings", "Share"],
        [[t.label, t.sla_label, _n(tier_counts[t]), _pct(tier_counts[t], ranked_rows)] for t in Tier],
    )
    if result.threat_first:
        L += ["", f"_Threat-first view: {_n(result.omitted_non_threat)} in-scope finding(s) without a threat signal are not in these counts._"]
    L.append("")

    # ---- SLA compliance
    L += [
        "## SLA compliance",
        "",
        "_Discovery clock: a finding is **breached** when `first_found` + its tier SLA is earlier than the "
        "as-of date (the remediation clock started when the scanner first saw it). Judged against the "
        "finding's CURRENT tier. Tier 4 has no hard SLA and is excluded. The forward-looking `fix_by` "
        "(as-of + SLA, the `due` column) is also recorded on every row._",
        "",
    ]
    brk = sla_breakdown(rows)
    L += _table(
        ["Tier", "SLA", "Findings", "Within SLA", "Breached", "Compliance", "No first_found"],
        [
            [b["tier"], b["sla"], _n(b["findings"]), _n(b["on_track"]), _n(b["breached"]),
             "n/a" if b["compliance"] is None else f"{100 * b['compliance']:.1f}%", _n(b["unknown"])]
            for b in brk
        ],
    )
    tot_b = sum(b["breached"] for b in brk)
    tot_ok = sum(b["on_track"] for b in brk)
    L += [
        "",
        f"Across Tiers 0-3 (assessable findings only): **{_n(tot_ok)} within SLA, {_n(tot_b)} breached "
        f"({_pct(tot_ok, tot_ok + tot_b)} compliant)**. The per-tier breakdown above is the real picture — a "
        "single total hides that the strictest tiers are usually the most overdue.",
        "",
    ]
    if tot_b:
        L += ["**Breach age**", ""]
        L += _table(["Overdue by", "Findings"], [[n, _n(c)] for n, c in overdue_buckets(rows)])
        L += ["", f"**Most overdue (top {TOP_OVERDUE})**", ""]
        L += _table(
            ["#", "Tier", "SLA status", "First found", "Asset", "Role", "CVE(s)", "Finding"],
            [
                [r["rank"], r["tier"], r["sla_status"], str(r["first_found"])[:10], r["asset"],
                 r["role"] or NO_ROLE, _clip(str(r["cves"]).replace(";", ", "), 40), _clip(str(r["finding"]), 70)]
                for r in top_overdue(rows)
            ],
        )
        L.append("")
    else:
        L += ["_No breached findings._", ""]

    # ---- per role
    L += ["## By asset role", "", "_Roles come from the CMDB overlay; the most urgent roles are listed first._", ""]
    groups = role_groups(rows)
    if groups:
        L += _table(
            ["Role", "Assets", "Findings", "T0", "T1", "T2", "T3", "T4", "KEV", "SLA breached"],
            [
                [g["role"], _n(g["assets"]), _n(g["findings"]), _n(g["T0"]), _n(g["T1"]), _n(g["T2"]),
                 _n(g["T3"]), _n(g["T4"]), _n(g["kev"]), _n(g["breached"])]
                for g in groups
            ],
        )
    else:
        L.append("_No findings in this view._")
    L.append("")

    # ---- top risks
    L += [f"## Top risks (top {TOP_RISKS})", "", "_Highest-ranked findings, each with the evidence and the inputs that produced its tier._", ""]
    top = rows[:TOP_RISKS]
    if top:
        L += _table(
            ["#", "Tier", "Asset (role)", "CVE(s)", "Finding", "Evidence", "Why this tier", "SLA status"],
            [
                [r["rank"], f"{r['tier']} · {r['sla']}", f"{r['asset']} ({r['role'] or NO_ROLE})",
                 _clip(str(r["cves"]).replace(";", ", "), 40), _clip(str(r["finding"]), 60),
                 _clip(str(r["evidence"]), 220), _why(r), r["sla_status"]]
                for r in top
            ],
        )
    else:
        L.append("_No findings in this view._")
    L.append("")

    # ---- divergence
    low = divergence_rows(rows, "vpr_low_but_exploited")
    high = divergence_rows(rows, "vpr_high_no_exploit_signal")
    L += [
        "## Divergence highlights",
        "",
        "_Where the vendor's VPR and open exploitation evidence disagree. `vpr_low_but_exploited`: VPR says Low but the CVE is on "
        "CISA KEV or has a weaponized exploit — the KEV floor keeps these from being buried. A human should review them._",
        "",
    ]
    if low:
        L += [f"**{_n(len(low))} finding(s) are `vpr_low_but_exploited`** (top {min(TOP_DIVERGENT, len(low))} by rank):", ""]
        L += _table(
            ["#", "Tier", "Asset (role)", "CVE(s)", "VPR", "Evidence"],
            [
                [r["rank"], r["tier"], f"{r['asset']} ({r['role'] or NO_ROLE})",
                 _clip(str(r["cves"]).replace(";", ", "), 40),
                 "" if r["probability_source"] != "vpr" or r["probability_value"] is None else f"{r['probability_value']:g}",
                 _clip(str(r["evidence"]), 200)]
                for r in low[:TOP_DIVERGENT]
            ],
        )
    elif result.offline and not result.intel_cache_name:
        L.append("_None detected — but this run was offline without an intel cache, so no exploitation evidence was consulted._")
    else:
        L.append("_None detected._")
    if high:
        L += ["", f"Also {_n(len(high))} finding(s) are `vpr_high_no_exploit_signal` (VPR Critical but no KEV / exploit / EPSS signal) — informational, never used to lower a tier."]
    L.append("")

    # ---- review items
    n_prob = sum(1 for r in rows if "reevaluate_probability" in str(r["flags"]))
    n_ctx = run.summary()["reevaluate_context"]
    L += [
        "## Needs a human look",
        "",
        f"- **{_n(n_ctx)}** finding(s) sit on assets whose context (environment / exposure) is unknown or assumed — extend the CMDB overlay to resolve them.",
        f"- **{_n(n_prob)}** finding(s) have no probability signal (no VPR / EPSS / KEV): scored on impact alone, capped at Tier 3, no exposure uplift. They re-score automatically once a signal appears.",
        f"- **{run.excluded_asset_count}** asset(s) ({_n(run.excluded_count)} findings) are out of scope per the overlay — listed in `excluded.csv`, never silently dropped.",
        "",
        "---",
        "_Every figure above is a count over `worklist.csv` / `informational.csv` / `excluded.csv`. Facts come from navi.db, "
        "the CMDB overlay and public feeds; the model only orchestrates. Same inputs and `--as-of` reproduce this report "
        "byte for byte (the measured time-to-worklist line aside)._",
        "",
    ]
    return "\n".join(L)
