"""Worklist rows + renderers (chat text, Markdown, CSV). Pure formatting, no scoring.

Row order is the scorer's stable ranking (``scoring.layer2._rank_key``): final tier, then
probability value (VPR; EPSS x10 if VPR is absent) desc, then CVSS desc, then asset
criticality, then exposure (external first), then ``finding_id`` as the final total tiebreak.
Due dates cannot break ties (all ``as_of`` + the same SLA within a tier). Same inputs and
``as_of`` give byte-identical output.
"""

from __future__ import annotations

import csv
import io
from collections import defaultdict
from typing import Any

from .context import AssetContext, ContextSource
from .pipeline import PipelineResult, threat_signals
from .scoring.layer2 import ScoredFinding
from .scoring.tiers import Tier

COLUMNS: tuple[str, ...] = (
    "rank", "tier", "sla", "due", "asset", "asset_id", "role", "role_source", "overlay_rule",
    "finding_id", "plugin_id", "finding", "cves", "port",
    "evidence", "inputs", "explanation",
    "impact_band", "impact_source", "impact_score",
    "probability_band", "probability_source", "probability_value",
    "kev", "kev_floor_applied",
    "asset_class", "shift_requested", "shift_applied", "shift_clamped",
    "environment", "environment_source", "exposure", "exposure_source",
    "criticality", "criticality_source", "in_scope", "in_scope_source",
    "flags", "divergence", "threat_signals", "intel_degraded", "as_of",
)  # fmt: skip

EXCLUDED_COLUMNS: tuple[str, ...] = (
    "asset", "asset_id", "role", "overlay_rule", "findings", "reason", "in_scope_source", "as_of",
)


def overlay_rule(ctx: AssetContext) -> str:
    """The CMDB overlay rule that matched this asset, e.g. ``rule 7 (perimeter_firewall)``;
    "" if none matched. Recorded by the resolver as the detail of the rule-set ``role``, so
    only rules that carry a ``role`` are identifiable (every lab rule does)."""
    r = ctx.role
    return (r.detail or "") if r.source is ContextSource.OVERLAY else ""


def _sources(rec: dict[str, Any]) -> str:
    return (
        f"env {rec['environment']}[{rec['environment_source']}], "
        f"exposure {rec['exposure']}[{rec['exposure_source']}], "
        f"criticality {rec['criticality']}[{rec['criticality_source']}]"
    )


def _inputs(rec: dict[str, Any]) -> str:
    """Every resolved input behind the tier, on one line (audit trail)."""
    score = "" if rec["impact_score"] is None else f" {rec['impact_score']:g}"
    pval = "" if rec["probability_value"] is None else f" {rec['probability_value']:g}"
    floor = ", KEV floor" if rec["kev_floor_applied"] else ""
    only = ", impact-only" if rec["impact_only"] else ""
    return (
        f"impact {rec['impact_band']} [{rec['impact_source']}{score}] x "
        f"probability {rec['probability_band']} [{rec['probability_source']}{pval}{floor}{only}]"
        f" -> {rec['layer1_tier']}; asset class {rec['asset_class']} "
        f"(shift {rec['shift_requested']:+d}, applied {rec['shift_applied']:+d}"
        f"{', clamped' if rec['shift_clamped'] else ''}"
        f"{', uplift withheld: no probability signal' if rec['uplift_suppressed'] else ''}"
        f"{', capped at T3: impact-only' if rec['impact_only_capped'] else ''}) "
        f"-> {rec['final_tier']}; {_sources(rec)}"
    )


def compact_evidence(evidence: str) -> str:
    """Collapse per-CVE clauses ("CVE-X: <text> | CVE-Y: <text>") that are identical apart
    from the CVE id, e.g. 14 CVEs all "feed unreachable" -> "14 CVEs, each: <text>".
    Lossless in meaning; clauses that differ are left untouched."""
    if " | " not in evidence:
        return evidence
    head, sep, tail = evidence.partition(" — DIVERGENCE")  # divergence suffix is appended once
    parts = head.split(" | ")
    bodies = []
    for p in parts:
        cve, colon, body = p.partition(": ")
        if not colon or not cve.startswith("CVE-"):
            return evidence
        bodies.append(body)
    if len(set(bodies)) != 1:
        return evidence
    return f"{len(parts)} CVEs, each: {bodies[0]}{sep}{tail}"


def offline_wording(evidence: str) -> str:
    """Under --offline no feed was down, none was consulted: S3's "unreachable" wording
    would be false, so say "not consulted" (run before :func:`compact_evidence`)."""
    return evidence.replace("(feed unreachable)", "(not consulted)").replace(
        " unreachable)", " not consulted)"
    )


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def _row(rank: int, sf: ScoredFinding, result: PipelineResult) -> dict[str, Any]:
    rec = sf.as_record()
    rule = overlay_rule(sf.context)
    ef = result.enriched[sf.finding_id]
    f = ef.finding
    # Why intel may be missing: nothing was consulted (offline), or this finding's CVEs were
    # deferred by --max-lookups. Either way "unreachable" would be false.
    if result.offline:
        not_consulted = "offline: threat-intel not consulted"
    elif result.skipped_cves & set(f.cves):
        not_consulted = "lookup budget reached: threat-intel not consulted for some CVEs"
    else:
        not_consulted = ""
    raw_evidence = offline_wording(ef.evidence) if not_consulted else ef.evidence
    evidence = compact_evidence(raw_evidence)
    if not_consulted and ef.degraded:
        evidence = f"[{not_consulted}] {evidence}"
    return {
        "rank": rank,
        "tier": rec["final_tier"],
        "sla": rec["final_sla"],
        "due": rec["due"] or "",
        "asset": sf.asset_name,
        "asset_id": sf.asset_id,
        "role": rec["role"] or "",
        "role_source": rec["role_source"],
        "overlay_rule": rule,
        "finding_id": sf.finding_id,
        "plugin_id": f.plugin_id,
        "finding": f.name or "",
        "cves": ";".join(f.cves),
        "port": "" if f.port is None else f.port,
        "evidence": evidence,
        "inputs": _inputs(rec) + (f"; overlay {rule}" if rule else ""),
        "explanation": rec["explanation"],
        "impact_band": rec["impact_band"],
        "impact_source": rec["impact_source"],
        "impact_score": rec["impact_score"],
        "probability_band": rec["probability_band"],
        "probability_source": rec["probability_source"],
        "probability_value": rec["probability_value"],
        "kev": rec["kev"],
        "kev_floor_applied": rec["kev_floor_applied"],
        "asset_class": rec["asset_class"],
        "shift_requested": rec["shift_requested"],
        "shift_applied": rec["shift_applied"],
        "shift_clamped": rec["shift_clamped"],
        "environment": rec["environment"],
        "environment_source": rec["environment_source"],
        "exposure": rec["exposure"],
        "exposure_source": rec["exposure_source"],
        "criticality": rec["criticality"],
        "criticality_source": rec["criticality_source"],
        "in_scope": rec["in_scope"],
        "in_scope_source": rec["in_scope_source"],
        "flags": ";".join(x for x in (rec["layer1_flags"], rec["context_flags"]) if x),
        "divergence": ";".join(d.value for d in ef.divergence),
        "threat_signals": ";".join(threat_signals(f)),
        "intel_degraded": ef.degraded,
        "as_of": result.as_of.isoformat(),
    }


def build_rows(result: PipelineResult) -> list[dict[str, Any]]:
    """One row per in-scope finding in the published view, ranked from 1."""
    return [_row(n, sf, result) for n, sf in enumerate(result.worklist, 1)]


def build_excluded_rows(result: PipelineResult) -> list[dict[str, Any]]:
    """Excluded findings grouped per asset (count + reason). Never dropped silently."""
    groups: dict[str, list[ScoredFinding]] = defaultdict(list)
    for sf in result.scoring.excluded:
        groups[sf.asset_id].append(sf)
    rows = []
    for asset_id, sfs in sorted(groups.items(), key=lambda kv: (kv[1][0].asset_name, kv[0])):
        rec = sfs[0].as_record()
        rows.append(
            {
                "asset": sfs[0].asset_name,
                "asset_id": asset_id,
                "role": rec["role"] or "",
                "overlay_rule": overlay_rule(sfs[0].context),
                "findings": len(sfs),
                "reason": sfs[0].exclusion_reason or "",
                "in_scope_source": rec["in_scope_source"],
                "as_of": result.as_of.isoformat(),
            }
        )
    return rows


# --------------------------------------------------------------------------
# CSV
# --------------------------------------------------------------------------
def _csv_cell(v: Any) -> Any:
    """Neutralize spreadsheet formula injection from tenant-controlled strings."""
    if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + v
    return "" if v is None else v


def to_csv(rows: list[dict[str, Any]], columns: tuple[str, ...]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(columns)
    for r in rows:
        w.writerow([_csv_cell(r[c]) for c in columns])
    return buf.getvalue()


# --------------------------------------------------------------------------
# Markdown
# --------------------------------------------------------------------------
def _md(v: Any) -> str:
    s = "" if v is None else str(v)
    return s.replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _table(headers: list[str], body: list[list[Any]]) -> list[str]:
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    out += ["| " + " | ".join(_md(c) for c in row) + " |" for row in body]
    return out


def _kv_table(d: dict[str, Any], key_header: str) -> list[str]:
    return _table([key_header, "count"], [[k, v] for k, v in d.items()]) if d else ["_none_"]


def to_markdown(result: PipelineResult, rows: list[dict[str, Any]], excluded: list[dict[str, Any]]) -> str:
    run, st = result.scoring, result.enrichment.stats
    view = "threat-first (threat-linked findings only)" if result.threat_first else "asset-first (all in-scope findings)"
    if result.offline and result.intel_cache_name:
        mode = (
            f"offline replay of frozen threat-intel cache `{result.intel_cache_name}` "
            f"(intel as of {result.intel_as_of or 'unstamped'}; deterministic, no network)"
        )
    elif result.offline:
        mode = "offline (deterministic; live threat-intel NOT consulted)"
    else:
        feeds = (
            "local feeds only: CISA KEV, Metasploit, Exploit-DB, Nuclei; per-CVE EPSS and PoC aggregators not consulted"
            if result.enrich_mode == "local"
            else "full: cached feeds + per-CVE EPSS and PoC aggregators"
        )
        cached = (
            f", written through cache `{result.intel_cache_name}` (intel as of {result.intel_as_of or 'unstamped'})"
            if result.intel_cache_name
            else ""
        )
        mode = f"live threat-intel ({feeds}){cached}"
    L: list[str] = [
        "# Vulnerability Remediation Worklist",
        "",
        f"**As of:** {result.as_of.isoformat()} · **View:** {view} · **Mode:** {mode}  ",
        f"**Source:** {result.source_name} · **Asset-context overlay:** {result.overlay_name or 'none (all assets unknown/internal, flagged)'}  ",
        "**Posture:** read-only — nothing was written to the Tenable tenant.",
        "",
        "## Summary",
        "",
        f"- Findings loaded: **{run.total}** → ranked worklist: **{len(rows)}**, "
        f"excluded (out of scope): **{run.excluded_count}** findings on **{run.excluded_asset_count}** asset(s)",
    ]
    if result.threat_first:
        L.append(
            f"- Threat-first view: {len(rows)} threat-linked finding(s) shown; "
            f"{result.omitted_non_threat} in-scope finding(s) without a threat signal omitted from this view "
            "(run asset-first for the full list)"
        )
    L += [
        f"- Threat-intel enrichment: {st.gated} of {st.findings} findings passed the gate; "
        f"{st.distinct_cves} distinct CVE lookup(s); {st.failures} failure(s)",
    ]
    if result.lookups is not None:
        lk = result.lookups
        L.append(
            f"- Live lookups: {lk.fetched} fetched, {lk.cache_hits} already in the cache, "
            f"{lk.failed} failed, {lk.deferred} deferred by --max-lookups "
            f"(top-ranked CVEs are looked up first; deferred ones are 'not consulted', re-run to continue)"
        )
    L += [
        f"- Assets whose context needs re-evaluation (unknown environment / assumed exposure): "
        f"**{run.summary()['reevaluate_context']}** finding(s)",
        "",
        "**By tier (all in-scope findings)**",
        "",
        *_kv_table(run.by_tier(), "tier"),
        "",
        "**By asset class (incl. excluded)**",
        "",
        *_kv_table(run.by_class(), "asset class"),
        "",
        "## Ranked worklist",
        "",
        "_Order: final tier → VPR (desc) → CVSS (desc) → asset criticality → exposure (external first) "
        "→ finding id (stable, reproducible). "
        "Each row shows the evidence and every resolved input with its source._",
        "",
    ]
    if not rows:
        L += ["_No findings in this view._", ""]
    by_tier: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        by_tier[r["tier"]].append(r)
    for tier in Tier:
        group = by_tier.get(tier.name)
        if not group:
            continue
        L += [f"### {tier.label} — {tier.sla_label} ({len(group)})", ""]
        L += _table(
            ["#", "Asset", "Role", "CVE(s)", "Finding", "Due", "Evidence", "Inputs / sources", "Flags"],
            [
                [
                    r["rank"], r["asset"], r["role"], r["cves"], r["finding"],
                    r["due"] or "next patch cycle", r["evidence"], r["inputs"],
                    "; ".join(x for x in (r["flags"], r["divergence"]) if x),
                ]
                for r in group
            ],
        )
        L.append("")
    L += ["## Excluded assets (out of scope — reported, not scheduled)", ""]
    if excluded:
        L += _table(
            ["Asset", "Role", "Findings", "Reason", "Source"],
            [[e["asset"], e["role"], e["findings"], e["reason"], e["in_scope_source"]] for e in excluded],
        )
    else:
        L.append("_No assets excluded._")
    L += [
        "",
        "---",
        "_Facts come from navi.db, the CMDB overlay and public feeds; the model only orchestrates. "
        "Same inputs and as-of time reproduce this report byte for byte._",
        "",
    ]
    return "\n".join(L)


# --------------------------------------------------------------------------
# chat (stdout)
# --------------------------------------------------------------------------
def to_chat(result: PipelineResult, rows: list[dict[str, Any]], *, top: int = 15) -> str:
    run = result.scoring
    L = [
        f"Vulnerability worklist — as of {result.as_of.isoformat()} "
        f"({'threat-first' if result.threat_first else 'asset-first'}, "
        f"{'offline' if result.offline else 'live'})",
        f"{run.total} findings: {len(rows)} ranked, {run.excluded_count} excluded "
        f"({run.excluded_asset_count} asset(s) out of scope)",
        "by tier: " + (", ".join(f"{k}={v}" for k, v in run.by_tier().items()) or "none"),
        "",
    ]
    if result.intel_cache_name:
        L.insert(3, f"threat-intel cache: {result.intel_cache_name} (intel as of {result.intel_as_of or 'unstamped'})")
    if result.lookups is not None and result.lookups.deferred:
        L.insert(3, f"{result.lookups.deferred} CVE(s) deferred by --max-lookups; re-run with the same cache to continue")
    for r in rows[:top]:
        due = r["due"] or "next patch cycle"
        L.append(f"{r['rank']:>3}. {r['tier']} · {r['sla']} · due {due}")
        cves = r["cves"].split(";") if r["cves"] else []
        cve_txt = ", ".join(cves[:3]) + (f" (+{len(cves) - 3} more)" if len(cves) > 3 else "") or "no CVE"
        L.append(
            f"     {r['asset']} ({r['role'] or 'no role'}) · {cve_txt} · "
            f"{_clip(r['finding'], 90)} [{r['finding_id']}]"
        )
        L.append(f"     evidence: {_clip(r['evidence'], 240)}")
        L.append(f"     inputs:   {_clip(r['inputs'], 300)}")
    if len(rows) > top:
        L.append(f"... {len(rows) - top} more in the report files (full evidence/inputs there)")
    return "\n".join(L) + "\n"
