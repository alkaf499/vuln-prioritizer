---
name: "vuln-prioritizer"
description: "Context-aware vulnerability prioritization: turns a navi.db (Tenable) vulnerability inventory plus a CMDB asset-context overlay into a ranked, evidence-backed, SLA-dated remediation worklist (Tier 0 emergency ~12h, T1 24h, T2 10d, T3 30d, T4 next cycle) with excluded assets reported separately. Deterministic two-layer model: Layer 1 = CVSS impact x VPR/EPSS/KEV probability; Layer 2 = asset exposure, criticality, environment and scope. Trigger on: \"what should we patch first\", \"prioritize these vulnerabilities / this navi.db\", \"remediation worklist\", \"which findings breach SLA\", \"are we exposed to <newly added KEV / CVE>\", \"patch priorities for <asset group>\", \"vulnerability triage report\". Read-only: never writes to the Tenable tenant."
---

# Vulnerability Prioritizer

Answer: **"fix these, in this order, by this date, because X."** The model orchestrates; every tier comes from a deterministic engine whose inputs are shown on each row. Never guess a tier yourself — run the tool and report what it printed.

## Read-only posture (non-negotiable)

The skill reads `navi.db`, the CMDB overlay and public threat-intel feeds. It **never** creates tags, writes ACRs, launches scans or otherwise writes to the Tenable tenant. `navi.db` contains API keys: keep it outside the repo (e.g. `~/tenable-lab/navi.db`) and never paste its contents into chat or commit it.

## Inputs to ask for (only if not already given)

1. **`--db`** path to `navi.db` (refresh it first with navi if stale — that is the user's call).
2. **`--overlay`** path to the CMDB classification overlay YAML (see `classification.example.yaml`; synthetic). Asset environment / exposure / criticality / scope are CMDB facts, not scanner facts. Without an overlay every asset is "unknown, internal, in scope" and flagged for re-evaluation — say so.
3. **`--out`** output directory (default `./out`, gitignored).

## Default pipeline — asset-first

```
vuln-prioritizer run --db <navi.db> --overlay <overlay.yaml> --out <dir>
```

1. **Adapter + overlay** — navi.db → normalized findings; asset context resolved per asset (Tenable One `exposure_classes` → tags → overlay → unknown+flag).
2. **Cheap gate** — severity ≥ High, CVSS ≥ 7, KEV, or EPSS ≥ 0.10 survive.
3. **Enrich (memoized)** — threat-intel-toolkit's `exploit-availability-check`, one lookup per distinct CVE (KEV, EPSS, Metasploit, Nuclei, Exploit-DB, PoC aggregators). A dead feed becomes "unknown", never "not listed".
4. **Score** — Layer 1 matrix (CVSS impact × VPR→EPSS→KEV-floor-High probability), then Layer 2 asset conditioning: one ±1 shift (external exposure +1 → T0 possible; non-prod / non-critical prod −1; business-critical baseline). `in_scope: false` is excluded and reported, never dropped.
5. **Rank** — final tier, then VPR (desc; EPSS×10 if VPR is absent), CVSS (desc), asset criticality (crown jewel first), exposure (external first), finding id. The top of each tier is highest-signal first; stable and reproducible.

Outputs in `--out`: `worklist.md`, `worklist.csv` (one row per finding: asset, role, CVE, tier, SLA, due date, evidence, resolved inputs and their sources, flags, divergence), `excluded.csv`. The ranked list is also printed to stdout — **relay the top of it to the user in chat** (tier, asset, CVE, evidence) and point to the files. Everything is stamped "as of <timestamp>".

## Threat-first toggle

When the question is "a CVE/KEV just landed — are we exposed?":

```
vuln-prioritizer run --db <navi.db> --overlay <overlay.yaml> --out <dir> --threat-first
```

Same scoring; the worklist is limited to threat-linked findings (on KEV, weaponized/public exploit, or a public exploit framework). The omitted count is reported — offer the full asset-first run if they want it.

## Offline / deterministic mode

`--offline` makes **no network calls**: enrichment answers from `--intel-cache <json>` (read-only) or reports "unknown". Use it for demos, CI and reproducible audits; add `--as-of <ISO8601>` to freeze the due-date anchor for byte-identical output.

## Live enrichment and the frozen intel cache

Without `--offline`, enrichment is live. Two modes (`--enrich local|full`):

- **`local` (default):** only the four cached feeds — CISA KEV, Metasploit, Exploit-DB, Nuclei. They download once (~35 MB, 24h TTL); after that every CVE is an in-memory lookup, so tens of thousands of CVEs take seconds. No per-CVE network, so no live EPSS: EPSS is used only if navi.db itself has an `epss` table (some tenants' and the event lab's navi.db do not), and otherwise a finding with no VPR and no KEV has no probability signal. Evidence for a CVE found nowhere reads "no exploit in Metasploit/Exploit-DB/Nuclei; PoC aggregators not consulted" — never "no public exploit found". Report that distinction accurately.
- **`full`:** adds the per-CVE EPSS API and the nomi-sec / trickest GitHub PoC aggregators — about three HTTP calls per CVE, so a real tenant can mean tens of thousands of requests. For `full`, **always use a cache and start small**:

```
vuln-prioritizer run --db <navi.db> --overlay <overlay.yaml> --out <dir> --enrich full --intel-cache <dir>/intel.json --max-lookups 200
```

A `full` run re-fetches (upgrades) cache entries that an earlier `local` run wrote; a `local` run accepts either.

- `--intel-cache FILE` is written through, **dated** (`_meta.as_of`), and **resumable**: an interrupted or capped run is continued by re-running the same command; CVEs already in the file are never re-fetched. Lookups that failed, or ran while a core feed was down, are not frozen and are retried next time.
- `--max-lookups N` fetches at most N new CVEs per run, **top-ranked first** (ranked by a preliminary scoring pass), so a small N covers the head of the worklist. Deferred CVEs are reported as "not consulted" (never "unreachable") — say so, and offer to continue.
- Progress lines go to stderr (`--progress-every N`, 0 = silent). `GITHUB_TOKEN` in the environment raises GitHub rate limits; never store or print it.
- **Replay:** `--offline --intel-cache <dir>/intel.json --as-of <ISO8601>` reproduces a live-enriched worklist **byte for byte**, and the report states the intel's as-of date. This is how a live result becomes a reproducible demo or audit artifact.
- Treat the cache like other real-data artifacts: it lists which CVEs your tenant holds. Keep it under `out/` (gitignored), not in the repo, unless you deliberately publish a synthetic one.

## How to report results

- Lead with counts per tier and the excluded-asset count + reasons, then the top of the ranking.
- Quote the **evidence string** and **inputs** verbatim — that is the audit trail ("Tier 0: internet-exposed + KEV + Metasploit + EPSS 97%").
- Call out `reevaluate_context`, `reevaluate_probability`, `impact_missing`, and `DIVERGENCE` flags as items needing a human look; do not silently resolve them.
- In offline runs, say that live threat-intel was not consulted.
- Findings with **no probability signal** (no VPR/EPSS/KEV — e.g. EoL/unsupported-software findings with no CVE) are scored on impact alone: **no exposure uplift and capped at Tier 3**, flagged `reevaluate_probability`. They are planned-remediation items, never an emergency; they re-score normally once a probability signal appears (re-run, ideally live).
- Purely-internal assets cap at Tier 2 by design (single ±1 shift, no no-downgrade floor, v0.7); Tier 1/0 need external exposure or independent Critical probability. Do not "fix" that.
- Never edit tiers by hand or override the engine; if the user disagrees, the lever is the overlay or the inputs, and the run is re-done.
