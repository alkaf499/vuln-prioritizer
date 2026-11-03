# vuln-prioritizer

Deterministic, context-aware vulnerability prioritization. See `CLAUDE.md` for the full spec.

**Status: S1 (Layer-1 scorer) + S2 (Layer-2 asset conditioning) + S3 (enrichment) + S4 (skill + run entrypoint).**

```
vuln-prioritizer run --db ~/tenable-lab/navi.db --overlay my-overlay.yaml --out ./out [--offline] [--threat-first]
```

Writes `worklist.md`, `worklist.csv`, `excluded.csv` (out-of-scope assets) and `informational.csv` (Info-severity
scanner output, counted but never ranked) to `--out` (gitignored) and prints the ranked list. Within a tier the order
is KEV first, then VPR, CVSS, criticality, exposure.
`--offline` = no network (enrichment from `--intel-cache` JSON or "unknown"); add `--as-of <ISO8601>` for
byte-identical output. Read-only against the tenant.

`--enrich local|full` (live; default `local`): `local` uses only the four cached feeds (CISA KEV, Metasploit,
Exploit-DB, Nuclei) — no per-CVE network — and its evidence says PoC aggregators were not consulted; `full`
adds per-CVE EPSS and the nomi-sec/trickest PoC repos (~3 HTTP calls per CVE).

Live enrichment writes through a dated, resumable `--intel-cache FILE` (`--max-lookups N` fetches the
top-ranked CVEs first; `--progress-every N` prints progress to stderr). Replaying that file with `--offline`
reproduces the live-enriched worklist byte for byte. Code: `enrichment/cache.py`. The Claude skill is `skills/vuln-prioritizer/SKILL.md`;
the plugin manifest is in `.claude-plugin/`.

- `vuln_prioritizer.pipeline` / `worklist` / `cli` — S4 orchestration, row builder + renderers, entrypoint.

- `vuln_prioritizer.context` — resolver chain (Tenable One → tags → CMDB overlay → unknown+flag), every attribute's source recorded; overlay loader for `classification.example.yaml` (synthetic; stdlib-only YAML subset).
- `vuln_prioritizer.scoring.layer2` — `score_findings(findings, overlay=..., as_of=...) -> ScoringRun`: asset class, ±1 shift (clamped T0/T4; one shift per asset by precedence, no floor — v0.7), `in_scope: false` exclusions reported separately in `ScoringRun.excluded`.

- `vuln_prioritizer.scoring` — `score_layer1(finding) -> Layer1Result`: pure, deterministic
  Layer-1 tier with every input recorded (`explain()`, `as_record()`).

### Extension points

- **Recorded Future (probability fallback).** §3 allows RF alongside EPSS when VPR is absent
  ("most conservative = highest-urgency band"). Not modelled in v1: no RF access and no RF→band
  map. To add it, give `Finding`/`CveSignal` an RF score, add an `rf_band` binning in
  `scoring/tiers.py`, and include its band among the fallback candidates in
  `scoring/layer1.py:resolve_probability`.
- **Impact-only policy.** With no probability signal (no VPR, EPSS or KEV), the default
  `ImpactOnlyPolicy.DIAGONAL` uses the impact band as the probability column. This differs from
  `WORST_CASE` only for Medium impact (T4 vs T2). Such findings are always flagged
  `reevaluate_probability`.

- `vuln_prioritizer.schema` — normalized `Finding` / `Asset` contract (the interface every later stage uses).
- `vuln_prioritizer.adapters.navi` — read-only `navi.db` → `list[Finding]`.
- `vuln_prioritizer.fixtures.navi_fixture` — builds a 100% synthetic `navi.db` (never committed; tests build it into a temp dir).

```
pip install -e .[dev]
pytest
python -m vuln_prioritizer.fixtures.navi_fixture ./demo-navi.db   # optional: write a fixture db
```

All fixture CVEs are `CVE-2099-*` and all hosts/IPs are invented (RFC 5737 / `.example.test`).

MIT licensed.
