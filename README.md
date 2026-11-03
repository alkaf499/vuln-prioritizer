# vuln-prioritizer

**A deterministic, context-aware vulnerability prioritization skill.** It turns a Tenable
[`navi`](https://github.com/packetchaos/navi) database (`navi.db`) plus a CMDB asset-context overlay
into a **ranked, evidence-backed, SLA-dated remediation worklist** and an **executive report** —
"fix these, in this order, by this date, because X."

Built for SWARM Global (Tenable + Anthropic), MIT licensed. Read-only against your tenant, always.

## Why

A scanner reports tens of thousands of findings; most are not remediation work, and "critical" is not
a priority. This tool answers the question an analyst actually has:

- **Drops the noise.** Nessus Info-severity plugins (service detection, OS/CPE/MAC identification,
  traceroute …) are not vulnerabilities. They are split off, counted, and listed separately.
- **Fuses three kinds of fact** — what the scanner knows (CVSS, VPR, KEV dates via navi), what the
  open exploit ecosystem knows (CISA KEV, EPSS, Metasploit, Exploit-DB, Nuclei via
  [threat-intel-toolkit](https://github.com/kevinmhorvath/threat-intel-toolkit)), and what only *you*
  know (is it internet-facing? a crown jewel? a dev box?) via a CMDB overlay.
- **Is deterministic and audit-defensible.** Same inputs and `--as-of` give byte-identical output.
  Every row shows every input behind its tier and where each input came from. The model never
  guesses a tier; it orchestrates and explains.
- **Sets achievable SLAs.** A KEV'd critical on the internal fleet is 30 days; the same CVE on an
  internet-facing host is 24 hours. Asset context relaxes or tightens the clock, so the SLAs you
  publish are ones you can actually meet.
- **Shows where you are already late.** An SLA-breach view measures each finding from the day the
  scanner first saw it.

> The spec is in [`CLAUDE.md`](CLAUDE.md). The Claude skill is
> [`skills/vuln-prioritizer/SKILL.md`](skills/vuln-prioritizer/SKILL.md).

## Quickstart

```bash
pip install -e ".[dev]"            # stdlib only at runtime; pytest for development
pytest                             # offline test suite (synthetic data, network blocked)

# Zero-setup demo on 100% synthetic data:
python -m vuln_prioritizer.fixtures.navi_fixture ./demo-navi.db
vuln-prioritizer run --db demo-navi.db --overlay classification.example.yaml --out out --offline

# Your tenant (navi.db stays OUTSIDE the repo: it contains your API keys):
vuln-prioritizer run --db ~/tenable-lab/navi.db --overlay ~/tenable-lab/classification.yaml --out out
```

Outputs in `--out` (gitignored — they are real-data artifacts):

| File | Contents |
|---|---|
| `executive_report.md` | Toil saved · tiers · **SLA compliance** · per-role view · top risks with evidence · divergence highlights |
| `worklist.md` / `worklist.csv` | One row per finding: tier, SLA, `fix_by` and `discovery_due` dates, SLA status, evidence, every resolved input and its source, flags |
| `excluded.csv` | `in_scope: false` assets: counted and reported, never silently dropped |
| `informational.csv` | Info-severity scanner output: counted, never ranked |

`vuln-prioritizer run --help` lists every option. A guided demo against the lab is in
[`scripts/demo.sh`](scripts/demo.sh).

## How it decides

**Layer 1 — vulnerability score** (asset-independent): CVSS impact band × probability band, on a fixed
matrix. Impact falls back NVD → CNA → unattributed CVSS → scan severity. Probability is Tenable VPR,
falling back to EPSS, with a **CISA KEV floor of High** applied last. No probability signal at all?
The finding is scored on impact only, flagged for re-evaluation, **never uplifted and capped at
Tier 3** — no exploitation evidence must never produce a false emergency.

**Layer 2 — asset context:** exactly one ±1 tier shift per asset, by precedence — externally exposed
**+1** (Tier 1 → **Tier 0**), non-production or non-critical prod **−1**, business-critical baseline.
`in_scope: false` excludes. Environment is descriptive; only scope excludes.

| Tier | SLA |
|---|---|
| T0 Emergency | ~12h / out-of-band |
| T1 | 24h |
| T2 | 10d |
| T3 | 30d |
| T4 | next patch cycle (no hard SLA) |

Within a tier, rows are ordered **KEV first** → VPR → CVSS → criticality → exposure → finding id.

### SLA-breach view

Each row records **two dates**:

- `fix_by` (the `due` column) = `as_of` + tier SLA — *when to fix it if you start today*.
- `discovery_due` = `first_found` + tier SLA — *when the clock ran out, counting from first detection*.

A finding is **BREACHED** when `discovery_due < as_of` (`sla_status` = `BREACHED +Nd`, `overdue_days` = N).
Tier 4 has no hard SLA and is never counted; a finding with no `first_found` is `unknown`, not
"on-track". It is judged against the finding's *current* tier. The executive report presents compliance
**per tier** (a single total hides that the strictest tiers are usually the most overdue), with breach
age buckets and the most overdue findings.

### Executive report and "toil saved"

`executive_report.md` opens with the funnel measured from the run itself — e.g.
*19,052 loaded → 10,283 ranked → 102 urgent; 8,769 informational removed* — plus the wall-clock
time-to-worklist. "Urgent" means Tier 0–1 (due within 24h). Pass `--triage-minutes M` to add an
analyst-days estimate; it is an assumption you supply and is labelled as one. Pass `--no-timing` to
omit the measured time and make the report byte-reproducible.

## Threat intel: offline vs live

| Mode | Command | Network | Notes |
|---|---|---|---|
| **Offline** | `--offline` | none | Enrichment from `--intel-cache` (read-only) or "unknown". Use for demos, CI, audits. |
| **Live, `local`** (default) | *(no flag)* | 4 cached feeds, once | CISA KEV, Metasploit, Exploit-DB, Nuclei. No per-CVE requests, so thousands of CVEs take seconds. No live EPSS. Evidence says the PoC aggregators were *not consulted*. |
| **Live, `full`** | `--enrich full` | ~3 HTTP calls/CVE | Adds per-CVE EPSS and the nomi-sec / trickest PoC aggregators. Pair with `--intel-cache` and `--max-lookups N` and start small. |

`--intel-cache FILE` is written through, **dated, and resumable** (an interrupted or capped run
continues where it stopped; CVEs already cached are never re-fetched). It records both labels:
`as_of` (the `--as-of` label — injectable for reproducible demos) and `fetched_at` (the **real**
wall-clock time the feeds were queried). Reports show both. Replaying with
`--offline --intel-cache FILE --as-of <same>` reproduces a live-enriched worklist **byte for byte**.
A dead feed becomes "unknown", never "not listed". Treat the cache like other real-data artifacts —
it lists which CVEs your tenant holds.

The upstream script is imported unmodified from `reference/threat-intel-toolkit/` (gitignored). Clone
it there, or point `EXPLOIT_CHECK_PATH` at `exploit_check.py`. Optional `GITHUB_TOKEN` in the
environment raises GitHub rate limits; it is never stored or printed.

## Asset context: the resolver chain

Environment, exposure, criticality and scope are **CMDB facts, not scanner facts**. Each attribute
resolves independently through a priority chain, and its source is recorded on every row:

1. **Tenable One** `exposure_classes` / asset criticality (when your entitlement has it)
2. **Tenable tags** (read-only) — if you already keep a convention
3. **CMDB classification overlay** (a local YAML file) ← the practical path
4. **Unknown** → internal, in scope, **flagged for re-evaluation**

An IP-derived exposure heuristic exists but is **off by default** (invalid where IPs are randomized).

### Pointing at a real CMDB

The overlay is an ordered list of rules; **first match wins**. `match` keys are `hostname`,
`operating_system`, `fqdn`, `ip`, `asset_id` (case-insensitive globs, all keys must match). Start
from [`classification.example.yaml`](classification.example.yaml) — it is synthetic and generic
(firewalls → external, hypervisors → CJ-support, network devices, BMCs → crown jewel, domain
controllers → crown jewel, workstations → non-production) — and:

- **Put specific rules first** (`dev-*` exclusions, domain controllers before the generic server rule).
- **Give every rule a `role`** — the executive report groups by it.
- **Generate rules from your CMDB export** rather than hand-writing hundreds. Any CSV with a host
  identifier and the attributes you track works:

  ```python
  import csv
  for r in csv.DictReader(open("cmdb_export.csv", encoding="utf-8")):
      print(f'  - match: {{ asset_id: "{r["tenable_uuid"]}" }}')   # or hostname / ip / fqdn
      print(f'    role: {r["ci_class"]}')
      print(f'    environment: {r["lifecycle"]}')        # production | non_production
      print(f'    exposure: {r["exposure"]}')            # internal | external
      print(f'    criticality: {r["criticality"]}')      # crown_jewel | cj_support | rto_defined | standard
  ```

  Paste the output under `assets:`, keep a few catch-all device-class rules below it, and keep the
  file **outside the repo**. Site-specific overlays belong in `out/` or your CMDB repo, never here.

## Posture and data handling

- **Read-only.** The tool opens `navi.db` with SQLite `mode=ro`; it never writes tags, ACRs or scans
  to Tenable. The only file it writes besides reports is the optional intel cache.
- **`navi.db` contains your API keys.** Keep it outside the repo. `.gitignore` covers `navi.db`, `.env`,
  `*.key`, `*.csv`, `out/` and intel caches. Before publishing, run
  [`scripts/secret_scan.sh`](scripts/secret_scan.sh) and see [`COMPLIANCE.md`](COMPLIANCE.md).
- Fixture data is 100% synthetic (`CVE-2099-*`, RFC 5737 IPs, `.example.test` hosts).
- CSV output neutralizes spreadsheet formula injection from tenant-controlled strings.

## Limitations

- **Source:** navi is adapter #1. The scorer is source-agnostic (normalized schema), but a second
  adapter (generic CSV, Defender export) is not built.
- **Windowed data:** a navi sync only holds what it was asked for (`navi config update full --days N`);
  SLA ages are only as old as that window.
- **SLA clock** is `first_found` + the *current* tier's SLA. A finding that was Tier 3 when first seen
  and became Tier 1 (new KEV listing) is judged against 24h — deliberate for an audit view, but it
  will look "late" the day it escalates. The Tier 0 window (12h) is a policy figure to confirm.
- **`local` enrichment has no live EPSS** (use `--enrich full`, or an `epss` table in navi.db).
- **Recorded Future** is not modelled (extension point documented in `scoring/layer1.py`).
- **Tenable One** tables (`exposure_classes`, ACR/AES) are used when present; the lab tenant had none,
  so classification there comes from the overlay. The navi join keys for those tables are unverified
  against a tenant that has them.
- **Overlay parser** supports the YAML subset the overlay uses (no anchors or multi-line scalars).
- Informational filtering keys off scan severity (Info); other scanners' "informational" notions are
  not mapped.
- Per-finding scoring only; there is no cross-finding "one patch fixes N findings" consolidation.

## Development

```bash
pip install -e ".[dev]"
pytest                    # offline (default; -m "not live")
pytest -m live            # hits real feeds; needs reference/threat-intel-toolkit
```

Layout: `adapters/` (navi → schema) · `context/` (overlay + resolver chain) · `enrichment/` (gate, cache,
upstream bridge) · `scoring/` (Layer 1, Layer 2, tiers) · `pipeline.py` · `sla.py` · `worklist.py` ·
`report.py` · `cli.py`. CI ([`.github/workflows/healthcheck.yml`](.github/workflows/healthcheck.yml))
runs the offline suite on every push and a weekly live smoke test of the threat-intel sources.

## License

MIT — see [`LICENSE`](LICENSE). Builds on `navi` and `threat-intel-toolkit`, both MIT.
