# Documentation

Full reference for `vuln-prioritizer`. For the overview, see the [README](README.md).

- [The scoring model](#the-scoring-model)
- [Asset context & overlays](#asset-context--overlays)
- [Threat-intel enrichment](#threat-intel-enrichment)
- [The AI classifier](#the-ai-classifier)
- [Outputs](#outputs)
- [CLI reference](#cli-reference)
- [Safety posture](#safety-posture)
- [Limitations](#limitations)

---

## The scoring model

Two layers: what the flaw is worth exploiting, then what the asset is worth compromising.

### Layer 1 — Vulnerability Score

**Impact** — CVSS base score, resolved through a fallback chain so a missing score never silently
becomes zero:

1. NVD base score
2. CNA-provided base score
3. CVSS with no stated source
4. Scan-source severity, mapped to a band
5. Nothing available → `Low` + `IMPACT_MISSING` flag

**Probability** — Tenable VPR, with fallbacks:

- VPR absent → EPSS (`≥0.90` Critical · `0.50–0.899` High · `0.10–0.499` Medium · `<0.10` Low)
- **CISA KEV floor** — a CVE on KEV forces probability to **at least High**, applied last, over any
  source including VPR. KEV counts as a probability signal, so such findings are not flagged for
  re-evaluation.
- No probability signal at all → scored on impact alone, **capped at Tier 3**, never uplifted, and
  flagged `reevaluate_probability`. It re-scores automatically once a signal appears.

Both axes resolve to a **band** (standard cutoffs: ≥9.0 Critical, ≥7.0 High, ≥4.0 Medium, else Low).
Multi-CVE findings take the worst case across their CVEs.

**The matrix:**

| impact ╲ probability | Critical | High | Medium | Low |
|---|---|---|---|---|
| **Critical** | Tier 1 · 24h | Tier 2 · 10d | Tier 3 · 30d | Tier 4 · next cycle |
| **High** | Tier 2 · 10d | Tier 2 · 10d | Tier 3 · 30d | Tier 4 · next cycle |
| **Medium** | Tier 2 · 10d | Tier 3 · 30d | Tier 4 · next cycle | Tier 4 · next cycle |
| **Low** | Tier 4 · next cycle | Tier 4 · next cycle | Tier 4 · next cycle | Tier 4 · next cycle |

### Layer 2 — Asset conditioning

| Asset class | Effect |
|---|---|
| **Externally exposed** (any environment) | **+1 uplift** (Tier 1 → **Tier 0**, Emergency ~12h; withheld when there is no probability signal) |
| Business-critical / crown jewel | baseline |
| Non-critical production | −1 downgrade |
| Non-production (dev/test/staging, workstations) | −1 downgrade, still in scope |
| `in_scope: false` | excluded, reported separately — never silently dropped |

Exactly **one ±1 shift** applies per asset, chosen by precedence (**external exposure wins**), clamped at
Tier 0 / Tier 4. Scope and environment are separate concerns: environment conditions the tier, only
`in_scope: false` excludes.

**Tier ladder:** `T4 (next cycle) < T3 (30d) < T2 (10d) < T1 (24h) < T0 (Emergency ~12h)`

**Ranking within a tier:** KEV first, then VPR, then CVSS, then criticality, then exposure — so an
actively-exploited finding leads its tier even if its vendor score is lower.

**Why there is no "no-downgrade floor":** a Patch-Tuesday wave of KEV'd criticals must not put an entire
laptop fleet on a 24-hour SLA. Asset context is allowed to relax the deadline, which is what makes the
SLAs achievable and defensible in audit. The single-shift limit means a KEV'd critical can never fall
past Tier 3.

---

## Asset context & overlays

Exposure, criticality and environment are **CMDB facts, not scanner facts**. They resolve through a
priority chain:

1. Tenable One exposure classes / asset criticality
2. Tenable tags (read-only)
3. **CMDB classification overlay** (YAML) — the practical path
4. Unknown → safe defaults, flagged for review

### Overlay format

```yaml
defaults: { environment: unknown, exposure: internal, criticality: standard, in_scope: true }
assets:
  - match: { operating_system: "*PAN-OS*" }      # firewalls are internet-facing by role
    role: perimeter_firewall
    environment: production
    exposure: external
  - match: { hostname: "dc*" }                   # domain controllers
    role: domain_controller
    environment: production
    criticality: crown_jewel
  - match: { hostname: "plc #*" }                # OT/ICS
    role: ot_plc
    environment: production
    criticality: crown_jewel
  - match: { hostname: "endpoint #*" }           # end-user devices: in scope, lower priority
    role: workstation
    environment: non_production
  - match: { hostname: "dev-*" }                 # covered by pre-prod patch testing
    in_scope: false
```

Match on `hostname`, `operating_system`, `fqdn`, `ip`, or `asset_id` with glob patterns. **First match
wins.** `--overlay` is repeatable and consulted in order, so a hand-written overlay listed first always
beats a generated one listed second. Every finding records which overlay file and rule classified it.

Point this at an export from your real CMDB and the tool works unchanged — that is the integration point.

An IP-derived exposure heuristic (public address ⇒ external) exists in the library as
`resolve_context(..., use_ip_heuristic=True)`. It is **off by default and not exposed as a CLI flag**, so
`vuln-prioritizer run` never uses it. It ranks last in the exposure chain, after Tenable One, tags and the
overlay, and is invalid wherever addressing doesn't reflect reachability (e.g. randomized lab IPs).

---

## Threat-intel enrichment

Powered by [threat-intel-toolkit](https://github.com/kevinmhorvath/threat-intel-toolkit) (key-free).

**Setup (once).** Enrichment imports the upstream `exploit_check.py` and **runs that third-party code
in-process**, so it is not vendored here — fetch it before any live run, or set `EXPLOIT_CHECK_PATH` to
an existing checkout:

```bash
git clone --depth 1 https://github.com/kevinmhorvath/threat-intel-toolkit reference/threat-intel-toolkit
```

`--offline` runs need none of this.

**`--enrich local` (default)** — CISA KEV, Metasploit, Exploit-DB and Nuclei from locally cached feeds.
One ~35 MB download, then every CVE resolves in-memory. No per-CVE network calls.

**`--enrich full`** — adds per-CVE EPSS and the GitHub PoC aggregators (~3 HTTP calls per CVE, so a real
tenant can mean tens of thousands of requests). Use `--max-lookups` to start small.

**Gating** — only findings worth deep enrichment are looked up: severity ≥ High, **or** CVSS ≥ 7, **or**
on KEV, **or** EPSS ≥ 0.10. Lookups are **memoized per distinct CVE**, so a CVE on 500 assets costs one
fetch.

**Caching & reproducibility** — a live run writes a dated, resumable cache. Replay it with
`--offline --intel-cache <file> --as-of <date>` for a byte-identical worklist. An interrupted run resumes.

**Evidence is precise about what it checked.** A CVE found in no feed reads *"no exploit in
Metasploit/Exploit-DB/Nuclei; PoC aggregators not consulted"* — never a false *"no public exploit found."*

**Divergence flags** — `vpr_low_but_exploited` marks findings where the vendor's VPR says Low but the CVE
is on KEV or has a weaponized exploit. These annotate the finding; they never silently change a tier.

---

## The AI classifier

`vuln-prioritizer classify` uses an LLM to propose asset classifications for the long tail that
deterministic rules can't resolve, reading scanner evidence (Device Type, OS fingerprint, CPE, open
ports) rather than guessing from a hostname.

It is deliberately constrained:

- **Firewalled from scoring.** `scoring/` never imports `classifier/`, enforced by an import-graph test
  and a fresh-interpreter check. The AI proposes, a human reviews and freezes, the deterministic engine
  decides.
- **Structurally cannot escalate.** It can never set `exposure: external`, `criticality: crown_jewel`, or
  `in_scope` — at any confidence. Those stay human decisions.
- **Abstains rather than fabricate.** Below the confidence threshold, or with no usable evidence, it
  returns `unknown` + a review flag and explains why.
- **Validated output.** Answers are checked against the project's enums; anything outside them is
  rejected. Asset data reaches the model as structured data, never as instructions.
- **No new dependency.** Stdlib `urllib`; `ANTHROPIC_API_KEY` from the environment only. With no key it
  logs a skip and the tool runs normally.

Output is a **draft overlay** under `out/` (tenant-derived — do not commit it). Review it, then pass it as
a *later* `--overlay` so hand rules win.

> On sparse scan data the honest outcome is abstention. In a reference run, only 7 of 201 unresolved
> assets carried any usable signal and the classifier declined to classify the rest — which is the
> intended behaviour: a fabricated crown-jewel designation would manufacture a false emergency.

---

## Outputs

Written to `--out`:

| File | Contents |
|---|---|
| `worklist.md` | Ranked worklist, grouped by tier, human-readable |
| `worklist.csv` | One row per finding: asset, role, CVE, tier, SLA, due date, evidence, every resolved input and its source, flags |
| `executive_report.md` | Toil-saved metric, findings by tier, SLA compliance, per-role breakdown, top risks, divergence highlights |
| `informational.csv` | Scanner artifacts (service detection, OS/CPE identification, traceroute…) — removed from remediation ranking |
| `excluded.csv` | Out-of-scope assets with reasons |

CSV cells beginning `= + - @` are neutralised, so the output is safe to open in a spreadsheet.

**SLA reporting uses two clocks:** `fix_by` (as-of + SLA) is the forward remediation deadline;
**breach** is computed from `first_found + SLA` against today, because auditors count from discovery.
Both appear on every row.

---

## CLI reference

### `run`

```
vuln-prioritizer run --db <navi.db> [--overlay <yaml>...] --out <dir>
                     [--offline] [--intel-cache <file>] [--enrich local|full]
                     [--as-of <ISO8601>] [--max-lookups N] [--progress-every N]
                     [--triage-minutes M] [--no-timing] [--top N] [--threat-first]
```

| Flag | Purpose |
|---|---|
| `--overlay` | Asset-context overlay; optional and repeatable, first match wins in the order given. Omitted ⇒ every asset is unknown/internal and flagged |
| `--offline` | No network; replays a frozen `--intel-cache` deterministically |
| `--intel-cache` | Dated, resumable threat-intel cache (write when live, read when offline) |
| `--enrich` | `local` (cached feeds, default) or `full` (adds per-CVE EPSS + PoC aggregators) |
| `--as-of` | Fixes the report date and due-date arithmetic; required for byte-identical reruns |
| `--max-lookups` | Cap new CVE lookups (highest-ranked first) |
| `--progress-every` | Live runs: progress line to stderr every N fetches (default 100; 0 = silent) |
| `--triage-minutes` | Per-finding assumption for the analyst-time estimate |
| `--no-timing` | Omit the measured time-to-worklist line so `executive_report.md` is byte-reproducible |
| `--top` | Rows to print to stdout (default 15) |
| `--threat-first` | Show only findings with active threat signal (KEV / weaponized / public exploit) |

### `classify`

```
vuln-prioritizer classify --db <navi.db> [--overlay <yaml>...] [--out <file>]
                          [--only-unclassified | --no-only-unclassified]
                          [--model <id>] [--batch N] [--min-confidence X]
                          [--cache <file>] [--limit N] [--as-of YYYY-MM-DD] [--dry-run]
```

| Flag | Purpose |
|---|---|
| `--out` | Draft overlay to write (default `out/classification.ai.yaml`) |
| `--overlay` | Preceding overlay(s); assets they already classify are skipped with `--only-unclassified` |
| `--only-unclassified` / `--no-only-unclassified` | Default on: classify only assets the preceding overlays leave unknown |
| `--model` | Model id (default `claude-haiku-5-5`) |
| `--batch` | Assets per API request (default 8) |
| `--min-confidence` | Abstain below this confidence (default 0.7) |
| `--cache` | Resumable cache file (default `<out>.cache.json`) |
| `--limit` | Classify at most N distinct (hostname, OS) targets |
| `--as-of` | Date stamped into each rule's `source` (default: today, UTC) |
| `--dry-run` | Count targets (cached vs. to classify) and exit; sends and writes nothing |

---

## Safety posture

- **Read-only against the tenant.** No tags, no ACR changes, no scans. Verified by test.
- **Deterministic.** Same inputs → byte-identical output, including live-enriched runs replayed from a
  frozen cache.
- **Auditable.** Every tier records impact value and source, probability value and source, the matrix
  cell, the asset class and shift applied, and any flags.
- **No false emergencies.** Findings with no exploitation evidence are capped and flagged, never
  escalated. The AI layer cannot escalate at all.
- **Secrets stay out.** `navi.db` holds Tenable API keys and belongs outside the repository; `.env` and
  generated tenant-derived overlays are gitignored.

---

## Limitations

- **Asset context is only as good as its source.** Without Tenable One exposure data, tags, or a CMDB
  overlay, assets resolve to safe defaults and are flagged — they are not guessed.
- **Findings with no CVE** (end-of-life software, configuration checks) have no probability signal by
  nature. They are scored on impact, capped at Tier 3, and flagged — correct, but they need a
  replacement track rather than a patch SLA.
- **`--enrich full` is expensive** on a real tenant. Start with `--max-lookups`.
- **The AI classifier needs evidence.** On sparse scan data it abstains, by design.
- **Recorded Future is not modelled** — the probability resolver has a clear extension point for it.
