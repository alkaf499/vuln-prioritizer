# SWARM Global — Context-Aware Vulnerability Prioritization Skill
## Design & Build Spec (v0.9)

**Event:** SWARM Global (virtual), Nov 2–6 2026 · Tenable + Anthropic · open-source, publish to CyberAgents Exchange.
**Entry type:** Skill (chains two existing Exchange entries) + a deterministic scoring tool; MCP server = stretch.
**License:** MIT (matches both upstreams).
**Team/time:** 1–3 people, 2–3 days, split across Claude Code sessions.

> **Architecture stance (per event QA):** Tenable integration is **not required** — any working skill
> that solves a real workflow qualifies. So the **scorer is source-agnostic**: it operates on a normalized
> finding schema, and **navi/`navi.db` is adapter #1** and the flagship demo.
>
> **Read-only posture (LOCKED):** the skill **never writes to the Tenable tenant**. All reads, no tags,
> no ACR writes, no scans. Mirrors navi's own write-gate ethos and is a safety claim worth making in the pitch.
>
> **v0.9 (pipeline/report only — no Layer-1/Layer-2 rule changes):** (1) Nessus **Info-severity**
> findings (Service Detection, Traceroute, OS ID, CPE, MAC addresses, …) are not remediation work: they
> are split off before enrichment/scoring, excluded from the ranked worklist, and reported in a separate
> counted "Informational" section + `informational.csv` (same pattern as `in_scope: false`). (2) Within a
> tier the worklist order is **KEV first** → VPR desc → CVSS desc → criticality → exposure → finding_id
> (confirmed exploitation outranks a higher VPR with no exploit evidence).
>
> **v0.8 change:** a finding with **no probability signal** (impact-only, `reevaluate_probability`) is
> **not eligible for the external-exposure uplift** and its final tier is **capped at Tier 3**. No
> exploitation evidence must never produce a false emergency (e.g. an EoL/no-CVE "critical" on an
> internet-facing firewall was becoming Tier 0). It is a planned-remediation item, flagged, and the
> normal matrix + uplift apply automatically once a probability signal (VPR/EPSS/KEV, incl. live
> threat-intel) appears. See decision #12.
>
> **v0.7 change:** the v0.6 "no-downgrade floor" is **removed** — it forced every KEV'd critical onto an
> unachievable 24h SLA fleet-wide (a Patch-Tuesday dump of KEV'd criticals would put the whole laptop
> estate in perpetual audit breach). Asset context must be allowed to relax the SLA for low-exposure assets.
> KEV floor stays at **High**.

---

## 1. One-line pitch

A **deterministic, context-aware exposure-prioritization skill** that fuses ground-truth vulnerability
inventory (via **navi** / `navi.db`) with open-source exploit-maturity intel (via **threat-intel-toolkit**)
and organizational asset context (CMDB overlay), applying a two-layer remediation-tier model to produce a
**ranked, evidence-backed, audit-defensible remediation worklist and executive report**.

The novel contribution = the **decision engine**: the two-layer scorer + the navi × exploit-maturity
cross-check + the ranked worklist. Upstreams supply facts; we supply "fix these, in this order, by this
date, because X."

---

## 2. Upstreams we build on (both MIT, both on the Exchange)

- **navi** (`packetchaos/navi`, `pip install navi-pro`) — deterministic Tenable engine → local SQLite
  mirror `navi.db`. **Adapter #1** into our normalized schema. Used **read-only**.
- **threat-intel-toolkit** (`kevinmhorvath/threat-intel-toolkit`) — key-free, stdlib-only, deterministic.
  **`exploit-availability-check`**: CVE → exploit-maturity tier + in-the-wild (CISA KEV, EPSS, Metasploit,
  Nuclei, Exploit-DB, nomi-sec/trickest).

---

## 3. The prioritization logic (LOCKED)

### Layer 1 — Vulnerability Score (intrinsic technical risk, asset-independent)

**Impact — CVSS base score (0–10), fallback hierarchy:**
1. NVD base score where available
2. CNA-provided CVSS base score where NVD not yet available
3. CVSS with no stated source (`cvss_unattributed`) — ranks below CNA, above scan severity
4. Scan-source severity (Tenable / MS Defender native), mapped directly to a band
5. Neither available → impact `Low` + `IMPACT_MISSING` flag

**Probability — Tenable VPR.** Fallbacks:
- VPR absent → supporting TI (EPSS; Recorded Future not modelled), **most conservative = highest-urgency band**
- No probability signal → impact band used as probability band (matrix diagonal, `IMPACT_ONLY_POLICY`),
  **flagged for re-evaluation**
- **EPSS → band map:** ≥0.90 Critical · 0.50–0.899 High · 0.10–0.499 Medium · <0.10 Low
- **KEV floor:** on CISA KEV → probability forced to **≥ High**, applied LAST, over any source incl. VPR.
  KEV counts as a probability signal, so a KEV finding with no VPR/EPSS is **not** flagged for re-evaluation.
  *(High, not Critical: KEV ensures a finding can't be buried, but routine KEV'd criticals must remain
  asset-conditionable — see Layer 2. A KEV'd critical only reaches Layer-1 Tier 1 when the probability
  signal is independently Critical, e.g. EPSS ≥0.90 or VPR 9–10.)*

Both axes resolve to a **band**; bin with standard cutoffs (≥9.0 Crit, ≥7.0 High, ≥4.0 Med, else Low).
Multi-CVE findings take the **worst case across CVEs** per signal.

**Tier matrix** (rows = CVSS impact band, cols = VPR probability band):

| impact \ probability | Crit (9–10) | High (7–8.9) | Med (4–6.9) | Low (0–3.9) |
|---|---|---|---|---|
| Critical (CVSS 9–10) | Tier 1 · 24h | Tier 2 · 10d | Tier 3 · 30d | Tier 4 · next cycle |
| High (CVSS 7–8.9) | Tier 2 · 10d | Tier 2 · 10d | Tier 3 · 30d | Tier 4 · next cycle |
| Medium (CVSS 4–6.9) | Tier 2 · 10d | Tier 3 · 30d | Tier 4 · next cycle | Tier 4 · next cycle |
| Low (CVSS 0–3.9) | Tier 4 · next cycle | Tier 4 · next cycle | Tier 4 · next cycle | Tier 4 · next cycle |

### Layer 2 — Asset classification (conditioning layer) — REVISED v0.7

**Scope and environment are separate concerns.** Environment is *descriptive* and conditions the tier;
it never excludes. Only an explicit `in_scope: false` excludes an asset — and excluded assets are
**reported separately, never silently dropped**.

| Asset class | Definition | Effect on tier |
|---|---|---|
| **Externally exposed** (any environment) | Internet-reachable, inbound path from open internet | **+1 uplift** (Tier 1 → **Tier 0 Emergency · ~12h / out-of-band**) |
| Business critical prod | Prod CJ / CJ-support / RTO-defined | Matrix as-is (baseline) |
| Non-critical prod | Prod, internal, not business-critical | **−1 downgrade** |
| **Non-production** (dev/test/staging, workstations) | Not a production-lifecycle asset | **−1 downgrade** (in scope) |
| `in_scope: false` | Policy exclusion (e.g. endpoints owned by desktop ops; pre-prod patch testing covers dev/test) | Excluded; reported separately |

Multi-class resolution: **external exposure takes precedence** (a single class, so a single shift applies).

**Shift rules (v0.7):** exactly **one** ±1 shift per asset (chosen by precedence), clamped at T0/T4.
**The downgrade always applies** — there is no no-downgrade floor. The single-shift limit already prevents
burial: a Layer-1 Tier 1 or Tier 2 finding can fall at most one tier, so a KEV'd critical never drops past
Tier 3 (never to "next cycle").

**Impact-only findings (v0.8).** If Layer 1 had **no probability signal** (no VPR, EPSS or KEV —
`IMPACT_ONLY_POLICY` diagonal, `reevaluate_probability` flag kept), Layer 2 (a) **withholds the +1
exposure uplift** (an external asset stays at its Layer-1 tier) and (b) **caps the final tier at
Tier 3 (30d)** *after* the shift. The −1 downgrade still applies. Tier 4 findings are unaffected (the
cap only lowers urgency; a withheld uplift never lifts a T4 to T3). Both effects are recorded per row
(`uplift_suppressed`, `impact_only_capped`). Example: EoL/no-CVE critical on an external firewall →
Layer-1 T1 → uplift withheld → capped **T3 · 30d, flagged, not T0**.

**Audit-defensible SLAs — worked example (KEV'd critical RCE, the Patch-Tuesday case):**

| Asset | low VPR (KEV→High) | EPSS ≥0.90 (Critical) |
|---|---|---|
| Internet-facing server | Layer-1 T2 → +1 → **T1 · 24h** | T1 → +1 → **T0 · 12h** |
| Crown-jewel internal server | baseline → **T2 · 10d** | **T1 · 24h** |
| Non-critical internal server | −1 → **T3 · 30d** | −1 → **T2 · 10d** |
| **Internal laptop** | −1 → **T3 · 30d** | −1 → **T2 · 10d** |
| **Remote-worker laptop (exposed)** | +1 → **T1 · 24h** | +1 → **T0 · 12h** |

Rationale: a KEV'd critical on the internal fleet = **30 days** (achievable, defensible in audit); the
genuinely high-probability ones = 10 days; the same CVE internet-facing = 24h. KEV can't be buried
(single-shift limit), but it doesn't force the whole estate to 24h. **A purely-internal laptop caps at
Tier 2 (10d);** it reaches T1/T0 only via external exposure (e.g. a remote-worker exposed service).

**Exposure uplift applies regardless of environment** — an internet-exposed staging box or remote-worker
laptop is a classic breach vector.

### Asset-context resolver chain (LOCKED v0.5)

Asset classification attributes (Environment, Criticality/CJ, Exposure, `in_scope`) are **CMDB facts,
not scanner facts**. Each resolves through a priority chain, mirroring the CVSS fallback pattern:

1. **Tenable One `exposure_classes` / asset criticality** — auto-used when present
2. **Tenable tags** (read-only) — if the org already maintains a convention
3. **CMDB classification overlay** (local YAML/CSV) ← **the practical + real-world path**
4. **Unknown** → default `internal` / in-scope, **flagged for re-evaluation**

**IP-derived exposure heuristic:** implemented but **opt-in only, off by default**, documented as invalid
where IPs are randomized (as in the event lab).

**Overlay format (the CMDB integration point).** Matching supports `hostname`, `operating_system`, `fqdn`,
`ip`, `asset_id` with glob patterns — **FQDN is empty on nearly all lab assets, so hostname/OS matching is
required**. First match wins; deterministic.

```yaml
defaults: { environment: unknown, exposure: internal, criticality: standard, in_scope: true }
assets:
  # OT/ICS assets — business-critical by definition
  - match: { hostname: "plc #*" }
    role: ot_plc
    environment: production
    criticality: crown_jewel
  - match: { hostname: "ot device #*" }
    role: ot_device
    environment: production
    criticality: crown_jewel
  # Perimeter devices — internet-facing by role
  - match: { operating_system: "Palo Alto Networks PAN-OS*" }
    role: perimeter
    environment: production
    exposure: external
  # Servers
  - match: { operating_system: "Microsoft Windows Server*" }
    role: server
    environment: production
  # End-user devices — non-production, but IN SCOPE
  - match: { hostname: "endpoint #*" }
    role: workstation
    environment: non_production
    criticality: standard
    in_scope: true        # flip to false if the VM procedure is server-only
  # Lifecycle exclusion — covered by pre-prod patch testing
  - match: { hostname: "dev-*" }
    environment: non_production
    in_scope: false
```

### Tier ladder (SLAs — LOCKED)

`T4 (next patch cycle) < T3 (30d) < T2 (10d) < T1 (24h) < T0 (Emergency ~12h / out-of-band)`

One ±1 shift per asset (by precedence), clamped at **T0 ceiling / T4 floor**
(T2→T1, T3→T2, T4→T3 on uplift; T1→T2, T2→T3, T3→T4 on downgrade). No no-downgrade floor.

### Decisions locked

1. Ordered tier ladder + clamp; **one ±1 shift per asset** — **accepted**
2. EPSS→band map + "most conservative = highest-urgency" — **accepted**
3. KEV floor = **≥ High** (not Critical), applied last over any source; KEV counts as a probability signal — **accepted**
4. Precedence: external exposure > business-critical > non-critical/non-prod — **accepted**
5. Per-finding scoring (asset × vuln); aggregate in reporting only — **accepted**
6. Every tier carries its inputs (impact source, probability source, matrix cell, asset class, shift) — **accepted**
7. Multi-CVE findings: worst-case across CVEs per signal — **accepted**
8. Read-only against the tenant; asset context via resolver chain + CMDB overlay — **accepted**
9. Environment ≠ scope. Only `in_scope: false` excludes; exclusions reported separately — **accepted**
10. ~~No-downgrade floor~~ — **REMOVED v0.7.** Operationally unrealistic (would force fleet-wide 24h on
    Patch-Tuesday KEV'd criticals). Downgrade applies normally; single-shift limit prevents burial.
    **Consequence: purely-internal laptops cap at Tier 2; reach T1/T0 only via exposure.**
11. Exposure uplift applies regardless of environment — **accepted**
12. S1 scorer choices: `CveSignal` schema addition · impact-only = matrix diagonal behind
    `IMPACT_ONLY_POLICY` · `cvss_unattributed` ranking · KEV-no-VPR not flagged · RF not modelled ·
    missing CVSS+severity → Low + `IMPACT_MISSING` — **all accepted**.
    **Amended v0.8:** impact-only findings are **ineligible for the exposure uplift** and **capped at
    Tier 3** (flag `reevaluate_probability` kept; downgrade still applies). Rationale: no
    exploitation evidence must never produce a false emergency — these are planned-remediation
    items, re-scored automatically when a probability signal appears, at which point the normal
    matrix + uplift apply.

---

## 4. Normalized schema + data-source mapping

Per-finding: `cve(s)`, `cvss_base` + `cvss_source`, `scan_severity`, `vpr`, `epss`, `kev`, `exploit_maturity`,
plus optional per-CVE `cve_signals[]` (`CveSignal(cve, cvss_base_score, cvss_source, epss_score, kev)`).
Per-asset: `exposure`, `criticality/CJ`, `environment`, `role`, `in_scope`, `acr/aes` — each with its
**resolved source** recorded.

| Normalized field | Source |
|---|---|
| CVSS base (impact) | `plugins.cvss_base_score` / `cvss3_base_score`; `tone_findings.finding_cvss3_source/_base_score` |
| Scan-source severity fallback | `plugins.severity`; `tone_findings.finding_severity` |
| VPR (probability) | `plugins.vpr_score`; `tone_findings.finding_vpr_score`/`finding_vpr2_score`; `vpr_updated` |
| Exploit maturity / ITW | `plugins.exploit_available`, `exploit_framework_*`; `epss` table; **threat-intel-toolkit** |
| ACR / AES | `assets.acr/aes`; `tone_assets.acr/aes` — **weak signal in lab: 1,102 assets have none, rest cluster 4–6** |
| **Exposure** | resolver chain → T1 `exposure_classes` → tags → **CMDB overlay** → unknown+flag |
| **Crown jewel / criticality** | resolver chain → T1 criticality / ACR → tags → **CMDB overlay** → default |
| **Environment / role / in_scope** | resolver chain → tags → **CMDB overlay** → unknown+flag (in scope) |
| CVE join key | `plugins.cves` / `vulns.cves` (LIKE-join, mirrors the shipped EPSS zipper) |

**Adapter #2 (stretch):** generic CSV or MS Defender export → same normalized schema.

---

## 5. Pipeline (asset-first — LOCKED default; threat-first as toggle)

1. **Adapter (navi.db)** + **CMDB overlay** → normalized findings with asset context.
2. **Cheap local gate** → severity ≥ high OR KEV OR EPSS ≥ threshold.
3. **exploit-availability-check** → deep maturity + evidence on survivors only.
4. **Two-layer scorer** → L1 (matrix) ∘ L2 (asset conditioning) → tier + SLA + due date.
5. **Output** → ranked evidence-backed worklist + executive report (incl. excluded-asset count).

**Threat-first toggle:** fresh KEV / trending CVEs → cross-check "are we exposed?" → surface hits.

---

## 6. Build plan — Claude Code sessions

Copy-paste kickoff prompts in **`session-prompts.md`**.

- **S0 · Scaffold + fixtures** ✅ *done*
- **S1 · Layer 1 scorer** ✅ *done — 116 tests; KEV floor = High verified (F08: VPR 3.0 → High → T2). No change in v0.7.*
- **S2 · Layer 2 conditioning** ✅ *built (205 tests) — needs v0.7 edit: **remove the no-downgrade floor**;
  downgrade applies to Layer-1 T1 normally; three-way case stays T0 via exposure precedence.*
- **S3 · Evidence/enrichment** (parallel to S2) — exploit-availability-check as fallback + KEV floor +
  evidence strings; cheap-gate ordering; divergence flag; populates `cve_signals`.
- **S4 · Skill + orchestration** — `SKILL.md`; ranked worklist (chat + md/csv); plugin manifest.
- **S5 · Exec report + polish** — exec report incl. **toil-saved metric**, per-`role` grouping, SLA-breach
  view (audit); README; CI healthcheck; demo script.

- **S4.5 · Optional LLM asset classifier ("Layer B")** — `classifier/` + `vuln-prioritizer classify`. Drafts an
  overlay (`out/classification.ai.yaml`, same format, per-rule `source`/`rationale`) for assets no hand rule
  covers. **Determinism firewall:** `scoring/`, `pipeline` and `run` never import or call it (import-graph
  tests enforce this); the pipeline consumes the draft only as an ordinary overlay FILE, passed explicitly as a
  *later* repeatable `--overlay` (first listed overlay with a matching rule wins; provenance names the file).
  Model output is untrusted: exact-enum validation, closed role list, abstain on low confidence / unknown
  environment / high-privilege results below 0.9; never emits `in_scope`. Stdlib `urllib`, key from
  `ANTHROPIC_API_KEY` only; no key ⇒ logs and skips. The draft and its cache are tenant-derived: never commit.

Dependency graph: S0 → {S1 → S2, S3} → S4 → S5; S4.5 sits beside S4 and feeds only overlay files.

---

## 7. Judging rubric & how we win each axis

| Weight | Axis | Our play |
|---|---|---|
| **40%** | **Mission impact** | Prioritization + SLA-dated worklist = direct toil kill. **Quantify**: N findings → ranked worklist in X s = analyst-days replaced. **Audit-defensible, achievable SLAs** (not fleet-wide 24h) is itself a mission-impact story. |
| **20%** | **Technical execution** | Deterministic + fixtures + live demo on the lab + CI healthcheck. Same inputs → same tiers, every input shown. |
| **20%** | **Innovation & creativity** | The **fusion**: weaponization cross-check + exposure → Tier 0 uplift + graceful degradation via resolver chains + "deterministic, not guessing." |
| **20%** | **Pitch execution** | The evidence-backed line *is* the pitch: "Tier 0 because internet-exposed + KEV + Metasploit + EPSS 97%." |

**Strategic priority:** mission impact (40%) outranks everything. Protect the **end-to-end worklist +
exec report on real data** over breadth (2nd adapter, MCP server, extra factors).

---

## 8. Submission compliance (hard gate)

- API keys via env/local config only — **never committed**. **`navi.db` contains the API keys**, so it is
  a secrets-bearing file — keep it **outside the repo** (`~/tenable-lab/`).
- `.gitignore`: `navi.db`, `.env`, `*.key`, CSV exports, real-data artifacts.
- Fixture + CMDB overlay used for the demo are **100% synthetic** and labelled as such
  (`classification.example.yaml`).
- Pre-submission: secret-scan repo + history, confirm MIT license, confirm no tenant data committed.

---

## 9. Lab environment — verified findings (Nov 2)

| Finding | Detail | Consequence |
|---|---|---|
| **Read-only API user** | Tag create → `403 You need to be an admin` | Cannot seed tags or write ACR. Asset context comes from the CMDB overlay. Reinforces read-only posture. |
| **No Tenable One tables** | `navi config update tone -a -f` → 400 | `exposure_classes` unavailable → resolver chain falls to overlay. Entitlement ask raised with Tenable. |
| **Windowed sync** | `navi config update full` = 30d vulns / 90d assets | Widen with `--days`; assets went 170 → 1,394. Lab reportedly holds 120k–250k. |
| **VPR + CVSS ~100% populated** | 7,677 plugins with both | Fallback branches won't fire on lab data — **the fixture remains the only place they're tested. Don't delete it.** |
| **Randomized IPs, no topology** | Synthetic hosts | IP-derived exposure heuristic stays **off by default**. |
| **Empty tags table** | No tags in tenant | Overlay is the path. |
| **ACR weak** | 1,102 assets no ACR; rest 4.0–6.0, no 8–10 | ACR won't identify crown jewels — **device-class rules carry criticality**. |
| **FQDN empty** | Nearly all assets | **Overlay must match on `hostname` + `operating_system`.** |
| **OT/ICS environment** | `plc #*`, `ot device #*`, `field device #*`, `comm. adapter #*`, `endpoint #*`; PAN-OS, Cisco IOS, Win Server, Win 10 Pro, EOL Linux, HP-UX | Real derivable structure → **rule-based overlay, not random assignment**. |

---

*Facts from navi.db, the CMDB overlay and public feeds; the model only orchestrates. Reproducible by design.*
