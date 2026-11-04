<h1 align="center">vuln-prioritizer</h1>
<p align="center"><b>Deterministic, context-aware vulnerability prioritization.</b></p>
<p align="center">
Turns a scanner dump into a ranked, evidence-backed remediation worklist — with defensible SLAs,
real threat intelligence, and no guessing.
</p>

<p align="center">
<a href="DOCS.md">Documentation</a> ·
<a href="#quickstart">Quickstart</a> ·
<a href="DOCS.md#cli-reference">CLI</a> ·
<a href="DOCS.md#the-ai-classifier">AI layer</a>
</p>

<p align="center">
<img alt="License: MIT" src="https://img.shields.io/badge/License-MIT-green.svg">
<img alt="Python 3.10+" src="https://img.shields.io/badge/python-3.10%2B-blue.svg">
<img alt="Tests" src="https://img.shields.io/badge/tests-489%20passing-brightgreen.svg">
<img alt="Runtime deps" src="https://img.shields.io/badge/runtime%20deps-none-lightgrey.svg">
<a href="https://exchange.tenable.com/"><img alt="Listed on CyberAgents Exchange" src="https://img.shields.io/badge/CyberAgents%20Exchange-Listed-E7FF00?style=flat-square&labelColor=1E2426"></a>
</p>

---

A scanner hands you tens of thousands of findings and no answer to the only question that matters:
**what do I fix first?** Sorting by CVSS is wrong — it measures theoretical severity, not whether a flaw
is actually being exploited, nor whether it sits on an internet-facing crown jewel or a dev laptop.

`vuln-prioritizer` fuses **ground-truth inventory**, **live exploit intelligence**, and **asset context**
into a two-layer model, and produces a worklist where every item carries its evidence, its tier, and its
due date — and where the same inputs always produce the same answer.

```mermaid
flowchart LR
    I[navi.db<br/>inventory · CVSS · VPR] --> S[two-layer scorer]
    T[threat intel<br/>KEV · exploit maturity] --> S
    C[CMDB overlay<br/>exposure · criticality] --> S
    S --> W[ranked worklist<br/>+ executive report]
```

On a reference tenant of **19,052 findings / 1,394 assets**:

| | |
|---|---|
| Analyst's starting list | **102 urgent** — a **99.5% reduction** |
| Informational scan artifacts separated | **8,769** |
| Actively-exploited vulns the vendor score rated *Low* | **9** |
| Time to worklist | **< 1s**, byte-reproducible |

## Quickstart

```bash
pip install -e .

# No tenant, no API key: build the 100% synthetic fixture and run the whole
# scored pipeline offline, then replay it byte-for-byte to prove determinism.
bash scripts/demo.sh

# Against your own data: point --db at a navi.db exported by navi (read-only).
vuln-prioritizer run --db ~/navi.db --overlay classification.example.yaml --out out --offline

# Live, key-free threat intel (CISA KEV + exploit maturity), cached and replayable.
vuln-prioritizer run --db ~/navi.db --overlay classification.example.yaml --out out \
  --intel-cache out/intel.json
```

Inventory comes from [navi](https://github.com/packetchaos/navi) (Tenable → local SQLite). Outputs land in
`out/`: `worklist.md` / `.csv`, `executive_report.md`, plus `informational.csv` and `excluded.csv`.

A worklist row explains itself:

> **Tier 0 · Emergency ~12h / out-of-band** — `fw-edge-01` (perimeter_firewall) · CVE-2026-109618
> *Evidence:* CVE-2026-109618: on CISA KEV since 2026-10-26; Exploit-DB 1 entry; Nuclei template
> *Inputs:* impact CRITICAL [cvss_unattributed 9.8] x probability CRITICAL [vpr 9.5] -> T1; asset class externally_exposed (shift +1, applied +1) -> T0; env production[overlay], exposure external[overlay], criticality standard[overlay_default]; overlay rule 3 (perimeter_firewall)

## Why deterministic

Every tier is a reproducible function of recorded inputs — CVSS, VPR, EPSS, CISA KEV, exploit maturity,
asset context. Same inputs, same answer, byte for byte, including live-enriched runs replayed from a
frozen cache. An LLM may *propose* asset classifications, but it is **firewalled from scoring**, cannot
set `external` or `crown_jewel`, and abstains rather than fabricate.

- **Read-only** — never writes to your tenant. Verified by test.
- **Auditable** — every tier records the inputs and sources that produced it.
- **Honest about gaps** — flags what needs a human instead of guessing.

**→ [Full documentation](DOCS.md)** — the scoring model, asset-context overlays, enrichment modes,
the AI classifier, CLI reference, and limitations.

## Built on

[navi](https://github.com/packetchaos/navi) for Tenable inventory ·
[threat-intel-toolkit](https://github.com/kevinmhorvath/threat-intel-toolkit) for key-free exploit
intelligence. Both MIT, both on the Tenable CyberAgents Exchange — chaining open security components is
what the Exchange is for.

## Install as a Claude Code plugin

```
/plugin marketplace add alkaf499/vuln_prioritizer
/plugin install vuln-prioritizer@vuln-prioritizer-marketplace
```

This installs the `vuln-prioritizer` skill. The `vuln-prioritizer` command itself still comes from
`pip install -e .` (see [Quickstart](#quickstart)).

## License

MIT — see [LICENSE](LICENSE). Upstream feeds and tools remain under their own licenses.
