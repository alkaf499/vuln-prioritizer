# Submission compliance checklist (hard gate — CLAUDE.md §8)

Run through this before publishing to the CyberAgents Exchange. Items marked **auto** are checked by
`bash scripts/secret_scan.sh`; the rest are human confirmations.

## Secrets and real data

- [ ] **auto** No tracked or historically committed `navi.db`, `.env`, `*.key`, `*.pem`, `*.csv`,
      `out/`, `reference/`, worklist/report files or intel caches (`scripts/secret_scan.sh` §1–2).
- [ ] **auto** No key-shaped strings (Tenable access/secret keys are 64 hex chars; private keys;
      cloud and GitHub tokens) in the working tree **or in any commit** (§3–4). Review every hit —
      the 64-hex pattern also matches SHA-256 digests.
- [ ] **auto** `.gitignore` covers `navi.db`, `.env`, `*.key`, `*.csv`, `out/` (§5).
- [ ] `navi.db` lives outside the repo (e.g. `~/tenable-lab/navi.db`). It contains API keys.
- [ ] Run a dedicated scanner as a second opinion if available:
      `gitleaks detect --source . --log-opts="--all"` or `trufflehog git file://. --since-commit HEAD~999`.
- [ ] If anything real was ever committed: **rotate the key first**, then rewrite history
      (`git filter-repo`); deleting the file in a later commit does not remove it.

## Synthetic-only content

- [ ] `classification.example.yaml` is labelled SYNTHETIC and contains only generic device-class rules
      (no tenant, host, or customer names). The lab-specific overlay (`out/classification.lab.yaml`)
      stays gitignored.
- [ ] The test fixture (`src/vuln_prioritizer/fixtures/navi_fixture.py`) uses only `CVE-2099-*`,
      RFC 5737 / `10.99.*` addresses and `.example.test` hosts.
- [ ] No lab output (worklists, executive reports, screenshots with real hostnames) is in the repo,
      the README, or the demo materials you publish. Quote counts, not hostnames, unless cleared.

## Licensing

- [ ] **auto** `LICENSE` is MIT (§6). Upstreams `navi` and `threat-intel-toolkit` are MIT; the upstream
      `exploit_check.py` is imported unmodified from `reference/` (not vendored into this repo).

## Posture claims you can make (and the evidence)

| Claim | Evidence |
|---|---|
| Never writes to the Tenable tenant | `adapters/navi.py` opens SQLite `mode=ro` + `PRAGMA query_only`; test `test_run_is_read_only_for_the_database`; no HTTP client talks to Tenable |
| Deterministic | Byte-identical re-runs: `test_offline_output_is_byte_identical`, `test_exec_report_is_byte_reproducible_without_timing`, CI end-to-end job |
| Every tier is explainable | Each row carries `inputs` and `evidence` (CSV and Markdown) |
| Exclusions are never silent | `excluded.csv`, `informational.csv`, counts in every report |

## Final gate

```bash
pytest                                  # offline suite green
bash scripts/secret_scan.sh             # RESULT: clean
git status --short                      # nothing under out/, no *.db, no *.csv
```
