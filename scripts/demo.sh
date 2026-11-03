#!/usr/bin/env bash
# Scripted demo: lab navi.db -> ranked worklist + executive report, then a byte-for-byte
# offline replay. Read-only against the tenant (it only reads navi.db). ~2 minutes.
#
#   NAVI_DB=~/tenable-lab/navi.db OVERLAY=out/classification.lab.yaml bash scripts/demo.sh
#
# With no NAVI_DB it falls back to the 100% synthetic fixture, so it runs anywhere (offline).
#
# Env: NAVI_DB, OVERLAY (default classification.example.yaml), OUT (default out/demo),
#      ENRICH (local|full, default local), TRIAGE_MINUTES (optional, an assumption you state aloud),
#      OFFLINE_ONLY=1 to skip the live feed step.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

OUT="${OUT:-out/demo}"
OVERLAY="${OVERLAY:-classification.example.yaml}"
ENRICH="${ENRICH:-local}"
CACHE="$OUT/intel.json"
mkdir -p "$OUT"

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

if [ -z "${NAVI_DB:-}" ]; then
  say "0. No NAVI_DB given: building the synthetic fixture (no tenant data)"
  NAVI_DB="$OUT/synthetic-navi.db"
  rm -f "$NAVI_DB"
  python -m vuln_prioritizer.fixtures.navi_fixture "$NAVI_DB" > /dev/null
  OFFLINE_ONLY=1
fi
# The as-of label is frozen so the replay below is byte-identical; real fetch time is recorded separately.
AS_OF="${AS_OF:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
TRIAGE=()
[ -n "${TRIAGE_MINUTES:-}" ] && TRIAGE=(--triage-minutes "$TRIAGE_MINUTES")

if [ "${OFFLINE_ONLY:-0}" != "1" ]; then
  say "1. LIVE run: load navi.db -> enrich (KEV/Metasploit/Exploit-DB/Nuclei, $ENRICH) -> score -> rank"
  python -m vuln_prioritizer run --db "$NAVI_DB" --overlay "$OVERLAY" --out "$OUT/live" \
    --enrich "$ENRICH" --intel-cache "$CACHE" --as-of "$AS_OF" --top 5 --progress-every 5000 ${TRIAGE[@]+"${TRIAGE[@]}"}
  REPLAY=(--offline --intel-cache "$CACHE")
  SHOW="$OUT/live/executive_report.md"   # includes the measured time-to-worklist
else
  say "1. OFFLINE run (live threat-intel skipped)"
  python -m vuln_prioritizer run --db "$NAVI_DB" --overlay "$OVERLAY" --out "$OUT/offline" \
    --offline --as-of "$AS_OF" --top 5 ${TRIAGE[@]+"${TRIAGE[@]}"}
  REPLAY=(--offline)
  SHOW="$OUT/offline/executive_report.md"
fi

say "2. OFFLINE replay twice: the report must be byte-identical (deterministic, auditable)"
for n in a b; do
  python -m vuln_prioritizer run --db "$NAVI_DB" --overlay "$OVERLAY" --out "$OUT/replay-$n" \
    "${REPLAY[@]}" --as-of "$AS_OF" --no-timing --top 0 > /dev/null
done
for f in worklist.md worklist.csv excluded.csv informational.csv executive_report.md; do
  cmp "$OUT/replay-a/$f" "$OUT/replay-b/$f" && echo "identical: $f"
done

say "3. Executive report (head)"
sed -n '1,45p' "$SHOW"

say "Files in $(dirname "$SHOW"): executive_report.md worklist.md worklist.csv excluded.csv informational.csv"
