#!/usr/bin/env bash
# Pre-submission compliance scan (CLAUDE.md §8). Read-only: only inspects git state.
#
#   bash scripts/secret_scan.sh
#
# Exits 1 if anything needs a human look. It is a grep-level scan, not a replacement for a
# dedicated scanner: run gitleaks / trufflehog too if you have them (see COMPLIANCE.md).
set -uo pipefail
cd "$(git rev-parse --show-toplevel)"

fail=0
SELF=':!scripts/secret_scan.sh'

# Tenable API keys are 64 hex chars; navi stores them as accessKey/secretKey.
PATTERNS='(access[_-]?key|secret[_-]?key|api[_-]?key|x-apikeys)["'"'"' :=]+[0-9a-fA-F]{32,}|[0-9a-fA-F]{64}|-----BEGIN [A-Z ]*PRIVATE KEY-----|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,}|xox[baprs]-[A-Za-z0-9-]{10,}'
FORBIDDEN='(^|/)(navi\.db|\.env(\..*)?|[^/]*\.key|[^/]*\.pem|[^/]*\.csv)$|^out/|^reference/|(^|/)worklist[^/]*\.md$|(^|/)executive_report\.md$|(^|/)intel[^/]*\.json$'

echo "== 1. real-data / secret-bearing files tracked in the working tree"
hits=$(git ls-files | grep -E "$FORBIDDEN" || true)
if [ -n "$hits" ]; then echo "$hits"; fail=1; else echo "none"; fi

echo
echo "== 2. the same paths ever committed (full history, all refs)"
hits=$(git log --all --pretty=format: --name-only --diff-filter=AM | sort -u | grep -E "$FORBIDDEN" || true)
if [ -n "$hits" ]; then echo "$hits"; fail=1; else echo "none"; fi

echo
echo "== 3. key-shaped strings in tracked files (working tree)"
hits=$(git grep -InE "$PATTERNS" -- . "$SELF" || true)
if [ -n "$hits" ]; then echo "$hits"; fail=1; else echo "none"; fi

echo
echo "== 4. key-shaped strings anywhere in history (commit:path:line)"
revs=$(git rev-list --all)
if [ -n "$revs" ]; then
  # shellcheck disable=SC2086
  hits=$(git grep -InE "$PATTERNS" $revs -- . "$SELF" || true)
else
  hits=""
fi
if [ -n "$hits" ]; then echo "$hits" | head -50; fail=1; else echo "none"; fi

echo
echo "== 5. .gitignore covers navi.db, .env, *.key, CSV exports, out/"
for p in 'navi.db' '.env' '*.key' '*.csv' 'out/'; do
  if grep -qxF "$p" .gitignore; then echo "ok   $p"; else echo "MISSING $p"; fail=1; fi
done

echo
echo "== 6. LICENSE is MIT"
if head -1 LICENSE | grep -q '^MIT License'; then echo "ok"; else echo "LICENSE is not MIT"; fail=1; fi

echo
if [ "$fail" -eq 0 ]; then echo "RESULT: clean"; else echo "RESULT: review the items above"; fi
exit "$fail"
