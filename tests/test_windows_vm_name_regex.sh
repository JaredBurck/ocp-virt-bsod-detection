#!/usr/bin/env bash
#
# test_windows_vm_name_regex.sh
# -----------------------------------------------------------------------------
# Direct regression test for the Windows-VM name-detection regex that is
# duplicated ("SINGLE CONTRACT", see CLAUDE.md) across:
#   - scripts/cnv-win-bsod-audit.sh
#   - scripts/cnv-qga-fleet-collect.sh
#   - must-gather/collection-scripts/common_bsod.sh
#   - insights-rules/plugins/bsod_cpu_checks.py (_WIN_NAME_RE, tested separately
#     in insights-rules/tests/test_cpu_checks.py::TestIsWindowsVM)
#
# Live-cluster E2E finding (2026-07-10): a real MTV-migrated VM named
# "winweb01-user1" -- with no OS annotation and no hyperv block yet (its
# freshly-imported, pre-template-application state) -- was invisible to
# every discovery layer because the regex required a non-letter boundary
# immediately after "win". This test locks in the fix and guards against
# regressing the existing "darwin"/"twin"/"winner" false-positive avoidance.
#
# This test extracts the regex directly from each shell file (so it can never
# silently drift out of sync with what actually ships) and validates it with
# jq against a shared table of expected matches/non-matches.
#
# Usage: tests/test_windows_vm_name_regex.sh
# Exit code: 0 if every file's regex produces the expected result for every
# name in the table, else 1.
# -----------------------------------------------------------------------------
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if ! command -v jq >/dev/null 2>&1; then
  echo "SKIP: jq is required but not installed"
  exit 0
fi

FILES=(
  "scripts/cnv-win-bsod-audit.sh"
  "scripts/cnv-qga-fleet-collect.sh"
  "must-gather/collection-scripts/common_bsod.sh"
)

# name -> expected (true/false)
# Positive cases include the exact live-cluster repro plus common enterprise
# role-name concatenations; negative cases are the pre-existing false-positive
# guards that must keep working.
declare -a CASES=(
  "winweb01-user1:true"
  "winweb01:true"
  "winsql-prod:true"
  "winapp02:true"
  "windc01:true"
  "winrdp1:true"
  "winrds-farm:true"
  "winsrv3:true"
  "winterm5:true"
  "winfs-share:true"
  "winprint01:true"
  "winhost1:true"
  "winshare1:true"
  "windns1:true"
  "windhcp1:true"
  "win2k22-bad-cpu:true"
  "win11-good:true"
  "windows-2022-vm:true"
  "windows2k16:true"
  "win10-test:true"
  "darwin-host:false"
  "twin-engine:false"
  "winner-vm:false"
  "wingnut:false"
  "winsome:false"
  "winter-server:false"
  "window-mgr:false"
  "winch-app:false"
  "cotwin:false"
)

PASS_COUNT=0
FAIL_COUNT=0

for rel_file in "${FILES[@]}"; do
  file="$REPO_ROOT/$rel_file"
  if [ ! -f "$file" ]; then
    # Layer 1 (must-gather) is absent from the public GitHub tree; skip
    # rather than FAIL so this harness still runs against exported scripts.
    echo "SKIP: $rel_file not in this tree"
    continue
  fi

  # Pull the regex string literal out of the jq test(...) call for the
  # "win(...)?" name heuristic. All 3 shell files use the identical pattern
  # `test("<regex>";"i")` immediately preceded by `.metadata.name |`.
  regex=$(grep -o '\.metadata\.name | test("[^"]*"' "$file" | head -1 | sed -E 's/.*test\("([^"]*)"/\1/')

  if [ -z "$regex" ]; then
    echo "FAIL: $rel_file -- could not extract Windows-VM name regex"
    FAIL_COUNT=$((FAIL_COUNT+1))
    continue
  fi

  for case in "${CASES[@]}"; do
    name="${case%%:*}"
    expected="${case##*:}"
    actual=$(printf '%s' "$name" | jq -Rr --arg re "$regex" 'test($re; "i")')
    if [ "$actual" = "$expected" ]; then
      PASS_COUNT=$((PASS_COUNT+1))
    else
      echo "FAIL: $rel_file -- name='$name' expected=$expected actual=$actual (regex=$regex)"
      FAIL_COUNT=$((FAIL_COUNT+1))
    fi
  done
done

echo
echo "=============================================="
echo " test_windows_vm_name_regex.sh: $PASS_COUNT passed, $FAIL_COUNT failed"
echo "=============================================="
[ "$FAIL_COUNT" -eq 0 ]
