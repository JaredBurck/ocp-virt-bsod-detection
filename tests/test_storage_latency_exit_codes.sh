#!/usr/bin/env bash
#
# test_storage_latency_exit_codes.sh
# -----------------------------------------------------------------------------
# Offline regression test for scripts/cnv-storage-latency-calibrate.sh's
# 3-way exit code contract (v0.16.0 #9):
#   0 -- WITHIN_THRESHOLDS
#   1 -- EXCEEDS_WARN / EXCEEDS_CRITICAL (a genuine finding)
#   2 -- acquisition/inconclusive (pre-flight failure, Thanos query failure,
#        no active series, or UNKNOWN verdict)
#
# The full script requires a live cluster (oc/curl/Thanos), so this test
# extracts only the final `case "$verdict" in ... esac` block verbatim by
# line range and exercises it directly against each possible $verdict value
# -- the same extract-and-stub philosophy as
# tests/test_qga_harden_staging_dir.sh, scoped to the one piece of logic
# that can be tested without a live cluster.
#
# Usage: tests/test_storage_latency_exit_codes.sh
# Exit code: 0 if every scenario matches its expected result, else 1.
# -----------------------------------------------------------------------------
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TARGET="$REPO_ROOT/scripts/cnv-storage-latency-calibrate.sh"

if [ ! -f "$TARGET" ]; then
  echo "FAIL: $TARGET not found"
  exit 1
fi

PASS_COUNT=0
FAIL_COUNT=0
pass() { echo "PASS: $1"; PASS_COUNT=$((PASS_COUNT+1)); }
fail() { echo "FAIL: $1"; FAIL_COUNT=$((FAIL_COUNT+1)); }

# shellcheck disable=SC2016  # single-quoted sed pattern is intentionally literal
CASE_SRC="$(sed -n '/^case "\$verdict" in$/,/^esac$/p' "$TARGET")"
if [ -z "$CASE_SRC" ]; then
  echo "FAIL: could not extract the verdict->exit-code case block from $TARGET"
  exit 1
fi

run_case() {
  local verdict="$1"
  ( eval "$CASE_SRC" ) >/dev/null 2>&1
  echo $?
}

rc="$(run_case "WITHIN_THRESHOLDS")"
if [ "$rc" -eq 0 ]; then
  pass "WITHIN_THRESHOLDS maps to exit 0"
else
  fail "WITHIN_THRESHOLDS: expected exit 0, got $rc"
fi

for verdict in EXCEEDS_WARN EXCEEDS_CRITICAL; do
  rc="$(run_case "$verdict")"
  if [ "$rc" -eq 1 ]; then
    pass "$verdict maps to exit 1 (genuine finding)"
  else
    fail "$verdict: expected exit 1, got $rc"
  fi
done

for verdict in UNKNOWN "" "something-unexpected"; do
  rc="$(run_case "$verdict")"
  if [ "$rc" -eq 2 ]; then
    pass "verdict='$verdict' maps to exit 2 (acquisition/inconclusive)"
  else
    fail "verdict='$verdict': expected exit 2, got $rc"
  fi
done

# The pre-flight/acquisition-failure exit sites (Thanos query failure, no
# active series) must use exit 2, not 1 -- these are lines, not a function,
# so assert directly on the source text rather than executing them (which
# would require stubbing oc/curl/Thanos for no additional signal).
if grep -qF 'ERROR: Thanos query failed' "$TARGET" && \
   awk '/ERROR: Thanos query failed/{found=1} found && /exit [0-9]/{print; exit}' "$TARGET" | grep -qE 'exit 2$'; then
  pass "Thanos query failure exits 2, not 1"
else
  fail "Thanos query failure does not exit 2"
fi

if grep -qF 'NO ACTIVE SERIES' "$TARGET" && \
   awk '/NO ACTIVE SERIES/{found=1} found && /exit [0-9]/{print; exit}' "$TARGET" | grep -qE 'exit 2$'; then
  pass "No-active-series case exits 2, not 1"
else
  fail "No-active-series case does not exit 2"
fi

echo
echo "=============================================="
echo " test_storage_latency_exit_codes.sh: $PASS_COUNT passed, $FAIL_COUNT failed"
echo "=============================================="
[ "$FAIL_COUNT" -eq 0 ]
