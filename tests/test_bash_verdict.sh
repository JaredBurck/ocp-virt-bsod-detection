#!/usr/bin/env bash
# Cross-layer bash verdict test harness (CR-1).
# Sources evaluate_driver_version_stream() from scripts/lib/driver-verdict.sh
# and validates each shared test vector produces the expected verdict.
#
# Requirements: bash, jq
# Usage: bash tests/test_bash_verdict.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

VECTORS_FILE="$REPO_ROOT/shared/driver-verdict-test-vectors.json"
THRESHOLDS_FILE="$REPO_ROOT/shared/virtio-win-thresholds.json"

if ! command -v jq >/dev/null 2>&1; then
  echo "SKIP: jq is required but not installed"
  exit 0
fi

if [ ! -f "$VECTORS_FILE" ]; then
  echo "SKIP: $VECTORS_FILE not found"
  exit 0
fi

if [ ! -f "$THRESHOLDS_FILE" ]; then
  echo "SKIP: $THRESHOLDS_FILE not found"
  exit 0
fi

DRIVER_BASELINE=$(jq -r '.remediation_baseline' "$THRESHOLDS_FILE")
TOOLING_FLOOR=$(jq -r '.tooling_floor' "$THRESHOLDS_FILE")

# Source the production verdict functions (single source of truth).
# source-path=SCRIPTDIR makes the source= path resolve relative to THIS
# file rather than the caller's cwd. Without it shellcheck could not
# follow the library, so every variable this harness sets for the library
# to read (DRIVER_BASELINE, TOOLING_FLOOR, STREAM_*) looked unused and
# raised SC2034 -- six warnings that made `shellcheck -x tests/*.sh` exit
# non-zero for anyone following CLAUDE.md, while CI stayed green because
# its matrix never linted this file.
# shellcheck source-path=SCRIPTDIR
# shellcheck source=../scripts/lib/driver-verdict.sh
source "$REPO_ROOT/scripts/lib/driver-verdict.sh"

PASS_COUNT=0
FAIL_COUNT=0
TOTAL=0
FAILURES=""

NUM_VECTORS=$(jq '.vectors | length' "$VECTORS_FILE")

for i in $(seq 0 $((NUM_VECTORS - 1))); do
  VERSION=$(jq -r ".vectors[$i].version" "$VECTORS_FILE")
  STREAM=$(jq -r ".vectors[$i].stream" "$VECTORS_FILE")
  EXPECTED=$(jq -r ".vectors[$i].expected" "$VECTORS_FILE")
  NOTE=$(jq -r ".vectors[$i].note" "$VECTORS_FILE")

  STREAM_FAIL=$(jq -r --arg s "$STREAM" '.streams[$s].fail // empty' "$THRESHOLDS_FILE")
  STREAM_WARN=$(jq -r --arg s "$STREAM" '.streams[$s].warn // empty' "$THRESHOLDS_FILE")
  STREAM_MAX=$(jq -r --arg s "$STREAM" '.streams[$s].max // empty' "$THRESHOLDS_FILE")

  # F-03/F-06: optional per-vector reason. Asserted ONLY when the vector
  # carries one, so the long-standing vectors stay valid unchanged. The reason
  # is what routes a finding's DOMAIN (at_stream_max -> weight-0 platform) and
  # its KCS/confidence (below_tooling_floor -> the 7128506 utility article),
  # so a verdict string that matches while the reason silently changes is a
  # scoring regression the verdict assertion alone cannot see.
  EXPECTED_REASON=$(jq -r ".vectors[$i].expected_reason // empty" "$VECTORS_FILE")

  DRIVER_VERDICT=""
  DRIVER_VERDICT_REASON=""
  evaluate_driver_version_stream "$VERSION"

  TOTAL=$((TOTAL + 1))
  if [ -n "$EXPECTED_REASON" ] && [ "${DRIVER_VERDICT_REASON:-}" != "$EXPECTED_REASON" ]; then
    FAIL_COUNT=$((FAIL_COUNT + 1))
    FAILURES="${FAILURES}  FAIL: version=$VERSION stream=$STREAM -> reason '${DRIVER_VERDICT_REASON:-<none>}', expected '$EXPECTED_REASON' ($NOTE)\n"
    echo "  FAIL: version=$VERSION stream=$STREAM -> reason '${DRIVER_VERDICT_REASON:-<none>}', expected '$EXPECTED_REASON' ($NOTE)"
  elif [ "$DRIVER_VERDICT" = "$EXPECTED" ]; then
    PASS_COUNT=$((PASS_COUNT + 1))
    echo "  PASS: version=$VERSION stream=$STREAM -> $DRIVER_VERDICT${EXPECTED_REASON:+ ($EXPECTED_REASON)} ($NOTE)"
  else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    FAILURES="${FAILURES}  FAIL: version=$VERSION stream=$STREAM -> got $DRIVER_VERDICT, expected $EXPECTED ($NOTE)\n"
    echo "  FAIL: version=$VERSION stream=$STREAM -> got $DRIVER_VERDICT, expected $EXPECTED ($NOTE)"
  fi
done

echo ""
echo "Bash verdict test results: $PASS_COUNT/$TOTAL passed, $FAIL_COUNT failed"

# N-06 (Wave 7, R-47): os_compat_vectors -- guest-OS-support axis, a SEPARATE
# function (evaluate_guest_os_driver_compatibility) from the stream-version
# axis tested above.
OS_SUPPORT_FILE="$REPO_ROOT/shared/virtio-win-guest-os-support.json"
if [ ! -f "$OS_SUPPORT_FILE" ]; then
  echo "SKIP: $OS_SUPPORT_FILE not found -- skipping os_compat_vectors"
else
  NUM_OS_VECTORS=$(jq '.os_compat_vectors | length' "$VECTORS_FILE")
  for i in $(seq 0 $((NUM_OS_VECTORS - 1))); do
    OS_HINT=$(jq -r ".os_compat_vectors[$i].os_hint" "$VECTORS_FILE")
    OS_VERSION=$(jq -r ".os_compat_vectors[$i].version" "$VECTORS_FILE")
    OS_EXPECTED=$(jq -r ".os_compat_vectors[$i].expected" "$VECTORS_FILE")
    OS_NOTE=$(jq -r ".os_compat_vectors[$i].note" "$VECTORS_FILE")

    OS_COMPAT_VERDICT=""
    evaluate_guest_os_driver_compatibility "$OS_HINT" "$OS_VERSION"

    TOTAL=$((TOTAL + 1))
    if [ "${OS_COMPAT_VERDICT:-}" = "$OS_EXPECTED" ]; then
      PASS_COUNT=$((PASS_COUNT + 1))
      echo "  PASS: os_hint=$OS_HINT version=$OS_VERSION -> '${OS_COMPAT_VERDICT:-}' ($OS_NOTE)"
    else
      FAIL_COUNT=$((FAIL_COUNT + 1))
      FAILURES="${FAILURES}  FAIL: os_hint=$OS_HINT version=$OS_VERSION -> got '${OS_COMPAT_VERDICT:-}', expected '$OS_EXPECTED' ($OS_NOTE)\n"
      echo "  FAIL: os_hint=$OS_HINT version=$OS_VERSION -> got '${OS_COMPAT_VERDICT:-}', expected '$OS_EXPECTED' ($OS_NOTE)"
    fi
  done
fi

echo ""
echo "Combined bash verdict test results: $PASS_COUNT/$TOTAL passed, $FAIL_COUNT failed"

if [ "$FAIL_COUNT" -gt 0 ]; then
  echo ""
  echo "Failures:"
  printf "%b" "$FAILURES"
  exit 1
fi
