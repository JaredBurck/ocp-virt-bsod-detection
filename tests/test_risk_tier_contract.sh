#!/usr/bin/env bash
#
# test_risk_tier_contract.sh
# -----------------------------------------------------------------------------
# Bash half of the cross-layer risk-tier contract (M-14).
#
# Sources the PRODUCTION scoring library (scripts/lib/risk-scoring.sh -- not a
# copy) and runs it against shared/risk-tier-test-vectors.json. The Python half
# (insights-rules/tests/test_risk_tier_contract.py) runs the same vectors
# through plugins/risk_scoring.py. If the two layers ever diverge again, one of
# them fails CI.
#
# Mirrors the proven test_bash_verdict.sh / test_ps_verdict.ps1 pattern already
# used to keep driver verdicts converged across bash/PowerShell/Python.
#
# Requires: jq. No cluster needed.
# -----------------------------------------------------------------------------
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VECTORS="$REPO_ROOT/shared/risk-tier-test-vectors.json"
# R-21: calibration vectors run through the SAME harness. Parity (do the layers
# agree?) and calibration (do the tiers mean anything?) are orthogonal
# properties, so they live in separate files -- but both must hold for the
# CUSTOMER-FACING bash layer, which is why calibration is asserted here and not
# only in pytest. See the calibration file's _why_separate_from_parity_vectors.
CALIBRATION="$REPO_ROOT/shared/risk-tier-calibration-vectors.json"

command -v jq >/dev/null 2>&1 || { echo "jq is required"; exit 2; }
[ -f "$VECTORS" ] || { echo "FAIL: missing $VECTORS"; exit 1; }
[ -f "$CALIBRATION" ] || { echo "FAIL: missing $CALIBRATION"; exit 1; }

# shellcheck source=SCRIPTDIR/../scripts/lib/risk-scoring.sh
source "$REPO_ROOT/scripts/lib/risk-scoring.sh"

if [ "${RS_CONFIG_LOADED:-0}" -ne 1 ]; then
  echo "FAIL: risk-scoring.sh could not load shared/risk-scoring.json"
  exit 1
fi

PASSED=0
FAILED=0

run_vector_file() {   # run_vector_file <path> <label>
local VECTORS="$1" LABEL="$2"
echo "--- $LABEL ---"
n_cases=$(jq '.cases | length' "$VECTORS")
for i in $(seq 0 $((n_cases - 1))); do
  name=$(jq -r ".cases[$i].name" "$VECTORS")
  want_score=$(jq -r ".cases[$i].expected_score // \"\"" "$VECTORS")
  want_tier=$(jq -r ".cases[$i].expected_tier" "$VECTORS")

  rs_reset
  while IFS=$'\t' read -r sev gate kcs; do
    [ -n "$sev" ] || continue
    rs_add "$sev" "$gate" "$kcs"
  done < <(jq -r ".cases[$i].findings[]? | \"\(.severity)\t\(.gate)\t\(.kcs)\"" "$VECTORS")

  got_score=$(rs_total)
  got_tier=$(rs_tier "$got_score")

  score_ok=1
  [ -n "$want_score" ] && [ "$got_score" -ne "$want_score" ] && score_ok=0
  if [ "$score_ok" -eq 1 ] && [ "$got_tier" = "$want_tier" ]; then
    echo "PASS: $name (score=$got_score tier=$got_tier)"
    PASSED=$((PASSED + 1))
  else
    echo "FAIL: $name"
    echo "        expected score=$want_score tier=$want_tier"
    echo "        got      score=$got_score tier=$got_tier"
    FAILED=$((FAILED + 1))
  fi
done
}

run_vector_file "$VECTORS" "parity: bash and Python agree on identical finding sets"
echo
run_vector_file "$CALIBRATION" "calibration: the tiers carry triage information"

echo
echo "=============================================="
echo " test_risk_tier_contract.sh: $PASSED passed, $FAILED failed"
echo "=============================================="
[ "$FAILED" -eq 0 ] || exit 1
