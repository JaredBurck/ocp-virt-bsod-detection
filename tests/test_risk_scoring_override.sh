#!/usr/bin/env bash
#
# test_risk_scoring_override.sh
# -----------------------------------------------------------------------------
# F15 (v0.17.0 deep-dive review): tests BSOD_RISK_WEIGHTS_OVERRIDE support in
# scripts/lib/risk-scoring.sh. Separate from test_risk_tier_contract.sh (which
# sources the library once at the top of that script's own process) because
# the override is read at SOURCE TIME -- each case here needs a fresh bash
# subprocess with the env var set BEFORE sourcing, which a single already-
# sourced test file cannot re-exercise.
#
# Requires: jq. No cluster needed.
# -----------------------------------------------------------------------------
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LIB="$REPO_ROOT/scripts/lib/risk-scoring.sh"
CANONICAL="$REPO_ROOT/shared/risk-scoring.json"

command -v jq >/dev/null 2>&1 || { echo "jq is required"; exit 2; }
[ -f "$LIB" ] || { echo "FAIL: missing $LIB"; exit 1; }

PASS_COUNT=0
FAIL_COUNT=0
pass() { echo "PASS: $1"; PASS_COUNT=$((PASS_COUNT+1)); }
fail() { echo "FAIL: $1"; FAIL_COUNT=$((FAIL_COUNT+1)); }

WORK="$(mktemp -d)"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

canonical_critical=$(jq -r '.tier_thresholds_x100.CRITICAL // 3000' "$CANONICAL")

# --- no override: canonical weights load as usual --------------------------
got=$(bash -c 'source "$1"; echo "$RS_TIER_CRITICAL"' _ "$LIB")
if [ "$got" = "$canonical_critical" ]; then
  pass "no override -- RS_TIER_CRITICAL matches canonical shared/risk-scoring.json ($got)"
else
  fail "no override -- expected RS_TIER_CRITICAL=$canonical_critical, got '$got'"
fi

# --- override present: overridden weights load instead ---------------------
jq '.tier_thresholds_x100.CRITICAL = 1' "$CANONICAL" > "$WORK/custom.json"
got=$(BSOD_RISK_WEIGHTS_OVERRIDE="$WORK/custom.json" bash -c 'source "$1"; echo "$RS_TIER_CRITICAL"' _ "$LIB")
if [ "$got" = "1" ]; then
  pass "override present -- RS_TIER_CRITICAL reflects the override file (1)"
else
  fail "override present -- expected RS_TIER_CRITICAL=1, got '$got'"
fi

# --- override present but does not exist: falls back + warns ---------------
out=$(BSOD_RISK_WEIGHTS_OVERRIDE="$WORK/does-not-exist.json" bash -c 'source "$1"; echo "$RS_TIER_CRITICAL"' _ "$LIB" 2>&1)
got=$(echo "$out" | tail -1)
if [ "$got" = "$canonical_critical" ] && echo "$out" | grep -q "BSOD_RISK_WEIGHTS_OVERRIDE.*not found"; then
  pass "missing override path -- falls back to canonical AND warns on stderr"
else
  fail "missing override path -- expected fallback + warning, got: $out"
fi

# --- canonical file on disk is never mutated by the override path ----------
before_hash=$(sha256sum "$CANONICAL" | cut -d' ' -f1)
BSOD_RISK_WEIGHTS_OVERRIDE="$WORK/custom.json" bash -c 'source "$1"' _ "$LIB" >/dev/null 2>&1
after_hash=$(sha256sum "$CANONICAL" | cut -d' ' -f1)
if [ "$before_hash" = "$after_hash" ]; then
  pass "canonical shared/risk-scoring.json is untouched by BSOD_RISK_WEIGHTS_OVERRIDE"
else
  fail "canonical shared/risk-scoring.json was modified by sourcing with an override set"
fi

echo
echo "=============================================="
echo " test_risk_scoring_override.sh: $PASS_COUNT passed, $FAIL_COUNT failed"
echo "=============================================="
[ "$FAIL_COUNT" -eq 0 ]
