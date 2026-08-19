#!/usr/bin/env bash
#
# test_plan_gate_amd_verdict.sh
# -----------------------------------------------------------------------------
# v0.17.0 F3 regression guard: before the fix, cnv-win-bsod-audit.sh's
# cluster-scope Gate 9 unconditionally warn()'d on AMD-node presence, and
# cnv-mtv-plan-gate.sh folds any cluster-scope WARN into its overall
# `verdict` -- so NO AMD fleet could ever reach `verdict: PASS` from
# `cnv-mtv-plan-gate.sh --json`, even one where every VM had
# arch-capabilities correctly disabled (KCS-7125237, 0x5D).
#
# This drives cnv-mtv-plan-gate.sh through its *live-mode* code path (no
# MTV_PLAN_JSON) against the REAL cnv-win-bsod-audit.sh (BSOD_CHECK_CMD),
# with mock-oc.sh serving both the Plan fetch and the per-VM/node fixtures --
# unlike test_fleet_readiness.sh, which drives the same live-mode path but
# with a *scripted* BSOD_CHECK_CMD (tests/stub-bsod-check.sh), this harness
# needs the production audit script itself in the loop so the assertion
# actually exercises Gate 9's fixed info()/warn_strict() split end-to-end,
# not a hand-written stand-in for it.
#
# Usage: tests/test_plan_gate_amd_verdict.sh
# Exit code: 0 if both scenarios match their expected verdict, else 1.
# -----------------------------------------------------------------------------
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
AUDIT_SCRIPT="$REPO_ROOT/scripts/cnv-win-bsod-audit.sh"
PLAN_GATE_SCRIPT="$REPO_ROOT/scripts/cnv-mtv-plan-gate.sh"
FIXTURES_DIR="$SCRIPT_DIR/fixtures/gates"

if [ ! -x "$AUDIT_SCRIPT" ] || [ ! -f "$PLAN_GATE_SCRIPT" ]; then
  echo "FAIL: $AUDIT_SCRIPT or $PLAN_GATE_SCRIPT not found"
  exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "SKIP: jq is required (cnv-mtv-plan-gate.sh depends on it)"
  exit 0
fi

PASS_COUNT=0
FAIL_COUNT=0

MOCK_BIN_DIR="$(mktemp -d)"
cp "$SCRIPT_DIR/mock-oc.sh" "$MOCK_BIN_DIR/oc"
chmod +x "$MOCK_BIN_DIR/oc"
WORK="$(mktemp -d)"
cleanup() { rm -rf "$MOCK_BIN_DIR" "$WORK"; }
trap cleanup EXIT

# run_scenario <label> <fixture-scenario> <plan-name> <expect_verdict> <expect_cluster_warn>
run_scenario() {
  local label="$1" scenario="$2" plan_name="$3" expect_verdict="$4" expect_cluster_warn="$5"
  local fixture_dir="$FIXTURES_DIR/$scenario"
  local json_out="$WORK/$label.json"

  if [ ! -f "$fixture_dir/plan.json" ]; then
    echo "FAIL: $label -- missing fixture $fixture_dir/plan.json"
    FAIL_COUNT=$((FAIL_COUNT+1))
    return
  fi

  PATH="$MOCK_BIN_DIR:$PATH" \
    MOCK_OC_FIXTURE_DIR="$fixture_dir" \
    BSOD_SKIP_MICROCODE_PROBE=1 \
        BSOD_OC_RETRIES=0 \
    BSOD_GUEST_EVIDENCE_DIR="$fixture_dir/guest-evidence" \
    BSOD_CHECK_CMD="$AUDIT_SCRIPT" \
    bash "$PLAN_GATE_SCRIPT" "$plan_name" openshift-mtv --json "$json_out" >/dev/null 2>&1

  if [ ! -f "$json_out" ]; then
    echo "FAIL: $label -- cnv-mtv-plan-gate.sh did not write $json_out"
    FAIL_COUNT=$((FAIL_COUNT+1))
    return
  fi

  local actual_verdict actual_cluster_warn
  actual_verdict=$(jq -r '.verdict' "$json_out")
  actual_cluster_warn=$(jq -r '.totals.cluster_warn' "$json_out")

  local ok=1
  if [ "$actual_verdict" != "$expect_verdict" ]; then
    echo "FAIL: $label -- expected verdict '$expect_verdict', got '$actual_verdict'"
    ok=0
  fi
  if [ "$actual_cluster_warn" != "$expect_cluster_warn" ]; then
    echo "FAIL: $label -- expected totals.cluster_warn=$expect_cluster_warn, got $actual_cluster_warn"
    ok=0
  fi

  if [ "$ok" -eq 1 ]; then
    echo "PASS: $label (verdict=$actual_verdict cluster_warn=$actual_cluster_warn)"
    PASS_COUNT=$((PASS_COUNT+1))
  else
    echo "---- $json_out ----"
    cat "$json_out"
    echo "---- end $json_out ----"
    FAIL_COUNT=$((FAIL_COUNT+1))
  fi
}

# Scenario 1 (the actual F3 regression guard): a fully-remediated AMD fleet --
# AMD worker nodes present, but the sole VM has arch-capabilities: disable,
# blockMultiQueue: false, and compliant guest evidence (virtio-win 1.9.60,
# no phantom NICs). Pre-fix, Gate 9's cluster-scope warn() alone would have
# forced totals.cluster_warn=1 and verdict=WARN here even though nothing is
# actually wrong. Post-fix it must be verdict=PASS, cluster_warn=0.
run_scenario amd_fleet_fully_remediated amd-nodes-remediated amd-remediated-plan PASS 0

# Scenario 2 (contrast -- the real per-VM signal must be unaffected): same
# AMD nodes, but the VM does NOT have arch-capabilities disabled. Gate 9's
# per-VM warn_strict() must still fire, so verdict stays WARN -- proving the
# info() downgrade only silenced the redundant cluster-scope pointer line,
# not the actual risk detection.
run_scenario amd_fleet_noncompliant_vm amd-nodes amd-noncompliant-plan WARN 0

echo
echo "=============================================="
echo " test_plan_gate_amd_verdict.sh: $PASS_COUNT passed, $FAIL_COUNT failed"
echo "=============================================="
[ "$FAIL_COUNT" -eq 0 ]
