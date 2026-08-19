#!/usr/bin/env bash
#
# test_fleet_readiness.sh
# -----------------------------------------------------------------------------
# Fixture-driven regression harness for the cluster-scope FAIL/WARN
# aggregation fix in scripts/cnv-mtv-fleet-readiness.sh.
#
# Background (live-cluster finding, 2026-07-10): cnv-mtv-plan-gate.sh can
# print "GATE: BLOCKED" purely from a cluster-scope hard failure (e.g. no
# auto-detectable Windows VMs, AMD Family 1Ah nodes) even when every
# individual VM in the Plan PASSes/WARNs -- that signal lives in the plan
# gate's stdout, not in its per-VM CSV rows. cnv-mtv-fleet-readiness.sh used
# to aggregate *only* from the combined per-VM CSV, so a real BLOCKED plan
# rolled up into a misleadingly reassuring "FLEET GATE: REVIEW". This test
# locks in the fix (CLUSTER_MAP capture + CFAIL/CWARN columns + verdict/exit
# logic).
#
# cnv-mtv-plan-gate.sh intentionally SKIPS its cluster-scope BSOD_CHECK_CMD
# call whenever MTV_PLAN_JSON is set (its offline/test hook), so exercising
# the cluster-scope path requires driving the *live-mode* code path instead:
# a mock `oc` (tests/stub-oc-fleet.sh, injected via PATH) stands in for plan
# enumeration/fetch and VM-existence checks, while BSOD_CHECK_CMD
# (tests/stub-bsod-check.sh) scripts the cluster-scope and per-VM check
# output. No live cluster or real audit-gate logic is required.
#
# Usage: tests/test_fleet_readiness.sh
# Exit code: 0 if every scenario matches its expected verdict/exit, else 1.
# -----------------------------------------------------------------------------
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
FLEET_SCRIPT="$REPO_ROOT/scripts/cnv-mtv-fleet-readiness.sh"
STUB="$SCRIPT_DIR/stub-bsod-check.sh"
MOCK_OC="$SCRIPT_DIR/stub-oc-fleet.sh"

if [ ! -f "$FLEET_SCRIPT" ]; then
  echo "FAIL: $FLEET_SCRIPT not found"
  exit 1
fi
if [ ! -x "$STUB" ] || [ ! -x "$MOCK_OC" ]; then
  echo "FAIL: $STUB or $MOCK_OC not found or not executable"
  exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "SKIP: jq is required (cnv-mtv-plan-gate.sh depends on it)"
  exit 0
fi

PASS_COUNT=0
FAIL_COUNT=0
WORK="$(mktemp -d)"
# Isolated PATH dir containing only our mock `oc` -- never shadows/mutates a
# real `oc` that might also be on PATH.
MOCK_BIN_DIR="$(mktemp -d)"
cp "$MOCK_OC" "$MOCK_BIN_DIR/oc"
chmod +x "$MOCK_BIN_DIR/oc"
cleanup() { rm -rf "$WORK" "$MOCK_BIN_DIR"; }
trap cleanup EXIT

plan_json() {
  # plan_json <target-ns> <vm-name...>
  local target_ns="$1"; shift
  local vms="[]"
  local first=1
  for vm in "$@"; do
    [ "$first" -eq 1 ] && vms="[" || vms="$vms,"
    vms="$vms{\"name\":\"$vm\"}"
    first=0
  done
  vms="$vms]"
  printf '{"spec":{"targetNamespace":"%s","warm":false,"vms":%s}}\n' "$target_ns" "$vms"
}

# run_scenario <label> <expect_any_blocked_exit(0|1)> <expect_cfail_total> <expect_cwarn_total>
run_scenario() {
  local label="$1" expect_exit="$2" expect_cfail="$3" expect_cwarn="$4"
  local plan_dir="$WORK/$label/plans"
  local fixtures_dir="$WORK/$label/fixtures"
  mkdir -p "$plan_dir" "$fixtures_dir/cluster"

  "${SCENARIO_SETUP[$label]}" "$plan_dir" "$fixtures_dir"

  local plan_names
  plan_names=$(cd "$plan_dir" && for f in *.json; do basename "$f" .json; done | tr '\n' ' ')

  local out actual_exit
  out=$(PATH="$MOCK_BIN_DIR:$PATH" \
        STUB_PLAN_NAMES="$plan_names" \
        STUB_PLAN_DIR="$plan_dir" \
        STUB_FIXTURES_DIR="$fixtures_dir" \
        BSOD_CHECK_CMD="$STUB" \
        bash "$FLEET_SCRIPT" "any-ns" 2>&1)
  actual_exit=$?

  local actual_cfail actual_cwarn
  actual_cfail=$(printf '%s\n' "$out" | sed -n 's/.*Fleet cluster-scope totals: FAIL=\([0-9][0-9]*\).*/\1/p' | head -1)
  actual_cwarn=$(printf '%s\n' "$out" | sed -n 's/.*Fleet cluster-scope totals:.*WARN=\([0-9][0-9]*\).*/\1/p' | head -1)

  local ok=1
  if [ "$actual_exit" -ne "$expect_exit" ]; then
    echo "FAIL: $label -- expected fleet exit $expect_exit, got $actual_exit"
    ok=0
  fi
  if [ "$actual_cfail" != "$expect_cfail" ]; then
    echo "FAIL: $label -- expected cluster-scope FAIL total $expect_cfail, got '$actual_cfail'"
    ok=0
  fi
  if [ "$actual_cwarn" != "$expect_cwarn" ]; then
    echo "FAIL: $label -- expected cluster-scope WARN total $expect_cwarn, got '$actual_cwarn'"
    ok=0
  fi

  if [ "$ok" -eq 1 ]; then
    echo "PASS: $label (exit=$actual_exit cfail=$actual_cfail cwarn=$actual_cwarn)"
    PASS_COUNT=$((PASS_COUNT+1))
  else
    echo "---- captured output: $label ----"
    echo "$out"
    echo "---- end captured output: $label ----"
    FAIL_COUNT=$((FAIL_COUNT+1))
  fi
}

declare -A SCENARIO_SETUP

# Scenario 1: one plan has a cluster-scope hard FAIL (e.g. Gate: no
# auto-detectable Windows VMs); its lone VM otherwise PASSes. A second plan
# is fully clean. Regression check: pre-fix, this rolled up as
# "FLEET GATE: REVIEW" (exit 0) because the combined per-VM CSV showed only
# PASS rows; post-fix it must BLOCK (exit 1) with cfail=1.
setup_cluster_fail() {
  local plan_dir="$1" fixtures_dir="$2"
  plan_json "planA-ns" "vm1" > "$plan_dir/planA.json"
  plan_json "planB-ns" "vm2" > "$plan_dir/planB.json"
  mkdir -p "$fixtures_dir/vm/planA-ns" "$fixtures_dir/vm/planB-ns"
  echo "  [FAIL] no Windows VMs auto-detected in namespace planA-ns" > "$fixtures_dir/cluster/planA-ns.txt"
  echo "  [ OK ] all gates clear" > "$fixtures_dir/vm/planA-ns/vm1.txt"
  echo "  [ OK ] all gates clear" > "$fixtures_dir/vm/planB-ns/vm2.txt"
}
SCENARIO_SETUP[cluster_fail]=setup_cluster_fail
run_scenario cluster_fail 1 1 0

# Scenario 2: a plan's cluster-scope check WARNs only (e.g. Gate 17's legacy
# template compliance) with a clean per-VM result, and a second plan is fully
# clean. No FAILs anywhere -- must roll up as REVIEW (exit 0), not silently
# CLEAR.
#
# v0.17.0 (F3): this fixture previously used Gate 9's cluster-scope AMD-nodes
# line as its example WARN text. That line was downgraded warn()->info() in
# cnv-win-bsod-audit.sh because it was a redundant pointer to the per-VM
# check below it (every AMD fleet has AMD nodes by definition, so it could
# never itself be resolved to a clean state) -- it no longer emits [WARN] at
# all, so using it here would silently stop exercising this scenario's real
# target (generic cluster-scope-WARN-only rollup handling). Gate 17's
# template-compliance WARN is a genuine, resolvable cluster-scope finding
# and remains one after the fix.
setup_cluster_warn_only() {
  local plan_dir="$1" fixtures_dir="$2"
  plan_json "planC-ns" "vm3" > "$plan_dir/planC.json"
  plan_json "planD-ns" "vm4" > "$plan_dir/planD.json"
  mkdir -p "$fixtures_dir/vm/planC-ns" "$fixtures_dir/vm/planD-ns"
  echo "  [WARN] 2/5 Windows template(s) missing hyperv feature block (0x20001 risk)" > "$fixtures_dir/cluster/planC-ns.txt"
  echo "  [ OK ] all gates clear" > "$fixtures_dir/vm/planC-ns/vm3.txt"
  echo "  [ OK ] all gates clear" > "$fixtures_dir/vm/planD-ns/vm4.txt"
}
SCENARIO_SETUP[cluster_warn_only]=setup_cluster_warn_only
run_scenario cluster_warn_only 0 0 1

# Scenario 3: fully clean fleet (no cluster-scope or per-VM findings at all)
# must still report CLEAR/exit 0 -- guards against the fix over-triggering.
setup_all_clean() {
  local plan_dir="$1" fixtures_dir="$2"
  plan_json "planE-ns" "vm5" > "$plan_dir/planE.json"
  mkdir -p "$fixtures_dir/vm/planE-ns"
  echo "  [ OK ] all gates clear" > "$fixtures_dir/vm/planE-ns/vm5.txt"
}
SCENARIO_SETUP[all_clean]=setup_all_clean
run_scenario all_clean 0 0 0

# --- N4: fully-UNASSESSED fleet must never report CLEAR ---------------------
# All VMs in the fleet are stopped/no VMI, so every per-VM check emits only
# [UNKN] lines (no FAIL/WARN). Pre-fix, the fleet-totals awk block had no
# UNASSESSED/other branch, so T_WARN/T_FAIL/T_PEND were all 0 despite T_VMS>0
# and the fleet rolled up as "FLEET GATE: CLEAR" -- migration-ready on a fleet
# that was never actually assessed. Post-fix it must report REVIEW (both exit
# 0, so the verdict text itself -- not just the exit code -- must be checked).
setup_all_unassessed() {
  local plan_dir="$1" fixtures_dir="$2"
  plan_json "planF-ns" "vm6" > "$plan_dir/planF.json"
  mkdir -p "$fixtures_dir/vm/planF-ns"
  echo "  [UNKN] guest virtio-win version not available for vm6" > "$fixtures_dir/vm/planF-ns/vm6.txt"
}
SCENARIO_SETUP[all_unassessed]=setup_all_unassessed

run_all_unassessed() {
  local label="all_unassessed"
  local plan_dir="$WORK/$label/plans"
  local fixtures_dir="$WORK/$label/fixtures"
  mkdir -p "$plan_dir" "$fixtures_dir/cluster"
  setup_all_unassessed "$plan_dir" "$fixtures_dir"

  local plan_names
  plan_names=$(cd "$plan_dir" && for f in *.json; do basename "$f" .json; done | tr '\n' ' ')

  local out actual_exit
  out=$(PATH="$MOCK_BIN_DIR:$PATH" \
        STUB_PLAN_NAMES="$plan_names" \
        STUB_PLAN_DIR="$plan_dir" \
        STUB_FIXTURES_DIR="$fixtures_dir" \
        BSOD_CHECK_CMD="$STUB" \
        bash "$FLEET_SCRIPT" "any-ns" 2>&1)
  actual_exit=$?

  local ok=1
  if [ "$actual_exit" -ne 0 ]; then
    echo "FAIL: $label -- expected fleet exit 0 (REVIEW, not BLOCKED), got $actual_exit"
    ok=0
  fi
  if echo "$out" | grep -q '^FLEET GATE: CLEAR'; then
    echo "FAIL: $label -- fully-UNASSESSED fleet reported CLEAR (evidence gap silently treated as migration-ready)"
    ok=0
  elif ! echo "$out" | grep -q '^FLEET GATE: REVIEW'; then
    echo "FAIL: $label -- expected 'FLEET GATE: REVIEW', got:"
    echo "$out" | grep '^FLEET GATE:'
    ok=0
  fi

  if [ "$ok" -eq 1 ]; then
    echo "PASS: $label (exit=$actual_exit, verdict=REVIEW, not CLEAR)"
    PASS_COUNT=$((PASS_COUNT+1))
  else
    echo "---- captured output: $label ----"
    echo "$out"
    echo "---- end captured output: $label ----"
    FAIL_COUNT=$((FAIL_COUNT+1))
  fi
}
run_all_unassessed

echo
echo "=============================================="
echo " test_fleet_readiness.sh: $PASS_COUNT passed, $FAIL_COUNT failed"
echo "=============================================="
[ "$FAIL_COUNT" -eq 0 ]
