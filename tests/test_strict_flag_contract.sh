#!/usr/bin/env bash
#
# test_strict_flag_contract.sh
# -----------------------------------------------------------------------------
# N12: BSOD_STRICT env-var contract for cnv-mtv-plan-gate.sh and
# cnv-mtv-fleet-readiness.sh.
#
# WHY THIS EXISTS
# ---------------
# Both scripts honored BSOD_STRICT via `[ -n "${BSOD_STRICT:-}" ]` -- true for
# ANY non-empty value, including the literal string "false". An operator
# setting BSOD_STRICT=false to explicitly opt OUT of --strict (e.g. a Tekton
# pipeline parameter defaulting to "false") had migration-critical warnings
# silently promoted to hard failures anyway. Only BSOD_STRICT=true must set
# --strict; unset, empty, "false", or any other value must not.
#
# Requires: jq. No cluster needed (MTV_PLAN_JSON + BSOD_CHECK_CMD stubs).
# -----------------------------------------------------------------------------
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PLAN_GATE="$REPO_ROOT/scripts/cnv-mtv-plan-gate.sh"

command -v jq >/dev/null 2>&1 || { echo "jq is required"; exit 2; }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

PASS_COUNT=0
FAIL_COUNT=0

cat > "$TMP/plan.json" <<'EOF'
{
  "metadata": {"name": "wave-1", "namespace": "openshift-mtv"},
  "spec": {
    "targetNamespace": "bsod-test",
    "warm": false,
    "vms": [{"name": "win2k22-a", "id": "vm-1"}]
  }
}
EOF

# Stub audit: WARNs unconditionally UNLESS invoked with --strict, in which
# case it FAILs. This makes --strict's effect on the plan gate's own exit
# code (and per-VM status) directly observable.
cat > "$TMP/stub-audit.sh" <<'EOF'
#!/usr/bin/env bash
for a in "$@"; do
  if [ "$a" = "--strict" ]; then
    printf '  [FAIL] promoted from WARN by --strict\n'
    exit 1
  fi
done
printf '  [WARN] a migration-critical warning\n'
exit 0
EOF
chmod +x "$TMP/stub-audit.sh"

# run_case <label> <BSOD_STRICT value or unset-marker> <expect_status> <expect_exit>
run_case() {
  local label="$1" strict_env="$2" want_status="$3" want_exit="$4"

  local out actual_exit
  if [ "$strict_env" = "__UNSET__" ]; then
    out=$(MTV_PLAN_JSON="$TMP/plan.json" BSOD_CHECK_CMD="$TMP/stub-audit.sh" \
          bash "$PLAN_GATE" wave-1 openshift-mtv --csv "$TMP/out.csv" 2>&1)
  else
    out=$(MTV_PLAN_JSON="$TMP/plan.json" BSOD_CHECK_CMD="$TMP/stub-audit.sh" \
          BSOD_STRICT="$strict_env" \
          bash "$PLAN_GATE" wave-1 openshift-mtv --csv "$TMP/out.csv" 2>&1)
  fi
  actual_exit=$?

  local actual_status
  actual_status=$(tail -n +2 "$TMP/out.csv" 2>/dev/null | cut -d',' -f5 | tr -d '"' | head -1)

  local ok=1
  if [ "$actual_status" != "$want_status" ]; then
    echo "FAIL: $label -- expected status=$want_status, got '$actual_status'"
    ok=0
  fi
  if [ "$actual_exit" -ne "$want_exit" ]; then
    echo "FAIL: $label -- expected exit=$want_exit, got $actual_exit"
    ok=0
  fi

  if [ "$ok" -eq 1 ]; then
    echo "PASS: $label (status=$actual_status exit=$actual_exit)"
    PASS_COUNT=$((PASS_COUNT+1))
  else
    echo "---- captured output: $label ----"
    echo "$out"
    echo "---- end captured output: $label ----"
    FAIL_COUNT=$((FAIL_COUNT+1))
  fi
}

# --- cnv-mtv-plan-gate.sh -----------------------------------------------------
run_case "plan-gate: BSOD_STRICT unset"      "__UNSET__" "WARN" 0
run_case "plan-gate: BSOD_STRICT=false"      "false"     "WARN" 0
run_case "plan-gate: BSOD_STRICT=true"       "true"      "FAIL" 1
run_case "plan-gate: BSOD_STRICT=1 (not 'true', must NOT set --strict)" "1" "WARN" 0

# --- cnv-mtv-fleet-readiness.sh (delegates BSOD_STRICT to the plan gate; the
# fleet script has its own identical --strict-derivation bug/fix) ------------
FLEET_SCRIPT="$REPO_ROOT/scripts/cnv-mtv-fleet-readiness.sh"
PLAN_DIR="$TMP/plans"
mkdir -p "$PLAN_DIR"
cp "$TMP/plan.json" "$PLAN_DIR/wave-1.json"

run_fleet_case() {
  local label="$1" strict_env="$2" expect_blocked_exit="$3"

  local out actual_exit
  if [ "$strict_env" = "__UNSET__" ]; then
    out=$(FLEET_PLAN_DIR="$PLAN_DIR" BSOD_CHECK_CMD="$TMP/stub-audit.sh" \
          bash "$FLEET_SCRIPT" openshift-mtv 2>&1)
  else
    out=$(FLEET_PLAN_DIR="$PLAN_DIR" BSOD_CHECK_CMD="$TMP/stub-audit.sh" \
          BSOD_STRICT="$strict_env" \
          bash "$FLEET_SCRIPT" openshift-mtv 2>&1)
  fi
  actual_exit=$?

  local ok=1
  if [ "$actual_exit" -ne "$expect_blocked_exit" ]; then
    echo "FAIL: $label -- expected fleet exit=$expect_blocked_exit, got $actual_exit"
    ok=0
  fi

  if [ "$ok" -eq 1 ]; then
    echo "PASS: $label (exit=$actual_exit)"
    PASS_COUNT=$((PASS_COUNT+1))
  else
    echo "---- captured output: $label ----"
    echo "$out"
    echo "---- end captured output: $label ----"
    FAIL_COUNT=$((FAIL_COUNT+1))
  fi
}

# BSOD_STRICT=false must NOT promote the WARN to a FAIL -> fleet stays REVIEW (exit 0).
run_fleet_case "fleet-readiness: BSOD_STRICT=false stays REVIEW (exit 0)" "false" 0
# BSOD_STRICT=true DOES promote it -> a FAIL VM blocks the fleet (exit 1).
run_fleet_case "fleet-readiness: BSOD_STRICT=true promotes to BLOCKED (exit 1)" "true" 1

echo
echo "=============================================="
echo " test_strict_flag_contract.sh: $PASS_COUNT passed, $FAIL_COUNT failed"
echo "=============================================="
[ "$FAIL_COUNT" -eq 0 ]
