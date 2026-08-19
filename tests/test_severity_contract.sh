#!/usr/bin/env bash
#
# test_severity_contract.sh
# -----------------------------------------------------------------------------
# Cross-layer contract test for the severity vocabulary.
#
# WHY THIS EXISTS
# ---------------
# cnv-mtv-plan-gate.sh classifies each VM by grepping cnv-win-bsod-audit.sh's
# output for severity literals ([FAIL], [WARN], [UNKN]). That coupling is
# invisible to both scripts' own tests: adding a severity to the producer
# without teaching the consumer about it makes the consumer classify those VMs
# as PASS -- i.e. introducing a brand-new false all-clear via the very mechanism
# intended to eliminate them.
#
# This harness drives the real plan gate with a stubbed audit command that emits
# a chosen severity, and asserts the resulting per-VM status and gate exit code.
# Any future severity MUST be added here.
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

PASSED=0
FAILED=0

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

# run_case <label> <emitted-line> <expected-status> <expected-exit> <expected-verdict>
run_case() {
  local label="$1" emit="$2" want_status="$3" want_exit="$4" want_verdict="$5"

  # Stub audit: emits the severity line under test. Cluster-scope invocation is
  # skipped entirely because MTV_PLAN_JSON is set, so only the per-VM path runs.
  cat > "$TMP/stub-audit.sh" <<EOF
#!/usr/bin/env bash
printf '%s\n' "$emit"
exit 0
EOF
  chmod +x "$TMP/stub-audit.sh"

  local out
  out=$(MTV_PLAN_JSON="$TMP/plan.json" BSOD_CHECK_CMD="$TMP/stub-audit.sh" \
        bash "$PLAN_GATE" wave-1 openshift-mtv --json "$TMP/out.json" 2>&1)
  local rc=$?

  local got_status got_verdict
  got_status=$(jq -r '.vms[0].status' "$TMP/out.json" 2>/dev/null)
  got_verdict=$(jq -r '.verdict' "$TMP/out.json" 2>/dev/null)

  if [ "$got_status" = "$want_status" ] && [ "$rc" -eq "$want_exit" ] \
     && [ "$got_verdict" = "$want_verdict" ]; then
    echo "PASS: $label (status=$got_status verdict=$got_verdict exit=$rc)"
    PASSED=$((PASSED+1))
  else
    echo "FAIL: $label"
    echo "        expected status=$want_status verdict=$want_verdict exit=$want_exit"
    echo "        got      status=$got_status verdict=$got_verdict exit=$rc"
    echo "$out" | sed 's/^/        | /' | head -12
    FAILED=$((FAILED+1))
  fi
}

echo "=============================================="
echo " Severity contract: audit output -> plan gate"
echo "=============================================="

run_case "FAIL blocks the wave" \
  "  [FAIL] boot disk uses sata -- 0x7B risk" \
  "FAIL" 1 "FAIL"

run_case "WARN routes to review" \
  "  [WARN] virtio-blk multiqueue active" \
  "WARN" 0 "WARN"

# The regression this file exists to prevent: before the consumer understood
# [UNKN], a VM with ONLY unassessed gates matched neither [FAIL] nor [WARN] and
# fell through to the PASS branch -- reported as cleared for migration despite
# nothing having been evaluated.
run_case "UNKNOWN must NOT classify as PASS" \
  "  [UNKN] vCPU topology could not be resolved (sparse spec)" \
  "UNASSESSED" 0 "WARN"

run_case "clean output passes" \
  "  [ OK ] boot disk uses virtio" \
  "PASS" 0 "PASS"

# Precedence: a real finding outranks an unassessed one.
run_case "FAIL outranks UNKNOWN" \
  "  [UNKN] topology unresolved
  [FAIL] evictionStrategy=None" \
  "FAIL" 1 "FAIL"

run_case "WARN outranks UNKNOWN" \
  "  [UNKN] topology unresolved
  [WARN] no hyperv feature block" \
  "WARN" 0 "WARN"

echo
echo "=============================================="
echo " test_severity_contract.sh: $PASSED passed, $FAILED failed"
echo "=============================================="
[ "$FAILED" -eq 0 ] || exit 1
