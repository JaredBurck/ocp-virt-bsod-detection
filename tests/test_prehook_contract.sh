#!/usr/bin/env bash
#
# test_prehook_contract.sh
# -----------------------------------------------------------------------------
# Contract tests for tekton/bsod-gate-prehook-job.yaml -- the framework's only
# UNATTENDED gate. Kubernetes Job success IS the migration decision here, with
# no human reading the report, so this file's job is to prove the Job blocks
# when it should.
#
# H2 (v0.16.0): before this, the PreHook ran `cnv-win-bsod-audit.sh --strict`
# as its entire command and let the raw exit code decide. `unknown()` never
# increments $FINDINGS and `--strict` promotes only WARN, so a stopped Windows
# VM with zero guest evidence -- every finding UNKNOWN -- exited 0 and MTV
# migrated a VM the framework never assessed.
#
# Two more defects were found in the same file while fixing that:
#   * BSOD_STRICT was declared in env and never consumed (the command
#     hardcoded --strict), so BSOD_STRICT=false did nothing. The sibling
#     bsod-gate-task.yaml gated on its own param correctly.
#   * The missing-annotation fallback ran --cluster-scope-only and the Job
#     still SUCCEEDED, so a VM Forklift failed to annotate was never
#     per-VM assessed yet migrated.
#
# The script under test is EXTRACTED FROM THE YAML, not copied here -- a test
# against a copy would pass while the shipped manifest rots.
#
# Usage: tests/test_prehook_contract.sh
# -----------------------------------------------------------------------------
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MANIFEST="$REPO_ROOT/tekton/bsod-gate-prehook-job.yaml"

PASS_COUNT=0
FAIL_COUNT=0

command -v python3 >/dev/null 2>&1 || { echo "FAIL: python3 required"; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "FAIL: jq required"; exit 1; }

WORK="$(mktemp -d)"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

# --- Extract the real command from the shipped manifest ---
python3 - "$MANIFEST" "$WORK/prehook.sh" <<'PY'
import sys, yaml
manifest, out = sys.argv[1], sys.argv[2]
doc = yaml.safe_load(open(manifest))
containers = doc["spec"]["template"]["spec"]["containers"]
assert len(containers) == 1, "expected exactly one container"
cmd = containers[0]["command"]
assert cmd[0] == "/bin/bash" and cmd[1] == "-c", f"unexpected command form: {cmd[:2]}"
open(out, "w").write("#!/usr/bin/env bash\n" + cmd[-1])
PY
chmod +x "$WORK/prehook.sh"

# --- Stub audit script: emits a caller-controlled summary + exit code ---
make_stub() {   # make_stub <exit_code> <fail> <warn> <unknown>
  cat > "$WORK/scripts/cnv-win-bsod-audit.sh" <<EOF
#!/usr/bin/env bash
# Records the flags it was invoked with so the test can assert on them.
printf '%s\n' "\$*" >> "$WORK/invocations.txt"
# R-25: the PreHook now derives its summary from the per-VM record written by
# --output-dir during the SAME run whose exit code is authoritative, instead of
# re-running the whole audit with --json. Mirror that contract here.
_od=""
_prev=""
for _a in \$*; do
  [ "\$_prev" = "--output-dir" ] && _od="\$_a"
  _prev="\$_a"
done
if [ -n "\$_od" ]; then
  mkdir -p "\$_od/\${VM_NAMESPACE:-bsod-test}"
  _f=""
  _i=0
  while [ "\$_i" -lt $4 ]; do _f="\$_f{\"severity\":\"UNKNOWN\"},"; _i=\$((_i+1)); done
  printf '{"name":"%s","namespace":"%s","fail_count":%s,"warn_count":%s,"findings":[%s]}\n' \
    "\${VM_NAME:-win2k22-good}" "\${VM_NAMESPACE:-bsod-test}" "$2" "$3" "\${_f%,}" \
    > "\$_od/\${VM_NAMESPACE:-bsod-test}/\${VM_NAME:-win2k22-good}.json"
fi
exit $1
EOF
  chmod +x "$WORK/scripts/cnv-win-bsod-audit.sh"
}

# Run the extracted PreHook script with our stub on PATH. Rewriting the
# hardcoded /scripts/ prefix is the only adaptation needed -- the logic under
# test is the manifest's own.
_run_prehook() {   # _run_prehook [KEY=VAL ...]
  sed "s#/scripts/#$WORK/scripts/#g" "$WORK/prehook.sh" > "$WORK/p.sh"
  env PATH="$WORK:$PATH" "$@" bash "$WORK/p.sh"
}

run_case() {  # run_case <label> <expect_exit> <stub_exit> <f> <w> <u> [env...]
  local label="$1" expect="$2" stub_exit="$3" f="$4" w="$5" u="$6"; shift 6
  rm -rf "$WORK/scripts" "$WORK/invocations.txt"; mkdir -p "$WORK/scripts"
  make_stub "$stub_exit" "$f" "$w" "$u"

  local out actual
  out=$(_run_prehook \
          "VM_NAME=${VM_NAME_OVERRIDE-win2k22-good}" \
          "VM_NAMESPACE=${VM_NS_OVERRIDE-bsod-test}" "$@" 2>&1)
  actual=$?

  # R-25 / U-23: the audit must be invoked EXACTLY ONCE per gated VM. It
  # previously ran twice -- once for the human report, once with --json purely
  # to print counts -- doubling apiserver load on the migration-blocking path,
  # and leaving open the possibility of the two runs observing different cluster
  # state and reporting counts that did not match the verdict.
  # EXPECT_INVOCATIONS defaults to 1. The cases that abort BEFORE reaching the
  # audit (missing VM_NAME/VM_NAMESPACE -- the hook cannot identify its subject
  # and must block) legitimately expect 0, and asserting 1 there would punish
  # exactly the fail-closed behaviour those cases exist to prove.
  local want_inv="${EXPECT_INVOCATIONS:-1}"
  local invocations=0
  [ -f "$WORK/invocations.txt" ] && invocations=$(grep -c . "$WORK/invocations.txt")

  if [ "$actual" -eq "$expect" ] && [ "$invocations" -eq "$want_inv" ]; then
    echo "PASS: $label (exit=$actual, audit invocations=$invocations)"
    PASS_COUNT=$((PASS_COUNT+1))
  elif [ "$actual" -eq "$expect" ]; then
    echo "FAIL: $label -- exit $actual correct, but audit ran $invocations time(s), expected $want_inv"
    [ -f "$WORK/invocations.txt" ] && sed 's/^/        /' "$WORK/invocations.txt"
    FAIL_COUNT=$((FAIL_COUNT+1))
  else
    echo "FAIL: $label -- expected exit $expect, got $actual"
    echo "$out" | sed 's/^/        /' | head -8
    FAIL_COUNT=$((FAIL_COUNT+1))
  fi
}

echo "=== PreHook gate contract (extracted from $(basename "$MANIFEST")) ==="

# The H2 scenario: audit exits 0 under --strict, but the VM was never assessed.
# With --fail-on-unknown wired in, the audit itself returns 1; the PreHook must
# propagate that rather than swallow it.
run_case "all-UNKNOWN VM blocks migration" 1 1 0 0 3

# A genuinely clean VM must still pass, or the gate is useless.
run_case "clean VM passes" 0 0 0 0 0

# A real BSOD trigger must block.
run_case "FAIL finding blocks migration" 1 1 1 0 0

# Missing Forklift annotations: the gate cannot identify its subject. It used
# to degrade to --cluster-scope-only and SUCCEED.
EXPECT_INVOCATIONS=0 VM_NAME_OVERRIDE="" run_case "missing VM_NAME blocks (was: silent pass)" 1 0 0 0 0
EXPECT_INVOCATIONS=0 VM_NS_OVERRIDE="" run_case "missing VM_NAMESPACE blocks (was: silent pass)" 1 0 0 0 0

# BSOD_STRICT / BSOD_FAIL_ON_UNKNOWN must actually reach the audit script.
rm -rf "$WORK/scripts" "$WORK/invocations.txt"; mkdir -p "$WORK/scripts"; make_stub 0 0 0 0
_run_prehook VM_NAME=v VM_NAMESPACE=n BSOD_STRICT=true BSOD_FAIL_ON_UNKNOWN=true >/dev/null 2>&1
if grep -q -- "--strict" "$WORK/invocations.txt" && grep -q -- "--fail-on-unknown" "$WORK/invocations.txt"; then
  echo "PASS: BSOD_STRICT=true and BSOD_FAIL_ON_UNKNOWN=true both reach the audit"
  PASS_COUNT=$((PASS_COUNT+1))
else
  echo "FAIL: flags not propagated -- got: $(head -1 "$WORK/invocations.txt")"
  FAIL_COUNT=$((FAIL_COUNT+1))
fi

# The N12 defect class, in this file: env declared but ignored.
rm -rf "$WORK/scripts" "$WORK/invocations.txt"; mkdir -p "$WORK/scripts"; make_stub 0 0 0 0
_run_prehook VM_NAME=v VM_NAMESPACE=n BSOD_STRICT=false BSOD_FAIL_ON_UNKNOWN=false >/dev/null 2>&1
if grep -q -- "--strict" "$WORK/invocations.txt"; then
  echo "FAIL: BSOD_STRICT=false was ignored -- --strict still passed (N12 defect class)"
  FAIL_COUNT=$((FAIL_COUNT+1))
else
  echo "PASS: BSOD_STRICT=false is honoured (not hardcoded)"
  PASS_COUNT=$((PASS_COUNT+1))
fi

echo
echo "=============================================="
echo " test_prehook_contract.sh: $PASS_COUNT passed, $FAIL_COUNT failed"
echo "=============================================="
[ "$FAIL_COUNT" -eq 0 ]
