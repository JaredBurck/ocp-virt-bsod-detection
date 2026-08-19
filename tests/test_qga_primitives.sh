#!/usr/bin/env bash
#
# test_qga_primitives.sh
# -----------------------------------------------------------------------------
# Offline unit-style regression test for the guest-communication primitives in
# scripts/cnv-qga-fleet-collect.sh: validate_k8s_name, find_launcher_pod,
# check_qga, qga_exec, qga_exec_capture, qga_file_read, qga_file_write.
#
# v0.16.0 #16: tests/test_qga_harden_staging_dir.sh already established the
# extract-and-stub pattern for harden_guest_staging_dir() by stubbing OUT
# qga_exec/qga_exec_capture themselves -- which means the primitives those
# stubs replace have shipped with zero direct coverage since introduction.
# A regression in the guest-exec-status polling loop, the base64
# encode/decode round-trip, or the short-write detection would not be
# caught by any existing test.
#
# Same approach as test_qga_harden_staging_dir.sh: extract each function
# verbatim by line range and source it in isolation (so this test can never
# silently drift out of sync with what actually ships), then stub the one
# real external dependency each primitive has -- `oc` (and `sleep`, so the
# guest-exec-status polling loop doesn't actually wait). `jq` and `base64`
# are left real: they are core to the base64/JSON round-trip these
# primitives exist to get right, and stubbing them would test nothing.
#
# Usage: tests/test_qga_primitives.sh
# Exit code: 0 if every scenario matches its expected result, else 1.
# -----------------------------------------------------------------------------
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TARGET="$REPO_ROOT/scripts/cnv-qga-fleet-collect.sh"

if [ ! -f "$TARGET" ]; then
  echo "FAIL: $TARGET not found"
  exit 1
fi

PASS_COUNT=0
FAIL_COUNT=0

pass() { echo "PASS: $1"; PASS_COUNT=$((PASS_COUNT+1)); }
fail() { echo "FAIL: $1"; FAIL_COUNT=$((FAIL_COUNT+1)); }

extract_func() {
  local name="$1"
  local src
  src="$(sed -n "/^${name}() {\$/,/^}\$/p" "$TARGET")"
  if [ -z "$src" ]; then
    echo "FAIL: could not extract ${name}() from $TARGET"
    exit 1
  fi
  # shellcheck disable=SC2086,SC1090,SC1091
  eval "$src"
  if ! declare -F "$name" >/dev/null; then
    echo "FAIL: ${name} did not source correctly"
    exit 1
  fi
}

for fn in validate_k8s_name find_launcher_pod check_qga qga_exec qga_exec_capture qga_file_read qga_file_write cleanup_started_vms; do
  extract_func "$fn"
done

# QGA_TIMEOUT is referenced by the extracted functions as a script-global
# variable set at the top of cnv-qga-fleet-collect.sh's top-level (not part
# of the functions themselves); shellcheck can't see that usage since the
# functions are eval'd in, not sourced as a file.
# shellcheck disable=SC2034
QGA_TIMEOUT=300
LOG_LINES=""
log() { LOG_LINES="${LOG_LINES}$*"$'\n'; }
red() { :; }

# --- Stub `oc`: a bash function shadows any real `oc` binary on PATH for
# every unqualified `oc ...` call the sourced functions make. Dispatches on
# the QGA "execute" verb (parsed from the last argument's JSON) so a single
# stub can serve guest-info / guest-exec / guest-exec-status /
# guest-file-{open,read,write,close) plus the plain `oc get pods` call
# find_launcher_pod makes.
#
# Every real call site in cnv-qga-fleet-collect.sh invokes `oc` via command
# substitution (`x=$(oc ...)`), which forks a fresh subshell per call -- an
# in-memory counter incremented inside this function (e.g. a plain
# `OC_STATUS_IDX=$((OC_STATUS_IDX+1))`) would be thrown away the instant
# that subshell exits, silently repeating the FIRST queued response forever
# instead of advancing through the scripted polling sequence. Queue
# position is therefore persisted to a file, which is real, and survives
# across subshells.
OC_STATE_DIR="$(mktemp -d)"
trap 'rm -rf "$OC_STATE_DIR"' EXIT

OC_GET_PODS_DOMAIN_OUTPUT=""
OC_GET_PODS_NAME_OUTPUT=""
OC_GUEST_INFO_OUTPUT=""
OC_GUEST_EXEC_OUTPUT=""
OC_STATUS_QUEUE=()
OC_FILE_OPEN_OUTPUT=""
OC_READ_CHUNKS=()
OC_FILE_WRITE_OUTPUT=""

_oc_next_idx() {
  # Reads-then-increments the on-disk counter named "$1" atomically enough
  # for this single-threaded test harness (no concurrent callers).
  local idx_file="$OC_STATE_DIR/$1"
  local idx
  idx="$(cat "$idx_file" 2>/dev/null || echo 0)"
  echo $((idx + 1)) > "$idx_file"
  echo "$idx"
}

oc() {
  echo "oc $*" >> "$OC_STATE_DIR/call_log"
  case "$1" in
    get)
      if printf '%s' "$*" | grep -q 'kubevirt\.io/domain='; then
        printf '%s' "$OC_GET_PODS_DOMAIN_OUTPUT"
      else
        printf '%s' "$OC_GET_PODS_NAME_OUTPUT"
      fi
      ;;
    exec)
      local last="${*: -1}"
      local verb
      verb=$(printf '%s' "$last" | jq -r '.execute // empty' 2>/dev/null)
      case "$verb" in
        guest-info) printf '%s' "$OC_GUEST_INFO_OUTPUT" ;;
        guest-exec) printf '%s' "$OC_GUEST_EXEC_OUTPUT" ;;
        guest-exec-status)
          local idx
          idx="$(_oc_next_idx status_idx)"
          printf '%s' "${OC_STATUS_QUEUE[$idx]:-}"
          ;;
        guest-file-open) printf '%s' "$OC_FILE_OPEN_OUTPUT" ;;
        guest-file-read)
          local idx
          idx="$(_oc_next_idx read_idx)"
          printf '%s' "${OC_READ_CHUNKS[$idx]:-}"
          ;;
        guest-file-write) printf '%s' "$OC_FILE_WRITE_OUTPUT" ;;
        guest-file-close) printf '%s' '{"return":{}}' ;;
        *) printf '%s' '{}' ;;
      esac
      ;;
    *)
      echo "mock oc: unhandled invocation: oc $*" >&2
      return 1
      ;;
  esac
}

sleep() { :; }  # the guest-exec-status polling loop must not actually wait

oc_call_log() { cat "$OC_STATE_DIR/call_log" 2>/dev/null || true; }

reset_oc_stub() {
  : > "$OC_STATE_DIR/call_log"
  : > "$OC_STATE_DIR/status_idx"
  : > "$OC_STATE_DIR/read_idx"
  OC_GET_PODS_DOMAIN_OUTPUT=""
  OC_GET_PODS_NAME_OUTPUT=""
  OC_GUEST_INFO_OUTPUT=""
  OC_GUEST_EXEC_OUTPUT=""
  OC_STATUS_QUEUE=()
  OC_FILE_OPEN_OUTPUT=""
  OC_READ_CHUNKS=()
  OC_FILE_WRITE_OUTPUT=""
  LOG_LINES=""
}
reset_oc_stub

# =============================================================================
# validate_k8s_name
# =============================================================================

if ( validate_k8s_name "namespace" "bsod-test" ) 2>/dev/null; then
  pass "validate_k8s_name accepts a normal namespace"
else
  fail "validate_k8s_name should accept 'bsod-test'"
fi

if ( validate_k8s_name "vm" "" ) 2>/dev/null; then
  pass "validate_k8s_name accepts an empty value (optional --vm)"
else
  fail "validate_k8s_name should accept an empty value"
fi

if ( validate_k8s_name "namespace" "foo; rm -rf /" ) 2>/dev/null; then
  fail "validate_k8s_name should reject shell metacharacters"
else
  pass "validate_k8s_name rejects shell metacharacters (exit 2)"
fi

if ( validate_k8s_name "namespace" "-leading-dash" ) 2>/dev/null; then
  fail "validate_k8s_name should reject a value starting with '-'"
else
  pass "validate_k8s_name rejects a leading dash"
fi

long_name="$(printf 'a%.0s' $(seq 1 254))"
if ( validate_k8s_name "namespace" "$long_name" ) 2>/dev/null; then
  fail "validate_k8s_name should reject a value over 253 characters"
else
  pass "validate_k8s_name rejects a value over 253 characters"
fi

# =============================================================================
# find_launcher_pod
# =============================================================================

reset_oc_stub
OC_GET_PODS_DOMAIN_OUTPUT="virt-launcher-win10-abcde"
result="$(find_launcher_pod ns win10)"
if [ "$result" = "virt-launcher-win10-abcde" ]; then
  pass "find_launcher_pod returns the pod from the kubevirt.io/domain selector"
else
  fail "find_launcher_pod: expected virt-launcher-win10-abcde, got '$result'"
fi

reset_oc_stub
OC_GET_PODS_DOMAIN_OUTPUT=""
OC_GET_PODS_NAME_OUTPUT="virt-launcher-win10-fallback"
result="$(find_launcher_pod ns win10)"
if [ "$result" = "virt-launcher-win10-fallback" ]; then
  pass "find_launcher_pod falls back to the vm.kubevirt.io/name selector when the domain selector finds nothing"
else
  fail "find_launcher_pod: expected fallback pod, got '$result'"
fi

reset_oc_stub
result="$(find_launcher_pod ns win10)"
if [ -z "$result" ]; then
  pass "find_launcher_pod returns empty when no pod matches either selector"
else
  fail "find_launcher_pod: expected empty result, got '$result'"
fi

# =============================================================================
# check_qga
# =============================================================================

reset_oc_stub
OC_GUEST_INFO_OUTPUT='{"return":{"version":"106"}}'
result="$(check_qga ns pod domain)"
if [ "$result" = "106" ]; then
  pass "check_qga extracts the QGA version from a healthy guest-info response"
else
  fail "check_qga: expected '106', got '$result'"
fi

reset_oc_stub
OC_GUEST_INFO_OUTPUT=''
result="$(check_qga ns pod domain)"
if [ -z "$result" ]; then
  pass "check_qga returns empty when the guest-info call fails/is unreachable"
else
  fail "check_qga: expected empty result for unreachable QGA, got '$result'"
fi

# =============================================================================
# qga_exec
# =============================================================================

reset_oc_stub
OC_GUEST_EXEC_OUTPUT='{"return":{"pid":4242}}'
OC_STATUS_QUEUE=(
  '{"return":{"exited":false}}'
  '{"return":{"exited":true,"exitcode":0}}'
)
result="$(qga_exec ns pod domain cmd.exe /c 'exit 0')"
if [ "$result" = "0" ]; then
  pass "qga_exec polls until exited=true and reports the real exit code"
else
  fail "qga_exec: expected exit code '0', got '$result'"
fi

reset_oc_stub
OC_GUEST_EXEC_OUTPUT='{"return":{"pid":4243}}'
OC_STATUS_QUEUE=('{"return":{"exited":true,"exitcode":1}}')
result="$(qga_exec ns pod domain cmd.exe /c 'exit 1')"
if [ "$result" = "1" ]; then
  pass "qga_exec reports a non-zero guest exit code"
else
  fail "qga_exec: expected exit code '1', got '$result'"
fi

reset_oc_stub
OC_GUEST_EXEC_OUTPUT='{"return":{}}'  # no pid -- guest-exec itself failed to start
result="$(qga_exec ns pod domain cmd.exe /c 'exit 0')"
rc=$?
if [ "$result" = "ERROR: failed to start guest exec" ] && [ "$rc" -eq 1 ]; then
  pass "qga_exec fails closed when guest-exec never returns a pid"
else
  fail "qga_exec: expected 'ERROR: failed to start guest exec' + rc=1, got '$result' rc=$rc"
fi

reset_oc_stub
OC_GUEST_EXEC_OUTPUT='{"return":{"pid":4244}}'
OC_STATUS_QUEUE=()  # every guest-exec-status poll returns nothing -- never exits
result="$(qga_exec ns pod domain cmd.exe /c 'hang')"
rc=$?
if [ "$result" = "TIMEOUT" ] && [ "$rc" -eq 1 ]; then
  pass "qga_exec reports TIMEOUT (not a fabricated exit code) when the guest never reports exited=true"
else
  fail "qga_exec: expected 'TIMEOUT' + rc=1 on a hung guest command, got '$result' rc=$rc"
fi

# =============================================================================
# qga_exec_capture
# =============================================================================

reset_oc_stub
OC_GUEST_EXEC_OUTPUT='{"return":{"pid":5000}}'
# base64 of "hello-guest"
OC_STATUS_QUEUE=('{"return":{"exited":true,"out-data":"aGVsbG8tZ3Vlc3Q="}}')
result="$(qga_exec_capture ns pod domain cmd.exe /c 'echo hello-guest')"
if [ "$result" = "hello-guest" ]; then
  pass "qga_exec_capture base64-decodes out-data on success"
else
  fail "qga_exec_capture: expected 'hello-guest', got '$result'"
fi

reset_oc_stub
OC_GUEST_EXEC_OUTPUT='{"return":{}}'
result="$(qga_exec_capture ns pod domain cmd.exe /c 'echo x')"
rc=$?
if [ -z "$result" ] && [ "$rc" -eq 1 ]; then
  pass "qga_exec_capture returns rc=1 with no output when guest-exec never returns a pid"
else
  fail "qga_exec_capture: expected empty output + rc=1, got '$result' rc=$rc"
fi

reset_oc_stub
OC_GUEST_EXEC_OUTPUT='{"return":{"pid":5001}}'
OC_STATUS_QUEUE=()  # never exits
result="$(qga_exec_capture ns pod domain cmd.exe /c 'hang' 2>/dev/null)"
rc=$?
if [ -z "$result" ] && [ "$rc" -eq 2 ]; then
  pass "qga_exec_capture returns the distinct rc=2 on timeout (not conflated with rc=1 'no output')"
else
  fail "qga_exec_capture: expected empty output + rc=2 on timeout, got '$result' rc=$rc"
fi

reset_oc_stub
OC_GUEST_EXEC_OUTPUT='{"return":{"pid":5002}}'
OC_STATUS_QUEUE=('{"return":{"exited":true}}')  # exited, but no out-data at all
result="$(qga_exec_capture ns pod domain cmd.exe /c 'echo nothing')"
rc=$?
if [ -z "$result" ] && [ "$rc" -eq 1 ]; then
  pass "qga_exec_capture returns rc=1 when the guest command exits with no captured output"
else
  fail "qga_exec_capture: expected empty output + rc=1 for missing out-data, got '$result' rc=$rc"
fi

# =============================================================================
# qga_file_read
# =============================================================================

reset_oc_stub
OC_FILE_OPEN_OUTPUT='{"return":7}'
# base64 of "guest file contents"
OC_READ_CHUNKS=('{"return":{"buf-b64":"Z3Vlc3QgZmlsZSBjb250ZW50cw==","eof":true}}')
local_out="$(mktemp)"
if qga_file_read ns pod domain 'C:\DebugInfo\out.txt' "$local_out"; then
  content="$(cat "$local_out")"
  if [ "$content" = "guest file contents" ]; then
    pass "qga_file_read decodes a single-chunk (eof=true immediately) transfer correctly"
  else
    fail "qga_file_read: decoded content mismatch: '$content'"
  fi
else
  fail "qga_file_read: expected success for a clean single-chunk transfer"
fi
rm -f "$local_out"

reset_oc_stub
OC_FILE_OPEN_OUTPUT='{"return":8}'
# base64("guest ") + base64("file part2") split across two chunks, concatenated
# BEFORE decoding (matches the real function's streaming-append design).
OC_READ_CHUNKS=(
  '{"return":{"buf-b64":"Z3Vlc3Qg","eof":false}}'
  '{"return":{"buf-b64":"ZmlsZSBwYXJ0Mg==","eof":true}}'
)
local_out="$(mktemp)"
if qga_file_read ns pod domain 'C:\DebugInfo\out2.txt' "$local_out"; then
  content="$(cat "$local_out")"
  if [ "$content" = "guest file part2" ]; then
    pass "qga_file_read concatenates multiple chunks across the polling loop before decoding"
  else
    fail "qga_file_read: multi-chunk decoded content mismatch: '$content'"
  fi
else
  fail "qga_file_read: expected success for a clean multi-chunk transfer"
fi
rm -f "$local_out"

reset_oc_stub
OC_FILE_OPEN_OUTPUT='{"return":null}'  # guest-file-open failed -- no handle
local_out="$(mktemp)"
if qga_file_read ns pod domain 'C:\DebugInfo\missing.txt' "$local_out"; then
  fail "qga_file_read should fail closed when guest-file-open returns no handle"
else
  pass "qga_file_read fails closed (rc=1) when guest-file-open returns no handle"
fi
rm -f "$local_out"

# =============================================================================
# qga_file_write
# =============================================================================

reset_oc_stub
OC_FILE_OPEN_OUTPUT='{"return":9}'
local_in="$(mktemp)"
printf 'stage me' > "$local_in"
expected_bytes=$(wc -c < "$local_in" | tr -d ' ')
OC_FILE_WRITE_OUTPUT="{\"return\":{\"count\":${expected_bytes},\"eof\":false}}"
if qga_file_write ns pod domain "$local_in" 'C:\DebugInfo\collect.ps1'; then
  pass "qga_file_write succeeds when the guest reports the full expected byte count"
else
  fail "qga_file_write: expected success on a full-byte-count write"
fi
rm -f "$local_in"

reset_oc_stub
OC_FILE_OPEN_OUTPUT='{"return":10}'
local_in="$(mktemp)"
printf 'stage me' > "$local_in"
OC_FILE_WRITE_OUTPUT='{"return":{"count":3,"eof":false}}'  # short write
if qga_file_write ns pod domain "$local_in" 'C:\DebugInfo\collect.ps1'; then
  fail "qga_file_write should fail on a short write (guest wrote fewer bytes than sent)"
else
  pass "qga_file_write fails on a short write"
fi
if oc_call_log | grep -q 'guest-file-close'; then
  pass "qga_file_write closes the guest file handle even after a short-write failure (no fd leak)"
else
  fail "qga_file_write: guest-file-close was not called after a short-write failure"
fi
rm -f "$local_in"

reset_oc_stub
OC_FILE_OPEN_OUTPUT='{"return":11}'
local_in="$(mktemp)"
printf 'stage me' > "$local_in"
OC_FILE_WRITE_OUTPUT='{"return":{}}'  # QGA rejected the write outright -- no count at all
if qga_file_write ns pod domain "$local_in" 'C:\DebugInfo\collect.ps1'; then
  fail "qga_file_write should fail when guest-file-write returns no byte count"
else
  pass "qga_file_write fails closed when guest-file-write returns no byte count"
fi
rm -f "$local_in"

# =============================================================================
# cleanup_started_vms (INT/TERM trap handler) -- v0.16.0 #11
# =============================================================================
# The trap handler exits unconditionally (exit 130), so it must be invoked
# in a subshell to observe its side effects without terminating this test
# script.

# shellcheck disable=SC2034  # consumed by the eval'd cleanup_started_vms body
STARTED_VMS=()
# shellcheck disable=SC2034
STARTED_VMS_LEGACY=()
# shellcheck disable=SC2034
NAMESPACE="ns"
leaked_tmpfile="$(mktemp "${TMPDIR:-/tmp}/bsod-qga-read-test.XXXXXX")"
printf 'partial transfer' > "$leaked_tmpfile"

(
  CURRENT_QGA_TMPFILE="$leaked_tmpfile"
  cleanup_started_vms
)
rc=$?

if [ "$rc" -eq 130 ]; then
  pass "cleanup_started_vms exits 130 on interrupt"
else
  fail "cleanup_started_vms: expected exit 130, got $rc"
fi

if [ ! -e "$leaked_tmpfile" ]; then
  pass "cleanup_started_vms removes the in-flight qga_file_read temp file on interrupt"
else
  fail "cleanup_started_vms: temp file '$leaked_tmpfile' still exists after interrupt"
  rm -f "$leaked_tmpfile"
fi

# No in-flight transfer (CURRENT_QGA_TMPFILE empty, the common case) must not
# error trying to remove a file that was never set.
(
  # shellcheck disable=SC2034
  CURRENT_QGA_TMPFILE=""
  cleanup_started_vms
) 2>/tmp/bsod-cleanup-stderr.$$
rc=$?
stderr_content="$(cat /tmp/bsod-cleanup-stderr.$$ 2>/dev/null)"
rm -f "/tmp/bsod-cleanup-stderr.$$"
if [ "$rc" -eq 130 ] && [ -z "$stderr_content" ]; then
  pass "cleanup_started_vms is a no-op for the temp file when no transfer is in flight"
else
  fail "cleanup_started_vms: unexpected stderr/rc with no in-flight transfer: rc=$rc stderr='$stderr_content'"
fi

echo
echo "=============================================="
echo " test_qga_primitives.sh: $PASS_COUNT passed, $FAIL_COUNT failed"
echo "=============================================="
[ "$FAIL_COUNT" -eq 0 ]
