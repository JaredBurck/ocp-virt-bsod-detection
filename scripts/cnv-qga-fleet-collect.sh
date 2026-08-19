#!/usr/bin/env bash
# cnv-qga-fleet-collect.sh -- Zero-touch guest data collection via QEMU Guest Agent
#
# Runs collect-windows-guest-info.ps1 inside Windows VMs through QGA exec
# without requiring RDP/console access. Uses virsh qemu-agent-command to
# execute PowerShell in the guest and retrieves artifacts via guest-file-read.
#
# Prerequisites:
#   - QEMU Guest Agent installed and running inside the Windows VM
#   - collect-windows-guest-info.ps1 staged on the guest (C:\DebugInfo\)
#     or use --stage to upload it via guest-file-write
#   - oc logged in to the cluster; jq installed
#
# Usage:
#   ./cnv-qga-fleet-collect.sh --namespace <ns> [--vm <vm>] [--all-windows]
#   ./cnv-qga-fleet-collect.sh --namespace <ns> --stage --vm <vm>
#   ./cnv-qga-fleet-collect.sh --namespace <ns> --all-windows --output /path/to/bsod
#
# Output: places guest artifacts into <output>/pre-flight/vms/<ns>/<vm>/guest/
#         compatible with analyze.py must-gather tree format.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

COMMON="$SCRIPT_DIR/../must-gather/collection-scripts/common_bsod.sh"
if [ -f "$COMMON" ]; then
  # shellcheck source=SCRIPTDIR/../must-gather/collection-scripts/common_bsod.sh
  source "$COMMON"
else
  log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"; }
  ensure_dir() { mkdir -p "$1" 2>/dev/null || true; }
fi

# --- Defaults ---
NAMESPACE=""
VM_NAME=""
ALL_WINDOWS=0
STAGE=0
OUTPUT_DIR="./bsod-qga-collect"
GUEST_SCRIPT_PATH='C:\DebugInfo\collect-windows-guest-info.ps1'
GUEST_OUT_DIR='C:\DebugInfo'
QGA_TIMEOUT=300
DRY_RUN=0
REMEDIATE=0
CONFIRM_REMEDIATE=0
EXPORT_FMT=""
START_HALTED=0
CONFIRM_START_HALTED=0
INCLUDE_SENSITIVE=0
# guest-file-read streams in 64KB chunks, one `oc exec` round-trip per chunk,
# buffering the entire base64 payload in memory before decoding -- unsuitable
# for multi-GB MEMORY.DMP files. This caps automatic retrieval of the
# CollectSystemInfo.ps1 SystemInfo_*.zip bundle (which contains MEMORY.DMP
# when --include-sensitive-data is used) to a safe size; larger bundles are
# left on the guest with a manual-retrieval hint instead of risking a hang.
MAX_DUMP_MB=200
# v0.16.0 #11: qga_file_read()'s streaming temp file (L8) is not registered
# with the script's INT/TERM trap (cleanup_started_vms, below) -- a Ctrl-C
# mid-transfer leaked the partially-downloaded base64 under /tmp. Tracked
# here (set/cleared by qga_file_read itself) so the trap handler can remove
# whichever transfer, if any, is in flight at interrupt time.
CURRENT_QGA_TMPFILE=""

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
amber() { printf '\033[33m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }

# Reject shell/JSON metacharacters in operator-supplied Kubernetes names.
validate_k8s_name() {
  local label="$1" value="$2"
  if [ -z "$value" ]; then
    return 0
  fi
  if [[ ! "$value" =~ ^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$ ]]; then
    red "ERROR: invalid $label '$value' (allowed: alphanumeric, '.', '_', '-'; must start/end alphanumeric)"
    exit 2
  fi
  if [ "${#value}" -gt 253 ]; then
    red "ERROR: $label exceeds 253 characters"
    exit 2
  fi
}

usage() {
  echo "Usage: $0 --namespace <ns> [OPTIONS]"
  echo ""
  echo "Options:"
  echo "  --namespace <ns>    Target namespace (required)"
  echo "  --vm <name>         Specific VM to collect from"
  echo "  --all-windows       Collect from all detected Windows VMs"
  echo "  --stage             Upload the PS script to guests before exec"
  echo "  --output <path>     Output directory (default: ./bsod-qga-collect)"
  echo "  --timeout <sec>     QGA exec timeout (default: 300)"
  echo "  --dry-run           Show what would be collected without executing"
  echo "  --include-sensitive-data  Pass -IncludeSensitiveData (MEMORY.DMP opt-in; default off)."
  echo "                       Also attempts size-guarded retrieval of the resulting"
  echo "                       SystemInfo_*.zip (see --max-dump-mb); bundles over the"
  echo "                       threshold are left on the guest with a manual-retrieval hint."
  echo "  --max-dump-mb <MB>   Max SystemInfo_*.zip size to auto-retrieve via QGA (default: 200)"
  echo "  --remediate         Pass -Remediate to guest PS script (requires --confirm-remediate,"
  echo "                       unless --export is also given -- see below)"
  echo "  --confirm-remediate Double-opt-in for fleet remediation"
  echo "  --export <fmt>      Peer-review Issue J: requires --remediate. Instead of mutating"
  echo "                       each guest, evaluates the same conditions -Remediate would act on"
  echo "                       and retrieves a reviewable artifact per VM -- 'reg' (.reg file),"
  echo "                       'ansible' (playbook), or 'both'. Nothing on any guest is modified,"
  echo "                       so this does NOT require --confirm-remediate."
  echo "  --start-halted      Temporarily start Halted VMs for collection (requires --confirm-start-halted)"
  echo "  --confirm-start-halted  Double-opt-in for starting halted VMs"
  echo "  -h, --help          Show this help"
  exit 0
}

while [ $# -gt 0 ]; do
  case "$1" in
    --namespace|-n) NAMESPACE="$2"; shift 2 ;;
    --vm)          VM_NAME="$2"; shift 2 ;;
    --all-windows) ALL_WINDOWS=1; shift ;;
    --stage)       STAGE=1; shift ;;
    --output|-o)   OUTPUT_DIR="$2"; shift 2 ;;
    --timeout)     QGA_TIMEOUT="$2"; shift 2 ;;
    --dry-run)     DRY_RUN=1; shift ;;
    --include-sensitive-data) INCLUDE_SENSITIVE=1; shift ;;
    --max-dump-mb) MAX_DUMP_MB="$2"; shift 2 ;;
    --remediate)   REMEDIATE=1; shift ;;
    --confirm-remediate) CONFIRM_REMEDIATE=1; shift ;;
    --export)      EXPORT_FMT="$2"; shift 2 ;;
    --start-halted) START_HALTED=1; shift ;;
    --confirm-start-halted) CONFIRM_START_HALTED=1; shift ;;
    -h|--help)     usage ;;
    *)             red "Unknown option: $1"; exit 2 ;;
  esac
done

if [ -n "$EXPORT_FMT" ]; then
  case "$EXPORT_FMT" in
    reg|ansible|both) ;;
    *) red "ERROR: --export must be one of: reg, ansible, both (got: $EXPORT_FMT)"; exit 2 ;;
  esac
  if [ "$REMEDIATE" -eq 0 ]; then
    red "ERROR: --export requires --remediate (e.g. --remediate --export $EXPORT_FMT)."
    exit 2
  fi
fi

# Issue J: --export is read-only on every targeted guest (evaluates state,
# writes an artifact, never mutates), so the dual-confirm gate that exists to
# protect against fleet-wide in-place mutation does not apply to it.
if [ "$REMEDIATE" -eq 1 ] && [ "$CONFIRM_REMEDIATE" -eq 0 ] && [ -z "$EXPORT_FMT" ]; then
  red "ERROR: --remediate requires --confirm-remediate for safety."
  red "  Fleet remediation modifies registry settings and removes phantom devices"
  red "  on ALL targeted Windows VMs. Back up your VMs before proceeding."
  red "  (If you only want a reviewable artifact with no guest mutation, use"
  red "  --remediate --export <reg|ansible|both> instead -- no --confirm-remediate needed.)"
  exit 2
fi

if [ "$START_HALTED" -eq 1 ] && [ "$CONFIRM_START_HALTED" -eq 0 ]; then
  red "ERROR: --start-halted requires --confirm-start-halted for safety."
  red "  This will temporarily start all Halted VMs in the namespace, collect"
  red "  guest data, then stop them again. Ensure no production impact."
  exit 2
fi

[ -z "$NAMESPACE" ] && { red "Error: --namespace is required"; usage; }
if [ -z "$VM_NAME" ] && [ "$ALL_WINDOWS" -eq 0 ]; then
  red "Error: specify --vm <name> or --all-windows"
  exit 2
fi

validate_k8s_name "namespace" "$NAMESPACE"
validate_k8s_name "vm" "$VM_NAME"

if ! command -v oc >/dev/null 2>&1; then red "oc is required"; exit 2; fi
if ! command -v jq >/dev/null 2>&1; then red "jq is required"; exit 2; fi

# --- Helper: find virt-launcher pod (filter by Running to avoid nondeterminism during live migration) ---
find_launcher_pod() {
  local ns="$1" vm="$2"
  local pod
  pod=$(oc get pods -n "$ns" -l "kubevirt.io/domain=$vm" \
    --field-selector=status.phase=Running \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
  if [ -z "$pod" ]; then
    pod=$(oc get pods -n "$ns" -l "vm.kubevirt.io/name=$vm" \
      --field-selector=status.phase=Running \
      -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
  fi
  echo "$pod"
}

# --- Helper: get domain name inside virt-launcher ---
get_domain_name() {
  local ns="$1" pod="$2"
  local dom
  dom=$(oc exec -n "$ns" "$pod" -c compute -- \
    bash -c 'virsh list --name 2>/dev/null | grep -v "^$" | head -1' 2>/dev/null)
  [ -z "$dom" ] && dom="1"
  echo "$dom"
}

# --- Helper: check QGA connectivity ---
check_qga() {
  local ns="$1" pod="$2" domain="$3"
  oc exec -n "$ns" "$pod" -c compute -- \
    virsh qemu-agent-command "$domain" '{"execute":"guest-info"}' 2>/dev/null | \
    jq -r '.return.version // empty' 2>/dev/null
}

# --- Helper: exec command in guest via QGA ---
qga_exec() {
  local ns="$1" pod="$2" domain="$3" path="$4"
  shift 4
  local args_json="[]"
  if [ $# -gt 0 ]; then
    args_json=$(printf '%s\n' "$@" | jq -R . | jq -s .)
  fi

  local cmd_json
  cmd_json=$(jq -n --arg path "$path" --argjson args "$args_json" \
    '{"execute":"guest-exec","arguments":{"path":$path,"arg":$args,"capture-output":true}}')

  local result
  result=$(oc exec -n "$ns" "$pod" -c compute -- \
    virsh qemu-agent-command "$domain" "$cmd_json" 2>/dev/null)

  local pid
  pid=$(echo "$result" | jq -r '.return.pid // empty')
  [ -z "$pid" ] && { echo "ERROR: failed to start guest exec"; return 1; }

  local elapsed=0
  local status_json=""
  local exited="false"
  while [ $elapsed -lt "$QGA_TIMEOUT" ]; do
    sleep 3
    elapsed=$((elapsed + 3))
    # Build JSON via jq --argjson so pid cannot break out of the payload
    local status_cmd
    status_cmd=$(jq -n --argjson pid "$pid" \
      '{"execute":"guest-exec-status","arguments":{"pid":$pid}}')
    status_json=$(oc exec -n "$ns" "$pod" -c compute -- \
      virsh qemu-agent-command "$domain" "$status_cmd" 2>/dev/null)
    exited=$(echo "$status_json" | jq -r '.return.exited // false')
    [ "$exited" = "true" ] && break
  done

  # A loop that exits via the timeout (never observed exited=true) must be
  # distinguishable from a real exit code -- '.return.exitcode // -1' would
  # otherwise silently print "-1" for a hung/slow guest command, which is
  # indistinguishable from a script that legitimately exited with code -1.
  if [ "$exited" != "true" ]; then
    echo "TIMEOUT"
    return 1
  fi

  local exit_code
  exit_code=$(echo "$status_json" | jq -r '.return.exitcode // -1')
  echo "$exit_code"
}

# --- Helper: run a guest command and capture its stdout (base64-decoded) ---
# Unlike qga_exec() above (which only returns the exit code), this decodes
# guest-exec-status's "out-data" so callers can read small text output --
# e.g. discovering a dynamically-named file's path and size.
qga_exec_capture() {
  local ns="$1" pod="$2" domain="$3" path="$4"
  shift 4
  local args_json="[]"
  if [ $# -gt 0 ]; then
    args_json=$(printf '%s\n' "$@" | jq -R . | jq -s .)
  fi

  local cmd_json
  cmd_json=$(jq -n --arg path "$path" --argjson args "$args_json" \
    '{"execute":"guest-exec","arguments":{"path":$path,"arg":$args,"capture-output":true}}')

  local result
  result=$(oc exec -n "$ns" "$pod" -c compute -- \
    virsh qemu-agent-command "$domain" "$cmd_json" 2>/dev/null)

  local pid
  pid=$(echo "$result" | jq -r '.return.pid // empty')
  [ -z "$pid" ] && return 1

  local elapsed=0
  local status_json=""
  local exited="false"
  while [ $elapsed -lt "$QGA_TIMEOUT" ]; do
    sleep 2
    elapsed=$((elapsed + 2))
    local status_cmd
    status_cmd=$(jq -n --argjson pid "$pid" \
      '{"execute":"guest-exec-status","arguments":{"pid":$pid}}')
    status_json=$(oc exec -n "$ns" "$pod" -c compute -- \
      virsh qemu-agent-command "$domain" "$status_cmd" 2>/dev/null)
    exited=$(echo "$status_json" | jq -r '.return.exited // false')
    [ "$exited" = "true" ] && break
  done

  # Timing out here would otherwise return 1 with empty stdout -- identical
  # to "the guest command ran and legitimately produced no output" -- so
  # callers (e.g. the SystemInfo_*.zip discovery command) would misreport a
  # timeout as "not found" instead of "guest did not respond in time".
  if [ "$exited" != "true" ]; then
    echo "TIMEOUT" >&2
    return 2
  fi

  local out_b64
  out_b64=$(echo "$status_json" | jq -r '.return."out-data" // empty')
  [ -z "$out_b64" ] && return 1
  echo "$out_b64" | base64 -d 2>/dev/null
  return 0
}

# --- Helper: read file from guest via QGA ---
qga_file_read() {
  local ns="$1" pod="$2" domain="$3" guest_path="$4" local_path="$5"

  local open_json
  open_json=$(jq -n --arg p "$guest_path" \
    '{"execute":"guest-file-open","arguments":{"path":$p,"mode":"r"}}')
  local handle_result
  handle_result=$(oc exec -n "$ns" "$pod" -c compute -- \
    virsh qemu-agent-command "$domain" "$open_json" 2>/dev/null)
  local handle
  handle=$(echo "$handle_result" | jq -r '.return // empty')
  [ -z "$handle" ] && { log "  WARN: cannot open $guest_path"; return 1; }

  # L8: stream chunks to a temp file instead of accumulating them in a shell
  # variable. `content="${content}${buf_b64}"` re-allocated and copied the
  # whole string on every 64 KB chunk -- O(n^2) in the number of chunks, and
  # for the 200 MB default --max-dump-mb it held ~270 MB of base64 resident in
  # the shell process before decoding. Appending is O(n) and holds one chunk.
  local b64_tmp
  b64_tmp=$(mktemp "${TMPDIR:-/tmp}/bsod-qga-read.XXXXXX") || {
    log "  ERROR: cannot create temp file for $guest_path"; return 1; }
  # v0.16.0 #11: register with the script-global INT/TERM trap so a Ctrl-C
  # mid-transfer removes this file instead of leaking it under /tmp -- large
  # (--include-sensitive-data) transfers can be in flight for minutes.
  CURRENT_QGA_TMPFILE="$b64_tmp"
  local eof="false"
  while [ "$eof" != "true" ]; do
    local read_json
    read_json=$(jq -n --argjson h "$handle" \
      '{"execute":"guest-file-read","arguments":{"handle":$h,"count":65536}}')
    local chunk
    chunk=$(oc exec -n "$ns" "$pod" -c compute -- \
      virsh qemu-agent-command "$domain" "$read_json" 2>/dev/null)
    local buf_b64
    buf_b64=$(echo "$chunk" | jq -r '.return."buf-b64" // empty')
    # v0.16.0 #16 (found while adding direct test coverage): jq's `//`
    # alternative operator treats a JSON `false` the same as `null` --
    # `.return.eof // "true"` therefore evaluated to the string "true" on
    # EVERY read, including a real, correctly-reported `"eof":false` mid-
    # transfer, not just a missing/malformed field. That silently ended the
    # streaming loop after exactly one 64KB chunk regardless of the guest
    # file's actual size, on every guest-file-read this function has ever
    # made. Explicit null-check + tostring distinguishes "field absent"
    # (fail toward stopping, preserving the original fallback's intent)
    # from "field present and false" (keep reading).
    eof=$(echo "$chunk" | jq -r 'if .return.eof == null then "true" else (.return.eof | tostring) end')
    if [ -n "$buf_b64" ]; then
      printf '%s' "$buf_b64" >> "$b64_tmp"
    fi
  done

  local close_json
  close_json=$(jq -n --argjson h "$handle" \
    '{"execute":"guest-file-close","arguments":{"handle":$h}}')
  oc exec -n "$ns" "$pod" -c compute -- \
    virsh qemu-agent-command "$domain" "$close_json" >/dev/null 2>&1

  if [ -s "$b64_tmp" ]; then
    # Decode once, streaming, so neither the encoded nor decoded payload is
    # ever fully resident in the shell.
    if base64 -d < "$b64_tmp" > "$local_path" 2>/dev/null; then
      rm -f "$b64_tmp"
      CURRENT_QGA_TMPFILE=""
      return 0
    fi
    log "  ERROR: base64 decode failed for $guest_path (truncated transfer?)"
  fi
  rm -f "$b64_tmp"
  CURRENT_QGA_TMPFILE=""
  return 1
}

# --- Helper: create + lock down the guest staging directory (L-9) ---
#
# The staged script is executed by QGA as LocalSystem with
# `-ExecutionPolicy Bypass`. Directories created under C:\ inherit an ACL that
# lets BUILTIN\Users create files -- and a standard user can pre-create
# C:\DebugInfo themselves, becoming its owner. Either way an unprivileged
# guest user could plant collect-windows-guest-info.ps1 and have it run as
# SYSTEM: a textbook local privilege escalation, triggered by the very command
# an administrator runs to diagnose the machine.
#
# Note the fix is the ACL, not the location: %ProgramData% grants users the
# same subfolder-creation right, so relocating alone would change nothing. We
# therefore keep C:\DebugInfo (referenced by the collector, the windows_exporter
# textfile collector and the runbook) and secure it in place.
#
# Well-known SIDs are used instead of names because "Administrators" and
# "SYSTEM" are localized -- `icacls /grant Administrators:F` fails outright on
# a German or Japanese Windows install.
harden_guest_staging_dir() {
  local ns="$1" pod="$2" domain="$3"
  local dir="$GUEST_OUT_DIR"

  # IMPORTANT: never embed a quoted guest path inside a single `cmd.exe /c`
  # command *string* (e.g. "icacls \"$dir\" ..."). Confirmed live against a
  # real Windows guest: QEMU-GA's argv-to-command-line escaping assumes
  # standard MSVCRT `\"`-escaping, but cmd.exe's own /c string parser does
  # NOT treat `\"` as an escape -- every literal `"` just toggles
  # quote-mode, backslash is never special to it -- so the two disagree on
  # where the quoted region ends. The failure is silent, not loud: the
  # mis-parsed command line still invokes *some* builtin, which exits 0
  # having done nothing to the ACL, so the exit-code-only qga_exec calls
  # below would never have caught it (this is exactly why the read-back
  # below uses qga_exec_capture and fails closed on unexpected content, not
  # just a non-zero exit). $dir has no spaces, so it never needed quoting in
  # the first place -- pass it as its own argv element instead, and invoke
  # icacls.exe directly rather than through cmd.exe /c.
  qga_exec "$ns" "$pod" "$domain" "cmd.exe" "/c" "mkdir" "$dir\\lib" >/dev/null 2>&1

  # Reclaim ownership first: if a low-privileged user pre-created the
  # directory they own it, and an owner can rewrite any DACL we set.
  qga_exec "$ns" "$pod" "$domain" "C:\\Windows\\System32\\icacls.exe" \
    "$dir" "/setowner" "*S-1-5-32-544" "/T" "/C" >/dev/null 2>&1

  # /inheritance:r drops the inherited ACEs from C:\ (this is what removes
  # BUILTIN\Users); /grant:r then replaces rather than adds, so re-running is
  # idempotent. (OI)(CI) propagates to files and subdirectories.
  # Harden the DIRECTORY only -- deliberately NO /T here.
  #
  # (OI)(CI) are CONTAINER inheritance flags. Applying them to leaf files with
  # /T, as this did until v0.27.0, is not merely redundant: combined with
  # /inheritance:r stripping each file's inherited ACEs, Windows drops the
  # malformed file ACE and leaves the file with an EMPTY DACL -- openable by
  # nobody, not even SYSTEM.
  #
  # The effect was that --stage worked exactly ONCE per guest. On a first run
  # C:\DebugInfo is empty so nothing is harmed, but every later run bricked the
  # previously-staged collector and every artifact beside it, and staging then
  # failed with "cannot open ... for write" forever. Observed on a live fleet:
  # the one guest with a pre-existing C:\DebugInfo failed to re-stage while the
  # four fresh ones succeeded, and `icacls` on the file printed no ACEs at all.
  qga_exec "$ns" "$pod" "$domain" "C:\\Windows\\System32\\icacls.exe" \
    "$dir" "/inheritance:r" "/grant:r" "*S-1-5-18:(OI)(CI)F" \
    "/grant:r" "*S-1-5-32-544:(OI)(CI)F" "/C" >/dev/null 2>&1

  # Now make existing children re-inherit from the hardened parent. /reset on
  # the CHILDREN (dir\*), never on $dir itself -- that would discard the grant
  # just applied. This is also the repair path for a guest already bricked by
  # the pre-v0.27.0 /T behaviour: resetting a file to inherit replaces its
  # empty DACL with the parent's SYSTEM+Administrators ACEs.
  #
  # /C keeps it going on errors, so an empty directory (where dir\* matches
  # nothing) is a harmless no-op rather than a failure.
  qga_exec "$ns" "$pod" "$domain" "C:\\Windows\\System32\\icacls.exe" \
    "$dir\\*" "/reset" "/T" "/C" >/dev/null 2>&1

  # Fail closed. If the ACL cannot be verified we do not know who can write to
  # the directory we are about to execute a script from, and "probably fine"
  # is not an acceptable basis for running unknown content as SYSTEM.
  # qga_exec_capture, not qga_exec: the latter returns only the exit code, and
  # icacls exits 0 while printing an ACL we would be refusing to inspect.
  local acl
  acl=$(qga_exec_capture "$ns" "$pod" "$domain" "C:\\Windows\\System32\\icacls.exe" "$dir" 2>/dev/null)
  if [ -z "$acl" ]; then
    log "  ERROR: could not read ACL on $dir (icacls returned nothing)"
    return 1
  fi
  # Any remaining Users/Everyone/Authenticated Users ACE means inheritance
  # removal did not take. Matched by SID and by the common English names,
  # since icacls prints resolved names when it can.
  if printf '%s' "$acl" | grep -qiE 'S-1-5-32-545|S-1-1-0|S-1-5-11|\\Users:|Everyone:|Authenticated Users:'; then
    log "  ERROR: $dir still grants access to non-administrative users after hardening:"
    log "$acl"
    return 1
  fi
  return 0
}

# --- Helper: upload file to guest via QGA ---
qga_file_write() {
  local ns="$1" pod="$2" domain="$3" local_path="$4" guest_path="$5"

  local open_json
  open_json=$(jq -n --arg p "$guest_path" \
    '{"execute":"guest-file-open","arguments":{"path":$p,"mode":"w"}}')
  local handle_result
  handle_result=$(oc exec -n "$ns" "$pod" -c compute -- \
    virsh qemu-agent-command "$domain" "$open_json" 2>/dev/null)
  local handle
  handle=$(echo "$handle_result" | jq -r '.return // empty')
  [ -z "$handle" ] && { log "  ERROR: cannot open $guest_path for write"; return 1; }

  local b64_content expected_bytes
  b64_content=$(base64 -w 0 < "$local_path")
  expected_bytes=$(wc -c < "$local_path" | tr -d ' ')

  local write_json write_result
  write_json=$(jq -n --argjson h "$handle" --arg b "$b64_content" \
    '{"execute":"guest-file-write","arguments":{"handle":$h,"buf-b64":$b}}')
  write_result=$(oc exec -n "$ns" "$pod" -c compute -- \
    virsh qemu-agent-command "$domain" "$write_json" 2>/dev/null)

  # M-9: the handle must be closed even when the write failed, otherwise a
  # failed --stage leaks a guest file descriptor per attempt. Close first,
  # judge the write afterwards.
  local close_json
  close_json=$(jq -n --argjson h "$handle" \
    '{"execute":"guest-file-close","arguments":{"handle":$h}}')
  oc exec -n "$ns" "$pod" -c compute -- \
    virsh qemu-agent-command "$domain" "$close_json" >/dev/null 2>&1

  # M-9: guest-file-write returns {"return":{"count":N,"eof":false}}. The write
  # result was previously discarded (>/dev/null) and the function returned
  # guest-file-close's status instead, so a short write -- or no write at all --
  # reported success and the caller went on to execute a script that was
  # truncated or absent in the guest. A partially written PowerShell collector
  # fails in ways that look like a guest problem, not a staging problem.
  local written
  written=$(echo "$write_result" | jq -r '.return.count // empty' 2>/dev/null)
  if [ -z "$written" ]; then
    log "  ERROR: guest-file-write to $guest_path returned no byte count (QGA may have rejected the write)"
    return 1
  fi
  if [ "$written" -ne "$expected_bytes" ]; then
    log "  ERROR: short write to $guest_path -- guest reported $written of $expected_bytes byte(s)"
    return 1
  fi
  return 0
}

# --- Determine target VMs ---
if [ -n "$VM_NAME" ]; then
  target_vms="$VM_NAME"
else
  if type get_windows_vms >/dev/null 2>&1; then
    target_vms=$(get_windows_vms "$NAMESPACE")
  else
    # R-10 (v0.19.0 unified review U-09): EMBEDDED COPY of the canonical
    # selector in shared/windows-vm-selector.json, reached only in standalone
    # mode (this script is documented as customer-shareable as a single file,
    # so it must work with neither common_bsod.sh nor the shared JSON present).
    #
    # This copy previously OMITTED the .metadata.labels["vm.kubevirt.io/template"]
    # clause, so VMs classifiable as Windows only via that top-level label were
    # silently skipped -- under-collection in exactly the deployment mode where
    # a missing VM is least likely to be noticed.
    #
    # scripts/ci/validate-windows-vm-selector.py asserts this block stays
    # byte-identical to what scripts/lib/windows-vm-selector.sh generates.
    target_vms=$(oc get vm -n "$NAMESPACE" -o json 2>/dev/null | jq -r '
      .items[]
      | select(
          (.spec.template.metadata.annotations["vm.kubevirt.io/os"] // "" | test("windows|win2k|win10|win11|win2016|win2019|win2022|win2025|win7|win8|win81|winxp";"i"))
          or (.spec.template.metadata.labels["vm.kubevirt.io/template"] // "" | test("windows|win2k|win10|win11|win2016|win2019|win2022|win2025|win7|win8|win81|winxp";"i"))
          or (.metadata.labels["vm.kubevirt.io/template"] // "" | test("windows|win2k|win10|win11|win2016|win2019|win2022|win2025|win7|win8|win81|winxp";"i"))
          or (.metadata.labels["vm.kubevirt.io/os"] // "" | test("windows|win2k|win10|win11|win2016|win2019|win2022|win2025|win7|win8|win81|winxp";"i"))
          or (.spec.template.spec.domain.features.hyperv != null)
          or (.metadata.name | test("(^|[^a-z])win(dows|web|sql|app|dc|ad|rdp|rds|srv|term|fs|print|host|share|dns|dhcp|xp)?([^a-z]|[0-9]|$)";"i"))
        )
      | .metadata.name')
  fi
fi

[ -z "$target_vms" ] && { red "No Windows VMs found in namespace $NAMESPACE"; exit 1; }

# Guest artifacts to retrieve after script execution
GUEST_ARTIFACTS=(
  "drv_list.csv"
  # N8: separate VMware-allowlist driver snapshot (collect-windows-guest-info.ps1
  # writes this so check_vmware_leftover_drivers() has real evidence to check --
  # drv_list.csv above is filtered to virtio-only device names and can never
  # contain a VMware driver, regardless of what's actually installed).
  "vmware_drv_list.csv"
  "virtio_version.txt"
  "virtio_disk.txt"
  "PhantomDevices.csv"
  "PhantomNICConfig.csv"
  "firstboot.log"
  "CrashDumpConfig.json"
  "InstalledKBs.json"
  "GuestFeatures.json"
  # F-01 follow-up (v0.27.0): the in-guest I/O baseline. Written by section 7
  # of collect-windows-guest-info.ps1 and consumed by
  # insights-rules/parsers/io_limits.py. Both ends existed for a long time with
  # nothing connecting them -- the collector printed the numbers to the console
  # and this list never asked for the file.
  "io-limits.json"
  "remediation.log"
  # Issue J: present only when --remediate --export was used; qga_file_read
  # tolerates a missing guest file the same way it already does for
  # remediation.log on a non-remediation run.
  "remediation-export.reg"
  "remediation-playbook.yml"
)

# Detect OCP version once for passing to guest scripts
FLEET_OCP_VER=""
if command -v oc >/dev/null 2>&1; then
  FLEET_OCP_VER=$(oc get clusterversion version -o jsonpath='{.status.desired.version}' 2>/dev/null | cut -d. -f1-2)
fi

# --- Collect cluster-level data once (for analyze.py self-contained runs) ---
CLUSTER_DIR="$OUTPUT_DIR/pre-flight/cluster"
ensure_dir "$CLUSTER_DIR"
oc get clusterversion version -o json > "$CLUSTER_DIR/clusterversion.json" 2>/dev/null || true

# Track nodes we've already collected to avoid re-fetching per VM
declare -A SEEN_NODES

echo "=============================================================="
echo " CNV QGA Fleet Collection"
echo " Namespace: $NAMESPACE"
echo " OCP Version: ${FLEET_OCP_VER:-unknown}"
echo " Output: $OUTPUT_DIR"
echo " Timeout: ${QGA_TIMEOUT}s per VM"
if [ "$START_HALTED" -eq 1 ]; then
echo " Start-Halted: enabled"
fi
if [ -n "$EXPORT_FMT" ]; then
echo " Remediation export: $EXPORT_FMT (read-only, no guest mutation)"
elif [ "$REMEDIATE" -eq 1 ]; then
echo " Remediation: in-place (guest registry/service/device mutation)"
fi
echo "=============================================================="
echo ""

# --- Start halted VMs if requested ---
# STARTED_VMS_LEGACY is a parallel array to STARTED_VMS: "1" if that VM uses
# the legacy spec.running boolean instead of spec.runStrategy, "0" otherwise.
# KubeVirt's admission webhook rejects a VM spec with both running AND
# runStrategy set, so the no-virtctl fallback patch below must target
# whichever field the VM actually uses -- patching runStrategy onto a
# legacy running-based VM would be rejected by the webhook.
STARTED_VMS=()
STARTED_VMS_LEGACY=()
# Only invoked indirectly via the `trap` below; shellcheck cannot see that
# call path and flags the body as unreachable/never-invoked (SC2317/SC2329).
# shellcheck disable=SC2317,SC2329
cleanup_started_vms() {
  if [ ${#STARTED_VMS[@]} -gt 0 ]; then
    echo ""
    log "Interrupt received -- stopping ${#STARTED_VMS[@]} VM(s) started by --start-halted..."
    for i in "${!STARTED_VMS[@]}"; do
      svm="${STARTED_VMS[$i]}"
      if command -v virtctl >/dev/null 2>&1; then
        virtctl stop "$svm" -n "$NAMESPACE" 2>/dev/null
      elif [ "${STARTED_VMS_LEGACY[$i]:-0}" = "1" ]; then
        oc patch vm "$svm" -n "$NAMESPACE" --type merge -p '{"spec":{"running":false}}' 2>/dev/null
      else
        oc patch vm "$svm" -n "$NAMESPACE" --type merge -p '{"spec":{"runStrategy":"Halted"}}' 2>/dev/null
      fi
      log "  Stopped: $svm"
    done
  fi
  # v0.16.0 #11: remove qga_file_read()'s in-flight streaming temp file, if
  # any -- a Ctrl-C during a multi-minute --include-sensitive-data transfer
  # otherwise leaked the partial base64 payload under /tmp indefinitely.
  if [ -n "$CURRENT_QGA_TMPFILE" ]; then
    rm -f "$CURRENT_QGA_TMPFILE"
    log "  Removed in-flight transfer temp file: $CURRENT_QGA_TMPFILE"
  fi
  exit 130
}
trap cleanup_started_vms INT TERM
if [ "$START_HALTED" -eq 1 ]; then
  log "Identifying Halted VMs to start temporarily..."
  for vm in $target_vms; do
    run_strategy=$(oc get vm "$vm" -n "$NAMESPACE" -o jsonpath='{.spec.runStrategy}' 2>/dev/null)
    # Legacy VMs (created before runStrategy existed, or still using the
    # older field) set spec.running: false instead of spec.runStrategy --
    # matching only runStrategy=="Halted" silently skips these, leaving
    # them permanently un-started by --start-halted with no error.
    legacy_running=$(oc get vm "$vm" -n "$NAMESPACE" -o jsonpath='{.spec.running}' 2>/dev/null)
    is_halted="false"
    is_legacy="0"
    if [ "$run_strategy" = "Halted" ]; then
      is_halted="true"
    elif [ -z "$run_strategy" ] && [ "$legacy_running" = "false" ]; then
      is_halted="true"
      is_legacy="1"
    fi
    pod=$(find_launcher_pod "$NAMESPACE" "$vm")
    if [ -z "$pod" ] && [ "$is_halted" = "true" ]; then
      log "  Starting halted VM: $vm"
      if command -v virtctl >/dev/null 2>&1; then
        virtctl start "$vm" -n "$NAMESPACE" 2>/dev/null
      elif [ "$is_legacy" = "1" ]; then
        oc patch vm "$vm" -n "$NAMESPACE" --type merge -p '{"spec":{"running":true}}' 2>/dev/null
      else
        oc patch vm "$vm" -n "$NAMESPACE" --type merge -p '{"spec":{"runStrategy":"Always"}}' 2>/dev/null
      fi
      STARTED_VMS+=("$vm")
      STARTED_VMS_LEGACY+=("$is_legacy")
    fi
  done

  if [ ${#STARTED_VMS[@]} -gt 0 ]; then
    log "Waiting for ${#STARTED_VMS[@]} VM(s) to become ready (up to 300s)..."
    waited=0
    while [ $waited -lt 300 ]; do
      all_ready=true
      for svm in "${STARTED_VMS[@]}"; do
        pod=$(find_launcher_pod "$NAMESPACE" "$svm")
        if [ -z "$pod" ]; then
          all_ready=false
          break
        fi
        qga_ver=$(check_qga "$NAMESPACE" "$pod" "$(get_domain_name "$NAMESPACE" "$pod")")
        if [ -z "$qga_ver" ]; then
          all_ready=false
          break
        fi
      done
      if [ "$all_ready" = true ]; then
        log "  All started VMs are ready."
        break
      fi
      sleep 15
      waited=$((waited + 15))
    done
    if [ "$all_ready" != true ]; then
      amber "  WARNING: Not all started VMs became ready within 300s. Proceeding with available VMs."
    fi
  fi
fi

TOTAL=0
SUCCESS=0
FAILED=0

for vm in $target_vms; do
  TOTAL=$((TOTAL + 1))
  echo "--- VM: $NAMESPACE/$vm ---"

  if [ "$DRY_RUN" -eq 1 ]; then
    green "  [DRY-RUN] Would collect from $vm via QGA"
    SUCCESS=$((SUCCESS + 1))
    continue
  fi

  pod=$(find_launcher_pod "$NAMESPACE" "$vm")
  if [ -z "$pod" ]; then
    amber "  [SKIP] No virt-launcher pod found for $vm (VM not running?)"
    FAILED=$((FAILED + 1))
    continue
  fi

  domain=$(get_domain_name "$NAMESPACE" "$pod")
  log "  Pod: $pod | Domain: $domain"

  qga_version=$(check_qga "$NAMESPACE" "$pod" "$domain")
  if [ -z "$qga_version" ]; then
    amber "  [SKIP] QEMU Guest Agent not responding on $vm"
    FAILED=$((FAILED + 1))
    continue
  fi
  log "  QGA version: $qga_version"

  # Collect cluster-side VM/VMI specs (makes output self-contained for analyze.py)
  VM_DIR="$OUTPUT_DIR/pre-flight/vms/$NAMESPACE/$vm"
  ensure_dir "$VM_DIR"
  oc get vm "$vm" -n "$NAMESPACE" -o json > "$VM_DIR/vm.json" 2>/dev/null || true
  oc get vmi "$vm" -n "$NAMESPACE" -o json > "$VM_DIR/vmi.json" 2>/dev/null || true

  # Collect node placement and labels (deduplicated across VMs)
  vm_node=$(oc get vmi "$vm" -n "$NAMESPACE" -o jsonpath='{.status.nodeName}' 2>/dev/null)
  if [ -n "$vm_node" ] && [ -z "${SEEN_NODES[$vm_node]+_}" ]; then
    NODE_DIR="$OUTPUT_DIR/pre-flight/nodes/$vm_node"
    ensure_dir "$NODE_DIR"
    oc get node "$vm_node" -o json 2>/dev/null | \
      jq '{name: .metadata.name, labels: .metadata.labels}' > "$NODE_DIR/labels.json" 2>/dev/null || true
    SEEN_NODES[$vm_node]=1
  fi

  # Stage script + stream-aware dependencies if requested
  if [ "$STAGE" -eq 1 ]; then
    local_script="$SCRIPT_DIR/collect-windows-guest-info.ps1"
    local_verdict="$SCRIPT_DIR/lib/Get-StreamDriverVerdict.ps1"
    local_export="$SCRIPT_DIR/lib/Export-RemediationArtifact.ps1"
    local_thresholds="$SCRIPT_DIR/../shared/virtio-win-thresholds.json"
    if [ ! -f "$local_script" ]; then
      red "  [ERROR] Cannot find $local_script for staging"
      FAILED=$((FAILED + 1))
      continue
    fi
    if [ ! -f "$local_verdict" ]; then
      red "  [ERROR] Cannot find $local_verdict for staging"
      FAILED=$((FAILED + 1))
      continue
    fi
    if [ ! -f "$local_export" ]; then
      red "  [ERROR] Cannot find $local_export for staging"
      FAILED=$((FAILED + 1))
      continue
    fi
    if [ ! -f "$local_thresholds" ]; then
      red "  [ERROR] Cannot find $local_thresholds for staging"
      FAILED=$((FAILED + 1))
      continue
    fi
    # Ensure C:\DebugInfo\lib exists on the guest before writing, with a
    # restrictive ACL (L-9).
    if ! harden_guest_staging_dir "$NAMESPACE" "$pod" "$domain"; then
      red "  [ERROR] Could not secure $GUEST_OUT_DIR on $vm -- refusing to stage"
      FAILED=$((FAILED + 1))
      continue
    fi
    log "  Staging script to guest: $GUEST_SCRIPT_PATH"
    if ! qga_file_write "$NAMESPACE" "$pod" "$domain" "$local_script" "$GUEST_SCRIPT_PATH"; then
      red "  [ERROR] Failed to stage script to $vm -- aborting this VM"
      FAILED=$((FAILED + 1))
      continue
    fi
    log "  Staging verdict helper: C:\\DebugInfo\\lib\\Get-StreamDriverVerdict.ps1"
    if ! qga_file_write "$NAMESPACE" "$pod" "$domain" "$local_verdict" \
         "C:\\DebugInfo\\lib\\Get-StreamDriverVerdict.ps1"; then
      red "  [ERROR] Failed to stage verdict helper to $vm -- aborting this VM"
      FAILED=$((FAILED + 1))
      continue
    fi
    # Issue J: collect-windows-guest-info.ps1 dot-sources this unconditionally
    # (same as the verdict helper above), so it must be staged on every run,
    # not only when -Remediate/-Export is actually used.
    log "  Staging export helper: C:\\DebugInfo\\lib\\Export-RemediationArtifact.ps1"
    if ! qga_file_write "$NAMESPACE" "$pod" "$domain" "$local_export" \
         "C:\\DebugInfo\\lib\\Export-RemediationArtifact.ps1"; then
      red "  [ERROR] Failed to stage export helper to $vm -- aborting this VM"
      FAILED=$((FAILED + 1))
      continue
    fi
    log "  Staging thresholds: C:\\DebugInfo\\virtio-win-thresholds.json"
    if ! qga_file_write "$NAMESPACE" "$pod" "$domain" "$local_thresholds" \
         "C:\\DebugInfo\\virtio-win-thresholds.json"; then
      red "  [ERROR] Failed to stage thresholds JSON to $vm -- aborting this VM"
      FAILED=$((FAILED + 1))
      continue
    fi
  fi

  # Execute the collection script inside the guest
  log "  Executing collect-windows-guest-info.ps1 in guest (timeout: ${QGA_TIMEOUT}s)..."
  qga_args=("powershell.exe" "-ExecutionPolicy" "Bypass" "-NonInteractive" "-File" "$GUEST_SCRIPT_PATH")
  if [ -n "$FLEET_OCP_VER" ]; then
    qga_args+=("-OCPVersion" "$FLEET_OCP_VER")
  fi
  if [ "$INCLUDE_SENSITIVE" -eq 1 ]; then
    qga_args+=("-IncludeSensitiveData")
    log "  [SENSITIVE] IncludeSensitiveData enabled for $vm (MEMORY.DMP may be collected)"
  fi
  # Issue J: --export takes precedence and needs no --confirm-remediate --
  # validated above to be mutually exclusive-safe (it still requires
  # --remediate itself). Dual-confirm is enforced above for the in-place
  # path: -Remediate is only ever passed there when both flags are set.
  if [ -n "$EXPORT_FMT" ]; then
    qga_args+=("-Remediate" "-Export" "$EXPORT_FMT")
    log "  [EXPORT] Export mode ($EXPORT_FMT) enabled for $vm -- read-only, no guest mutation"
  elif [ "$REMEDIATE" -eq 1 ] && [ "$CONFIRM_REMEDIATE" -eq 1 ]; then
    qga_args+=("-Remediate")
    log "  [REMEDIATE] Remediation mode enabled for $vm"
  fi
  # Pre-flight: confirm the collector is actually ON the guest before exec'ing
  # it. Without --stage this script's documented prerequisite is that
  # collect-windows-guest-info.ps1 was staged to C:\DebugInfo\ beforehand, and
  # when it has not been, powershell.exe simply returns -1 and every artifact
  # read that follows prints "cannot open ...". That output describes the
  # SYMPTOM (no files) and never the CAUSE (no script), so the operator's most
  # likely first-run mistake produced 14 lines of noise pointing nowhere.
  # Diagnosed exactly that way on a live 5-VM fleet: 4 guests had no script and
  # the run reported "script may not have completed" for all of them.
  #
  # Only checked when STAGE=0 -- with --stage we just wrote the file and a
  # failed write already aborts the VM above with its own error.
  if [ "$STAGE" -eq 0 ]; then
    script_present=$(qga_exec "$NAMESPACE" "$pod" "$domain" \
      "cmd.exe" "/c" "if exist \"$GUEST_SCRIPT_PATH\" (exit 0) else (exit 1)")
    if [ "$script_present" != "0" ]; then
      red "  [FAIL] $GUEST_SCRIPT_PATH is not present on $vm"
      echo "         The collector was never staged to this guest, so there is"
      echo "         nothing to execute. Re-run with --stage to upload it:"
      echo "           $0 --namespace $NAMESPACE --vm $vm --stage"
      echo "         (or stage it yourself if guest-file-write is unavailable)."
      FAILED=$((FAILED + 1))
      continue
    fi
  fi

  exit_code=$(qga_exec "$NAMESPACE" "$pod" "$domain" "${qga_args[@]}")

  if [ "$exit_code" = "ERROR: failed to start guest exec" ]; then
    red "  [FAIL] QGA exec failed on $vm"
    FAILED=$((FAILED + 1))
    continue
  fi
  if [ "$exit_code" = "TIMEOUT" ]; then
    red "  [TIMEOUT] collect-windows-guest-info.ps1 did not report completion within ${QGA_TIMEOUT}s on $vm."
    red "  [TIMEOUT] The guest process may still be running (e.g. slow CollectSystemInfo.ps1 on a large system) --"
    red "  [TIMEOUT] re-run with a larger --timeout, or check the guest directly, before assuming a hang/failure."
    FAILED=$((FAILED + 1))
    continue
  fi
  log "  Script exit code: $exit_code"

  # Retrieve artifacts
  DEST="$OUTPUT_DIR/pre-flight/vms/$NAMESPACE/$vm/guest"
  ensure_dir "$DEST"

  retrieved=0
  for artifact in "${GUEST_ARTIFACTS[@]}"; do
    guest_file="${GUEST_OUT_DIR}\\${artifact}"
    local_file="$DEST/$artifact"
    if qga_file_read "$NAMESPACE" "$pod" "$domain" "$guest_file" "$local_file" 2>/dev/null; then
      retrieved=$((retrieved + 1))
      log "  Retrieved: $artifact"
    fi
  done

  # --- Size-guarded retrieval of the CollectSystemInfo.ps1 SystemInfo_*.zip bundle ---
  # This bundle is guest-resident only by default -- it is NOT in GUEST_ARTIFACTS
  # above because its name is timestamped (not a fixed filename) and, with
  # -IncludeSensitiveData, it embeds MEMORY.DMP and can be many GB. qga_file_read
  # streams over one `oc exec` per 64KB chunk and buffers the whole base64 payload
  # in memory -- safe for a few hundred MB, not safe (or fast) for a multi-GB dump.
  # We discover the bundle's actual size first and only auto-retrieve under
  # $MAX_DUMP_MB; otherwise we leave it on the guest and print a manual-retrieval
  # command (KCS-7128506 / see "Guest Data & Sensitive Dumps" in the runbook).
  if [ "$INCLUDE_SENSITIVE" -eq 1 ]; then
    log "  Locating CollectSystemInfo.ps1 output (SystemInfo_*.zip) in $GUEST_OUT_DIR..."
    # NOTE: uses PowerShell string concatenation (+), not the "$($f.Foo)"
    # subexpression syntax -- the latter needs each inner '$' escaped
    # separately for bash, which is easy to get wrong. ShellCheck (SC2154)
    # caught an earlier draft that left one '$f' unescaped, so bash tried to
    # interpolate its own undefined $f variable instead of passing it
    # through to PowerShell literally.
    zip_info=$(qga_exec_capture "$NAMESPACE" "$pod" "$domain" "powershell.exe" \
      "-NonInteractive" "-Command" \
      "\$f = Get-ChildItem -Path '${GUEST_OUT_DIR}' -Filter 'SystemInfo_*.zip' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1; if (\$f) { Write-Output (\$f.FullName + '|' + \$f.Length) }")
    zip_info_rc=$?
    if [ "$zip_info_rc" -eq 2 ]; then
      # rc=2 is qga_exec_capture's explicit timeout signal (distinct from
      # rc=1's "ran fine, no output" / "not found") -- see its definition.
      amber "  [TIMEOUT] SystemInfo_*.zip discovery did not complete within ${QGA_TIMEOUT}s on $vm -- guest may be"
      amber "  [TIMEOUT] slow/unresponsive. This is NOT the same as 'no dump found'; re-check manually or re-run"
      amber "  [TIMEOUT] with a larger --timeout before assuming no sensitive-data bundle exists."
    elif [ -n "${zip_info:-}" ] && [[ "$zip_info" == *"|"* ]]; then
      zip_path="${zip_info%|*}"
      zip_bytes="${zip_info##*|}"
      zip_bytes="${zip_bytes//[$'\r\n' ]/}"
      if [[ "$zip_bytes" =~ ^[0-9]+$ ]]; then
        zip_mb=$((zip_bytes / 1048576))
      else
        zip_mb=-1
      fi
      if [ "$zip_mb" -ge 0 ] && [ "$zip_mb" -le "$MAX_DUMP_MB" ]; then
        log "  Found $zip_path (${zip_mb}MB, <= ${MAX_DUMP_MB}MB threshold) -- retrieving..."
        zip_local="$DEST/SystemInfo.zip"
        if qga_file_read "$NAMESPACE" "$pod" "$domain" "$zip_path" "$zip_local" 2>/dev/null; then
          retrieved=$((retrieved + 1))
          log "  Retrieved: SystemInfo.zip (from $zip_path)"
        else
          amber "  [WARN] Found $zip_path but retrieval failed -- retrieve manually (see below)"
        fi
      else
        amber "  [WARN] $zip_path is ${zip_mb}MB (> ${MAX_DUMP_MB}MB threshold or unknown size) -- leaving on guest."
        amber "  [WARN] Sensitive data (may include MEMORY.DMP) remains guest-resident at $zip_path on VM $vm."
        amber "  [WARN] QGA guest-file-read cannot safely transfer a file this large (chunked over many oc exec"
        amber "  [WARN] round-trips, buffered in memory) -- there is no pod-filesystem path to 'oc cp' from, since"
        amber "  [WARN] this file lives inside the Windows guest disk, not the virt-launcher pod. Retrieve it via a"
        amber "  [WARN] path with a real bulk-transfer channel instead: RDP/console file copy, a mapped SMB/network"
        amber "  [WARN] share from inside the guest, or re-run with a larger --max-dump-mb if you accept the QGA"
        amber "  [WARN] transfer time/memory cost. Delete the guest-side copy after retrieval to avoid leaving"
        amber "  [WARN] sensitive data (MEMORY.DMP may contain guest secrets/credentials) on the VM indefinitely."
      fi
    else
      log "  No SystemInfo_*.zip found in $GUEST_OUT_DIR (CollectSystemInfo.ps1 may not have run yet, or ran to a different OutDir)."
    fi
  fi

  # Persist QGA metadata alongside guest artifacts
  jq -n \
    --arg ver "$qga_version" \
    --arg pod_name "$pod" \
    --arg dom "$domain" \
    --arg node "${vm_node:-}" \
    --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{qga_version:$ver, pod:$pod_name, domain:$dom, node:$node, collected_at:$ts}' \
    > "$DEST/qga_info.json" 2>/dev/null || true

  if [ $retrieved -gt 0 ]; then
    green "  [OK] Collected $retrieved artifact(s) from $vm -> $DEST"
    SUCCESS=$((SUCCESS + 1))
  else
    amber "  [WARN] No artifacts retrieved from $vm (script may not have completed)"
    FAILED=$((FAILED + 1))
  fi
  echo ""
done

# --- Stop VMs that were started by --start-halted ---
if [ ${#STARTED_VMS[@]} -gt 0 ]; then
  log "Stopping ${#STARTED_VMS[@]} VM(s) that were started by --start-halted..."
  for i in "${!STARTED_VMS[@]}"; do
    svm="${STARTED_VMS[$i]}"
    if command -v virtctl >/dev/null 2>&1; then
      virtctl stop "$svm" -n "$NAMESPACE" 2>/dev/null
    elif [ "${STARTED_VMS_LEGACY[$i]:-0}" = "1" ]; then
      oc patch vm "$svm" -n "$NAMESPACE" --type merge -p '{"spec":{"running":false}}' 2>/dev/null
    else
      oc patch vm "$svm" -n "$NAMESPACE" --type merge -p '{"spec":{"runStrategy":"Halted"}}' 2>/dev/null
    fi
    log "  Stopped: $svm"
  done
fi

echo "=============================================================="
echo " QGA Fleet Collection Summary"
echo "   Total VMs: $TOTAL"
echo "   Success: $SUCCESS"
echo "   Failed/Skipped: $FAILED"
if [ ${#STARTED_VMS[@]} -gt 0 ]; then
echo "   Started/Stopped: ${#STARTED_VMS[@]} (via --start-halted)"
fi
echo "=============================================================="
echo ""
echo "Next steps:"
echo "  1. Run analysis: python3 insights-rules/analyze.py --input $OUTPUT_DIR"
echo "  2. Or integrate into must-gather: export BSOD_QGA_COLLECT=1"

[ $FAILED -gt 0 ] && exit 1
exit 0
