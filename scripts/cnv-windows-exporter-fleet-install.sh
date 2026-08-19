#!/usr/bin/env bash
# cnv-windows-exporter-fleet-install.sh -- Zero-touch windows_exporter install via QEMU Guest Agent
#
# Stages windows-exporter/install-windows-exporter.ps1 (+ its dependent helper
# scripts, mirroring the repo's relative directory layout) into running
# Windows VMs via QGA guest-file-write, executes it, then runs the BSOD
# textfile collector once and restarts the service so config.yaml takes
# effect. No RDP/console access or guest-side networking config required.
#
# Prerequisites:
#   - QEMU Guest Agent installed and running inside the Windows VM
#   - oc logged in to the cluster; jq installed
#
# Usage:
#   ./cnv-windows-exporter-fleet-install.sh --namespace <ns> --vm <vm> [OPTIONS]
#   ./cnv-windows-exporter-fleet-install.sh --namespace <ns> --all-windows [OPTIONS]
#
# Output: a per-VM OK/FAIL status line to stdout plus a TSV summary
#         (see --status-file).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

COMMON="$SCRIPT_DIR/../must-gather/collection-scripts/common_bsod.sh"
if [ -f "$COMMON" ]; then
  # shellcheck source=SCRIPTDIR/../must-gather/collection-scripts/common_bsod.sh
  source "$COMMON"
else
  log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"; }
  # R-10 (v0.19.0 unified review U-09): this fallback previously read
  #   oc get vm -n "$1" -o jsonpath='{.items[*].metadata.name}'
  # which applies NO Windows filter whatsoever -- it returns every VM in the
  # namespace. This script installs and executes windows_exporter inside each
  # returned guest via QGA, so in standalone mode (common_bsod.sh absent) it
  # would attempt a Windows MSI install against Linux VMs.
  #
  # Of the three Windows-selector drifts found at v0.19.0 this was the worst:
  # the other two omitted a clause, this one omitted the contract entirely.
  # Now an EMBEDDED COPY of the canonical selector in
  # shared/windows-vm-selector.json, held byte-identical by
  # scripts/ci/validate-windows-vm-selector.py.
  get_windows_vms() {
    oc get vm -n "$1" -o json 2>/dev/null | jq -r '
      .items[]
      | select(
          (.spec.template.metadata.annotations["vm.kubevirt.io/os"] // "" | test("windows|win2k|win10|win11|win2016|win2019|win2022|win2025|win7|win8|win81|winxp";"i"))
          or (.spec.template.metadata.labels["vm.kubevirt.io/template"] // "" | test("windows|win2k|win10|win11|win2016|win2019|win2022|win2025|win7|win8|win81|winxp";"i"))
          or (.metadata.labels["vm.kubevirt.io/template"] // "" | test("windows|win2k|win10|win11|win2016|win2019|win2022|win2025|win7|win8|win81|winxp";"i"))
          or (.metadata.labels["vm.kubevirt.io/os"] // "" | test("windows|win2k|win10|win11|win2016|win2019|win2022|win2025|win7|win8|win81|winxp";"i"))
          or (.spec.template.spec.domain.features.hyperv != null)
          or (.metadata.name | test("(^|[^a-z])win(dows|web|sql|app|dc|ad|rdp|rds|srv|term|fs|print|host|share|dns|dhcp|xp)?([^a-z]|[0-9]|$)";"i"))
        )
      | .metadata.name'
  }
fi

# --- Defaults ---
NAMESPACE=""
VM_NAME=""
ALL_WINDOWS=0
OCP_VERSION=""
QGA_TIMEOUT=500
STATUS_FILE=""
DRY_RUN=0
WIDEN_FIREWALL=0
CONFIRM_WIDEN_FIREWALL=0
POD_NETWORK_CIDR=""

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
amber() { printf '\033[33m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }

validate_k8s_name() {
  local label="$1" value="$2"
  if [ -z "$value" ]; then return 0; fi
  if [[ ! "$value" =~ ^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$ ]]; then
    red "ERROR: invalid $label '$value' (allowed: alphanumeric, '.', '_', '-'; must start/end alphanumeric)"
    exit 2
  fi
}

# R-15 (v0.19.0 unified review U-13): POD_NETWORK_CIDR is interpolated into a
# PowerShell -Command string that runs as SYSTEM inside the guest via QGA:
#
#     Set-NetFirewallRule ... -RemoteAddress '$POD_NETWORK_CIDR'
#
# A single-quote breakout in that value therefore yields arbitrary PowerShell in
# every targeted Windows guest. VM and namespace names were already run through
# validate_k8s_name(); this one was not -- and it is the only one of the three
# that can also arrive from `oc get network.config` rather than the CLI, so
# "it's operator-supplied, they'd only hurt themselves" does not hold either.
#
# Validated STRUCTURALLY (dotted quad + prefix length, each octet 0-255, prefix
# 0-32) rather than by blocklisting quotes: an allowlist of the only shape this
# value may legitimately take cannot be bypassed by an escaping trick.
validate_cidr() {
  local label="$1" value="$2"
  if [ -z "$value" ]; then return 0; fi
  if [[ ! "$value" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
    red "ERROR: invalid $label '$value' (expected IPv4 CIDR, e.g. 10.128.0.0/14)"
    exit 2
  fi
  local ip="${value%%/*}" prefix="${value##*/}"
  local IFS=.
  local -a octets
  read -ra octets <<< "$ip"
  local o
  for o in "${octets[@]}"; do
    if [ "$o" -gt 255 ]; then
      red "ERROR: invalid $label '$value' (octet $o exceeds 255)"
      exit 2
    fi
  done
  if [ "$prefix" -gt 32 ]; then
    red "ERROR: invalid $label '$value' (prefix /$prefix exceeds /32)"
    exit 2
  fi
}

usage() {
  cat <<EOF
Usage: $0 --namespace <ns> [--vm <name> | --all-windows] [OPTIONS]

Options:
  --namespace <ns>          Target namespace (required)
  --vm <name>                Specific VM to install on
  --all-windows               Install on all running, QGA-connected Windows VMs
  --ocp-version <ver>          Passed to the installer for stream-aware bsod_virtio_driver_outdated (e.g. 4.18)
  --timeout <sec>             QGA exec timeout per command (default: 500 -- MSI download+install can take minutes)
  --status-file <path>        Write a VM<TAB>STATUS<TAB>detail TSV summary here
  --widen-firewall            After install, widen the exporter's firewall rule to -Profile Any (see below)
  --confirm-widen-firewall     Double-opt-in required alongside --widen-firewall
  --pod-network-cidr <cidr>    CIDR to scope the widened rule's -RemoteAddress to (default: auto-detected via
                               'oc get network.config cluster')
  --dry-run                   List target VMs without installing anything
  -h, --help                  Show this help

Cloned/unjoined Windows VMs on masquerade networking report NetConnectionProfile
= Public (not Private/Domain), so install-windows-exporter.ps1's default
-FirewallProfile Domain,Private rule never matches inbound Prometheus scrapes
from the pod network -- they fail with "context deadline exceeded", not
"connection refused". --widen-firewall re-scopes the rule to -Profile Any
while still restricting -RemoteAddress to the pod network CIDR, so exposure
stays bounded to cluster-internal traffic. This is a real (if scoped) increase
in network exposure, hence the explicit double opt-in -- see
windows-exporter/README.md's "Security Considerations" section before using
it against anything other than a disposable lab VM.
EOF
  exit 0
}

while [ $# -gt 0 ]; do
  case "$1" in
    --namespace|-n)         NAMESPACE="$2"; shift 2 ;;
    --vm)                   VM_NAME="$2"; shift 2 ;;
    --all-windows)          ALL_WINDOWS=1; shift ;;
    --ocp-version)          OCP_VERSION="$2"; shift 2 ;;
    --timeout)               QGA_TIMEOUT="$2"; shift 2 ;;
    --status-file)          STATUS_FILE="$2"; shift 2 ;;
    --widen-firewall)        WIDEN_FIREWALL=1; shift ;;
    --confirm-widen-firewall) CONFIRM_WIDEN_FIREWALL=1; shift ;;
    --pod-network-cidr)      POD_NETWORK_CIDR="$2"; shift 2 ;;
    --dry-run)                DRY_RUN=1; shift ;;
    -h|--help)               usage ;;
    *)                       red "Unknown option: $1"; exit 2 ;;
  esac
done

[ -z "$NAMESPACE" ] && { red "Error: --namespace is required"; usage; }
if [ -z "$VM_NAME" ] && [ "$ALL_WINDOWS" -eq 0 ]; then
  red "Error: specify --vm <name> or --all-windows"
  exit 2
fi
if [ "$WIDEN_FIREWALL" -eq 1 ] && [ "$CONFIRM_WIDEN_FIREWALL" -eq 0 ]; then
  red "ERROR: --widen-firewall requires --confirm-widen-firewall."
  red "  This widens the windows_exporter (TCP 9182) firewall rule's profile to Any"
  red "  on every targeted VM. Read the note in --help before proceeding."
  exit 2
fi

validate_k8s_name "namespace" "$NAMESPACE"
validate_k8s_name "vm" "$VM_NAME"
validate_cidr "--pod-network-cidr" "$POD_NETWORK_CIDR"

if ! command -v oc >/dev/null 2>&1; then red "oc is required"; exit 2; fi
if ! command -v jq >/dev/null 2>&1; then red "jq is required"; exit 2; fi

find_launcher_pod() {
  local ns="$1" vm="$2"
  oc get pods -n "$ns" -l "kubevirt.io/domain=$vm" \
    --field-selector=status.phase=Running \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null
}

get_domain_name() {
  local ns="$1" pod="$2"
  local dom
  dom=$(oc exec -n "$ns" "$pod" -c compute -- \
    bash -c 'virsh list --name 2>/dev/null | grep -v "^$" | head -1' 2>/dev/null)
  [ -z "$dom" ] && dom="1"
  echo "$dom"
}

check_qga() {
  local ns="$1" pod="$2" domain="$3"
  oc exec -n "$ns" "$pod" -c compute -- \
    virsh qemu-agent-command "$domain" '{"execute":"guest-info"}' 2>/dev/null | \
    jq -r '.return.version // empty' 2>/dev/null
}

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
  local elapsed=0 status_json="" exited="false"
  while [ $elapsed -lt "$QGA_TIMEOUT" ]; do
    sleep 3
    elapsed=$((elapsed + 3))
    local status_cmd
    status_cmd=$(jq -n --argjson pid "$pid" '{"execute":"guest-exec-status","arguments":{"pid":$pid}}')
    status_json=$(oc exec -n "$ns" "$pod" -c compute -- \
      virsh qemu-agent-command "$domain" "$status_cmd" 2>/dev/null)
    exited=$(echo "$status_json" | jq -r '.return.exited // false')
    [ "$exited" = "true" ] && break
  done
  if [ "$exited" != "true" ]; then echo "TIMEOUT"; return 1; fi
  echo "$status_json" | jq -r '.return.exitcode // -1'
}

# Files created via guest-file-open/write can come back with an empty
# (deny-all) DACL regardless of the parent directory's inherited permissions
# -- observed live (a file staged this way ended up with zero ACEs while a
# sibling staged the same way in a different directory did not). Grant
# SYSTEM + Administrators on each staged file directly rather than relying on
# inheritance from the containing directory.
qga_file_write() {
  local ns="$1" pod="$2" domain="$3" local_path="$4" guest_path="$5"
  local open_json
  open_json=$(jq -n --arg p "$guest_path" '{"execute":"guest-file-open","arguments":{"path":$p,"mode":"w"}}')
  local handle_result
  handle_result=$(oc exec -n "$ns" "$pod" -c compute -- \
    virsh qemu-agent-command "$domain" "$open_json" 2>/dev/null)
  local handle
  handle=$(echo "$handle_result" | jq -r '.return // empty')
  [ -z "$handle" ] && { echo "ERROR: cannot open $guest_path for write" >&2; return 1; }
  local b64_content expected_bytes
  b64_content=$(base64 -w 0 < "$local_path")
  expected_bytes=$(wc -c < "$local_path" | tr -d ' ')
  local write_json
  write_json=$(jq -n --argjson h "$handle" --arg b "$b64_content" \
    '{"execute":"guest-file-write","arguments":{"handle":$h,"buf-b64":$b}}')
  # R-16 (v0.19.0 unified review U-14): CAPTURE the write result.
  #
  # This discarded it (>/dev/null) and returned the outer `oc exec` status, so a
  # QGA-level rejection or a SHORT WRITE reported success -- and this script then
  # went on to EXECUTE the staged content in the guest under PowerShell. A
  # truncated installer or textfile collector fails in ways that look like a
  # guest problem rather than a staging problem.
  #
  # The hardened logic already existed in the sibling
  # cnv-qga-fleet-collect.sh (M-9), with regression coverage in
  # tests/test_qga_primitives.sh; it was never ported to this duplicate.
  local write_result
  write_result=$(oc exec -n "$ns" "$pod" -c compute -- \
    virsh qemu-agent-command "$domain" "$write_json" 2>/dev/null)
  local close_json
  close_json=$(jq -n --argjson h "$handle" '{"execute":"guest-file-close","arguments":{"handle":$h}}')
  oc exec -n "$ns" "$pod" -c compute -- \
    virsh qemu-agent-command "$domain" "$close_json" >/dev/null 2>&1

  local written
  written=$(echo "$write_result" | jq -r '.return.count // empty' 2>/dev/null)
  if [ -z "$written" ]; then
    echo "ERROR: guest-file-write to $guest_path returned no byte count (QGA may have rejected the write)" >&2
    return 1
  fi
  if [ "$written" -ne "$expected_bytes" ]; then
    echo "ERROR: short write to $guest_path -- guest reported $written of $expected_bytes byte(s)" >&2
    return 1
  fi
  return 0
}

# --- Determine target VMs (running + QGA-connected only) ---
if [ -n "$VM_NAME" ]; then
  candidate_vms="$VM_NAME"
else
  # R-10 follow-up: there used to be a THIRD branch here --
  #   oc get vm -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}'
  # -- reached when get_windows_vms was undefined. Like the fallback definition
  # at the top of this file, it applied NO Windows filter and returned every VM
  # in the namespace, which this script then installs and executes a Windows MSI
  # into via QGA. It is removed rather than fixed: get_windows_vms is now always
  # defined (sourced from common_bsod.sh, or the embedded canonical selector),
  # so the branch was unreachable dead code carrying a live footgun.
  #
  # It also escaped scripts/ci/validate-windows-vm-selector.py, which matches
  # jq `select(...)` bodies -- a jsonpath one-liner has no select() to find.
  # That validator now also rejects unfiltered `oc get vm` name extraction.
  candidate_vms=$(get_windows_vms "$NAMESPACE")
fi
[ -z "$candidate_vms" ] && { red "No Windows VMs found in namespace $NAMESPACE"; exit 1; }

if [ "$WIDEN_FIREWALL" -eq 1 ] && [ -z "$POD_NETWORK_CIDR" ]; then
  POD_NETWORK_CIDR=$(oc get network.config cluster -o jsonpath='{.spec.clusterNetwork[0].cidr}' 2>/dev/null)
  if [ -z "$POD_NETWORK_CIDR" ]; then
    red "ERROR: --widen-firewall was requested but could not auto-detect the pod network CIDR."
    red "  Pass --pod-network-cidr explicitly."
    exit 2
  fi
  # Validated even though it came from the API: this is defence in depth, and
  # the value still ends up inside a PowerShell -Command string either way.
  validate_cidr "auto-detected pod network CIDR" "$POD_NETWORK_CIDR"
  log "Auto-detected pod network CIDR for firewall widening: $POD_NETWORK_CIDR"
fi

[ -n "$STATUS_FILE" ] && : > "$STATUS_FILE"

TOTAL=0
SUCCESS=0
FAILED=0
SKIPPED=0

for VM in $candidate_vms; do
  TOTAL=$((TOTAL + 1))
  echo "=== $VM: starting ==="

  if [ "$DRY_RUN" -eq 1 ]; then
    green "  [DRY-RUN] Would install windows_exporter on $VM"
    SUCCESS=$((SUCCESS + 1))
    continue
  fi

  POD=$(find_launcher_pod "$NAMESPACE" "$VM")
  if [ -z "$POD" ]; then
    amber "  [SKIP] No running virt-launcher pod for $VM"
    [ -n "$STATUS_FILE" ] && echo -e "$VM\tSKIP\tno-pod" >> "$STATUS_FILE"
    SKIPPED=$((SKIPPED + 1))
    continue
  fi
  DOMAIN=$(get_domain_name "$NAMESPACE" "$POD")

  qga_version=$(check_qga "$NAMESPACE" "$POD" "$DOMAIN")
  if [ -z "$qga_version" ]; then
    amber "  [SKIP] QEMU Guest Agent not responding on $VM"
    [ -n "$STATUS_FILE" ] && echo -e "$VM\tSKIP\tno-qga" >> "$STATUS_FILE"
    SKIPPED=$((SKIPPED + 1))
    continue
  fi

  qga_exec "$NAMESPACE" "$POD" "$DOMAIN" "cmd.exe" "/c" \
    "mkdir C:\\ProgramData\\windows_exporter 2>nul & mkdir C:\\Temp\\windows-exporter 2>nul & mkdir C:\\Temp\\scripts\\lib 2>nul & mkdir C:\\Temp\\shared 2>nul" >/dev/null

  # R-17 (v0.19.0 unified review U-15): harden the staging DIRECTORIES here --
  # immediately after mkdir and BEFORE any file is written into them.
  #
  # These paths are created with inherited ACLs from C:\, which on a default
  # Windows install leaves BUILTIN\Users able to create and modify files. The
  # previous order was mkdir -> write every file -> harden each file, so between
  # the first write and the last per-file icacls there was a window in which an
  # unprivileged guest process could replace or pre-create staged content that
  # this script then EXECUTES as SYSTEM. Per-file hardening also cannot fix a
  # directory a low-privileged user already owns, because an owner can rewrite
  # any DACL applied afterwards.
  #
  # Mirrors harden_guest_staging_dir() in cnv-qga-fleet-collect.sh and
  # Protect-GuestStagingDir.ps1: reclaim ownership FIRST (an owner outranks the
  # DACL), then /inheritance:r to drop the inherited Users ACE, then /grant:r so
  # re-running is idempotent. (OI)(CI) propagates to files created later, which
  # is what makes this a fix rather than a narrowing of the race.
  #
  # icacls.exe is invoked directly with the path as its own argv element -- never
  # inside a quoted `cmd.exe /c` string. QEMU-GA escapes argv with MSVCRT
  # `\"` rules that cmd.exe's /c parser does not honour, and the mis-parse is
  # SILENT: some builtin still runs and exits 0 having touched no ACL.
  for _stage_dir in "C:\\ProgramData\\windows_exporter" "C:\\Temp\\windows-exporter" \
                    "C:\\Temp\\scripts" "C:\\Temp\\shared"; do
    qga_exec "$NAMESPACE" "$POD" "$DOMAIN" \
      "C:\\Windows\\System32\\icacls.exe" "$_stage_dir" "/setowner" "*S-1-5-32-544" "/T" "/C" >/dev/null 2>&1  # _STAGE_DIR_MARKER
    qga_exec "$NAMESPACE" "$POD" "$DOMAIN" \
      "C:\\Windows\\System32\\icacls.exe" "$_stage_dir" "/inheritance:r" \
      "/grant:r" "*S-1-5-18:(OI)(CI)(F)" \
      "/grant:r" "*S-1-5-32-544:(OI)(CI)(F)" "/T" "/C" >/dev/null 2>&1
  done

  # install-windows-exporter.ps1 dot-sources ..\scripts\lib\Protect-GuestStagingDir.ps1
  # relative to $PSScriptRoot -- the guest layout must mirror the repo layout
  # (windows-exporter/ and scripts/lib/ as siblings) or the install aborts
  # with CommandNotFoundException before it does anything else.
  declare -A STAGE_MAP=(
    ["$REPO_DIR/windows-exporter/bsod-textfile-collector.ps1"]='C:\ProgramData\windows_exporter\bsod-textfile-collector.ps1'
    ["$REPO_DIR/windows-exporter/install-windows-exporter.ps1"]='C:\Temp\windows-exporter\install-windows-exporter.ps1'
    ["$REPO_DIR/scripts/lib/Protect-GuestStagingDir.ps1"]='C:\Temp\scripts\lib\Protect-GuestStagingDir.ps1'
    ["$REPO_DIR/scripts/lib/Get-StreamDriverVerdict.ps1"]='C:\Temp\scripts\lib\Get-StreamDriverVerdict.ps1'
    ["$REPO_DIR/shared/virtio-win-thresholds.json"]='C:\Temp\shared\virtio-win-thresholds.json'
  )
  stage_ok=1
  for local_f in "${!STAGE_MAP[@]}"; do
    guest_f="${STAGE_MAP[$local_f]}"
    if [ ! -f "$local_f" ]; then
      red "  [ERROR] missing local file $local_f"
      stage_ok=0
      break
    fi
    # guest-file-open in write ("w") mode can fail with "Access is denied" on
    # a pre-existing file even when SYSTEM holds Full Control on it -- observed
    # live re-running this script against an already-installed VM (the file's
    # DACL from the prior install apparently degrades to zero entries over
    # time, cause unconfirmed). Deleting first sidesteps needing write access
    # to the *old* file's (possibly broken) DACL -- delete only needs an
    # unbroken ACL on the containing directory, which Protect-GuestStagingDir
    # keeps hardened with (OI)(CI) SYSTEM+Administrators Full Control. Makes
    # re-running this script against already-installed VMs idempotent.
    #
    # IMPORTANT: pass the guest path as its OWN argv element below, never
    # embedded inside a pre-quoted command *string* (e.g. never build
    # "del /f /q \"$guest_f\""). None of our guest paths contain spaces, so
    # they don't need quoting -- and if you add literal double-quotes around
    # a path inside a single cmd.exe /c string that also needs re-quoting
    # (has spaces/wraps a redirection), QEMU-GA's argv-to-command-line
    # escaping (assumes standard MSVCRT \"-escaping) and cmd.exe's own /c
    # string parser (which does NOT honor \" as an escape -- every literal "
    # just toggles quote-mode, backslash is never special to it) disagree
    # with each other. Confirmed live: `dir "C:\ProgramData\windows_exporter"`
    # sent this way comes back "The filename, directory name, or volume label
    # syntax is incorrect" even though the identical path *unquoted*, or
    # passed as a separate argv element, works fine. This silently broke the
    # per-file icacls grant below on some VMs (icacls still exited 0, since
    # the mis-parsed command line just invoked a builtin that itself no-ops
    # on empty/malformed args, not a real error) while leaving the ACL
    # unfixed.
    qga_exec "$NAMESPACE" "$POD" "$DOMAIN" "cmd.exe" "/c" "del" "/f" "/q" "$guest_f" >/dev/null
    if ! qga_file_write "$NAMESPACE" "$POD" "$DOMAIN" "$local_f" "$guest_f"; then
      red "  [ERROR] staging $(basename "$local_f") to $VM"
      stage_ok=0
      break
    fi
    # A plain `icacls /grant:r` here is not enough: a file written via
    # guest-file-open/write can come back with a DACL so broken that even
    # SYSTEM lacks WRITE_DAC to add a grant to it (confirmed live -- a bare
    # /grant:r silently no-ops, and install-windows-exporter.ps1's own
    # Protect-GuestStagingDir call later fails on the same file with "Access
    # is denied" trying to re-ACL it). /setowner first reclaims ownership via
    # SeTakeOwnershipPrivilege (which SYSTEM always holds, independent of the
    # existing DACL), and owning the file grants the WRITE_DAC needed for the
    # /inheritance:r /grant:r that follows -- the same two-step order
    # harden_guest_staging_dir() (this file's directory-level sibling, above)
    # and Protect-GuestStagingDir.ps1 both already use for exactly this
    # reason. Invoke icacls.exe directly (path as its own argv element, no
    # cmd.exe, no embedded quotes) rather than through a cmd.exe /c string --
    # see the del comment above for why the latter is unsafe.
    qga_exec "$NAMESPACE" "$POD" "$DOMAIN" \
      "C:\\Windows\\System32\\icacls.exe" "$guest_f" "/setowner" "*S-1-5-18" "/C" >/dev/null
    qga_exec "$NAMESPACE" "$POD" "$DOMAIN" \
      "C:\\Windows\\System32\\icacls.exe" "$guest_f" "/inheritance:r" \
      "/grant:r" "*S-1-5-18:F" "/grant:r" "*S-1-5-32-544:F" "/C" >/dev/null
  done
  unset STAGE_MAP
  if [ "$stage_ok" != "1" ]; then
    [ -n "$STATUS_FILE" ] && echo -e "$VM\tFAIL\tstage-failed" >> "$STATUS_FILE"
    FAILED=$((FAILED + 1))
    continue
  fi

  echo "  running installer (this can take 1-3 min: MSI download + install)..."
  installer_args=("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" \
    "-NoProfile" "-ExecutionPolicy" "Bypass" "-File" "C:\\Temp\\windows-exporter\\install-windows-exporter.ps1")
  if [ -n "$OCP_VERSION" ]; then
    installer_args+=("-OCPVersion" "$OCP_VERSION")
  fi
  RC=$(qga_exec "$NAMESPACE" "$POD" "$DOMAIN" "${installer_args[@]}")
  echo "  installer exit=$RC"

  if [ "$RC" != "0" ]; then
    red "  [FAIL] installer FAILED (exit=$RC) on $VM"
    [ -n "$STATUS_FILE" ] && echo -e "$VM\tFAIL\texit-$RC" >> "$STATUS_FILE"
    FAILED=$((FAILED + 1))
    continue
  fi

  qga_exec "$NAMESPACE" "$POD" "$DOMAIN" \
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" \
    "-NoProfile" "-ExecutionPolicy" "Bypass" "-File" "C:\\ProgramData\\windows_exporter\\bsod-textfile-collector.ps1" >/dev/null
  qga_exec "$NAMESPACE" "$POD" "$DOMAIN" \
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" \
    "-NoProfile" "-Command" "Restart-Service windows_exporter" >/dev/null

  if [ "$WIDEN_FIREWALL" -eq 1 ]; then
    fw_rc=$(qga_exec "$NAMESPACE" "$POD" "$DOMAIN" \
      "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" \
      "-NoProfile" "-Command" \
      "Set-NetFirewallRule -DisplayName 'windows_exporter (TCP 9182)' -Profile Any -RemoteAddress '$POD_NETWORK_CIDR'")
    if [ "$fw_rc" != "0" ]; then
      amber "  [WARN] firewall widen failed (exit=$fw_rc) on $VM -- exporter installed but may not be reachable"
    else
      log "  firewall rule widened to -Profile Any -RemoteAddress $POD_NETWORK_CIDR"
    fi
  fi

  green "  [OK] $VM: windows_exporter installed + collector run + service restarted"
  [ -n "$STATUS_FILE" ] && echo -e "$VM\tOK\t0" >> "$STATUS_FILE"
  SUCCESS=$((SUCCESS + 1))
done

echo "=============================================================="
echo " windows_exporter Fleet Install Summary"
echo "   Total VMs: $TOTAL"
echo "   Success: $SUCCESS"
echo "   Failed: $FAILED"
echo "   Skipped (no pod / no QGA): $SKIPPED"
echo "=============================================================="

[ $FAILED -gt 0 ] && exit 1
exit 0
